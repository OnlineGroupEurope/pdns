/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnssecinfra.hh"
#include "namespaces.hh"

#include "md5.hh"
#include "dnsseckeeper.hh"
#include "dns_random.hh"
#include "lock.hh"
#include "arguments.hh"
#include "statbag.hh"
extern StatBag S;

static pthread_rwlock_t g_signatures_lock = PTHREAD_RWLOCK_INITIALIZER;
typedef map<pair<string, string>, string> signaturecache_t;
static array<signaturecache_t, 128> g_signatures;
static array<uint32_t, 128> g_cacheweekno;

AtomicCounter* g_signatureCount;

static void fillOutRRSIG(DNSSECPrivateKey& dpk, const DNSName& signQName, RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& toSign
    uint32_t startOfWeekOffset, uint32_t startOfWeek, uint32_t weekNumber)
{
  if(!g_signatureCount)
    g_signatureCount = S.getPointer("signatures");

  DNSKEYRecordContent drc = dpk.getDNSKEY();
  const std::shared_ptr<DNSCryptoKeyEngine> rc = dpk.getKey();
  rrc.d_tag = drc.getTag();
  rrc.d_algorithm = drc.d_algorithm;

  string msg=getMessageForRRSET(signQName, rrc, toSign); // this is what we will hash & sign
  pair<string, string> lookup(rc->getPubKeyHash(), pdns_md5sum(msg));  // this hash is a memory saving exercise

  bool doCache=1;
  uint32_t cacheChunk = startOfWeekOffset / (86400*8/128);
  if(cacheChunk > 128)
  {
    // This shouldn't happen but better be safe than sorry..
    L<<Logger::Error<<"Invalid startOfWeekOffset detected - skipping cache!"<<endl;
    doCache = 0;
  }

  if(doCache)
  {
    ReadLock l(&g_signatures_lock);
    signaturecache_t::const_iterator iter = g_signatures[cacheChunk].find(lookup);
    if(iter != g_signatures[cacheChunk].end()) {
      rrc.d_signature=iter->second;
      return;
    }
    // else cerr<<"Miss!"<<endl;
  }

  rrc.d_signature = rc->sign(msg);
  (*g_signatureCount)++;
  if(doCache) {
    const static int maxcachesize=::arg().asNum("max-signature-cache-entries", INT_MAX);

    WriteLock l(&g_signatures_lock);
    if(g_cacheweekno[cacheChunk] < weekNumber || g_signatures[cacheChunk].size() >= (uint) maxcachesize / 128) { // blunt but effective (C) Habbie, mind04
      L<<Logger::Warning<<"Cleared signature cache chunk "<<cacheChunk<<endl;
      g_signatures[cacheChunk].clear();
      g_cacheweekno[cacheChunk] = weekNumber;
    }
    g_signatures[cacheChunk][lookup] = rrc.d_signature;
  }
}

/* this is where the RRSIGs begin, keys are retrieved,
   but the actual signing happens in fillOutRRSIG */
static int getRRSIGsForRRSET(DNSSECKeeper& dk, const DNSName& signer, const DNSName signQName, uint16_t signQType, uint32_t signTTL,
                             vector<shared_ptr<DNSRecordContent> >& toSign, vector<RRSIGRecordContent>& rrcs)
{
  if(toSign.empty())
    return -1;

  uint32_t startOfWeekOffset = getStartOfWeekOffset(signer);
  uint32_t starOfWeek, weekNumber;
  tie(startOfWeek, weekNumber) = getStartOfWeek(startOfWeekOffset);

  RRSIGRecordContent rrc;
  rrc.d_type=signQType;

  rrc.d_labels=signQName.countLabels()-signQName.isWildcard();
  rrc.d_originalttl=signTTL; 
  rrc.d_siginception=startOfWeek - 7*86400; // XXX should come from zone metadata
  rrc.d_sigexpire=startOfWeek + 14*86400;
  rrc.d_signer = signer;
  rrc.d_tag = 0;

  DNSSECKeeper::keyset_t keys = dk.getKeys(signer);

  for(DNSSECKeeper::keyset_t::value_type& keymeta : keys) {
    if(!keymeta.second.active)
      continue;

    if((signQType == QType::DNSKEY && keymeta.second.keyType == DNSSECKeeper::ZSK) ||
       (signQType != QType::DNSKEY && keymeta.second.keyType == DNSSECKeeper::KSK)) {
      continue;
    }

    fillOutRRSIG(keymeta.first, signQName, rrc, toSign, startOfWeekOffset, startOfWeek, weekNumber);
    rrcs.push_back(rrc);
  }
  return 0;
}

// this is the entrypoint from DNSPacket
static void addSignature(DNSSECKeeper& dk, UeberBackend& db, const DNSName& signer, const DNSName signQName, const DNSName& wildcardname, uint16_t signQType,
                         uint32_t signTTL, DNSResourceRecord::Place signPlace,
                         vector<shared_ptr<DNSRecordContent> >& toSign, vector<DNSZoneRecord>& outsigned, uint32_t origTTL)
{
  //cerr<<"Asked to sign '"<<signQName<<"'|"<<DNSRecordContent::NumberToType(signQType)<<", "<<toSign.size()<<" records\n";
  if(toSign.empty())
    return;
  vector<RRSIGRecordContent> rrcs;
  if(dk.isPresigned(signer)) {
    //cerr<<"Doing presignatures"<<endl;
    dk.getPreRRSIGs(db, signer, signQName, wildcardname, QType(signQType), signPlace, outsigned, origTTL); // does it all
  }
  else {
    if(getRRSIGsForRRSET(dk, signer, wildcardname.countLabels() ? wildcardname : signQName, signQType, signTTL, toSign, rrcs) < 0)  {
      // cerr<<"Error signing a record!"<<endl;
      return;
    } 
  
    DNSZoneRecord rr;
    rr.dr.d_name=signQName;
    rr.dr.d_type=QType::RRSIG;
    if(origTTL)
      rr.dr.d_ttl=origTTL;
    else
      rr.dr.d_ttl=signTTL;
    rr.auth=false;
    rr.dr.d_place = signPlace;
    for(RRSIGRecordContent& rrc :  rrcs) {
      rr.dr.d_content = std::make_shared<RRSIGRecordContent>(rrc);
      outsigned.push_back(rr);
    }
  }
  toSign.clear();
}

uint64_t signatureCacheSize(const std::string& str)
{
  ReadLock l(&g_signatures_lock);
  uint64_t cacheSize = 0;
  for(int i=0;i<128;i++) {
    cacheSize += g_signatures[i].size()
  }
  return cacheSize;
}

static bool rrsigncomp(const DNSZoneRecord& a, const DNSZoneRecord& b)
{
  return tie(a.dr.d_place, a.dr.d_type) < tie(b.dr.d_place, b.dr.d_type);
}

static bool getBestAuthFromSet(const set<DNSName>& authSet, const DNSName& name, DNSName& auth)
{
  auth.trimToLabels(0);
  DNSName sname(name);
  do {
    if(authSet.find(sname) != authSet.end()) {
      auth = sname;
      return true;
    }
  }
  while(sname.chopOff());
  
  return false;
}

void addRRSigs(DNSSECKeeper& dk, UeberBackend& db, const set<DNSName>& authSet, vector<DNSZoneRecord>& rrs)
{
  stable_sort(rrs.begin(), rrs.end(), rrsigncomp);
  
  DNSName signQName, wildcardQName;
  uint16_t signQType=0;
  uint32_t signTTL=0;
  uint32_t origTTL=0;
  
  DNSResourceRecord::Place signPlace=DNSResourceRecord::ANSWER;
  vector<shared_ptr<DNSRecordContent> > toSign;

  vector<DNSZoneRecord> signedRecords;
  signedRecords.reserve(rrs.size()*1.5);
  //  cout<<rrs.size()<<", "<<sizeof(DNSZoneRecord)<<endl;
  DNSName signer;
  for(auto pos = rrs.cbegin(); pos != rrs.cend(); ++pos) {
    if(pos != rrs.cbegin() && (signQType != pos->dr.d_type  || signQName != pos->dr.d_name)) {
      if(getBestAuthFromSet(authSet, signQName, signer))
        addSignature(dk, db, signer, signQName, wildcardQName, signQType, signTTL, signPlace, toSign, signedRecords, origTTL);
    }
    signedRecords.push_back(*pos);
    signQName= pos->dr.d_name.makeLowerCase();
    if(!pos->wildcardname.empty())
      wildcardQName = pos->wildcardname.makeLowerCase();
    else
      wildcardQName.clear();
    signQType = pos->dr.d_type;
    if(pos->signttl)
      signTTL = pos->signttl;
    else
      signTTL = pos->dr.d_ttl;
    origTTL = pos->dr.d_ttl;
    signPlace = pos->dr.d_place;
    if(pos->auth || pos->dr.d_type == QType::DS) {
      toSign.push_back(pos->dr.d_content); // so ponder.. should this be a deep copy perhaps?
    }
  }
  if(getBestAuthFromSet(authSet, signQName, signer))
    addSignature(dk, db, signer, signQName, wildcardQName, signQType, signTTL, signPlace, toSign, signedRecords, origTTL);
  rrs.swap(signedRecords);
}
