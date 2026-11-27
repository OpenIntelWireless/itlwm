// Read-only classification of received AWDL frames against our own address.
// Nothing here admits a peer or delivers data. The counters answer one question
// that firmware TX status cannot: did anyone on the air react to our frames?
#pragma once
#include <AWDLDataFrame.hpp>
namespace ItlAWDL {
struct ObservedCounts {
    uint32_t selfEchoes;      // Our own source address came back (not a peer).
    uint32_t actionToUs;      // A peer's action frame had us as receiver.
    uint32_t actionMentions;  // A peer's action frame body carried our address.
    uint32_t dataMulticast;   // Peer IPv6 data to a group address.
    uint32_t dataToUs;        // Peer IPv6 data unicast to us.
    uint32_t dataToOther;     // Peer IPv6 data unicast between other stations.
    uint32_t dataMDNS;        // Subset of the above: IPv6/UDP to port 5353.
    uint32_t dataEchoReply;   // ICMPv6 echo reply from a peer.
    uint32_t dataNeighbor;    // ICMPv6 neighbor advertisement from a peer.
    uint32_t dataSolicit;     // ICMPv6 neighbor solicitation from a peer.
};
struct AckCounts {
    uint32_t acked[7], failed[7], retries[7], lastFailure[7];
};
// index is an AckProbe value. Status 1 is firmware's success; retries come from
// its no-ACK failure count. Out-of-range indexes count nothing.
inline void recordAck(AckCounts &c,int index,unsigned status,unsigned retries) {
    if(index<0 || index>6) return;
    c.retries[index]+=retries;
    if(status==1) ++c.acked[index];
    else { ++c.failed[index]; c.lastFailure[index]=status; }
}
inline bool sameAddress(const uint8_t *a,const uint8_t *b) {
    for(unsigned i=0;i<6;++i) if(a[i]!=b[i]) return false;
    return true;
}
inline bool knownAddress(const uint8_t *a) {
    for(unsigned i=0;i<6;++i) if(a[i]) return true;
    return false;
}
inline bool containsAddress(const uint8_t *bytes,size_t length,const uint8_t *address) {
    if(length<6) return false;
    for(size_t i=0;i<=length-6;++i) if(sameAddress(bytes+i,address)) return true;
    return false;
}
// Frames on the air that bear on ACK behaviour. Monitor mode accepts control
// frames, so raw ACKs may be visible even when firmware doesn't credit them. If
// none are seen, that may only mean firmware doesn't pass them up. A peer's retry
// bit on a frame addressed to us means it did not get our ACK for an earlier try.
// typesToUs is indexed by the frame's type and subtype bits, to identify frames
// that aren't IPv6 data. foreign is an address we never ACK: replies sent to it
// are the control for the retry-bit reading.
struct AirCounts {
    uint32_t ackToAWDL, ackToHardware, unicastToUs, unicastToUsRetried;
    uint32_t ackToForeign, unicastToForeign, unicastToForeignRetried;
    uint32_t typesToUs[64];
};
inline const uint8_t *foreignAddress() {
    static const uint8_t address[6] = {0x02, 0x77, 0x88, 0x99, 0xaa, 0xbb};
    return address;
}
inline void observeAir(AirCounts &c,const uint8_t *f,size_t length,const uint8_t *own,const uint8_t *hardware) {
    if(!f || length<10 || !own || !hardware || !knownAddress(own)) return;
    if(f[0]==0xd4) {
        if(sameAddress(f+4,own)) ++c.ackToAWDL;
        else if(sameAddress(f+4,hardware)) ++c.ackToHardware;
        else if(sameAddress(f+4,foreignAddress())) ++c.ackToForeign;
        return;
    }
    if(length<24 || (f[0]&0x0c)==4) return;
    if(sameAddress(f+4,foreignAddress())) {
        ++c.unicastToForeign;
        if(f[1]&0x08) ++c.unicastToForeignRetried;
        return;
    }
    if(!sameAddress(f+4,own)) return;
    ++c.unicastToUs;
    ++c.typesToUs[(f[0]>>2)&63];
    if(f[1]&0x08) ++c.unicastToUsRetried;
}
// Results per probed peer, so a strong nearby device can be told from others.
struct PeerProbe { uint8_t address[6]; uint32_t acked, tries; int rssi; };
inline void recordPeerProbe(PeerProbe *table,unsigned capacity,unsigned &count,const uint8_t *address,bool acked,int rssi) {
    unsigned i=0;
    while(i<count && !sameAddress(table[i].address,address)) ++i;
    if(i==count) {
        if(count==capacity) return;
        for(unsigned b=0;b<6;++b) table[i].address[b]=address[b];
        table[i].acked=table[i].tries=0;
        ++count;
    }
    ++table[i].tries;
    if(acked) ++table[i].acked;
    table[i].rssi=rssi;
}
// Counts TLV types in a validated plain action frame excluding FCS. A malformed
// stream stops the walk, keeping what was already counted.
inline void countActionTLVs(uint32_t *counts,const uint8_t *frame,size_t length) {
    if(!counts || !frame || length<40) return;
    size_t offset=40;
    while(length-offset>=3) {
        const size_t count=size_t(frame[offset+1])|(size_t(frame[offset+2])<<8);
        if(count>length-offset-3) return;
        ++counts[frame[offset]];
        offset+=3+count;
    }
}
// A digest of every TLV of one type in an action frame, so a change of services shows. Returns
// how many TLVs of that type there were, with their total length in `bytes`.
inline unsigned digestActionTLVs(const uint8_t *frame,size_t length,uint8_t type,uint32_t *digest,uint32_t *bytes) {
    if(!frame || !digest || !bytes || length<40) return 0;
    unsigned n=0;uint32_t h=2166136261U,total=0;
    size_t offset=40;
    while(length-offset>=3) {
        const size_t count=size_t(frame[offset+1])|(size_t(frame[offset+2])<<8);
        if(count>length-offset-3) break;
        if(frame[offset]==type) {
            ++n;total+=uint32_t(count);
            for(size_t i=0;i<count;++i) { h^=frame[offset+3+i];h*=16777619U; }
        }
        offset+=3+count;
    }
    *digest=n?h:0;*bytes=total;
    return n;
}
// A short record of when services changed, ours and the peer's, in order.
struct TlvChange { uint32_t ms; uint8_t fromPeer, count; uint16_t bytes; uint32_t digest; };
struct TlvChangeLog {
    TlvChange entries[96];
    uint32_t total, lastDigest[2];
    void note(uint32_t ms,bool fromPeer,unsigned count,uint32_t bytes,uint32_t digest) {
        const unsigned side=fromPeer?1:0;
        if(total && digest==lastDigest[side]) return;
        lastDigest[side]=digest;
        entries[total%96]=TlvChange{ms,uint8_t(side),uint8_t(count>255?255:count),uint16_t(bytes>65535?65535:bytes),digest};
        ++total;
    }
};
// The contents of TLV 2 each time they change, ours and the peer's. Frames without TLV 2 are
// skipped, since AWDL alternates frames that carry services with frames that don't.
struct ServiceSnapshot { uint32_t ms; uint8_t fromPeer, count; uint16_t length; uint8_t bytes[480]; };
struct ServiceSnapshotLog {
    static constexpr unsigned kEntries = 32;
    ServiceSnapshot entries[kEntries];
    uint32_t total, lastDigest[2];
    bool dirty;
    void note(uint32_t ms,bool fromPeer,const uint8_t *frame,size_t length) {
        uint32_t digest=0,bytes=0;
        const unsigned count=digestActionTLVs(frame,length,2,&digest,&bytes);
        const unsigned side=fromPeer?1:0;
        if(!count || digest==lastDigest[side]) return;
        lastDigest[side]=digest;
        ServiceSnapshot &e=entries[total%kEntries];
        e.ms=ms;e.fromPeer=uint8_t(side);e.count=uint8_t(count>255?255:count);
        // Each TLV 2 value, preceded by its 2-byte length, as far as fits.
        size_t out=0,offset=40;
        while(length-offset>=3) {
            const size_t n=size_t(frame[offset+1])|(size_t(frame[offset+2])<<8);
            if(n>length-offset-3) break;
            if(frame[offset]==2 && out+2<=sizeof(e.bytes)) {
                e.bytes[out++]=uint8_t(n);e.bytes[out++]=uint8_t(n>>8);
                for(size_t i=0;i<n && out<sizeof(e.bytes);++i) e.bytes[out++]=frame[offset+3+i];
            }
            offset+=3+n;
        }
        e.length=uint16_t(out);
        ++total;dirty=true;
    }
};
// frame is a validated plain management frame excluding FCS. Returns true only
// when a different station's frame carried our address in its action body, which
// a station can only do after hearing us. Unknown own address counts nothing.
inline bool observeAction(ObservedCounts &c,const uint8_t *frame,size_t length,const uint8_t *own) {
    if(!frame || length<24 || !own || !knownAddress(own)) return false;
    if(sameAddress(frame+10,own)) { ++c.selfEchoes; return false; }
    if(sameAddress(frame+4,own)) ++c.actionToUs;
    if(!containsAddress(frame+24,length-24,own)) return false;
    ++c.actionMentions;
    return true;
}
// Why a data frame addressed to us didn't become an IPv6 packet. Frames that parseDataFrame
// reports as malformed or unsupported already have counters of their own.
enum class DataSkip : uint8_t { None, Chained, FrameType, Bssid, Llc, Other };
struct DataSkipCounts {
    uint32_t chained, frameType, bssid, llc, other, retried, outerHeader;
    uint32_t skippedLengths[16], parsedLengths[16];
};
inline unsigned dataLengthBin(size_t length) { const size_t bin=length/128; return bin>15?15U:unsigned(bin); }
inline DataSkip dataSkipReason(const uint8_t *f,size_t captured,bool chained,ParseResult parsed) {
    if(chained) return DataSkip::Chained;
    if(parsed!=ParseResult::NotAWDL || !f || captured<28) return DataSkip::None;
    if(f[0]!=0x08 && f[0]!=0x88) return DataSkip::FrameType;
    const uint8_t bssid[6]={0,0x25,0,0xff,0x94,0x73};
    for(unsigned i=0;i<6;++i) if(f[16+i]!=bssid[i]) return DataSkip::Bssid;
    return DataSkip::Llc;
}
inline void noteDataSkip(DataSkipCounts &c,DataSkip reason,const uint8_t *f,size_t totalLength) {
    switch(reason) {
    case DataSkip::None: return;
    case DataSkip::Chained: ++c.chained; break;
    case DataSkip::FrameType: ++c.frameType; break;
    case DataSkip::Bssid: ++c.bssid; break;
    case DataSkip::Llc: ++c.llc; break;
    default: ++c.other; break;
    }
    if(f[1]&0x08) ++c.retried;
    ++c.skippedLengths[dataLengthBin(totalLength)];
}
// How a peer divides its 16 AWDL slots, from TLV 18: a 6-byte header, then pairs of channel
// and flags. The layout comes from captures, so anything else is refused.
struct PeerSlots { uint8_t channel6, channel149, channel44, channel36, off, other; };
inline bool peerSlotsFromAction(const uint8_t *frame, size_t length, PeerSlots *out) {
    if (!frame || !out || length < 40) return false;
    for (size_t i = 40; i + 3 <= length;) {
        const size_t value = size_t(frame[i + 1]) | size_t(frame[i + 2]) << 8;
        if (i + 3 + value > length) return false;
        if (frame[i] == 18) {
            if (value < 6 + 32) return false;
            PeerSlots slots{};
            for (unsigned n = 0; n < 16; ++n) {
                switch (frame[i + 3 + 6 + 2 * n]) {
                case 6: ++slots.channel6; break;
                case 149: ++slots.channel149; break;
                case 44: ++slots.channel44; break;
                case 36: ++slots.channel36; break;
                case 0: ++slots.off; break;
                default: ++slots.other; break;
                }
            }
            *out = slots;
            return true;
        }
        i += 3 + value;
    }
    return false;
}
// Bins of microseconds: under 250, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000, and above.
inline unsigned flightBin(uint64_t us) {
    static const uint32_t limits[9] = {250, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000};
    for (unsigned i = 0; i < 9; ++i) if (us < limits[i]) return i;
    return 9;
}
// Bins of queue depth: 0, 1, 2 to 3, 4 to 7, up to 128 or more.
inline unsigned depthBin(unsigned depth) {
    unsigned bin = 0;
    while (depth && bin < 8) { depth >>= 1; ++bin; }
    return bin;
}
// Counts of the raw firmware rate word on frames addressed to us, to read offline.
struct RxRateEntry { uint32_t rate, count; };
inline void noteRxRate(RxRateEntry *table,unsigned capacity,uint32_t rate,uint32_t &overflow) {
    for(unsigned i=0;i<capacity;++i) {
        if(table[i].count && table[i].rate==rate) { ++table[i].count; return; }
        if(!table[i].count) { table[i]={rate,1}; return; }
    }
    ++overflow;
}

// Where the Mac's single-frame sends spend their time, from the firmware's answer for each one.
// The gap is the time since the previous completion, counted only when this frame was already
// waiting in the firmware then, so it's the firmware's time for this frame alone. Air is the
// firmware's own measure of time on the air, retries included.
inline unsigned airBin(uint32_t us) {
    static const uint32_t limits[7] = {100, 200, 400, 800, 1600, 3200, 6400};
    for (unsigned i = 0; i < 7; ++i) if (us < limits[i]) return i;
    return 7;
}
struct TxServiceStats {
    uint32_t gapBins[10], airBins[8];
    uint64_t gapSumUS, gapAirSumUS, airSumUS;
    uint32_t frames, gapFrames, failureFrames, failureRts, btKills, framesWithRetries;
    uint64_t lastDoneUS;
    bool lastBusy;
    RxRateEntry rates[8];
    uint32_t rateOverflow;
    // What was received during each gap: every frame the radio passed up, and those from the peer.
    // Slow is 500 us or more.
    uint32_t lastRxAll, lastRxPeer;
    uint32_t slowGaps, slowRxAll, slowRxPeer, slowWithPeer, fastGaps, fastRxAll, fastRxPeer, fastWithPeer;
    // `stillWaiting` says whether other frames remain in the firmware after this one. `rxAll` and
    // `rxPeer` are running totals of received frames.
    void note(uint64_t nowUS, bool stillWaiting, uint32_t airUS, uint8_t failedFrames, uint8_t failedRts,
              uint8_t btKill, uint32_t rate, uint32_t rxAll = 0, uint32_t rxPeer = 0) {
        const uint32_t heardAll = rxAll - lastRxAll, heardPeer = rxPeer - lastRxPeer;
        lastRxAll = rxAll;
        lastRxPeer = rxPeer;
        ++frames;
        ++airBins[airBin(airUS)];
        airSumUS += airUS;
        failureFrames += failedFrames;
        failureRts += failedRts;
        btKills += btKill;
        if (failedFrames) ++framesWithRetries;
        if (lastBusy && lastDoneUS && nowUS >= lastDoneUS) {
            const uint64_t gap = nowUS - lastDoneUS;
            ++gapBins[flightBin(gap)];
            gapSumUS += gap;
            gapAirSumUS += airUS;
            ++gapFrames;
            if (gap >= 500) {
                ++slowGaps; slowRxAll += heardAll; slowRxPeer += heardPeer; if (heardPeer) ++slowWithPeer;
            } else {
                ++fastGaps; fastRxAll += heardAll; fastRxPeer += heardPeer; if (heardPeer) ++fastWithPeer;
            }
        }
        noteRxRate(rates, 8, rate, rateOverflow);
        lastDoneUS = nowUS;
        lastBusy = stillWaiting;
    }
};
// A timeline of the first single-frame completions during sustained sending, with the times of the
// peer's frames over the same period, so pauses can be lined up against the clock and the peer.
// Filled once; nothing is overwritten.
struct TxTraceEntry {
    uint32_t doneUS, flightUS;  // Completion time (low 32 bits of uptime), and time since submit.
    uint16_t airUS;
    uint8_t flags;              // 1 frame was waiting at the previous completion, 2 acknowledged, 4 wide rate requested.
    uint8_t inFlight;           // Frames in the window when this one completed, itself included.
};
struct TxTrace {
    static constexpr unsigned kEntries = 4096, kPeerTimes = 4096;
    uint32_t count, peerCount;
    TxTraceEntry entries[kEntries];
    uint32_t peerUS[kPeerTimes];
    bool full() const { return count >= kEntries; }
    // Recording starts with the first completion of a frame that was already waiting.
    void noteCompletion(uint64_t nowUS, uint64_t submitUS, bool waiting, bool acked, bool wide, uint32_t airUS,
                        unsigned inFlight) {
        if (full() || (!count && !waiting)) return;
        TxTraceEntry &e = entries[count++];
        e.doneUS = uint32_t(nowUS);
        const uint64_t flight = nowUS >= submitUS ? nowUS - submitUS : 0;
        e.flightUS = flight > 0xffffffffULL ? 0xffffffffU : uint32_t(flight);
        e.airUS = airUS > 0xffff ? 0xffff : uint16_t(airUS);
        e.flags = uint8_t((waiting ? 1 : 0) | (acked ? 2 : 0) | (wide ? 4 : 0));
        e.inFlight = inFlight > 255 ? 255 : uint8_t(inFlight);
    }
    // Only while the completion timeline is being filled.
    void notePeerFrame(uint64_t nowUS) {
        if (!count || full() || peerCount >= kPeerTimes) return;
        peerUS[peerCount++] = uint32_t(nowUS);
    }
};
// The same for the Mac's A-MPDU path: one entry per Block Ack notification on its queue.
struct BaTraceEntry {
    uint32_t doneUS, wirelessTime, rate;  // Uptime low 32 bits; the firmware's air time and rate fields, raw.
    uint16_t sent, acked;
    uint8_t retries, queuedBefore, queuedAfter, flags;  // Frames in the firmware queue before and after reclaim.
};
struct BaTrace {
    static constexpr unsigned kEntries = 4096;
    uint32_t count;
    BaTraceEntry entries[kEntries];
    bool full() const { return count >= kEntries; }
    void note(uint64_t nowUS, uint32_t wirelessTime, uint32_t rate, unsigned sent, unsigned acked, unsigned retries,
              unsigned queuedBefore, unsigned queuedAfter, uint32_t flags) {
        if (full()) return;
        BaTraceEntry &e = entries[count++];
        e.doneUS = uint32_t(nowUS);
        e.wirelessTime = wirelessTime;
        e.rate = rate;
        e.sent = sent > 0xffff ? 0xffff : uint16_t(sent);
        e.acked = acked > 0xffff ? 0xffff : uint16_t(acked);
        e.retries = retries > 255 ? 255 : uint8_t(retries);
        e.queuedBefore = queuedBefore > 255 ? 255 : uint8_t(queuedBefore);
        e.queuedAfter = queuedAfter > 255 ? 255 : uint8_t(queuedAfter);
        e.flags = uint8_t(flags);
    }
};
inline void observeData(ObservedCounts &c,const DataFrameView &v,const uint8_t *own) {
    const bool known=own && knownAddress(own);
    if(known && sameAddress(v.source,own)) { ++c.selfEchoes; return; }
    if(*v.destination&1) ++c.dataMulticast;
    else if(known && sameAddress(v.destination,own)) ++c.dataToUs;
    else ++c.dataToOther;
    if(v.ip.length>=48 && v.ip.bytes[6]==17 &&
       v.ip.bytes[42]==(5353>>8) && v.ip.bytes[43]==(5353&255)) ++c.dataMDNS;
    if(v.ip.length>=44 && v.ip.bytes[6]==58) {
        if(v.ip.bytes[40]==129) ++c.dataEchoReply;
        else if(v.ip.bytes[40]==136) ++c.dataNeighbor;
        else if(v.ip.bytes[40]==135) ++c.dataSolicit;
    }
}
}
