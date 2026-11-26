// Independent LLC/AWDL/IPv6 payload codec. Wire layout cross-checked against
// seemoo-lab/owl src/frame.h, src/tx.c and src/rx.c. No radio/queue ownership.
#pragma once
#include <AWDLFrameBuilder.hpp>
namespace ItlAWDL {
// minExtension and presence are the two bytes after the AWDL LLC header. macOS fills them per
// frame from its current settings (IO80211 adjustAwdlSnapHeader, 26.7.2: the minimum window
// extension, then the presence mode), so they're reported, not checked.
struct IPv6PayloadView { const uint8_t *bytes; size_t length; uint16_t sequence;
                         uint8_t minExtension, presence; };
inline bool validIPv6Payload(const uint8_t *p, size_t n) {
    // Initial transport supports a 1500-byte IPv6 MTU and no jumbograms.
    return p && n >= 40 && n <= 1500 && (p[0] >> 4) == 6 &&
        ((size_t(p[4]) << 8) | p[5]) == n-40;
}
// Output must be disjoint from input; both remain caller-owned. On rejection,
// neither the destination nor written changes. Excludes 802.11 header and FCS.
inline BuildResult buildIPv6DataPayload(const uint8_t *ip, size_t length,
        uint16_t sequence, uint8_t *output, size_t available, size_t *written) {
    if (!output || !written || !validIPv6Payload(ip,length)) return BuildResult::Invalid;
    if (available < length+16) return BuildResult::NoSpace;
    // 3 and 4: the values macOS sends with its default settings.
    const uint8_t prefix[16] = {0xaa,0xaa,3,0,0x17,0xf2,8,0,3,4,0,0,0,0,0x86,0xdd};
    for(unsigned i=0;i<16;++i) output[i]=prefix[i];
    write16(output+10,sequence);
    for(size_t i=0;i<length;++i) output[16+i]=ip[i];
    *written=16+length;
    return BuildResult::Ready;
}
// A borrowed view, not authorization to deliver a packet. Peer validation,
// replay handling and native buffer ownership belong to the caller.
// Peers put one more LLC header before the AWDL prefix on some frames, most often large
// ones. Seen on the air, not taken from a specification: an empty OUI, then a big-endian
// length of everything after this header.
inline bool hasOuterDataHeader(const uint8_t *frame, size_t length) {
    const uint8_t outer[6]={0xaa,0xaa,3,0,0,0};
    if (!frame || length<8) return false;
    for(unsigned i=0;i<6;++i) if(frame[i]!=outer[i]) return false;
    return true;
}
inline ParseResult parseIPv6DataPayload(const uint8_t *frame, size_t length,
                                      IPv6PayloadView *output) {
    if (!frame || !output || length<16) return ParseResult::Malformed;
    if (hasOuterDataHeader(frame,length)) {
        // A different length could mean several packets in one frame, which isn't handled.
        if (((size_t(frame[6])<<8)|frame[7])!=length-8) return ParseResult::Unsupported;
        frame+=8;length-=8;
        if (length<16) return ParseResult::Malformed;
    }
    const uint8_t llc[8]={0xaa,0xaa,3,0,0x17,0xf2,8,0};
    for(unsigned i=0;i<8;++i) if(frame[i]!=llc[i]) return ParseResult::NotAWDL;
    if (read16(frame+12)!=0 || frame[14]!=0x86 || frame[15]!=0xdd) return ParseResult::Unsupported;
    if (!validIPv6Payload(frame+16,length-16)) return ParseResult::Malformed;
    *output={frame+16,length-16,read16(frame+10),frame[8],frame[9]};
    return ParseResult::Valid;
}
}
