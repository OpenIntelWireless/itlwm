// Local AWDL action-frame construction only; no radio submission or scheduling.
// Wire layout cross-checked against the pinned RTW89 reference used by the RX
// parser. The caller supplies its own schedule and native-generated static TLVs.
#pragma once
#include <AWDLFrameParser.hpp>

namespace ItlAWDL {
enum class BuildResult { Invalid, NoSpace, Ready };
struct LocalFrame {
    uint8_t source[6];
    uint8_t receiver[6];
    uint8_t subtype;
    uint16_t sequence;
    uint32_t phyTime;
    uint32_t targetTime;
    const uint8_t *sync;
    size_t syncLength;
    const uint8_t *staticTLVs;
    size_t staticLength;
};

inline void write16(uint8_t *p, uint16_t v) { p[0] = uint8_t(v); p[1] = uint8_t(v >> 8); }
inline void write32(uint8_t *p, uint32_t v)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = uint8_t(v >> (8*i));
}

// Header-only vendor action for a single descriptor/firmware transport probe.
// It advertises no synchronization schedule, identity TLVs or services. Peers
// may discard it; a successful radio completion is not AWDL interoperability.
// The caller's local monotonic time is diagnostic, not a calibrated PHY clock.
inline BuildResult buildTransportProbe(const uint8_t *source, uint32_t time,
                                      uint8_t *output, size_t available, size_t *written)
{
    if (!source || !output || !written) return BuildResult::Invalid;
    uint8_t local[6];
    bool nonzero = false;
    for (unsigned i = 0; i < 6; ++i) { local[i] = source[i]; nonzero |= source[i] != 0; }
    if (!nonzero || (local[0] & 1)) return BuildResult::Invalid;
    if (available < 40) return BuildResult::NoSpace;
    for (unsigned i = 0; i < 40; ++i) output[i] = 0;
    output[0] = 0xd0;
    const uint8_t bssid[6] = {0, 0x25, 0, 0xff, 0x94, 0x73};
    for (unsigned i = 0; i < 6; ++i) {
        output[4+i] = 0xff; // broadcast: do not solicit an ACK from a peer
        output[10+i] = local[i];
        output[16+i] = bssid[i];
    }
    output[24] = 0x7f;
    output[26] = 0x17; output[27] = 0xf2; output[28] = 8;
    output[29] = 0x10; output[30] = 3;
    write32(output+32, time); write32(output+36, time);
    *written = 40;
    return BuildResult::Ready;
}

// All validation precedes writes. Inputs and output must be disjoint; callers
// retain ownership. The result excludes FCS, which the radio would generate.
inline BuildResult buildLocalFrame(const LocalFrame &p, uint8_t *output,
                                  size_t available, size_t *written)
{
    bool nonzero = false, receiverSet = false;
    for (unsigned i = 0; i < 6; ++i) {
        nonzero |= p.source[i] != 0;
        receiverSet |= p.receiver[i] != 0;
    }
    if (!nonzero || !receiverSet || (p.source[0] & 1) || p.sequence > 4095 ||
        (p.subtype != 0 && p.subtype != 3) || !p.sync ||
        p.syncLength < 27 || p.syncLength > 255 || p.staticLength > 1828 ||
        (p.staticLength && !p.staticTLVs) || !output || !written)
        return BuildResult::Invalid;
    // The dedicated synchronization payload is inserted once. Refuse malformed
    // or duplicate synchronization TLVs in the native static-template stream.
    size_t offset = 0;
    while (offset < p.staticLength) {
        if (p.staticLength-offset < 3) return BuildResult::Invalid;
        const size_t length = read16(p.staticTLVs+offset+1);
        if (p.staticTLVs[offset] == 4 || length > p.staticLength-offset-3)
            return BuildResult::Invalid;
        offset += 3+length;
    }
    const size_t required = 43+p.syncLength+p.staticLength;
    if (available < required) return BuildResult::NoSpace;
    for (size_t i = 0; i < required; ++i) output[i] = 0;
    output[0] = 0xd0;
    const uint8_t address[6] = {0, 0x25, 0, 0xff, 0x94, 0x73};
    for (unsigned i = 0; i < 6; ++i) {
        output[4+i] = p.receiver[i];
        output[10+i] = p.source[i];
        output[16+i] = address[i];
    }
    write16(output+22, uint16_t(p.sequence << 4));
    output[24] = 0x7f;
    output[26] = 0x17; output[27] = 0xf2; output[28] = 8;
    output[29] = 0x10; output[30] = p.subtype;
    write32(output+32, p.phyTime); write32(output+36, p.targetTime);
    output[40] = 4; write16(output+41, uint16_t(p.syncLength));
    for (size_t i = 0; i < p.syncLength; ++i) output[43+i] = p.sync[i];
    for (size_t i = 0; i < p.staticLength; ++i)
        output[43+p.syncLength+i] = p.staticTLVs[i];
    *written = required;
    return BuildResult::Ready;
}
} // namespace ItlAWDL
