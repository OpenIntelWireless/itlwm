// Allocation-free AWDL action-frame decoding. Wire layout reference:
// FranciumOS-org/Airport_RTW89, 90b6cfc5a69c271688fad188857cfaeb58053dc5,
// src/compat_rtw89/rtw89_awdl.c. This decoder never transmits or changes state.
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ItlAWDL {
enum class ParseResult { NotAWDL, Malformed, Unsupported, Valid };

struct ActionFrame {
    uint8_t subtype;
    uint32_t phyTxTime;
    uint32_t targetTxTime;
    bool hasSync;
    uint8_t nextChannel;
    uint8_t masterChannel;
    uint16_t txDownCounter;
    uint16_t awPeriod;
    uint16_t afPeriod;
    uint16_t remainingAW;
    uint8_t masterAddress[6];
};

inline uint16_t read16(const uint8_t *p)
{
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
}
inline uint32_t read32(const uint8_t *p)
{
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
           (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

// Input is a contiguous 802.11 management frame, without radiotap or FCS.
// On any failure, the caller's output remains untouched.
inline ParseResult parseAction(const uint8_t *frame, size_t length, ActionFrame *output)
{
    if (!frame || !output || length < 29 || frame[0] != 0xd0)
        return ParseResult::NotAWDL;
    const uint8_t bssid[6] = {0x00, 0x25, 0x00, 0xff, 0x94, 0x73};
    for (unsigned i = 0; i < 6; ++i)
        if (frame[16+i] != bssid[i])
            return ParseResult::NotAWDL;
    if (frame[24] != 0x7f || frame[25] != 0 || frame[26] != 0x17 ||
        frame[27] != 0xf2 || frame[28] != 8)
        return ParseResult::NotAWDL;
    // Protected or HT-control-bearing management frames need a different
    // layout/decryption path. Never interpret those bytes as a plain header.
    if ((frame[1] & 0xc7) || (frame[22] & 0x0f))
        return ParseResult::Unsupported;
    if (length < 40)
        return ParseResult::Malformed;
    if (frame[29] != 0x10 || (frame[30] != 0 && frame[30] != 3))
        return ParseResult::Unsupported;
    ActionFrame decoded = {};
    decoded.subtype = frame[30];
    decoded.phyTxTime = read32(frame+32);
    decoded.targetTxTime = read32(frame+36);
    size_t offset = 40;
    while (offset < length) {
        if (length-offset < 3)
            return ParseResult::Malformed;
        const uint8_t type = frame[offset];
        const size_t count = read16(frame+offset+1);
        offset += 3;
        if (count > length-offset)
            return ParseResult::Malformed;
        if (type == 4) {
            // Only the fixed 27-byte synchronization prefix is decoded.
            // An appended channel sequence remains opaque for now.
            if (count < 27 || decoded.hasSync)
                return ParseResult::Malformed;
            const uint8_t *p = frame+offset;
            decoded.hasSync = true;
            decoded.nextChannel = p[0];
            decoded.txDownCounter = read16(p+1);
            decoded.masterChannel = p[3];
            decoded.awPeriod = read16(p+5);
            decoded.afPeriod = read16(p+7);
            decoded.remainingAW = read16(p+15);
            for (unsigned i = 0; i < 6; ++i)
                decoded.masterAddress[i] = p[21+i];
        }
        offset += count;
    }
    *output = decoded;
    return ParseResult::Valid;
}

// Some setups deliver the listener's AWDL action frames with zero padding after the last TLV: 8 bytes
// in every frame on an AX211 8086:51F1 (ThinkPad E16 Gen 3) with an iPhone 16 Pro, issue #6.
// parseAction reads the zeros as empty type-0 TLVs, and the leftover bytes make the frame Malformed.
// This returns the length up to the end of the last TLV that isn't an empty type-0 one, but only when
// the frame doesn't parse as given, every byte after that point is zero, and the shorter frame parses.
// Otherwise it returns length unchanged. It walks the TLVs exactly as parseAction does, and never
// removes anything but zero bytes. Approach and diagnosis by keenerdavid18 (issue #6).
inline size_t trimZeroPadding(const uint8_t *frame, size_t length)
{
    ActionFrame decoded;
    if (!frame || length <= 40 || parseAction(frame, length, &decoded) != ParseResult::Malformed)
        return length;
    size_t offset = 40, end = 40;
    while (length-offset >= 3) {
        const size_t count = read16(frame+offset+1);
        if (count > length-offset-3)
            break;
        if (frame[offset] != 0 || count != 0)
            end = offset+3+count;
        offset += 3+count;
    }
    if (end == 40)
        return length;
    for (size_t i = end; i < length; ++i)
        if (frame[i] != 0)
            return length;
    return parseAction(frame, end, &decoded) == ParseResult::Valid ? end : length;
}

// Captured monitor frames can include FCS; the caller must state the actual
// hardware format. Do not heuristically trim bytes from malformed payloads.
inline ParseResult parseCapturedAction(const uint8_t *frame, size_t capturedLength,
                                      bool includesFCS, ActionFrame *output,
                                      size_t *frameLength)
{
    if (includesFCS && capturedLength < 4)
        return ParseResult::Malformed;
    const size_t length = capturedLength-(includesFCS ? 4 : 0);
    const ParseResult result = parseAction(frame, length, output);
    if (result == ParseResult::Valid && frameLength)
        *frameLength = length;
    return result;
}
} // namespace ItlAWDL
