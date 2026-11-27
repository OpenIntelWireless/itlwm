#pragma once
// -itlawdlsvcmerge: a peer spreads its service records (TLV 2) across its frames, while
// IO80211Family only turns them into Bonjour records for about 4 frames after the peer's
// service update indicator (SUI, in TLV 6) changes. A record missing from those frames stays
// missing until the next change. So the records a peer has sent under its current SUI are kept
// here, and any missing from a frame are added before the frame goes to the native stack.
// Nothing here is sent on the air.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace ItlAWDL {

constexpr size_t kActionTlvStart = 40;
// A merged frame stays at or under this, well within the native stack's buffers.
constexpr size_t kServiceMergeFrameMax = 1500;

// The SUI: bytes 3 and 4 of TLV 6's value, little-endian (IO80211Family reads offset 6 from the
// start of the TLV, header included).
inline bool readServiceUpdateIndicator(const uint8_t *f, size_t length, uint16_t *sui) {
    if (!f || !sui || length < kActionTlvStart) return false;
    size_t offset = kActionTlvStart;
    while (length - offset >= 3) {
        const size_t n = size_t(f[offset + 1]) | (size_t(f[offset + 2]) << 8);
        if (n > length - offset - 3) return false;
        if (f[offset] == 6 && n >= 5) {
            *sui = uint16_t(f[offset + 6] | f[offset + 7] << 8);
            return true;
        }
        offset += 3 + n;
    }
    return false;
}

// Whole TLV 2 entries, header included, exactly as the peer sent them.
struct PeerServiceCache {
    static constexpr size_t kBytes = 1536;
    static constexpr unsigned kRecordsMax = 48;
    uint8_t peer[6];
    uint16_t sui;
    bool valid;
    unsigned records;
    size_t used;
    uint16_t offsets[kRecordsMax], lengths[kRecordsMax];
    uint8_t bytes[kBytes];
    uint32_t resets, overflow;

    void clear() { valid = false; records = 0; used = 0; }
    bool holds(const uint8_t *tlv, size_t n) const {
        for (unsigned i = 0; i < records; ++i)
            if (lengths[i] == n && !memcmp(bytes + offsets[i], tlv, n)) return true;
        return false;
    }
    // Records a frame from `from`. Call for every valid action frame from that peer.
    void note(const uint8_t *from, const uint8_t *f, size_t length) {
        uint16_t frameSui = 0;
        if (!from || !readServiceUpdateIndicator(f, length, &frameSui)) return;
        if (!valid || memcmp(peer, from, 6) || frameSui != sui) {
            if (valid) ++resets;
            clear();
            memcpy(peer, from, 6);
            sui = frameSui;
            valid = true;
        }
        size_t offset = kActionTlvStart;
        while (length - offset >= 3) {
            const size_t n = size_t(f[offset + 1]) | (size_t(f[offset + 2]) << 8);
            if (n > length - offset - 3) return;
            if (f[offset] == 2 && !holds(f + offset, 3 + n)) {
                if (records >= kRecordsMax || used + 3 + n > kBytes) {
                    ++overflow;
                } else {
                    offsets[records] = uint16_t(used);
                    lengths[records] = uint16_t(3 + n);
                    memcpy(bytes + used, f + offset, 3 + n);
                    used += 3 + n;
                    ++records;
                }
            }
            offset += 3 + n;
        }
    }
    // Writes `f` with any cached records it lacks added after its last TLV. Only for this
    // peer's frames with TLV 6 and the cached SUI, since the kernel reads TLV 2 only after TLV 6.
    // Returns the new length, or 0 when nothing would be added or it doesn't fit.
    size_t merge(const uint8_t *from, const uint8_t *f, size_t length, uint8_t *out, size_t capacity,
                 unsigned *added) const {
        if (added) *added = 0;
        uint16_t frameSui = 0;
        if (!valid || !from || memcmp(peer, from, 6) || !out || !readServiceUpdateIndicator(f, length, &frameSui) ||
            frameSui != sui)
            return 0;
        // The frame's own TLVs must parse to the end, so the additions land after the last one.
        size_t offset = kActionTlvStart;
        unsigned present = 0;
        bool have[kRecordsMax] = {};
        while (length - offset >= 3) {
            const size_t n = size_t(f[offset + 1]) | (size_t(f[offset + 2]) << 8);
            if (n > length - offset - 3) return 0;
            if (f[offset] == 2) {
                ++present;
                for (unsigned i = 0; i < records; ++i)
                    if (lengths[i] == 3 + n && !memcmp(bytes + offsets[i], f + offset, 3 + n)) have[i] = true;
            }
            offset += 3 + n;
        }
        if (offset != length) return 0;
        size_t extra = 0;
        unsigned count = 0;
        for (unsigned i = 0; i < records; ++i)
            if (!have[i]) { extra += lengths[i]; ++count; }
        // The kernel stops at about 100 TLV 2 entries in one frame.
        if (!count || present + count > 96 || length + extra > capacity) return 0;
        memcpy(out, f, length);
        size_t w = length;
        for (unsigned i = 0; i < records; ++i)
            if (!have[i]) { memcpy(out + w, bytes + offsets[i], lengths[i]); w += lengths[i]; }
        if (added) *added = count;
        return w;
    }
};

}  // namespace ItlAWDL
