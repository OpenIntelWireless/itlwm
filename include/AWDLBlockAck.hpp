#pragma once
// Reading a peer's ADDBA request and writing the answer, for the -itlawdlba probe.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace ItlAWDL {

constexpr uint16_t kBaWindowMax = 64;
constexpr size_t kAddbaResponseLength = 33;

struct AddbaRequest {
    uint8_t peer[6], bssid[6];
    uint8_t token, tid;
    bool immediate;
    bool amsdu;   // the peer may send A-MSDUs inside this session's A-MPDUs (parameter bit 0)
    uint16_t window, ssn;
};

// The listener has one peer station. Coalesce repeats per TID while retaining
// requests for other TIDs, including those waiting for a DELBA to finish.
struct PendingAddbaRequests {
    bool empty() const { return !pending; }
    // The peer the waiting requests are from (they are all from one), or null.
    const uint8_t *peer() const { return pending ? requests[__builtin_ctz(pending)].peer : nullptr; }
    bool has(unsigned tid) const { return tid < 8 && (pending & (1U << tid)); }
    void clear() { pending = 0; }
    void discard(unsigned tid) {
        if (has(tid))
            pending &= uint8_t(~(1U << tid));
    }
    void keepPeer(const uint8_t *peer) {
        if (pending && memcmp(requests[__builtin_ctz(pending)].peer, peer, 6))
            clear();
    }
    bool note(const AddbaRequest &request) {
        if (!request.immediate || request.tid >= 8 ||
            (pending && memcmp(requests[__builtin_ctz(pending)].peer, request.peer, 6)))
            return false;
        requests[request.tid] = request;
        pending |= uint8_t(1U << request.tid);
        return true;
    }
    bool take(uint8_t blocked, AddbaRequest &request) {
        const unsigned ready = pending & ~blocked;
        if (!ready)
            return false;
        const unsigned tid = __builtin_ctz(ready);
        request = requests[tid];
        discard(tid);
        return true;
    }

private:
    uint8_t pending = 0;
    AddbaRequest requests[8]{};
};

// A management action frame to `own`: category 3 (Block Ack), action 0 (ADDBA request).
inline bool parseAddbaRequest(const uint8_t *f, size_t length, const uint8_t *own, AddbaRequest *out) {
    if (!f || !own || !out || length < 33 || f[0] != 0xd0 || memcmp(f + 4, own, 6) || f[24] != 3 || f[25] != 0)
        return false;
    const uint16_t params = uint16_t(f[27] | f[28] << 8);
    const uint16_t sequenceControl = uint16_t(f[31] | f[32] << 8);
    const unsigned tid = (params >> 2) & 15U;
    if (tid >= 8)
        return false;
    memcpy(out->peer, f + 10, 6);
    memcpy(out->bssid, f + 16, 6);
    out->token = f[26];
    out->tid = uint8_t(tid);
    out->immediate = params & 2U;
    out->amsdu = params & 1U;
    const uint16_t asked = params >> 6;
    out->window = !asked || asked > kBaWindowMax ? kBaWindowMax : asked;
    out->ssn = sequenceControl >> 4;
    return true;
}

// Exactly the frames written here, an answer or a request, for the send path's check on monitor frames.
inline bool isAddbaFrame(const uint8_t *f, size_t length) {
    return f && length == kAddbaResponseLength && f[0] == 0xd0 && f[24] == 3 && (f[25] == 0 || f[25] == 1);
}
// Asks `peer` for a session to send to it: immediate, no A-MSDU, no timeout. The same length as an answer.
// `offerAmsdu` (-itlawdlamsdutx): parameter bit 0, we may send A-MSDUs inside this session's A-MPDUs; the peer's answer
// says whether it accepts them (AddbaAnswer::amsdu). Off, the frame is byte-for-byte as before.
inline size_t buildAddbaRequest(uint8_t *out, size_t capacity, const uint8_t *peer, const uint8_t *own, const uint8_t *bssid,
                                uint8_t token, uint8_t tid, uint16_t window, uint16_t startSequence, uint16_t sequence,
                                bool offerAmsdu = false) {
    if (!out || !peer || !own || !bssid || capacity < kAddbaResponseLength || tid >= 8)
        return 0;
    memset(out, 0, kAddbaResponseLength);
    out[0] = 0xd0;
    memcpy(out + 4, peer, 6);
    memcpy(out + 10, own, 6);
    memcpy(out + 16, bssid, 6);
    const uint16_t sequenceControl = uint16_t(sequence << 4);
    out[22] = uint8_t(sequenceControl);
    out[23] = uint8_t(sequenceControl >> 8);
    out[24] = 3;
    out[25] = 0;
    out[26] = token;
    const uint16_t params = uint16_t((offerAmsdu ? 1U : 0U) | 2U | unsigned(tid) << 2 | unsigned(window) << 6);
    out[27] = uint8_t(params);
    out[28] = uint8_t(params >> 8);
    // Bytes 29 and 30 are timeout 0.
    const uint16_t start = uint16_t(startSequence << 4);
    out[31] = uint8_t(start);
    out[32] = uint8_t(start >> 8);
    return kAddbaResponseLength;
}
struct AddbaAnswer {
    uint8_t token, tid;
    uint16_t status, window;
    bool immediate; // Block Ack policy bit: immediate (the only kind supported) when set.
    bool amsdu;     // parameter bit 0: the peer accepts A-MSDUs inside A-MPDUs from us (only meaningful if we offered)
};
// The peer's answer to our request: category 3, action 1, to `own`.
inline bool parseAddbaAnswer(const uint8_t *f, size_t length, const uint8_t *own, AddbaAnswer *out) {
    if (!f || !own || !out || length < 33 || f[0] != 0xd0 || memcmp(f + 4, own, 6) || f[24] != 3 || f[25] != 1)
        return false;
    out->token = f[26];
    out->status = uint16_t(f[27] | f[28] << 8);
    const uint16_t params = uint16_t(f[29] | f[30] << 8);
    out->tid = uint8_t((params >> 2) & 15U);
    out->window = params >> 6;
    out->immediate = params & 2U;
    out->amsdu = params & 1U;
    return true;
}
// A peer ending a session: category 3, action 2. `peerWasSender` says which direction: true is its
// session for sending to us, false is ours for sending to it.
inline bool parseDelba(const uint8_t *f, size_t length, const uint8_t *own, bool *peerWasSender, uint8_t *tid) {
    if (!f || !own || !peerWasSender || !tid || length < 28 || f[0] != 0xd0 || memcmp(f + 4, own, 6) ||
        f[24] != 3 || f[25] != 2)
        return false;
    const uint16_t params = uint16_t(f[26] | f[27] << 8);
    *peerWasSender = params & (1U << 11);
    *tid = uint8_t(params >> 12);
    return true;
}
// Turns a plain data frame into a QoS one for this TID. Returns the new length, or 0 if it doesn't fit.
inline size_t buildQosData(const uint8_t *in, size_t length, uint8_t tid, uint16_t sequence, uint8_t *out, size_t capacity) {
    if (!in || !out || length < 24 || in[0] != 0x08 || capacity < length + 2)
        return 0;
    memcpy(out, in, 24);
    out[0] = 0x88;
    const uint16_t sequenceControl = uint16_t(sequence << 4);
    out[22] = uint8_t(sequenceControl);
    out[23] = uint8_t(sequenceControl >> 8);
    out[24] = tid & 7U;
    out[25] = 0;
    memcpy(out + 26, in + 24, length - 24);
    return length + 2;
}

// Ends a Block Ack session: category 3, action 2. `weOriginated` sets the initiator bit (we set the session
// up); `reason` is an 802.11 reason code (39, timeout, for an idle session). 30 bytes.
constexpr size_t kDelbaLength = 30;
inline size_t buildDelba(uint8_t *out, size_t capacity, const uint8_t *peer, const uint8_t *own, const uint8_t *bssid,
                         uint8_t tid, bool weOriginated, uint16_t reason, uint16_t sequence) {
    if (!out || !peer || !own || !bssid || capacity < kDelbaLength || tid >= 8)
        return 0;
    memset(out, 0, kDelbaLength);
    out[0] = 0xd0;
    memcpy(out + 4, peer, 6);
    memcpy(out + 10, own, 6);
    memcpy(out + 16, bssid, 6);
    const uint16_t sequenceControl = uint16_t(sequence << 4);
    out[22] = uint8_t(sequenceControl);
    out[23] = uint8_t(sequenceControl >> 8);
    out[24] = 3;
    out[25] = 2;
    const uint16_t params = uint16_t((weOriginated ? 1U << 11 : 0U) | unsigned(tid) << 12);
    out[26] = uint8_t(params);
    out[27] = uint8_t(params >> 8);
    out[28] = uint8_t(reason);
    out[29] = uint8_t(reason >> 8);
    return kDelbaLength;
}
// A TX response reclaims `freed` slots from `tail` on an `n`-slot ring, and its status belongs to the slot whose
// low 8 bits match the header index. Returns that slot (the newest match), or -1 if none is in the range.
inline int reclaimStatusSlot(int tail, int freed, int n, uint8_t headerIndex) {
    if (n <= 0 || freed <= 0 || freed > n || tail < 0 || tail >= n)
        return -1;
    for (int k = freed - 1; k >= 0; --k) {
        const int slot = (tail + k) % n;
        if (uint8_t(slot) == headerIndex)
            return slot;
    }
    return -1;
}
inline bool isDelbaFrame(const uint8_t *f, size_t length) {
    return f && length == kDelbaLength && f[0] == 0xd0 && f[24] == 3 && f[25] == 2;
}

// Accepts with no timeout, or refuses with `status` (37: request declined, for example when the firmware has no room
// for another session). A-MSDU is allowed only if the peer asked for it and `allowAmsdu` (-itlawdlamsdurx): the
// firmware splits received A-MSDUs into their MSDUs, as on the station's path. Returns the length written, or 0 if
// it doesn't fit.
constexpr uint16_t kAddbaDeclined = 37;
inline size_t buildAddbaResponse(uint8_t *out, size_t capacity, const AddbaRequest &request, const uint8_t *own, uint16_t sequence,
                                 uint16_t status = 0, bool allowAmsdu = false) {
    if (!out || !own || capacity < kAddbaResponseLength)
        return 0;
    memset(out, 0, kAddbaResponseLength);
    out[0] = 0xd0;
    memcpy(out + 4, request.peer, 6);
    memcpy(out + 10, own, 6);
    memcpy(out + 16, request.bssid, 6);
    const uint16_t sequenceControl = uint16_t(sequence << 4);
    out[22] = uint8_t(sequenceControl);
    out[23] = uint8_t(sequenceControl >> 8);
    out[24] = 3;
    out[25] = 1;
    out[26] = request.token;
    out[27] = uint8_t(status);
    out[28] = uint8_t(status >> 8);
    const uint16_t params = uint16_t((!status && allowAmsdu && request.amsdu ? 1U : 0U) | 2U |
                                     unsigned(request.tid) << 2 | unsigned(request.window) << 6);
    out[29] = uint8_t(params);
    out[30] = uint8_t(params >> 8);
    // Bytes 31 and 32 are timeout 0, none.
    return kAddbaResponseLength;
}

// With the promiscuous filter off, Block Acks reach the peer, but starting a send gets unreliable.
// So the filter comes off only while a lot of data is arriving, and goes back on when it stops.
constexpr uint64_t kBaFilterCheckUS = 1000000;
// Busy is low on purpose: with a session open and the filter on, the peer's frames go unacknowledged,
// so even setting up a send has to turn it off.
constexpr uint32_t kBaFilterBusyFrames = 16, kBaFilterQuietFrames = 8, kBaFilterQuietChecks = 3;
struct BaFilterState {
    uint64_t lastCheckUS;
    uint32_t lastFrames, quietChecks;
    bool off;
};
// Call often. Returns true when the filter should change, and `off` already holds the new state.
inline bool noteBaFilterTraffic(BaFilterState &s, uint64_t nowUS, uint32_t frames) {
    if (!s.lastCheckUS) {
        s.lastCheckUS = nowUS;
        s.lastFrames = frames;
        return false;
    }
    if (nowUS - s.lastCheckUS < kBaFilterCheckUS)
        return false;
    const uint32_t delta = frames - s.lastFrames;
    s.lastCheckUS = nowUS;
    s.lastFrames = frames;
    if (!s.off) {
        s.quietChecks = 0;
        if (delta < kBaFilterBusyFrames)
            return false;
        s.off = true;
        return true;
    }
    if (delta >= kBaFilterQuietFrames) {
        s.quietChecks = 0;
        return false;
    }
    if (++s.quietChecks < kBaFilterQuietChecks)
        return false;
    s.quietChecks = 0;
    s.off = false;
    return true;
}

// The Mac's A-MPDU path only while a bulk send is running. Short exchanges, such as setting up a
// connection, stay on the monitor queue, where the driver resends a frame lost while the peer is
// away. The firmware's A-MPDU queue doesn't, and those exchanges stalled through it.
constexpr uint32_t kBaTxBulkFrames = 200, kBaTxQuietFrames = 40, kBaTxQuietChecks = 2;
struct BaTxBulkState {
    uint64_t lastCheckUS;
    uint32_t lastFrames, quietChecks;
    bool bulk;
};
// `frames` counts unicast data frames to the peer, on either path. Returns true on a change.
// Coexistence can recognize the same frame rate on a shorter entry sample.
inline bool noteBaTxTraffic(BaTxBulkState &s, uint64_t nowUS, uint32_t frames, bool fastEntry = false) {
    constexpr uint64_t fastEntryUS = kBaFilterCheckUS / 4;
    const bool shortSample = fastEntry && !s.bulk;
    const uint64_t sampleUS = shortSample ? fastEntryUS : kBaFilterCheckUS;
    const uint32_t entryFrames = shortSample ? kBaTxBulkFrames / 4 : kBaTxBulkFrames;
    if (!s.lastCheckUS) {
        s.lastCheckUS = nowUS;
        s.lastFrames = frames;
        return false;
    }
    if (nowUS - s.lastCheckUS < sampleUS)
        return false;
    const uint32_t delta = frames - s.lastFrames;
    s.lastCheckUS = nowUS;
    s.lastFrames = frames;
    if (!s.bulk) {
        s.quietChecks = 0;
        if (delta < entryFrames)
            return false;
        s.bulk = true;
        return true;
    }
    if (delta >= kBaTxQuietFrames) {
        s.quietChecks = 0;
        return false;
    }
    if (++s.quietChecks < kBaTxQuietChecks)
        return false;
    s.quietChecks = 0;
    s.bulk = false;
    return true;
}

// What a peer's data frames to us look like: how many are new, and how they're grouped. A long
// run of retries or repeats means the peer isn't hearing that its frames arrived.
struct RxSequenceCounts {
    uint32_t frames, fresh, repeats, retryBit, retryBitFresh, duplicatesDropped, aggregates, ampduFrames, noQos;
    uint64_t allBytes, freshBytes;
};
struct RxSequenceTracker {
    static constexpr unsigned kTids = 8, kSequences = 4096;
    uint8_t seen[kTids][kSequences / 8];
    bool toggleKnown, lastToggle;
    RxSequenceCounts counts;
    // Returns whether this sequence number is new for this TID. A number leaves the record once
    // the sequence has moved on by half its range, so wrapping round reads as new.
    bool note(unsigned tid, uint16_t sequence, bool retry, size_t length) {
        counts.allBytes += length;
        ++counts.frames;
        if (retry)
            ++counts.retryBit;
        if (tid >= kTids)
            tid = 0;
        sequence &= kSequences - 1;
        const uint8_t bit = uint8_t(1U << (sequence & 7U));
        uint8_t &entry = seen[tid][sequence >> 3];
        if (entry & bit) {
            ++counts.repeats;
            return false;
        }
        entry |= bit;
        const unsigned opposite = (sequence + kSequences / 2) & (kSequences - 1);
        seen[tid][opposite >> 3] &= uint8_t(~(1U << (opposite & 7U)));
        ++counts.fresh;
        counts.freshBytes += length;
        if (retry)
            ++counts.retryBitFresh;
        return true;
    }
    // The firmware flips the toggle for each aggregate.
    void noteAmpdu(bool toggle) {
        ++counts.ampduFrames;
        if (!toggleKnown || toggle != lastToggle)
            ++counts.aggregates;
        toggleKnown = true;
        lastToggle = toggle;
    }
};

}  // namespace ItlAWDL
