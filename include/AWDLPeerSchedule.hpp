#pragma once
// -itlawdlpeerpause: when the peer's own schedule has it away from our channel, the driver pauses
// sending to it, so frames wait instead of failing, and the firmware's rate control only sees the
// time the peer is there.
//
// Timing, as our own sync TLV encodes it (AWDLLocalSchedule.hpp, after seemoo-lab/owl): the AW
// counter (sync TLV bytes 29 and 30) goes up once per AW of awPeriod TU, and the down counter
// (bytes 1 and 2) is the TU left in the current extended AW of 4 AWs. Each of the 16 entries in
// the peer's channel sequence (TLV 18) covers one extended AW. Which entry is current is
// eaw % 16 plus an offset that is found from the peer's own frames, not assumed: frames heard on
// our channel can only fall in entries where the peer is on it.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace ItlAWDL {

constexpr unsigned kPeerSeqEntries = 16;
constexpr uint64_t kPeerScheduleStaleUS = 2000000;  // No sync heard for this long: don't pause.
constexpr uint64_t kPeerPauseEarlyUS = 3000;        // Pause this long before the peer leaves.
constexpr uint64_t kPeerResumeLateUS = 1000;        // Resume this long after it returns.
constexpr uint64_t kPeerPauseMaxUS = 150000;        // Longest pause when the away run isn't known.
constexpr uint64_t kPeerPauseCeilingUS = 450000;    // Longest pause even for a long predicted run.
constexpr uint64_t kPeerEdgeUS = 1500;              // Frames this close to an entry edge aren't counted.
constexpr uint32_t kPeerCalibrateFrames = 300;
constexpr uint32_t kPeerCalibrateMaxAwayPercent = 3;
constexpr uint64_t kPeerPhaseJumpUS = 8192;
// iface161: a peer whose sequence has this many entries or fewer on our channel is in an idle schedule
// (Idle 5, Infra Priority 2, Low Power 2 in the phone's logs; data modes have 7, 11 or 15). Unless it sent us
// data recently it is then only reliably awake at the start of each AW.
constexpr unsigned kPeerDozeMaxEntries = 5;

struct PeerSyncInfo {
    uint16_t awCounter, downCounterTU, awPeriodTU;
    uint8_t channels[kPeerSeqEntries];
    // TLV 4's AW extension and common lengths (TU) and presence mode, for the Apple election rules.
    uint16_t awExtTU, awCommonTU;
    uint8_t presenceMode;
};

// Reads the AW counter, down counter and period from TLV 4 and the 16 channels from TLV 18.
// Anything unexpected is refused, and `out` is untouched.
inline bool peerSyncFromAction(const uint8_t *f, size_t length, PeerSyncInfo *out, bool *badSequence = nullptr) {
    if (badSequence) *badSequence = false;
    if (!f || !out || length < 40) return false;
    PeerSyncInfo info{};
    bool haveSync = false, haveSeq = false;
    for (size_t i = 40; i + 3 <= length;) {
        const size_t n = size_t(f[i + 1]) | size_t(f[i + 2]) << 8;
        if (f[i] == 18 && badSequence) *badSequence = true;
        if (i + 3 + n > length) return false;
        const uint8_t *v = f + i + 3;
        if (f[i] == 4 && n >= 31) {
            info.downCounterTU = uint16_t(v[1] | v[2] << 8);
            info.awPeriodTU = uint16_t(v[5] | v[6] << 8);
            info.awCounter = uint16_t(v[29] | v[30] << 8);
            info.awExtTU = uint16_t(v[11] | v[12] << 8);
            info.awCommonTU = uint16_t(v[13] | v[14] << 8);
            info.presenceMode = v[27];
            haveSync = v[27] == 4 && info.awPeriodTU >= 8 && info.awPeriodTU <= 64 &&
                       info.downCounterTU <= uint32_t(info.awPeriodTU) * 4;
        } else if (f[i] == 18) {
            // Accept the two-byte layouts used by the local and captured schedules.
            if (haveSeq || n < 6 + 2 * kPeerSeqEntries || v[0] != kPeerSeqEntries - 1 ||
                (v[1] != 1 && v[1] != 3) || v[2] != 0 || v[3] != 3 || v[4] != 0xff || v[5] != 0xff)
                return false;
            for (unsigned k = 0; k < kPeerSeqEntries; ++k) {
                const uint8_t first = v[6 + 2 * k], second = v[7 + 2 * k];
                if (first == 0xff && second == 0xff) continue;
                const uint8_t channel = v[1] == 1 ? second : first;
                const uint8_t opClass = v[1] == 3 ? second : 0;
                if (channel && (channel > 177 ||
                    (v[1] == 3 && !(channel <= 14 ? opClass >= 81 && opClass <= 84 :
                                                     opClass >= 115 && opClass <= 130))))
                    return false;
                info.channels[k] = channel;
            }
            haveSeq = true;
            if (badSequence) *badSequence = false;
        }
        i += 3 + n;
    }
    if (!haveSync || !haveSeq) return false;
    *out = info;
    return true;
}

struct PeerSchedule {
    bool valid;
    uint64_t heardUS;          // When the anchor was taken.
    uint64_t anchorEndUS;      // End of extended AW anchorEaw.
    uint64_t eawUS;            // Length of an extended AW.
    uint32_t anchorEaw;
    uint8_t channels[kPeerSeqEntries];
    uint8_t ourChannel;
    // Calibration: the peer's frames by eaw % 16, since the sequence last changed.
    uint32_t bins[kPeerSeqEntries], binFrames;
    bool calibrated;
    uint8_t offset;
    uint32_t sequenceChanges, calibrations, decalibrations;
    // Checked after calibration: frames heard during entries that say the peer is away.
    uint32_t checkedFrames, awayFrames;
    uint32_t lastAwayEntry;
    bool multipleAwayEntries;
    // iface161 (-itlawdlcoexcalwait turns it off): the entry is the extended AW number modulo 16, offset 0,
    // as the wire format defines and as every calibration and the phone's own per-entry receive counts
    // found. Pauses and holds may use that before 300 frames have calibrated it. The same check that
    // revokes a calibration refutes the assumption; it then waits for a calibration or a new anchor.
    bool assumeZero;  // Policy, kept across reset().
    bool refuted;
    uint32_t refutations;

    void reset() { const bool a = assumeZero; memset(this, 0, sizeof(*this)); assumeZero = a; }
    // Whether the entry for a time is known: calibrated, or assumed at offset 0 and not refuted.
    bool known() const { return calibrated || (assumeZero && !refuted); }
    uint8_t entryOffset() const { return calibrated ? offset : 0; }
    unsigned presentEntries() const {
        unsigned n = 0;
        for (unsigned k = 0; k < kPeerSeqEntries; ++k) n += channels[k] == ourChannel;
        return n;
    }
    void clearEvidence() {
        memset(bins, 0, sizeof(bins));
        binFrames = checkedFrames = awayFrames = 0;
        multipleAwayEntries = false;
    }
    void invalidate() {
        valid = false;
        if (calibrated) ++decalibrations;
        calibrated = false;
        refuted = false;  // A new anchor: the assumption gets a fresh check.
        clearEvidence();
    }
    // `nowUS` is when the frame arrived; the counters describe that moment closely enough.
    void note(const PeerSyncInfo &s, uint64_t nowUS, uint8_t channel) {
        const uint64_t newPeriod = uint64_t(s.awPeriodTU) * 4 * 1024;
        const uint64_t newEnd = nowUS + uint64_t(s.downCounterTU) * 1024;
        if (valid && memcmp(channels, s.channels, sizeof(channels))) {
            ++sequenceChanges;
            clearEvidence();
        }
        if (valid && (!fresh(nowUS) || channel != ourChannel || newPeriod != eawUS)) {
            invalidate();
        } else if (valid && eawUS) {
            uint64_t into = 0;
            const uint32_t predicted = eawAt(newEnd, &into);
            const uint32_t expected = s.awCounter / 4 + 1;
            // A 16-bit AW counter wraps every 16,384 extended windows.
            const bool nearBoundary = ((predicted - expected) & 0x3fffU) == 0 && into <= kPeerPhaseJumpUS;
            const bool justBefore = ((predicted + 1 - expected) & 0x3fffU) == 0 &&
                eawUS - into <= kPeerPhaseJumpUS;
            if (!nearBoundary && !justBefore)
                invalidate();
        }
        memcpy(channels, s.channels, sizeof(channels));
        ourChannel = channel;
        eawUS = newPeriod;
        anchorEaw = s.awCounter / 4;
        anchorEndUS = newEnd;
        heardUS = nowUS;
        valid = true;
    }
    bool fresh(uint64_t nowUS) const { return valid && nowUS >= heardUS && nowUS - heardUS < kPeerScheduleStaleUS; }
    // The extended AW number at `t`, and how far into it `t` is.
    uint32_t eawAt(uint64_t t, uint64_t *intoUS) const {
        int64_t d = int64_t(t) - int64_t(anchorEndUS);
        int64_t k = d >= 0 ? d / int64_t(eawUS) : -((-d + int64_t(eawUS) - 1) / int64_t(eawUS));
        if (intoUS) *intoUS = uint64_t(d - k * int64_t(eawUS));
        return uint32_t(int64_t(anchorEaw) + 1 + k);
    }
    bool presentInEntry(uint32_t eaw) const {
        return channels[(eaw + entryOffset()) % kPeerSeqEntries] == ourChannel;
    }
    // -itlschedsecond: the channel the peer's sequence names at `t`, or 0 when its timing isn't known (no fresh,
    // known schedule). For sending on a second channel only to the peers that are there now.
    uint8_t channelAt(uint64_t t) const {
        if (!known() || !fresh(t) || !eawUS)
            return 0;
        uint64_t into = 0;
        return channels[(eawAt(t, &into) + entryOffset()) % kPeerSeqEntries];
    }
    // Every frame heard from the peer. Feeds calibration, then checks it. `heardOn` (-itlschedsecond): the channel
    // the frame was heard on when it isn't ourChannel (a second-channel visit). Such a frame checks the timing
    // against the entry naming that channel, and never feeds calibration, whose bins count frames on ourChannel.
    void notePeerFrame(uint64_t t, uint8_t heardOn = 0) {
        if (!fresh(t) || !eawUS) return;
        uint64_t into = 0;
        const uint32_t eaw = eawAt(t, &into);
        if (into < kPeerEdgeUS || eawUS - into < kPeerEdgeUS) return;
        const bool elsewhere = heardOn && heardOn != ourChannel;
        if (elsewhere && !known()) return;
        if (known()) {
            ++checkedFrames;
            const bool where = elsewhere ? channels[(eaw + entryOffset()) % kPeerSeqEntries] == heardOn :
                presentInEntry(eaw);
            if (!where) {
                multipleAwayEntries |= awayFrames && lastAwayEntry != eaw;
                lastAwayEntry = eaw;
                ++awayFrames;
            }
            // A single RX burst can distort timing. Require contradictions across entries.
            if (checkedFrames >= 200 && multipleAwayEntries && awayFrames * 10 > checkedFrames) {
                if (calibrated) ++decalibrations;
                else ++refutations;
                calibrated = false;
                refuted = true;
                clearEvidence();
                return;
            } else if (checkedFrames >= 400) {
                checkedFrames = awayFrames = 0;
                multipleAwayEntries = false;
            }
        }
        if (!calibrated && !elsewhere) {
            if (binFrames >= 4096) clearEvidence();
            ++bins[eaw % kPeerSeqEntries];
            if (++binFrames >= kPeerCalibrateFrames) calibrate();
        }
    }
    // Picks the offset where the fewest of the peer's frames fall in entries that say it's away.
    // Only when there is an away entry to tell offsets apart, and the best one is nearly clean.
    void calibrate() {
        unsigned away = 0;
        for (unsigned k = 0; k < kPeerSeqEntries; ++k) away += channels[k] != ourChannel;
        if (!away || away == kPeerSeqEntries) return;
        uint32_t best = 0xffffffff, second = 0xffffffff;
        uint8_t bestOffset = 0;
        for (unsigned r = 0; r < kPeerSeqEntries; ++r) {
            uint32_t inAway = 0;
            for (unsigned s = 0; s < kPeerSeqEntries; ++s)
                if (channels[(s + r) % kPeerSeqEntries] != ourChannel) inAway += bins[s];
            if (inAway < best) { second = best; best = inAway; bestOffset = uint8_t(r); }
            else if (inAway < second) second = inAway;
        }
        if (best * 100 > binFrames * kPeerCalibrateMaxAwayPercent || second <= best) return;
        offset = bestOffset;
        calibrated = true;
        refuted = false;
        ++calibrations;
        checkedFrames = awayFrames = 0;
    }
    // -itlawdlawsync: an idle peer is reliably awake only at the start of each AW (a quarter of an
    // extended AW) in its entries on our channel, so our sync and service frames are timed there.
    uint64_t awUS() const { return eawUS / 4; }
    // -itlawdlcoexawsync0: sync frame timing may use the sequence before any data frames have calibrated
    // it, taking the entry as the extended AW number modulo 16 (offset 0), which is what the wire format
    // defines and what every recorded calibration found. Only for timing our own sync frames: a frame
    // sent at a wrong moment costs nothing. Pauses and holds need known() (calibrated, or iface161's assumption).
    bool timingUsable(uint64_t t, bool assumeOffsetZero) const {
        return fresh(t) && eawUS && (known() || assumeOffsetZero);
    }
    bool presentForTiming(uint32_t eaw) const {
        return channels[(eaw + entryOffset()) % kPeerSeqEntries] == ourChannel;
    }
    // Whether `t` is within `windowUS` of the start of an AW in an entry where the peer is on our channel.
    bool inPresentAwStart(uint64_t t, uint64_t windowUS, bool assumeOffsetZero = false) const {
        if (!timingUsable(t, assumeOffsetZero)) return false;
        uint64_t into = 0;
        const uint32_t eaw = eawAt(t, &into);
        return presentForTiming(eaw) && into % awUS() < windowUS;
    }
    // Time from `t` to the start of the next such AW, looking at most one full sequence ahead.
    // 0 when unknown.
    uint64_t usUntilPresentAw(uint64_t t, bool assumeOffsetZero = false) const {
        if (!timingUsable(t, assumeOffsetZero)) return 0;
        uint64_t into = 0;
        eawAt(t, &into);
        uint64_t ahead = awUS() - into % awUS();
        for (unsigned k = 0; k < kPeerSeqEntries * 4; ++k, ahead += awUS()) {
            uint64_t nextInto = 0;
            const uint32_t eaw = eawAt(t + ahead, &nextInto);
            if (presentForTiming(eaw)) return ahead;
        }
        return 0;
    }
    // How long a pause starting at `t` may last: through the run of away entries that is current or
    // about to start, plus the margins and 2 ms, at most kPeerPauseCeilingUS.
    uint64_t pauseLimitUS(uint64_t t) const {
        if (!known() || !fresh(t) || !eawUS) return kPeerPauseMaxUS;
        uint64_t into = 0;
        uint32_t eaw = eawAt(t, &into);
        uint64_t limit = kPeerPauseEarlyUS + kPeerResumeLateUS + 2000;
        if (presentInEntry(eaw)) { limit += eawUS - into; ++eaw; } else { limit -= kPeerPauseEarlyUS; limit += eawUS - into; ++eaw; }
        for (unsigned k = 0; k < kPeerSeqEntries && !presentInEntry(eaw); ++k, ++eaw) limit += eawUS;
        return limit > kPeerPauseCeilingUS ? kPeerPauseCeilingUS : limit;
    }
    // Whether sending should be paused at `t`: within the early margin before an away entry,
    // during it, or within the late margin after it.
    bool shouldPause(uint64_t t) const {
        if (!known() || !fresh(t) || !eawUS) return false;
        uint64_t into = 0;
        const uint32_t eaw = eawAt(t, &into);
        if (!presentInEntry(eaw)) return true;
        if (eawUS - into <= kPeerPauseEarlyUS && !presentInEntry(eaw + 1)) return true;
        if (into < kPeerResumeLateUS && !presentInEntry(eaw - 1)) return true;
        return false;
    }
    // iface161 send gate, for frames to the peer outside an aggregated bulk send. Away: the schedule has it
    // off our channel (with the pause margins). Doze: it is on our channel but idle (`dozing`), and `t` is
    // past the first `awWindowUS` of the current AW, when an idle peer may not be listening. A frame sent
    // then is retried for a few milliseconds and dropped, which QUIC reads as loss and backs off from.
    enum class SendGate : uint8_t { Open, Away, Doze };
    SendGate sendGate(uint64_t t, bool dozing, uint64_t awWindowUS) const {
        if (!known() || !fresh(t) || !eawUS) return SendGate::Open;
        if (shouldPause(t)) return SendGate::Away;
        if (dozing) {
            uint64_t into = 0;
            eawAt(t, &into);
            if (into % awUS() >= awWindowUS) return SendGate::Doze;
        }
        return SendGate::Open;
    }
};

// Turns the wish to pause into commands: pauses and resumes only on a change, and never stays
// paused past kPeerPauseMaxUS.
constexpr uint64_t kPeerPauseHoldOffUS = 50000;     // After a forced resume, no pause for this long.
struct PeerPauseState {
    bool paused;
    uint64_t pausedSinceUS, pausedTotalUS, holdOffUntilUS;
    uint32_t pauses, resumes, forcedResumes, commandErrors, framesHeldBack;
    uint64_t limitUS;  // Of the current pause.
    // Returns +1 to pause, -1 to resume, 0 for no change. `limitUS` is used when a pause starts.
    int step(bool want, uint64_t nowUS, uint64_t newLimitUS = kPeerPauseMaxUS) {
        if (paused && nowUS >= pausedSinceUS && nowUS - pausedSinceUS >= (limitUS ? limitUS : kPeerPauseMaxUS)) {
            ++forcedResumes;
            holdOffUntilUS = nowUS + kPeerPauseHoldOffUS;
            want = false;
        }
        if (want && nowUS < holdOffUntilUS) want = false;
        if (want == paused) return 0;
        if (want) { paused = true; pausedSinceUS = nowUS; limitUS = newLimitUS; ++pauses; return 1; }
        paused = false;
        if (nowUS >= pausedSinceUS) pausedTotalUS += nowUS - pausedSinceUS;
        ++resumes;
        return -1;
    }
};

// Pausing only pays while the Mac is sending a lot: during connection setup or while the peer sends
// to us, the Mac's few frames are replies, and holding them back slows the other side. So pausing is
// allowed only after `frames` (the Mac's A-MPDU frames sent) rises at kPeerBulkFramesPerSec or more,
// and stops being allowed after two checks below kPeerQuietFramesPerSec.
constexpr uint64_t kPeerBulkCheckUS = 250000;
constexpr uint32_t kPeerBulkFramesPerSec = 1000, kPeerQuietFramesPerSec = 300;
struct PeerBulkState {
    uint64_t lastUS;
    uint32_t lastFrames, quietChecks, changes;
    bool active;
    // Call often. Returns whether pausing is allowed now.
    bool note(uint64_t nowUS, uint32_t frames) {
        if (!lastUS || nowUS < lastUS) { lastUS = nowUS; lastFrames = frames; return active; }
        const uint64_t elapsed = nowUS - lastUS;
        if (elapsed < kPeerBulkCheckUS) return active;
        const uint64_t perSec = uint64_t(frames - lastFrames) * 1000000 / elapsed;
        lastUS = nowUS;
        lastFrames = frames;
        if (!active) {
            if (perSec >= kPeerBulkFramesPerSec) { active = true; quietChecks = 0; ++changes; }
        } else if (perSec < kPeerQuietFramesPerSec) {
            if (++quietChecks >= 2) { active = false; quietChecks = 0; ++changes; }
        } else {
            quietChecks = 0;
        }
        return active;
    }
};

}  // namespace ItlAWDL
