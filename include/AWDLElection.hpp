//
//  AWDLElection.hpp
// (-itlschedclock): AWDL master election and the master's clock, so our schedule (macOS's plan)
//  is laid on the same slots as the peers', as on a real Mac, where the chip firmware runs the election and
//  macOS only sets its inputs (setAWDL_ELECTION_METRIC, _ID, _RSSI_THRESHOLDS, _PARAMS).
//
//  Election rules after seemoo-lab/owl src/election.c (independently implemented, no code copied): a peer is
//  a better sync source when its master's counter, then its master's metric, is higher; on a tie, when it is
//  closer to the master; on a tie again, when its address is higher. Peers that sync to us, or whose tree is
//  too deep, are never chosen. The peers' views come from their election v2 TLV (24); field layout as in
//  OWL's frame.h and the AWDL paper.
//
// like IO80211's own parent election (IO80211AWDLPeerManager::isPeerQualifiedForElection, 26.7.2:
//  a candidate must have been heard within 3 s and reach the election RSSI threshold, -78 dBm by default from
//  determineAndSetEdgeRssiThreshold), run() can skip peers whose smoothed RSSI is below a minimum. Without it a
//  distant device heard now and then wins (a far higher master counter), is dropped as stale 3 s later, and the
//  clock flips back and forth under the peers that sync to us.
//
//  Pure logic, host-tested in tests/awdl_election.cpp. Times are host microseconds (awdlUptimeUS).
//

#ifndef AWDLElection_hpp
#define AWDLElection_hpp

#include <stdint.h>
#include <string.h>
#include <AWDLPeerSchedule.hpp>

namespace ItlAWDL {

constexpr unsigned kElectionPeers = 8;
constexpr uint64_t kElectionPeerStaleUS = 3000000;   // a peer not heard for 3 s is dropped
constexpr uint64_t kElectionClockStaleUS = 2000000;  // the master's clock needs a sync TLV this recent
constexpr uint32_t kElectionMaxHeight = 10;          // OWL's limit on the sync tree's depth
constexpr uint64_t kClockEawUS = 64 * 1024;          // one extended AW, 4 AWs of 16 TU
constexpr int32_t kElectionNoRssi = -1000;           // note(): the frame's RSSI isn't known
constexpr int32_t kElectionDefaultMinRssi = -78;     // IO80211's default election RSSI threshold (dBm)

// A node's election view, from its election v2 TLV (type 24, at least 40 bytes of value).
struct ElectionView {
    uint8_t master[6], sync[6];
    uint32_t masterCounter, height, masterMetric, selfMetric, selfCounter;
    uint32_t electionId;   // offset 28, compared with ours by IO80211 (its +0x918b)
};

inline uint32_t electionRead32(const uint8_t *p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}

// The election v2 TLV of a TLV list (each TLV: type, 16-bit little-endian length, value). False if absent,
// short or malformed; `out` is untouched then.
inline bool electionFromTLVs(const uint8_t *tlvs, size_t length, ElectionView *out) {
    if (!tlvs || !out) return false;
    for (size_t i = 0; i + 3 <= length;) {
        const size_t n = size_t(tlvs[i + 1]) | size_t(tlvs[i + 2]) << 8;
        if (i + 3 + n > length) return false;
        if (tlvs[i] == 24 && n >= 40) {
            const uint8_t *v = tlvs + i + 3;
            ElectionView e{};
            memcpy(e.master, v, 6);
            memcpy(e.sync, v + 6, 6);
            e.masterCounter = electionRead32(v + 12);
            e.height = electionRead32(v + 16);
            e.masterMetric = electionRead32(v + 20);
            e.selfMetric = electionRead32(v + 24);
            e.selfCounter = electionRead32(v + 36);
            e.electionId = electionRead32(v + 28);
            *out = e;
            return true;
        }
        i += 3 + n;
    }
    return false;
}

// the AWDL version from a TLV list's version TLV (21): its first value byte (e.g. 0x3e).
inline bool electionVersionFromTLVs(const uint8_t *tlvs, size_t length, uint8_t *version) {
    if (!tlvs || !version) return false;
    for (size_t i = 0; i + 3 <= length;) {
        const size_t n = size_t(tlvs[i + 1]) | size_t(tlvs[i + 2]) << 8;
        if (i + 3 + n > length) return false;
        if (tlvs[i] == 21 && n >= 1) { *version = tlvs[i + 3]; return true; }
        i += 3 + n;
    }
    return false;
}
inline bool electionVersionFromAction(const uint8_t *frame, size_t length, uint8_t *version) {
    if (!frame || length < 40) return false;
    return electionVersionFromTLVs(frame + 40, length - 40, version);
}

// An action frame's election view: its TLVs start at byte 40 (24-byte header, 16-byte AWDL fixed header).
inline bool electionFromAction(const uint8_t *frame, size_t length, ElectionView *out) {
    if (!frame || length < 40) return false;
    return electionFromTLVs(frame + 40, length - 40, out);
}

// An AWDL clock: extended AW number `anchorEaw` ends at `anchorEndUS`; each lasts `eawUS`. The Mac's own clock
// (epoch 0 in uptime, AWDLLocalSchedule.hpp) is {kClockEawUS, 0, kClockEawUS}.
struct Clock {
    uint64_t anchorEndUS;
    uint32_t anchorEaw;
    uint64_t eawUS;
};

inline Clock ownClock() { return Clock{kClockEawUS, 0, kClockEawUS}; }

// The extended AW number at `t`, and how far into it `t` is (as PeerSchedule::eawAt).
inline uint32_t clockEawAt(const Clock &c, uint64_t t, uint64_t *intoUS) {
    const int64_t d = int64_t(t) - int64_t(c.anchorEndUS);
    const int64_t e = int64_t(c.eawUS);
    const int64_t k = d >= 0 ? d / e : -((-d + e - 1) / e);
    if (intoUS) *intoUS = uint64_t(d - k * e);
    return uint32_t(int64_t(c.anchorEaw) + 1 + k);
}

// The start time of extended AW `eaw` (which must not be more than 2^31 entries from the anchor).
inline uint64_t clockEawStart(const Clock &c, uint32_t eaw) {
    const int64_t steps = int64_t(int32_t(eaw - (c.anchorEaw + 1)));
    return uint64_t(int64_t(c.anchorEndUS) + steps * int64_t(c.eawUS));
}

// How far clock `b` puts each extended AW from where clock `a` puts the same one (b minus a, in us). A clock
// re-anchored on a newer sync frame from the same master moves only by the drift between them (microseconds);
// a different master or numbering moves it by whole windows.
inline int64_t clockShiftUS(const Clock &a, const Clock &b) {
    return int64_t(b.anchorEndUS - a.anchorEndUS) - int64_t(int32_t(b.anchorEaw - a.anchorEaw)) * int64_t(a.eawUS);
}

// Whether a run timed on clock `a` is still where clock `b` puts it: the same window length and every window
// within `toleranceUS`.
inline bool clockSameWithin(const Clock &a, const Clock &b, uint64_t toleranceUS) {
    if (a.eawUS != b.eawUS)
        return false;
    const int64_t s = clockShiftUS(a, b);
    return uint64_t(s < 0 ? -s : s) <= toleranceUS;
}

// A clock taken from a peer's sync TLV heard at `heardUS`: the AW counter it carries, and the TU left until
// its current extended AW ends (as PeerSchedule::note).
inline Clock clockFromSync(const PeerSyncInfo &s, uint64_t heardUS) {
    return Clock{heardUS + uint64_t(s.downCounterTU) * 1024, uint32_t(s.awCounter / 4),
                 uint64_t(s.awPeriodTU) * 4 * 1024};
}

// For buildLocalFixedSchedule (epoch-based): the epoch (the start of the current extended AW, never after
// `nowUS`) and the AW counter at that epoch, so our sync TLV carries the clock `c`.
inline void clockEpoch(const Clock &c, uint64_t nowUS, uint64_t *epochUS, uint16_t *initialAW) {
    const uint32_t eaw = clockEawAt(c, nowUS, nullptr);
    if (epochUS) *epochUS = clockEawStart(c, eaw);
    if (initialAW) *initialAW = uint16_t((eaw * 4) & 0xffff);
}

struct ElectionPeer {
    bool used;
    uint8_t addr[6];
    ElectionView view;
    uint64_t heardUS;
    bool haveSync;
    PeerSyncInfo sync;
    uint64_t syncHeardUS;
    bool haveRssi;
    int32_t rssiDbm;         // smoothed: 3/4 of the previous value plus 1/4 of the new frame's
    // the same per band (IO80211 judges a peer seen on 5 GHz by its 5 GHz RSSI), and the version.
    bool haveRssi5, haveRssi24, haveVersion;
    int32_t rssi5Dbm, rssi24Dbm;
    uint8_t version;
};

// inputs for Election::runApple, IO80211's own parent election (26.7.2 runParentElection,
// isPeerQualifiedForElection, isPeerSafeForElection).
struct AppleElectionInputs {
    uint32_t selfMetric, selfCounter;
    int32_t minRssi5Dbm;     // 5 GHz peers (IO80211 +0x2820: -65, or -78 when it sends the chip -78)
    int32_t hostEdgeDbm;     // peers not seen on 5 GHz, against their 2.4 GHz RSSI - 10 (+0x2824: -45 or -58)
    bool haveElectionId;
    uint32_t electionId;     // ours, as macOS puts it in our election TLV
};
// A root IO80211 refuses outright ("Breaking to avoid prohibited Root").
constexpr uint8_t kElectionProhibitedRoot[6] = {0xfe, 0xff, 0xff, 0x00, 0x01, 0x04};
constexpr uint8_t kElectionMinVersion = 0x33;     // older peers are "Legacy" and never parent or root

struct ElectionResult {
    bool following;          // true: we sync to a peer (`peer`); false: we are our own master
    int peer;                // index into Election::peers, -1 when not following
    uint8_t master[6], sync[6];
    uint32_t height, masterMetric, masterCounter;
    bool clockValid;         // following and the sync peer's clock is recent enough
    Clock clock;             // the clock to use: the sync peer's, else our own
    unsigned weakSkipped;    // live peers left out for being below the minimum RSSI
    // runApple: live peers left out per rule.
    unsigned legacySkipped, idSkipped, badAwSkipped, olderSkipped, loopSkipped;
};

struct Election {
    ElectionPeer peers[kElectionPeers];

    void reset() { memset(this, 0, sizeof(*this)); }

    // A frame from `addr` with its election view and, if it carried one, its sync TLV.
    void note(const uint8_t *addr, const ElectionView *view, const PeerSyncInfo *sync, uint64_t nowUS,
              int32_t rssiDbm = kElectionNoRssi, bool on5GHz = true, int version = -1) {
        if (!addr || !view) return;
        int slot = -1, oldest = 0;
        for (unsigned i = 0; i < kElectionPeers; ++i) {
            if (peers[i].used && !memcmp(peers[i].addr, addr, 6)) { slot = int(i); break; }
            if (!peers[i].used && slot < 0) slot = int(i);
        }
        if (slot < 0 || (peers[slot].used && memcmp(peers[slot].addr, addr, 6))) {
            for (unsigned i = 1; i < kElectionPeers; ++i)
                if (peers[i].heardUS < peers[oldest].heardUS) oldest = int(i);
            if (slot < 0 || peers[slot].used) slot = oldest;
        }
        ElectionPeer &p = peers[slot];
        if (!p.used || memcmp(p.addr, addr, 6)) {
            memset(&p, 0, sizeof(p));
            memcpy(p.addr, addr, 6);
            p.used = true;
        }
        p.view = *view;
        p.heardUS = nowUS;
        if (sync) {
            p.sync = *sync;
            p.syncHeardUS = nowUS;
            p.haveSync = true;
        }
        if (rssiDbm > kElectionNoRssi && rssiDbm <= 0) {
            p.rssiDbm = p.haveRssi ? (3 * p.rssiDbm + rssiDbm) / 4 : rssiDbm;
            p.haveRssi = true;
            bool &have = on5GHz ? p.haveRssi5 : p.haveRssi24;
            int32_t &band = on5GHz ? p.rssi5Dbm : p.rssi24Dbm;
            band = have ? (3 * band + rssiDbm) / 4 : rssiDbm;
            have = true;
        }
        if (version >= 0 && version <= 0xff) {
            p.version = uint8_t(version);
            p.haveVersion = true;
        }
    }

    unsigned count(uint64_t nowUS) const {
        unsigned n = 0;
        for (const auto &p : peers) n += p.used && nowUS - p.heardUS < kElectionPeerStaleUS;
        return n;
    }

    // minRssiDbm 0 = no RSSI rule; otherwise peers with a known smoothed RSSI below it are skipped.
    ElectionResult run(const uint8_t *self, uint32_t selfMetric, uint32_t selfCounter, uint64_t nowUS,
                       int32_t minRssiDbm = 0) const {
        ElectionResult r{};
        r.peer = -1;
        memcpy(r.master, self, 6);
        memcpy(r.sync, self, 6);
        r.masterMetric = selfMetric;
        r.masterCounter = selfCounter;
        r.height = 0;
        const uint8_t *bestAddr = self;
        for (unsigned i = 0; i < kElectionPeers; ++i) {
            const ElectionPeer &p = peers[i];
            if (!p.used || nowUS - p.heardUS >= kElectionPeerStaleUS) continue;
            if (p.view.height + 1 > kElectionMaxHeight) continue;
            if (minRssiDbm && p.haveRssi && p.rssiDbm < minRssiDbm) { ++r.weakSkipped; continue; }
            if (!memcmp(p.view.sync, self, 6) || !memcmp(p.view.master, self, 6)) continue;   // no cycles
            int cmp = p.view.masterCounter < r.masterCounter ? -1 : p.view.masterCounter > r.masterCounter;
            if (!cmp) cmp = p.view.masterMetric < r.masterMetric ? -1 : p.view.masterMetric > r.masterMetric;
            if (cmp < 0) continue;
            if (cmp == 0) {
                if (p.view.height > (r.peer < 0 ? 0 : r.height - 1)) continue;
                if (p.view.height == (r.peer < 0 ? 0 : r.height - 1) && memcmp(p.addr, bestAddr, 6) <= 0) continue;
            }
            r.peer = int(i);
            memcpy(r.master, p.view.master, 6);
            memcpy(r.sync, p.addr, 6);
            r.masterMetric = p.view.masterMetric;
            r.masterCounter = p.view.masterCounter;
            r.height = p.view.height + 1;
            bestAddr = p.addr;
        }
        r.following = r.peer >= 0;
        r.clock = ownClock();
        if (r.following) {
            const ElectionPeer &p = peers[r.peer];
            if (p.haveSync && nowUS - p.syncHeardUS < kElectionClockStaleUS && p.sync.awPeriodTU) {
                r.clock = clockFromSync(p.sync, p.syncHeardUS);
                r.clockValid = true;
            }
        }
        return r;
    }

    // IO80211's parent election rules (decoded from 26.7.2), in place of OWL's.
    //  Candidates: heard within 3 s; version >= 0x33 when known; the same election ID as ours when we know it;
    //  RSSI: a peer seen on 5 GHz needs its 5 GHz RSSI >= minRssi5Dbm, else its 2.4 GHz RSSI - 10 >= hostEdgeDbm
    //  (a peer without an RSSI reading stays eligible); a master counter (RLFC) other than 0; its root and parent
    //  not us; not the prohibited root; AW period, extension and common lengths 16 TU and presence mode 1..4
    //  when its sync TLV is known; not relaying an older RLFC for a root than another live candidate does.
    //  Order: for different roots the higher root metric wins, then the higher root address; for the same
    //  root the higher root metric, then the higher RLFC, then the lower hop count. We are root ourselves when
    //  our metric is above the winner's root metric (equal: follow).
    ElectionResult runApple(const uint8_t *self, const AppleElectionInputs &in, uint64_t nowUS) const {
        ElectionResult r{};
        r.peer = -1;
        memcpy(r.master, self, 6);
        memcpy(r.sync, self, 6);
        r.masterMetric = in.selfMetric;
        r.masterCounter = in.selfCounter;
        bool ok[kElectionPeers] = {};
        for (unsigned i = 0; i < kElectionPeers; ++i) {
            const ElectionPeer &p = peers[i];
            if (!p.used || nowUS - p.heardUS >= kElectionPeerStaleUS) continue;
            if (p.haveVersion && p.version < kElectionMinVersion) { ++r.legacySkipped; continue; }
            if (in.haveElectionId && p.view.electionId != in.electionId) { ++r.idSkipped; continue; }
            if (p.haveRssi5 ? p.rssi5Dbm < in.minRssi5Dbm : p.haveRssi24 && p.rssi24Dbm - 10 < in.hostEdgeDbm) {
                ++r.weakSkipped;
                continue;
            }
            if (!p.view.masterCounter) { ++r.legacySkipped; continue; }
            if (!memcmp(p.view.sync, self, 6) || !memcmp(p.view.master, self, 6) ||
                !memcmp(p.view.master, kElectionProhibitedRoot, 6)) { ++r.loopSkipped; continue; }
            if (p.haveSync && (p.sync.awPeriodTU != 16 || p.sync.awExtTU != 16 || p.sync.awCommonTU != 16 ||
                               p.sync.presenceMode < 1 || p.sync.presenceMode > 4)) { ++r.badAwSkipped; continue; }
            if (p.view.height + 1 > kElectionMaxHeight) continue;
            ok[i] = true;
        }
        int best = -1;
        for (unsigned i = 0; i < kElectionPeers; ++i) {
            if (!ok[i]) continue;
            const ElectionView &v = peers[i].view;
            bool older = false;
            for (unsigned j = 0; j < kElectionPeers && !older; ++j)
                older = ok[j] && j != i && !memcmp(peers[j].view.master, v.master, 6) &&
                        peers[j].view.masterCounter > v.masterCounter;
            if (older) { ++r.olderSkipped; continue; }
            if (best < 0) { best = int(i); continue; }
            const ElectionView &b = peers[best].view;
            bool better;
            if (memcmp(v.master, b.master, 6))
                better = v.masterMetric != b.masterMetric ? v.masterMetric > b.masterMetric :
                                                            memcmp(v.master, b.master, 6) > 0;
            else if (v.masterMetric != b.masterMetric)
                better = v.masterMetric > b.masterMetric;
            else if (v.masterCounter != b.masterCounter)
                better = v.masterCounter > b.masterCounter;
            else
                better = v.height < b.height;
            if (better) best = int(i);
        }
        r.clock = ownClock();
        if (best < 0 || in.selfMetric > peers[best].view.masterMetric) {
            r.following = false;
            return r;
        }
        const ElectionPeer &p = peers[best];
        r.peer = best;
        r.following = true;
        memcpy(r.master, p.view.master, 6);
        memcpy(r.sync, p.addr, 6);
        r.masterMetric = p.view.masterMetric;
        r.masterCounter = p.view.masterCounter;
        r.height = p.view.height + 1;
        if (p.haveSync && nowUS - p.syncHeardUS < kElectionClockStaleUS && p.sync.awPeriodTU) {
            r.clock = clockFromSync(p.sync, p.syncHeardUS);
            r.clockValid = true;
        }
        return r;
    }
};

}  // namespace ItlAWDL

#endif /* AWDLElection_hpp */
