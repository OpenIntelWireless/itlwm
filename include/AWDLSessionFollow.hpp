//
//  AWDLSessionFollow.hpp
// When to ask the firmware for listener airtime.
//
//  On firmware -68 the only command that puts the listener on air for a chosen length is session protection
//  (P2P_DEVICE_DISCOV) on a P2P Device listener context, and it has no start time: it starts when sent, a few
//  ms later (measured). So the driver sends it just before each run of the peer's schedule entries on
//  the listener's channel. With no usable peer schedule, it sends one long session per sequence ("duty"), so
//  the otherwise deaf listener can hear the peer and learn its schedule.
//
//  Pure logic, host-tested in tests/awdl_session_follow.cpp. Times are host microseconds, as PeerSchedule's.
//

#ifndef AWDLSessionFollow_hpp
#define AWDLSessionFollow_hpp

#include <stdint.h>
#include <AWDLPeerSchedule.hpp>
#include <AWDLElection.hpp>

namespace ItlAWDL {

constexpr uint64_t kFollowLeadUS = 7000;   // mean start delay 7 ms after the send
constexpr uint64_t kFollowArmWindowUS = 250000;   // Arm a timer only for a run starting this soon
constexpr uint64_t kFollowMinRunUS = 16 * 1024;   // Don't ask for less than one AW
constexpr unsigned kFollowMaxEntries = 6;         // At most 6 entries (393 ms) per session, as tested
constexpr unsigned kFollowHorizonEntries = 17;    // Look a little more than one sequence ahead
constexpr uint32_t kFollowDutyTU = 384;           // Duty session: 6 entries
constexpr uint64_t kFollowDutyPeriodUS = 16ULL * 64 * 1024;   // One per sequence (1024 TU)

struct FollowRun {
    uint64_t startUS, endUS;
    unsigned entries;
    bool inProgress;   // `now` is inside the run's first entry
};

// The next run of entries where the peer is on our channel: the one in progress (from now) or the next to
// start, within kFollowHorizonEntries, at most kFollowMaxEntries long, and with at least kFollowMinRunUS left.
inline bool nextPeerRun(const PeerSchedule &s, uint64_t nowUS, FollowRun *out) {
    if (!out || !s.fresh(nowUS) || !s.known() || !s.eawUS) return false;
    uint64_t into = 0;
    const uint32_t cur = s.eawAt(nowUS, &into);
    const uint64_t curStart = nowUS - into;
    for (unsigned k = 0; k < kFollowHorizonEntries; ++k) {
        const uint32_t e = cur + k;
        if (!s.presentInEntry(e)) continue;
        unsigned n = 0;
        while (n < kFollowMaxEntries && s.presentInEntry(e + n)) ++n;
        const uint64_t start = curStart + uint64_t(k) * s.eawUS;
        const uint64_t end = start + uint64_t(n) * s.eawUS;
        const uint64_t from = start > nowUS ? start : nowUS;
        if (end <= from || end - from < kFollowMinRunUS) {
            k += n - 1;   // too little left of this run: skip it whole
            continue;
        }
        out->startUS = start;
        out->endUS = end;
        out->entries = n;
        out->inProgress = k == 0;
        return true;
    }
    return false;
}

enum class FollowAction : uint8_t { None, SendNow, Arm, Duty };

struct FollowDecision {
    FollowAction action;
    uint64_t sendAtUS;   // Arm: when to send
    uint64_t endUS;      // SendNow/Arm: when the session should end
    unsigned entries;
    uint64_t runStartUS = 0;   // SendNow/Arm: when the run itself starts (start-vs-run statistics)
};

// What to do at `nowUS` when no session is running or awaited. `schedule` is null when there is no current
// peer schedule. `lastDutyUS` is when the last duty session was sent (0 = never).
inline FollowDecision followDecide(const PeerSchedule *schedule, uint64_t nowUS, uint64_t lastDutyUS) {
    FollowDecision d{FollowAction::None, 0, 0, 0};
    FollowRun r{};
    if (schedule && nextPeerRun(*schedule, nowUS, &r)) {
        const uint64_t sendAt = r.startUS > kFollowLeadUS ? r.startUS - kFollowLeadUS : 0;
        d.endUS = r.endUS;
        d.entries = r.entries;
        d.runStartUS = r.startUS;
        if (r.inProgress || sendAt <= nowUS) {
            d.action = FollowAction::SendNow;
        } else if (sendAt - nowUS <= kFollowArmWindowUS) {
            d.action = FollowAction::Arm;
            d.sendAtUS = sendAt;
        }
        return d;
    }
    if (!lastDutyUS || nowUS - lastDutyUS >= kFollowDutyPeriodUS)
        d.action = FollowAction::Duty;
    return d;
}

// macOS's own plan on the Mac's own AWDL clock. The Mac advertises its clock
// from an epoch of 0 in the driver's uptime (AWDLLocalSchedule.hpp, called with epoch 0 and an AW period of
// 16 TU), so extended AW n spans [n * 64 TU, (n + 1) * 64 TU) of uptime and its plan entry is n % 16.
constexpr uint64_t kPlanEawUS = 64 * 1024;

// The next run of macOS's entries on `ourChannel`: in progress or next to start within kFollowHorizonEntries,
// at most kFollowMaxEntries long, at least kFollowMinRunUS left.
// on any AWDL clock (the master's when following one, else our own, `ownClock()`).
inline bool nextPlanRun(const uint8_t (&plan)[16], uint8_t ourChannel, uint64_t nowUS, const Clock &clock,
                        FollowRun *out) {
    if (!out || !ourChannel || !clock.eawUS) return false;
    uint64_t into = 0;
    const uint32_t cur = clockEawAt(clock, nowUS, &into);
    const uint64_t curStart = nowUS - into;
    const uint64_t kPlanEawUS = clock.eawUS;
    auto present = [&](uint64_t e) { return plan[e % 16] == ourChannel; };
    for (unsigned k = 0; k < kFollowHorizonEntries; ++k) {
        const uint64_t e = cur + k;
        if (!present(e)) continue;
        unsigned n = 0;
        while (n < kFollowMaxEntries && present(e + n)) ++n;
        const uint64_t start = curStart + uint64_t(k) * kPlanEawUS;
        const uint64_t end = start + uint64_t(n) * kPlanEawUS;
        const uint64_t from = start > nowUS ? start : nowUS;
        if (end <= from || end - from < kFollowMinRunUS) {
            k += n - 1;
            continue;
        }
        out->startUS = start;
        out->endUS = end;
        out->entries = n;
        out->inProgress = k == 0;
        return true;
    }
    return false;
}

inline bool nextPlanRun(const uint8_t (&plan)[16], uint8_t ourChannel, uint64_t nowUS, FollowRun *out) {
    return nextPlanRun(plan, ourChannel, nowUS, ownClock(), out);
}

// As followDecide, from macOS's plan (null = no plan yet: duty sessions), on `clock` (default: our own).
// `leadUS` is how long before the run the session is requested (the firmware starts it 0.3-10 ms
// after the request); the end stays the run's end, so a longer lead only starts the session earlier.
inline FollowDecision followDecidePlan(const uint8_t (*plan)[16], uint8_t ourChannel, uint64_t nowUS,
                                       uint64_t lastDutyUS, const Clock &clock = ownClock(),
                                       uint64_t leadUS = kFollowLeadUS) {
    FollowDecision d{FollowAction::None, 0, 0, 0};
    FollowRun r{};
    if (plan && nextPlanRun(*plan, ourChannel, nowUS, clock, &r)) {
        const uint64_t sendAt = r.startUS > leadUS ? r.startUS - leadUS : 0;
        d.endUS = r.endUS;
        d.entries = r.entries;
        d.runStartUS = r.startUS;
        if (r.inProgress || sendAt <= nowUS) {
            d.action = FollowAction::SendNow;
        } else if (sendAt - nowUS <= kFollowArmWindowUS) {
            d.action = FollowAction::Arm;
            d.sendAtUS = sendAt;
        }
        return d;
    }
    if (!plan && (!lastDutyUS || nowUS - lastDutyUS >= kFollowDutyPeriodUS))
        d.action = FollowAction::Duty;
    return d;
}

// How many of the plan's 16 entries each kind of channel has: ours (the listener's), the station's, other.
inline void planCounts(const uint8_t (&plan)[16], uint8_t ours, uint8_t station, unsigned *listener,
                       unsigned *stationSlots, unsigned *other) {
    unsigned l = 0, s = 0, o = 0;
    for (unsigned i = 0; i < 16; ++i) {
        if (plan[i] == ours) ++l;
        else if (plan[i] == station) ++s;
        else ++o;
    }
    if (listener) *listener = l;
    if (stationSlots) *stationSlots = s;
    if (other) *other = o;
}

// Session length in TU for a session sent at `nowUS` that should end at `endUS`; 0 if too short to send.
inline uint32_t followDurationTU(uint64_t nowUS, uint64_t endUS) {
    if (endUS <= nowUS || endUS - nowUS < kFollowMinRunUS) return 0;
    const uint64_t tu = (endUS - nowUS) / 1024;
    return tu > kFollowMaxEntries * 64 ? kFollowMaxEntries * 64 : uint32_t(tu);
}

}  // namespace ItlAWDL

#endif /* AWDLSessionFollow_hpp */
