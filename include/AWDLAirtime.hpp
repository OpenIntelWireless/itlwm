//
//  AWDLAirtime.hpp
//  AirportItlwm
//
//  Where the time goes while we send to an AWDL peer (-itlawdlairtime). Diagnostics only: nothing here changes
//  what is sent or when.
//
//  Each sample describes the interval from it to the next sample, sorted into exactly one state, checked in
//  this order:
//    no airtime      our radio isn't on the AWDL channel (the station has it, or no session is open)
//    peer away       the peer's schedule says it is on another channel or asleep
//    no demand       nothing waits for the peer on awdl0 and nothing is in the firmware's queue
//    policy blocked  frames wait, but a rule holds them (peer pause, send gate, TX pause, a channel move)
//    empty, ready    frames wait and may go, but the firmware's queue is empty: the host isn't feeding it
//    queued          the firmware has frames for the peer
//  A gap longer than the cap between two samples isn't credited to the earlier state: it goes to "unsampled",
//  so an idle stretch with no events can't inflate whichever state came last.
//
//  The model follows the native-control study's WindowAccounting (05-throughput), with the gap cap added.
//

#ifndef AWDLAirtime_hpp
#define AWDLAirtime_hpp

#include <stdint.h>

namespace ItlAWDL {

enum AirtimeState : uint8_t {
    kAirtimeNoAirtime,
    kAirtimePeerAway,
    kAirtimeNoDemand,
    kAirtimePolicyBlocked,
    kAirtimeEmptyWithReady,
    kAirtimeQueued,
    kAirtimeStates,
};

struct AirtimeSample {
    bool localWindow;      // our radio is on the AWDL channel
    bool peerAvailable;    // the peer is there, by its schedule (true when we have no schedule for it)
    bool hostReady;        // frames wait on awdl0
    bool policyAllows;     // no rule holds them
    bool firmwareQueued;   // the firmware's queues hold frames for the peer
};

constexpr AirtimeState airtimeClassify(AirtimeSample s) {
    return !s.localWindow ? kAirtimeNoAirtime :
           !s.peerAvailable ? kAirtimePeerAway :
           (!s.hostReady && !s.firmwareQueued) ? kAirtimeNoDemand :
           (!s.policyAllows && !s.firmwareQueued) ? kAirtimePolicyBlocked :
           s.firmwareQueued ? kAirtimeQueued : kAirtimeEmptyWithReady;
}

struct AirtimeAccount {
    uint64_t us[kAirtimeStates] = {};
    uint64_t unsampledUS = 0;
    uint32_t samples = 0;
    uint32_t maxGapUS = 0;   // the longest gap credited to a state (at most the cap)

    uint64_t totalUS() const {
        uint64_t t = 0;
        for (unsigned i = 0; i < kAirtimeStates; ++i)
            t += us[i];
        return t;
    }
    // per mille of the credited time
    uint32_t share(unsigned state) const {
        const uint64_t t = totalUS();
        return state < kAirtimeStates && t ? uint32_t(us[state] * 1000 / t) : 0;
    }
};

// One account for all the time and one for the time the peer's sends count as bulk: the bulk one is the one
// that explains a transfer's speed. The state a sample opens is credited to the account chosen at that sample.
class AirtimeMeter {
public:
    static constexpr uint32_t kGapCapUS = 20000;

    AirtimeAccount all, bulk;

    // Returns false (and changes nothing) for a sample older than the last one.
    bool sample(uint64_t nowUS, AirtimeSample s, bool inBulk) {
        if (started && nowUS < atUS)
            return false;
        if (started) {
            const uint64_t gap = nowUS - atUS;
            credit(all, gap);
            if (lastBulk)
                credit(bulk, gap);
        }
        started = true;
        atUS = nowUS;
        last = airtimeClassify(s);
        lastBulk = inBulk;
        ++all.samples;
        if (inBulk)
            ++bulk.samples;
        return true;
    }

    // A new peer, generation or firmware restart: the next sample starts fresh intervals (totals kept).
    void restart() { started = false; }
    void clear() { *this = AirtimeMeter{}; }

private:
    void credit(AirtimeAccount &a, uint64_t gap) {
        if (gap > kGapCapUS) {
            a.unsampledUS += gap;
            return;
        }
        a.us[last] += gap;
        if (gap > a.maxGapUS)
            a.maxGapUS = uint32_t(gap);
    }

    uint64_t atUS = 0;
    AirtimeState last = kAirtimeNoAirtime;
    bool lastBulk = false;
    bool started = false;
};

}   // namespace ItlAWDL

#endif /* AWDLAirtime_hpp */
