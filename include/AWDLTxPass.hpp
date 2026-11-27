// -itlschedsecond: while the listener is on a second channel, only unicast data for the peers that are on that
// channel now may leave awdl0's queue; every other peer's frames are parked, in their order, until the listener
// is back where that peer is. The pump fills this list; popTransmit (AirportItlwmV2.cpp) reads it. Group frames
// aren't affected. Inactive means no such rule (every caller outside the second-channel visits).
#pragma once
#include <stdint.h>
#include <string.h>

namespace ItlAWDL {

static constexpr unsigned kTxPassMax = 12;   // one per peer station the firmware can hold (12; 11 on an AX211)

struct TxPassList {
    bool active = false;
    unsigned count = 0;
    uint8_t addr[kTxPassMax][6] = {};

    void clear() { active = false; count = 0; }
    bool add(const uint8_t *a) {
        if (!a || contains(a))
            return a != nullptr;
        if (count >= kTxPassMax)
            return false;
        memcpy(addr[count++], a, 6);
        return true;
    }
    bool contains(const uint8_t *a) const {
        for (unsigned i = 0; i < count; ++i)
            if (!memcmp(addr[i], a, 6))
                return true;
        return false;
    }
    // Whether a unicast frame to `a` has to wait: the rule is active and `a` isn't on the list.
    bool holds(const uint8_t *a) const { return active && !contains(a); }
};

}  // namespace ItlAWDL
