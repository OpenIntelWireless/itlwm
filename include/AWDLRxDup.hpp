// Duplicate-detection state per transmitter for AWDL peers. The receive path's duplicate check keeps the last
// sequence number per TID; upstream keeps one such record, the Wi-Fi network's, for every frame. With several AWDL
// peers that mixed their sequence numbers: a retry from one peer could be dropped because another had just sent the
// same number, and a real duplicate could pass after another peer's frame. Each peer gets its own record here, the
// least recently used one goes when all are taken, and a new owner starts from a cleared record.
#pragma once
#include <stdint.h>
#include <string.h>

namespace ItlAWDL {

template <typename State, unsigned N> struct TransmitterStates {
    struct Entry {
        uint8_t addr[6];
        bool used;
        uint32_t lastUse;
        State state;
    };
    Entry entries[N] = {};
    uint32_t clock = 0;
    uint32_t replaced = 0;     // records handed to a new transmitter while all were in use

    State *stateFor(const uint8_t *addr) {
        Entry *victim = nullptr;
        for (Entry &e : entries) {
            if (e.used && !memcmp(e.addr, addr, 6)) {
                e.lastUse = ++clock;
                return &e.state;
            }
            if (!victim || (victim->used && (!e.used || e.lastUse < victim->lastUse)))
                victim = &e;
        }
        if (victim->used)
            ++replaced;
        memset(victim, 0, sizeof(*victim));
        memcpy(victim->addr, addr, 6);
        victim->used = true;
        victim->lastUse = ++clock;
        return &victim->state;
    }

    void clear() {
        memset(entries, 0, sizeof(entries));
        clock = 0;
    }
};

}  // namespace ItlAWDL
