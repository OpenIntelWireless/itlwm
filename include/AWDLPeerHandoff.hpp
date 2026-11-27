#pragma once
#include "AWDLBlockAck.hpp"
namespace ItlAWDL {
// One bounded challenger; no firmware operations or allocation in receive context.
struct PeerHandoff {
    static constexpr uint64_t requestLifetimeUS = 2000000;
    static constexpr uint64_t minimumIdleUS = 3000000;
    AddbaRequest request{};
    bool valid = false;
    uint64_t seenUS = 0;
    int generation = -1;
    uint32_t listener = 0, epoch = 0;
    void clear() { valid = false; }
    bool current(uint64_t now, int gen, uint32_t token, uint32_t owner) const {
        return valid && now >= seenUS && now - seenUS <= requestLifetimeUS &&
            generation == gen && listener == token && epoch == owner;
    }
    bool note(const AddbaRequest &incoming, uint64_t now, int gen, uint32_t token, uint32_t owner) {
        if (!incoming.immediate || incoming.tid >= 8) return false;
        if (current(now, gen, token, owner) && memcmp(request.peer, incoming.peer, 6)) return false;
        request = incoming; seenUS = now; generation = gen; listener = token; epoch = owner; valid = true;
        return true;
    }
    bool canRetire(uint64_t now, uint64_t lastData, bool queued, bool controlBusy) const {
        return lastData && now >= lastData && now - lastData >= minimumIdleUS && !queued && !controlBusy;
    }
};
}
