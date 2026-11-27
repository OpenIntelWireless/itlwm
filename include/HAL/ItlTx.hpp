//
//  ItlTx.hpp
//  AirportItlwm
//
//  Created by laobamac on 2026/10/11.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef ItlTx_hpp
#define ItlTx_hpp

#include <stdint.h>

template<unsigned QueueCount>
struct ItlQueueMask {
    uint32_t bits[(QueueCount + 31) / 32];
    uint32_t count;

    void reset() {
        for (auto &word : bits)
            word = 0;
        count = 0;
    }

    void set(unsigned qid) {
        if (qid >= QueueCount)
            return;
        const uint32_t bit = uint32_t(1) << (qid % 32);
        auto &word = bits[qid / 32];
        if (!(word & bit)) {
            word |= bit;
            ++count;
        }
    }

    void clear(unsigned qid) {
        if (qid >= QueueCount)
            return;
        const uint32_t bit = uint32_t(1) << (qid % 32);
        auto &word = bits[qid / 32];
        if (word & bit) {
            word &= ~bit;
            --count;
        }
    }

    bool empty() const { return count == 0; }
};

inline bool itlTxCompletionValid(unsigned tail, unsigned queued,
    unsigned index, unsigned size) {
    if (!size || tail >= size || index >= size || queued >= size)
        return false;
    const unsigned advance = index >= tail ? index - tail : size - tail + index;
    return advance <= queued;
}

constexpr uint16_t itlTxOffloadHeader(unsigned headerBytes) {
    return uint16_t(((headerBytes / 2) << 8) | ((headerBytes % 4) ? (1U << 13) : 0));
}

#endif
