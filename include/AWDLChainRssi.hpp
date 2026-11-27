// Received signal per antenna (the firmware's energy_a / energy_b), kept apart for AWDL frames and for the
// station's AP. The driver otherwise keeps only the stronger chain, which hides a weak antenna. Every
// management frame, AWDL's included, is sent on one antenna (sc_mgmt_last_antenna_idx), so a large gap
// between the chains on what the Mac receives says how much weaker the other devices hear its AWDL frames
// when that antenna is the weak one. ITLAWDLChainRssi.
#pragma once
#include <stdint.h>
#include <stddef.h>

namespace ItlAWDL {

struct ChainRssi {
    uint32_t frames = 0;          // frames with at least one chain measured
    uint32_t onlyA = 0, onlyB = 0;// one chain reported nothing
    int64_t sumA = 0, sumB = 0;   // dBm sums over frames where that chain was measured
    uint32_t nA = 0, nB = 0;
    uint32_t aAhead10 = 0, bAhead10 = 0;  // both measured and one at least 10 dB stronger
    int32_t minA = 0, maxA = -256, minB = 0, maxB = -256;

    // energy as the descriptor gives it: 0 = not measured, else -dBm.
    void note(uint8_t energyA, uint8_t energyB) {
        const bool a = energyA != 0, b = energyB != 0;
        if (!a && !b)
            return;
        ++frames;
        const int32_t dA = -int32_t(energyA), dB = -int32_t(energyB);
        if (a) {
            ++nA; sumA += dA;
            if (nA == 1 || dA < minA) minA = dA;
            if (dA > maxA) maxA = dA;
        }
        if (b) {
            ++nB; sumB += dB;
            if (nB == 1 || dB < minB) minB = dB;
            if (dB > maxB) maxB = dB;
        }
        if (a && !b) ++onlyA;
        if (b && !a) ++onlyB;
        if (a && b) {
            if (dA - dB >= 10) ++aAhead10;
            else if (dB - dA >= 10) ++bAhead10;
        }
    }
    int32_t meanA() const { return nA ? int32_t(sumA / int64_t(nA)) : 0; }
    int32_t meanB() const { return nB ? int32_t(sumB / int64_t(nB)) : 0; }
};

}  // namespace ItlAWDL
