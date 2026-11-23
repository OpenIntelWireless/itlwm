/* HE-PR1064: pure, host-testable policy for a recent completed-TX
 * rate to override the older TLC-selected initial rate in Debug and Release builds.
 * No firmware commands, queue ownership, or TX decisions.
 */
#ifndef HE_PR1064_RATE_FRESH_V1_HPP
#define HE_PR1064_RATE_FRESH_V1_HPP
#include <stdint.h>
namespace hepr1064 {
static inline bool eligible(bool optIn, bool runHeSta,
                            uint32_t sampleRaw, uint32_t sampleGeneration,
                            uint32_t currentGeneration, uint32_t sampleEpoch,
                            uint32_t currentEpoch, uint64_t sampleClock,
                            uint64_t nowClock, uint64_t ageNs,
                            uint64_t maxAgeNs)
{
    return optIn && runHeSta && sampleRaw != 0U &&
           sampleGeneration == currentGeneration &&
           sampleEpoch == currentEpoch &&
           sampleClock != 0ULL && nowClock >= sampleClock &&
           ageNs <= maxAgeNs;
}
}
#endif
