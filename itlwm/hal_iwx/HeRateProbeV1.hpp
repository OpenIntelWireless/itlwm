/* HE-PR1063: pure host-testable selection policy for read-only rate witnesses.
 * Does not authorize, reconfigure, or influence firmware transmission.
 * No identifiers, addresses, kernel allocations, or logging.
 */
#ifndef HE_PR1063_RATE_PROBE_V1_HPP
#define HE_PR1063_RATE_PROBE_V1_HPP
#include <stdint.h>
namespace hepr1063 {
static inline bool acceptBA(bool contextOK, bool fullHeader,
                            uint32_t flags, uint32_t normalAggregateFlag,
                            uint8_t station, uint8_t infrastructureStation,
                            uint16_t transmitted, uint16_t acknowledged,
                            uint16_t tfdCount, bool verifiedStockTidQueue)
{
    return contextOK && fullHeader && flags == normalAggregateFlag &&
           station == infrastructureStation && transmitted != 0U &&
           acknowledged != 0U && acknowledged <= transmitted &&
           tfdCount != 0U && verifiedStockTidQueue;
}
static inline bool acceptSingle(bool contextOK, bool fullHeader,
                                uint8_t frames, uint8_t station,
                                uint8_t infrastructureStation,
                                uint16_t status, uint16_t successStatus,
                                uint16_t frameControl, uint16_t frameTypeMask,
                                uint16_t dataFrameType, bool verifiedStockQueue)
{
    return contextOK && fullHeader && frames == 1U &&
           station == infrastructureStation && status == successStatus &&
           (frameControl & frameTypeMask) == dataFrameType &&
           verifiedStockQueue;
}
}
#endif
