// Fixed synchronization prefix encoder, not a clock or channel scheduler.
// Wire offsets follow the reference documented in AWDLFrameParser.hpp.
#pragma once
#include <AWDLFrameBuilder.hpp>

namespace ItlAWDL {
struct SyncPrefix {
    uint8_t nextChannel, masterChannel, guardTime;
    uint16_t txDownCounter, awPeriod, afPeriod, flags;
    uint16_t extensionLength, commonLength, remainingAW;
    uint8_t minExtension, multicastExtension, unicastExtension, actionExtension;
    uint8_t master[6];
};

// Encode only the known 27-byte prefix. Channel sequence/election/static
// templates and a calibrated transmit time must be supplied separately.
// Inputs/output must be disjoint. Validate before changing either output.
inline BuildResult buildSyncPrefix(const SyncPrefix &p, uint8_t *output,
                                  size_t available, size_t *written)
{
    bool masterSet = false;
    for (unsigned i = 0; i < 6; ++i) masterSet |= p.master[i] != 0;
    if (!output || !written || !masterSet || (p.master[0] & 1) ||
        !p.nextChannel || !p.masterChannel || !p.awPeriod || !p.afPeriod)
        return BuildResult::Invalid;
    if (available < 27) return BuildResult::NoSpace;
    output[0] = p.nextChannel;
    write16(output+1, p.txDownCounter);
    output[3] = p.masterChannel; output[4] = p.guardTime;
    write16(output+5, p.awPeriod); write16(output+7, p.afPeriod);
    write16(output+9, p.flags); write16(output+11, p.extensionLength);
    write16(output+13, p.commonLength); write16(output+15, p.remainingAW);
    output[17] = p.minExtension; output[18] = p.multicastExtension;
    output[19] = p.unicastExtension; output[20] = p.actionExtension;
    for (unsigned i = 0; i < 6; ++i) output[21+i] = p.master[i];
    *written = 27;
    return BuildResult::Ready;
}
} // namespace ItlAWDL
