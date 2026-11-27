// Local, always-present fixed-channel schedule serialization. This is not peer
// synchronization or a transmit timer. Timing semantics cross-checked against
// seemoo-lab/owl src/sync.c and src/tx.c; independently implemented here.
#pragma once
#include <AWDLSyncPrefix.hpp>
#include <AWDLChannels.hpp>

namespace ItlAWDL {
// Caller supplies local identity, explicit flags/periods and one monotonic
// epoch. Never derive our identity or schedule by replaying a received frame.
// `slots`, null by default: the 16 channels the radio really follows, in place of sixteen copies
// of nextChannel; each must be a fixed-schedule channel.
// The 73-byte payload includes the known prefix, presence/counter fields,
// sixteen identical legacy slots and two zero padding bytes. Channel 149 uses the
// 5 GHz form of channel 6's 20 MHz flags: 0x2b has the 2.4 GHz band bit, 0x1b the
// 5 GHz one, as peers' own 5 GHz entries (0x1d) show. Inferred, not from a document.
inline BuildResult buildLocalFixedSchedule(const SyncPrefix &settings,
        uint64_t epochUS, uint64_t nowUS, uint16_t initialAW,
        uint8_t *output, size_t available, size_t *written, const uint8_t *slots = nullptr)
{
    if (slots)
        for (unsigned i = 0; i < 16; ++i)
            if (!fixedScheduleChannel(slots[i])) return BuildResult::Invalid;
    if (!output || !written || nowUS < epochUS || (initialAW & 3) ||
        !fixedScheduleChannel(settings.nextChannel) ||
        settings.masterChannel != settings.nextChannel ||
        !settings.awPeriod || settings.awPeriod > 16383 ||
        settings.commonLength > settings.awPeriod)
        return BuildResult::Invalid;
    if (available < 73) return BuildResult::NoSpace;
    const uint64_t elapsedTU = (nowUS - epochUS) / 1024;
    const uint32_t extendedTU = uint32_t(settings.awPeriod) * 4;
    const uint32_t phaseTU = uint32_t(elapsedTU % extendedTU);
    const uint16_t counter = uint16_t((elapsedTU / settings.awPeriod + initialAW) & 0xffff);
    SyncPrefix p = settings;
    p.txDownCounter = uint16_t(extendedTU - phaseTU);
    p.remainingAW = phaseTU < p.commonLength ? uint16_t(p.commonLength - phaseTU) : 0;
    uint8_t payload[73] = {};
    size_t prefixLength;
    const auto result = buildSyncPrefix(p, payload, sizeof(payload), &prefixLength);
    if (result != BuildResult::Ready) return result;
    payload[27] = 4;
    write16(payload+29, counter);
    // No infrastructure AP is associated in this monitor test: alignment 0.
    payload[33] = 15; payload[34] = 1; payload[36] = 3;
    payload[37] = 0xff; payload[38] = 0xff;
    for (unsigned i = 0; i < 16; ++i) {
        const uint8_t slot = slots ? slots[i] : settings.nextChannel;
        payload[39+2*i] = legacySlotFlags(slot);
        payload[40+2*i] = slot;
    }
    for (unsigned i = 0; i < 73; ++i) output[i] = payload[i];
    *written = 73;
    return BuildResult::Ready;
}
} // namespace ItlAWDL
