#pragma once
#include <AWDLFrameParser.hpp>
#include <IOKit/IOReturn.h>

namespace ItlAWDL {
// Native actionFrameInput accepts at most 72 bytes of auxiliary metadata.
// Peer address and apple80211_channel are the known prefix; other fields zero.
struct ManagementMetadata {
    uint8_t peer[6];
    uint8_t reserved[6];
    uint32_t version;
    uint32_t channel;
    uint32_t channelFlags;
    uint8_t tail[20];
    int32_t rssi;       // dBm. The native peer path compares offset 0x2c to a threshold.
    uint8_t tail2[24];
};
static_assert(sizeof(ManagementMetadata) == 72, "AWDL management metadata ABI");
static_assert(offsetof(ManagementMetadata, version) == 12, "AWDL channel offset");
static_assert(offsetof(ManagementMetadata, rssi) == 0x2c, "AWDL RSSI offset");

// Backend submit consumes the acquired buffer even when native parsing rejects
// it. Before submit, every failure returns the lease exactly once.
template <typename Backend>
IOReturn copyManagementFrame(Backend &backend, const uint8_t *frame, size_t length,
                            uint32_t channel, uint32_t channelFlags, int32_t rssi = 0)
{
    ActionFrame decoded;
    if (!channel || channel > 255 ||
        parseAction(frame, length, &decoded) != ParseResult::Valid)
        return kIOReturnBadArgument;
    // Native actionFrameHasCorrectOUI reads OUI at cursor +1, type at +4,
    // version at +5: its input starts at the action category, not MAC header.
    const size_t bodyLength = length-24;
    auto *buffer = backend.acquire();
    if (!buffer)
        return kIOReturnNoResources;
    auto *bytes = static_cast<uint8_t *>(backend.bytes(buffer));
    if (!bytes || bodyLength > backend.capacity(buffer)) {
        backend.giveBack(buffer);
        return kIOReturnNoSpace;
    }
    for (size_t i = 0; i < bodyLength; ++i)
        bytes[i] = frame[24+i];
    backend.setLength(buffer, bodyLength);
    ManagementMetadata metadata = {};
    for (unsigned i = 0; i < 6; ++i)
        metadata.peer[i] = frame[10+i];
    metadata.version = 1;
    metadata.channel = channel;
    metadata.channelFlags = channelFlags;
    metadata.rssi = rssi;
    backend.submit(buffer, &metadata);
    return kIOReturnSuccess; // Submitted, not proof that a peer was accepted.
}
} // namespace ItlAWDL
