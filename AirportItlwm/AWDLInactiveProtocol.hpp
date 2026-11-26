// Disabled-state behavior shared by the kernel interface and host tests.
#pragma once
#include <IOKit/IOReturn.h>

inline IOReturn itlAWDLSetInactiveState(const apple80211_awdl_sync_state *data)
{
    if (!data || data->version > APPLE80211_VERSION || data->state < 1 || data->state > 3)
        return kIOReturnBadArgument;
    // Native configure uses state 1 for DISABLE. The inactive transport can
    // acknowledge that idempotently; other states need real radio support.
    return data->state == 1 ? kIOReturnSuccess : kIOReturnUnsupported;
}

inline IOReturn itlAWDLGetInactiveState(apple80211_awdl_sync_state *data)
{
    if (!data)
        return kIOReturnBadArgument;
    *data = {};
    data->version = APPLE80211_VERSION;
    data->state = 1;
    return kIOReturnSuccess;
}

// What Apple's peer manager has asked of the sync machinery. With accept off, this
// behaves exactly as the inactive functions above. With accept on, it records the
// request and reports it back so reads and writes agree. Accepting does NOT mean
// this driver synchronizes, elects or hops: this only lets the native stack stay up.
class ItlAWDLNativeState {
public:
    bool accept = false;
    IOReturn setEnabled(const apple80211_awdl_sync_enabled *data) {
        if (!data || data->version > APPLE80211_VERSION || data->enabled > 1)
            return kIOReturnBadArgument;
        if (data->enabled && !accept)
            return kIOReturnUnsupported;
        enabled = data->enabled != 0;
        return kIOReturnSuccess;
    }
    IOReturn getEnabled(apple80211_awdl_sync_enabled *data) const {
        if (!data)
            return kIOReturnBadArgument;
        *data = {};
        data->version = APPLE80211_VERSION;
        data->enabled = enabled ? 1 : 0;
        return kIOReturnSuccess;
    }
    IOReturn setState(const apple80211_awdl_sync_state *data) {
        const IOReturn result = itlAWDLSetInactiveState(data);
        if (result == kIOReturnBadArgument || (result == kIOReturnUnsupported && !accept))
            return result;
        state = data->state;
        return kIOReturnSuccess;
    }
    IOReturn getState(apple80211_awdl_sync_state *data) const {
        const IOReturn result = itlAWDLGetInactiveState(data);
        if (result == kIOReturnSuccess)
            data->state = state;
        return result;
    }
private:
    bool enabled = false;
    uint32_t state = 1;
};

class ItlAWDLFrameTemplate {
public:
    // Conservative driver-owned storage cap, based on the legacy/reference
    // path. Tahoe's observed length/pointer fields do not prove this maximum.
    // This buffer is not itself an 802.11 frame or a TX submission.
    static constexpr size_t capacity = 0x724;
    IOReturn set(const void *payload, size_t length) {
        if (length > capacity || (length && !payload))
            return kIOReturnBadArgument;
        const auto *source = static_cast<const uint8_t *>(payload);
        for (size_t i = 0; i < length; ++i)
            bytes[i] = source[i];
        for (size_t i = length; i < used; ++i)
            bytes[i] = 0;
        used = length;
        return kIOReturnSuccess;
    }
    size_t size() const { return used; }
    // Caller must serialize access, including this copy and template updates.
    IOReturn copy(void *destination, size_t available) const {
        if (available < used || (used && !destination))
            return kIOReturnNoSpace;
        auto *target = static_cast<uint8_t *>(destination);
        for (size_t i = 0; i < used; ++i)
            target[i] = bytes[i];
        return kIOReturnSuccess;
    }
private:
    uint8_t bytes[capacity] = {};
    size_t used = 0;
};
