// Storage for fixed-size, pointer-free AWDL configuration records.
// A stored request does not imply that it has been applied to the radio.
#pragma once
#include <IOKit/IOReturn.h>

template <typename T> class ItlAWDLRequestedValue {
public:
    IOReturn set(const T *request) {
        // Native peer-manager internal requests are zero-initialized and do
        // not stamp a version (25G241 configure, AWDL_BSSID). User-facing
        // records use version 1. Reject later layouts rather than guessing.
        if (!request || request->version > 1)
            return kIOReturnBadArgument;
        value = *request;
        value.version = 1;
        valid = true;
        return kIOReturnSuccess;
    }
    IOReturn get(T *reply) const {
        if (!reply)
            return kIOReturnBadArgument;
        if (!valid)
            return kIOReturnNotReady;
        *reply = value;
        return kIOReturnSuccess;
    }
private:
    T value = {};
    bool valid = false;
};
