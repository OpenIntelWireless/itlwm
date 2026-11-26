// Decisions on outgoing HCI commands, kept free of kernel types for host tests.
#pragma once
#include <stdint.h>
#include <stddef.h>
namespace BTLEAdv {
enum : uint16_t {
    kOpReset = 0x0c03, kOpLeEventMask = 0x2001, kOpLeRandomAddress = 0x2005,
    kOpSetRandomAddress = 0x2035, kOpExtAdvParams = 0x2036,
    kOpRemoveSet = 0x203c, kOpClearSets = 0x203d, kOpExtAdvEnable = 0x2039,
};
// IntelBTPatcher sends this fixed address before the first legacy scan, to work around a
// bluetoothd bug. Lilu panics if a second plugin hooks the same function as IntelBTPatcher,
// so with this kext active, IntelBTPatcher is disabled and that job moves here. The address
// must never become an advertising address, because that would make the Mac trackable.
static const uint8_t kFixedPatcherAddress[6] = {0x94,0x50,0x64,0xd0,0x78,0x6b};
// address is the general fallback: bluetoothd's LE random address (0x2005). It never comes from another
// set: a set's address replayed onto a second set gives the Mac two advertisers with one address (#102).
// setAddress is what bluetoothd chose for each set.
// existingSets: sets made with 0x2036 and not removed. checkAtEnable: sets whose address only this kext
// sent; the controller's answer to that send isn't seen here (a USB success isn't an accepted command), and
// bluetoothd may enable the set before it lands, so the address goes again right before the set's first
// enable (#102). bluetoothd's own 0x2035 for a set that exists clears it.
struct State {
    uint8_t address[6]; bool haveAddress; bool haveGeneralAddress;
    uint32_t addressedSets; bool legacyAddressSent;
    uint8_t setAddress[32][6]; uint32_t knownSetAddresses;
    uint32_t existingSets, checkAtEnable;
};
enum : uint16_t { kOpLeScanParams = 0x200b };
// True once per controller start, before the first legacy scan parameters command.
inline bool wantsLegacyScanAddress(State &s, const uint8_t *hci, size_t length) {
    if (!hci || length < 3 || uint16_t(hci[0] | hci[1] << 8) != kOpLeScanParams || s.legacyAddressSent)
        return false;
    s.legacyAddressSent = true;
    return true;
}
// before: Advertising Set Random Address commands to send ahead of this command (an enable), at most
// kMaxBefore; beforeHandle names their sets.
enum : unsigned { kMaxBefore = 4 };
struct Action {
    bool sendSetAddress, sendEventMask; uint8_t output[11]; size_t outputLength;
    uint8_t before[kMaxBefore][10]; uint8_t beforeHandle[kMaxBefore]; unsigned beforeCount;
};
inline void setAddressCommand(uint8_t *out, uint8_t handle, const uint8_t *address) {
    out[0] = kOpSetRandomAddress & 0xff; out[1] = kOpSetRandomAddress >> 8; out[2] = 7; out[3] = handle;
    for (unsigned i = 0; i < 6; ++i) out[4 + i] = address[i];
}
inline bool same(const uint8_t *a, const uint8_t *b) {
    for (unsigned i = 0; i < 6; ++i) if (a[i] != b[i]) return false;
    return true;
}
// hci is the whole command, opcode first. Call this for every outgoing command. The returned
// action must be sent after the command itself, since a set exists only after 0x2036.
inline Action onCommand(State &s, const uint8_t *hci, size_t length, bool extendedScanning) {
    Action a{};
    if (!hci || length < 3) return a;
    const uint16_t op = uint16_t(hci[0] | hci[1] << 8);
    switch (op) {
    case kOpReset:
        s = State{};
        break;
    case kOpLeRandomAddress:
        if (length >= 9 && !same(hci + 3, kFixedPatcherAddress)) {
            for (unsigned i = 0; i < 6; ++i) s.address[i] = hci[3 + i];
            s.haveAddress = true;
            s.haveGeneralAddress = true;
        }
        break;
    case kOpSetRandomAddress:
        // bluetoothd's address for this set. It's rejected if the set doesn't exist yet, so
        // this doesn't count as the set having one, but it's kept for when the set is created.
        if (length >= 10 && !same(hci + 4, kFixedPatcherAddress)) {
            if (hci[3] < 32) {
                for (unsigned i = 0; i < 6; ++i) s.setAddress[hci[3]][i] = hci[4 + i];
                s.knownSetAddresses |= 1U << hci[3];
                // Sent by bluetoothd to a set that exists: its own address is installed, nothing to redo.
                if (s.existingSets & (1U << hci[3]))
                    s.checkAtEnable &= ~(1U << hci[3]);
            }
        }
        break;
    case kOpExtAdvParams:
        // Handle at parameter 0, Own_Address_Type at parameter 10.
        if (length >= 4 && hci[3] < 32)
            s.existingSets |= 1U << hci[3];
        if (length >= 14 && hci[13] == 1 && hci[3] < 32 && !(s.addressedSets & (1U << hci[3])) &&
            (s.haveGeneralAddress || (s.knownSetAddresses & (1U << hci[3])))) {
            const uint8_t *chosen = (s.knownSetAddresses & (1U << hci[3])) ? s.setAddress[hci[3]] : s.address;
            s.addressedSets |= 1U << hci[3];
            s.checkAtEnable |= 1U << hci[3];
            a.sendSetAddress = true;
            setAddressCommand(a.output, hci[3], chosen);
            a.outputLength = 10;
        }
        break;
    case kOpExtAdvEnable:
        // Enable, Number_of_Sets, then per set: handle, duration (2), max events. A set this kext addressed
        // gets its address again once, ahead of the enable, so it's in place whatever became of the first send.
        if (length >= 5 && hci[3] == 1) {
            const unsigned sets = hci[4];
            for (unsigned i = 0; i < sets && 5 + 4 * i < length && a.beforeCount < kMaxBefore; ++i) {
                const uint8_t h = hci[5 + 4 * i];
                if (h >= 32 || !(s.checkAtEnable & (1U << h)))
                    continue;
                const bool own = s.knownSetAddresses & (1U << h);
                if (!own && !s.haveGeneralAddress)
                    continue;
                s.checkAtEnable &= ~(1U << h);
                setAddressCommand(a.before[a.beforeCount], h, own ? s.setAddress[h] : s.address);
                a.beforeHandle[a.beforeCount++] = h;
            }
        }
        break;
    case kOpRemoveSet:
        // A removed set forgets its address too: a set made later with the same handle must not be
        // given an address from before bluetoothd rotated it.
        if (length >= 4 && hci[3] < 32) {
            s.addressedSets &= ~(1U << hci[3]);
            s.knownSetAddresses &= ~(1U << hci[3]);
            s.existingSets &= ~(1U << hci[3]);
            s.checkAtEnable &= ~(1U << hci[3]);
            for (unsigned i = 0; i < 6; ++i) s.setAddress[hci[3]][i] = 0;
            // Without a general address, the fallback came from a set: forget it with the set, so a
            // re-created set can't get the removed set's address (audit P-R07).
            if (!s.haveGeneralAddress)
                s.haveAddress = false;
        }
        break;
    case kOpClearSets:
        s.addressedSets = 0;
        s.knownSetAddresses = 0;
        s.existingSets = 0;
        s.checkAtEnable = 0;
        for (auto &address : s.setAddress)
            for (unsigned i = 0; i < 6; ++i) address[i] = 0;
        if (!s.haveGeneralAddress)      // audit P-R07
            s.haveAddress = false;
        break;
    case kOpLeEventMask:
        // Extended scanning reports are bit 12, which bluetoothd leaves off for this chip.
        if (extendedScanning && length >= 11 && !(hci[4] & 0x10)) {
            a.sendEventMask = true;
            for (unsigned i = 0; i < 11; ++i) a.output[i] = hci[i];
            a.output[4] |= 0x10;
            a.outputLength = 11;
        }
        break;
    default:
        break;
    }
    return a;
}
// Read-only record of how bluetoothd uses the controller's resolving list, for Instant Hotspot: its LE connection to
// the iPhone's identity (public) address never completed on 2026-11-20 (6 s of connection scan, then status 702).
// That needs the controller to resolve the iPhone's private address. Nothing is changed here, only counted.
enum : uint16_t {
    kOpLeCreateConnection = 0x200d, kOpLeAddResolving = 0x2027, kOpLeRemoveResolving = 0x2028,
    kOpLeClearResolving = 0x2029, kOpLeAddressResolution = 0x202d, kOpLeExtCreateConnection = 0x2043,
};
struct PrivacyStats {
    uint32_t resolvingAdds, resolvingRemoves, resolvingClears, resolutionOn, resolutionOff;
    uint32_t connects[4];   // LE (extended) create connection by peer address type: public, random, public id, random id
    uint32_t connectsWithoutResolution;   // to an identity address while resolution was never turned on
    bool resolutionEnabled;
};
inline void notePrivacy(PrivacyStats &p, const uint8_t *hci, size_t length) {
    if (!hci || length < 3) return;
    const uint16_t op = uint16_t(hci[0] | hci[1] << 8);
    int peerType = -1;
    switch (op) {
    case kOpReset: p.resolutionEnabled = false; break;
    case kOpLeAddResolving: ++p.resolvingAdds; break;
    case kOpLeRemoveResolving: ++p.resolvingRemoves; break;
    case kOpLeClearResolving: ++p.resolvingClears; break;
    case kOpLeAddressResolution:
        if (length >= 4) { p.resolutionEnabled = hci[3] == 1; ++(hci[3] == 1 ? p.resolutionOn : p.resolutionOff); }
        break;
    case kOpLeCreateConnection: if (length >= 9) peerType = hci[8]; break;      // after interval, window, filter
    case kOpLeExtCreateConnection: if (length >= 6) peerType = hci[5]; break;   // after filter, own type
    default: break;
    }
    if (peerType >= 0 && peerType < 4) {
        ++p.connects[peerType];
        if (!p.resolutionEnabled && p.resolvingAdds) ++p.connectsWithoutResolution;
    }
}
// Intel Bluetooth controllers never send an LE Data Length Change event on Tahoe, so bluetoothd
// stays at LE_READY_WAIT_FOR_LENGTH after the link encrypts and a new BLE HID device (a mouse, a
// keyboard) never binds: "No database exists". Already bonded devices skip GATT discovery, which
// is why they still work. IntelBTPatcher's fix is to send LE Read Remote Features twice more and
// rewrite the two duplicate completions into the events bluetoothd is waiting for. Lilu panics if
// two plugins hook the same function, so with this kext active that job is here instead.
// OpenIntelWireless/IntelBluetoothFirmware#514.
enum : uint16_t { kOpLeReadRemoteFeatures = 0x2016 };
enum : uint8_t { kEvtLeMeta = 0x3e, kLeMetaReadRemoteFeaturesComplete = 0x04 };
// The link is up and encrypted when this runs, so the two events describe that link: the handle
// comes from the completion being replaced. Values are IntelBTPatcher's: 27 octets, 328 us.
enum : size_t { kPhyUpdateEventLength = 8, kDataLengthEventLength = 13 };
//
// The duplicates are tracked per connection handle (audit BT03): with one shared stage, a second link
// reading remote features while the first link's duplicates were pending reset the stage, and the fake
// events could carry the wrong handle. An entry that gets no events (a controller may answer a duplicate
// with a Command Status error only) expires after kDataLengthExpiryNs, so nothing waits forever.
enum : unsigned { kDataLengthLinks = 8 };
// At most this many interrupt reads are wrapped per round, whatever else happens (PR #61): a round that
// never matches can't keep every read of the controller's event pipe wrapped until it expires.
enum : uint32_t { kMaxWrappedReads = 24 };
enum : uint64_t { kDataLengthExpiryNs = 2000000000ULL };
struct DataLengthLink {
    uint16_t handle;       // 12-bit connection handle
    uint8_t stage;         // 0: the real completion, 1: fake PHY update, 2: fake data length
    uint8_t outstanding;   // duplicates whose completion hasn't been rewritten yet; 0 = free slot
    uint64_t armedNs;      // when the duplicates were sent
};
struct DataLengthState {
    DataLengthLink links[kDataLengthLinks];
    uint32_t expired;      // entries given up after kDataLengthExpiryNs
    uint32_t aborts;       // rounds dropped because nothing could be rewritten into a read (PR #61)
    uint32_t wrapped;      // reads wrapped since the last round was armed
};
inline uint16_t dataLengthHandle(uint8_t low, uint8_t high) { return uint16_t((low | high << 8) & 0x0fff); }
inline DataLengthLink *findLink(DataLengthState &s, uint16_t handle) {
    for (auto &l : s.links)
        if (l.outstanding && l.handle == handle)
            return &l;
    return nullptr;
}
// Frees the entries older than the expiry. Returns whether any entry is still waiting.
inline bool expireLinks(DataLengthState &s, uint64_t nowNs) {
    bool waiting = false;
    for (auto &l : s.links) {
        if (!l.outstanding)
            continue;
        if (nowNs - l.armedNs > kDataLengthExpiryNs) {
            l = DataLengthLink{};
            ++s.expired;
        } else {
            waiting = true;
        }
    }
    return waiting;
}
// Drops every pending link, keeping the counters: used when a read can't be rewritten (a failed transfer,
// no hold of our own on the buffer, a short write). Which link it belonged to can't be known without
// reading it, and a dropped round only leaves bluetoothd on the timeout it already had.
inline void abortLinks(DataLengthState &s) {
    for (auto &l : s.links)
        l = DataLengthLink{};
    ++s.aborts;
}
inline bool dataLengthPending(const DataLengthState &s) {
    for (auto &l : s.links)
        if (l.outstanding)
            return true;
    return false;
}
// How many copies of this command to send after it. Only LE Read Remote Features with its handle, and
// a controller start forgets every command still in flight. With every slot busy, no copies are sent:
// that link then behaves as it would without this fix.
inline unsigned extraRemoteReads(DataLengthState &s, const uint8_t *hci, size_t length, uint64_t nowNs) {
    if (!hci || length < 3)
        return 0;
    const uint16_t op = uint16_t(hci[0] | hci[1] << 8);
    if (op == kOpReset) {
        const uint32_t expired = s.expired, aborts = s.aborts;
        s = DataLengthState{};
        s.expired = expired;
        s.aborts = aborts;
        return 0;
    }
    if (op != kOpLeReadRemoteFeatures || length < 5 || hci[2] < 2)
        return 0;
    expireLinks(s, nowNs);
    const uint16_t handle = dataLengthHandle(hci[3], hci[4]);
    DataLengthLink *l = findLink(s, handle);
    if (!l) {
        for (auto &free : s.links)
            if (!free.outstanding) {
                l = &free;
                break;
            }
        if (!l)
            return 0;
    }
    // A repeated read on the same link starts over: its earlier duplicates are folded into this one.
    l->handle = handle;
    l->stage = 0;
    l->outstanding = 2;
    l->armedNs = nowNs;
    s.wrapped = 0;   // a new round starts with a full budget of wrapped reads
    return 2;
}
// Whether to wrap an interrupt read: something is waiting, the buffer can hold the longest rewritten
// event (PR #61), and the round's budget isn't spent. A spent budget drops the round.
inline bool wrapRead(DataLengthState &s, uint64_t nowNs, size_t bufferLength) {
    if (!expireLinks(s, nowNs) || bufferLength < kDataLengthEventLength)
        return false;
    if (s.wrapped >= kMaxWrappedReads) {
        abortLinks(s);
        return false;
    }
    ++s.wrapped;
    return true;
}
// A copy that couldn't be sent never produces an event, so it's not waited for.
inline void forgetRemoteRead(DataLengthState &s, const uint8_t *hci, size_t length) {
    if (!hci || length < 5)
        return;
    DataLengthLink *l = findLink(s, dataLengthHandle(hci[3], hci[4]));
    if (l && !--l->outstanding)
        *l = DataLengthLink{};
}
// Rewrites one incoming event in place and returns its new size. Everything except a duplicate
// LE Read Remote Features Complete for a link that is waiting passes through untouched; the first of
// that link's two duplicates becomes PHY Update Complete, the second LE Data Length Change, as in
// IntelBTPatcher.
inline size_t rewriteEvent(DataLengthState &s, uint8_t *event, size_t length) {
    if (!event || length < 6 || event[0] != kEvtLeMeta || event[2] != kLeMetaReadRemoteFeaturesComplete)
        return length;
    const uint8_t handleLow = event[4], handleHigh = event[5];
    DataLengthLink *l = findLink(s, dataLengthHandle(handleLow, handleHigh));
    if (!l)
        return length;
    if (l->stage == 0) {  // the real completion goes to bluetoothd as it is
        l->stage = 1;
        return length;
    }
    // Status 0, both directions 2M.
    if (l->stage == 1) {
        const uint8_t fake[kPhyUpdateEventLength] = {kEvtLeMeta, 6, 0x0c, 0x00, handleLow, handleHigh, 0x02, 0x02};
        for (unsigned i = 0; i < kPhyUpdateEventLength; ++i)
            event[i] = fake[i];
        l->stage = 2;
        if (!--l->outstanding)
            *l = DataLengthLink{};
        return kPhyUpdateEventLength;
    }
    // A Data Length Change has no status byte, so the handle moves to parameter 0.
    const uint8_t fake[kDataLengthEventLength] = {kEvtLeMeta, 11, 0x07, handleLow, handleHigh,
                                                  0x1b, 0x00, 0x48, 0x01, 0x1b, 0x00, 0x48, 0x01};
    for (unsigned i = 0; i < kDataLengthEventLength; ++i)
        event[i] = fake[i];
    *l = DataLengthLink{};
    return kDataLengthEventLength;
}
}
