//
//  WCL.hpp
//  AirportItlwm
//
//  Created by laobamac on 2026/10/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef AirportWCL_hpp
#define AirportWCL_hpp

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace AirportWCL {

// The kernel's IFNET_LQM_THRESH_OFF: link quality "off".
constexpr int32_t kLinkQualityOff = -2;

template <typename Report>
inline void resetLinkQuality(int32_t &reported, Report report) {
    if (!reported)
        return;
    report(kLinkQualityOff);
    reported = 0;
}

enum class MacUpdate { Invalid, Unchanged, Busy, Change };
inline MacUpdate planMacUpdate(const uint8_t *current, const uint8_t *requested,
                               size_t length, bool initializing) {
    if (!current || !requested || length != 6 || (requested[0] & 1))
        return MacUpdate::Invalid;
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i) bits |= requested[i];
    if (!bits) return MacUpdate::Invalid;
    if (memcmp(current, requested, 6) == 0) return MacUpdate::Unchanged;
    return initializing ? MacUpdate::Busy : MacUpdate::Change;
}

// Returns true when this is an internal MAC operation, not an adapter reset.
inline bool consumeMacReconfiguration(bool &pending, bool ready) {
    if (!pending) return false;
    if (ready) pending = false;
    return true;
}

struct HardwareAddress {
    uint32_t version;
    uint8_t address[6];
    uint8_t padding[2];
};
static_assert(sizeof(HardwareAddress) == 12, "HW_ADDR native wire size");
static_assert(offsetof(HardwareAddress, address) == 4, "HW_ADDR native address offset");
inline bool copyHardwareAddress(const uint8_t *address, HardwareAddress &out) {
    out = {};
    if (planMacUpdate(address, address, 6, false) == MacUpdate::Invalid) return false;
    out.version = 1;
    memcpy(out.address, address, 6);
    return true;
}

enum BeaconFlags : uint32_t {
    SSIDPresent = 1U << 1,
    RSSIValid = 1U << 14
};

enum Message : uint32_t {
    ResetInterface = 49,
    DriverAvailable = 55,
    ScanResult = 201,
    Deauth = 203,
    AssocComplete = 211,
    FirstBeacon = 212,
    ConnectComplete = 213,
    JoinAbortComplete = 214,
    LinkStatus = 216,
    LqmUpdate = 39,
    ScanDone = 237
};

struct SequoiaLqmUpdate {
    uint8_t rssiValid;
    uint8_t reserved0[3];
    int32_t rssi;
    uint8_t reserved1[0x150 - 8];
};
static_assert(sizeof(SequoiaLqmUpdate) == 0x150, "Sequoia LQM size");
static_assert(offsetof(SequoiaLqmUpdate, rssi) == 4, "Sequoia LQM RSSI offset");

// WCLNetManager::handleLqmUpdate consumes this 0x1dc snapshot. Read from its 25G241 code: byte 0 is
// the RSSI valid flag and the int32 at 4 the RSSI in dBm, which it stores as the link's current RSSI.
// Without them WCL sees 0 dBm, airportd rates en0's LinkQuality "off" (-2), and apsd then treats Wi-Fi
// as unusable, so push, iMessage and other Apple services can't connect. Beacon reception is the
// only other part filled unless measured SNR/noise are available. Those offsets
// were tested only on Tahoe 26.7.2/26.7.3 (25G332/25G342), not 26.7.1.
// Population remains enabled on Tahoe; 26.7.1 still needs validation.
// Core RSSI and CCA stay invalid.
struct LqmBeaconUpdate {
    uint8_t rssiValid;
    uint8_t reserved0[3];
    int32_t rssi;
    uint8_t reservedCore[3];                     // 0x08..0x0a
    uint8_t snrValid;                            // 0x0b
    int16_t snr;                                 // 0x0c
    uint8_t noiseValid;                          // 0x0e
    uint8_t reservedPad;
    int16_t noise;                               // 0x10
    uint8_t prefix[0x28 - 0x12];                 // includes unused CCA
    uint32_t receivedDelta;
    uint32_t scheduledDelta;
    uint8_t beaconValid;
    uint8_t reserved[0x1d8 - 0x31];
    uint8_t snapshotValid;
    uint8_t countersValid;
    uint8_t tail[2];
};
static_assert(sizeof(LqmBeaconUpdate) == 0x1dc, "WCL LQM update size");
static_assert(offsetof(LqmBeaconUpdate, snrValid) == 0x0b, "WCL SNR valid offset");
static_assert(offsetof(LqmBeaconUpdate, snr) == 0x0c, "WCL SNR offset");
static_assert(offsetof(LqmBeaconUpdate, noiseValid) == 0x0e, "WCL noise valid offset");
static_assert(offsetof(LqmBeaconUpdate, noise) == 0x10, "WCL noise offset");
static_assert(offsetof(LqmBeaconUpdate, receivedDelta) == 0x28, "WCL beacon delta offset");
static_assert(offsetof(LqmBeaconUpdate, rssi) == 4, "WCL LQM RSSI offset");
static_assert(offsetof(LqmBeaconUpdate, beaconValid) == 0x30, "WCL beacon valid offset");
static_assert(offsetof(LqmBeaconUpdate, snapshotValid) == 0x1d8, "WCL snapshot valid offset");
inline bool makeBeaconUpdate(uint32_t receivedDelta, LqmBeaconUpdate &out)
{
    out = {};
    if (!receivedDelta)
        return false;
    out.receivedDelta = receivedDelta;
    out.beaconValid = out.snapshotValid = out.countersValid = 1;
    return true;
}

inline void setBeaconRadio(LqmBeaconUpdate &out, int32_t rssi, int16_t noise) {
    // sc_noise is 0 before statistics and -127 when no antenna has a reading.
    if (rssi >= 0 || noise >= 0 || noise < -120)
        return;
    const int32_t snr = rssi - noise;
    if (snr < INT16_MIN || snr > INT16_MAX)
        return;
    out.noiseValid = out.snrValid = 1;
    out.noise = noise;
    out.snr = static_cast<int16_t>(snr);
}

struct DriverAvailability {
    uint32_t version;
    uint32_t reserved0;
    uint32_t available;
    uint32_t reserved1;
    uint32_t reason;
    uint32_t subReason;
    uint8_t reserved2[0xf8 - 24];
};

static_assert(sizeof(DriverAvailability) == 0xf8, "DriverAvailability size");

struct BeaconMetadata {
    uint32_t ieLength;
    uint16_t channelSpec;
    uint8_t ssid[32];
    uint8_t ssidLength;
    uint8_t channel;
    uint8_t reserved0;
    uint8_t bssid[6];
    uint8_t reserved1;
    int32_t rssi;
    int16_t noise;
    int16_t snr;
    uint16_t interval;
    uint16_t capability;
#if !defined(__IO80211_TARGET) || __IO80211_TARGET != __MAC_15_2
    uint32_t reserved2;
#endif
    uint32_t flags;
};

struct AssociationEvent {
    uint16_t status;
    uint16_t reason;
    uint8_t mlo;
    uint8_t bssid[6];
    uint8_t reserved;
    uint32_t mloData[2];
    int32_t driverStatus;
    int32_t driverReason;
};

struct ConnectionPeer {
    uint8_t bssid[6];
    uint16_t reserved;
    int32_t driverStatus;
    int32_t driverReason;
};

struct FirstBeaconEvent {
    uint16_t status;
    uint16_t reason;
    ConnectionPeer peer;
};

struct ConnectionEvent {
    uint16_t status;
    uint16_t reason;
    ConnectionPeer peers[10];
};

struct LinkStatusEvent {
    uint8_t bssid[6];
    uint8_t up;
    uint8_t inSleep;
    uint32_t reason;
    uint32_t reserved;
};
static_assert(sizeof(LinkStatusEvent) == 16, "LinkStatusEvent size");
static_assert(offsetof(LinkStatusEvent, up) == 6, "LinkStatusEvent up offset");

struct DeauthEvent {
    int32_t driverStatus;
    int32_t driverReason;
    uint16_t reason;
    uint8_t bssid[6];
    uint8_t disassociation;
    uint8_t reserved[3];
};

struct __attribute__((packed)) ChannelEntry {
    uint16_t channelSpec;
    uint8_t reserved[4];
    uint8_t channel;
    uint8_t flags;
};

struct __attribute__((packed)) ChannelInfo {
    ChannelEntry channels[400];
    uint16_t count;
    uint8_t country[3];
    uint8_t supports6GHz;
};

#if defined(__IO80211_TARGET) && __IO80211_TARGET == __MAC_15_2
static_assert(sizeof(BeaconMetadata) == 0x40, "Sequoia BeaconMetadata size");
static_assert(offsetof(BeaconMetadata, flags) == 0x3c, "Sequoia BeaconMetadata flags");
#else
static_assert(sizeof(BeaconMetadata) == 0x44, "BeaconMetadata size");
static_assert(offsetof(BeaconMetadata, flags) == 0x40, "BeaconMetadata flags");
#endif
static_assert(offsetof(BeaconMetadata, bssid) == 0x29, "BeaconMetadata BSSID");
static_assert(offsetof(BeaconMetadata, rssi) == 0x30, "BeaconMetadata RSSI");
static_assert(sizeof(AssociationEvent) == 0x1c, "AssociationEvent size");
static_assert(sizeof(FirstBeaconEvent) == 0x14, "FirstBeaconEvent size");
static_assert(sizeof(ConnectionEvent) == 0xa4, "ConnectionEvent size");
static_assert(sizeof(DeauthEvent) == 0x14, "DeauthEvent size");
static_assert(sizeof(ChannelInfo) == 0xc86, "ChannelInfo size");

struct NativeChannelInfo {
    uint8_t reserved0[8];
    uint8_t country[4];
    uint16_t count;
    uint16_t channelSpec[400];
    uint8_t channel[400];
    uint8_t indoor[400];
    uint8_t dfs[400];
    uint8_t passive[400];
    uint8_t supports40MHz[400];
    uint8_t supports80MHz[400];
    uint8_t reserved1[2];
    uint32_t firmwareChannelSpec[400];
    uint32_t channelBitmap[400];
    uint8_t reserved2[0x2720 - 0x1910];
};
static_assert(sizeof(NativeChannelInfo) == 0x2720, "CHANNELS_INFO native size");
static_assert(offsetof(NativeChannelInfo, country) == 8, "CHANNELS_INFO country");
static_assert(offsetof(NativeChannelInfo, count) == 0xc, "CHANNELS_INFO count");
static_assert(offsetof(NativeChannelInfo, channelSpec) == 0xe, "CHANNELS_INFO chanspec");
static_assert(offsetof(NativeChannelInfo, channel) == 0x32e, "CHANNELS_INFO channel");
static_assert(offsetof(NativeChannelInfo, indoor) == 0x4be, "CHANNELS_INFO indoor");
static_assert(offsetof(NativeChannelInfo, dfs) == 0x64e, "CHANNELS_INFO DFS");
static_assert(offsetof(NativeChannelInfo, passive) == 0x7de, "CHANNELS_INFO passive");
static_assert(offsetof(NativeChannelInfo, supports40MHz) == 0x96e, "CHANNELS_INFO 40 MHz");
static_assert(offsetof(NativeChannelInfo, supports80MHz) == 0xafe, "CHANNELS_INFO 80 MHz");
static_assert(offsetof(NativeChannelInfo, firmwareChannelSpec) == 0xc90, "CHANNELS_INFO firmware chanspec");
static_assert(offsetof(NativeChannelInfo, channelBitmap) == 0x12d0, "CHANNELS_INFO bitmap");

inline bool appendChannel(NativeChannelInfo &info, unsigned channel, bool fiveGHz,
                          bool dfs, bool passive, bool supports40MHz, bool supports80MHz)
{
    if (!channel || channel > 255 || info.count >= 400)
        return false;
    unsigned index = info.count++;
    uint16_t spec = uint16_t(channel | (fiveGHz ? 0xd000 : 0x1000));
    info.channelSpec[index] = spec;
    info.firmwareChannelSpec[index] = spec;
    info.channel[index] = channel;
    info.dfs[index] = dfs;
    info.passive[index] = passive;
    info.supports40MHz[index] = supports40MHz;
    info.supports80MHz[index] = supports80MHz;
    info.channelBitmap[index] = 3U | (fiveGHz ? 4U : 0U) |
        (dfs ? 8U : 0U) | (passive ? 32U : 0U);
    return true;
}

struct TrafficCounters {
    uint64_t realtimeInfraTx;
    uint64_t realtimeInfraRx;
    uint64_t infraTx;
    uint64_t infraRx;
    uint64_t realtimeAwdlTx;
    uint64_t realtimeNanTx;
    uint64_t timestampNanoseconds;
};
static_assert(sizeof(TrafficCounters) == 0x38, "WCL_TRAFFIC_COUNTERS native size");
static_assert(offsetof(TrafficCounters, timestampNanoseconds) == 0x30, "WCL traffic timestamp");

inline TrafficCounters makeTrafficCounters(const uint64_t *tx, const uint64_t *rx,
                                           uint64_t timestampNanoseconds)
{
    TrafficCounters out = {};
    out.realtimeInfraTx = tx[2] + tx[3];
    out.realtimeInfraRx = rx[2] + rx[3];
    for (unsigned ac = 0; ac < 4; ++ac) {
        out.infraTx += tx[ac];
        out.infraRx += rx[ac];
    }
    out.timestampNanoseconds = timestampNanoseconds;
    return out;
}

struct ScanTiming {
    uint32_t maxOutTU;
    bool fragmented;
    uint32_t suspendTU;
};

// Off-channel timing for scans while associated, after Linux iwlwifi's scan
// types: a 120 TU visit fits a whole passive dwell (110 TU), followed by 120 TU
// back on the home channel. Passive dwells are split into short fragments
// (44 TU out, 95 TU home) only when the caller asks for a short away time,
// i.e. low latency. Splitting by default made each passive channel cost
// ~0.8 s and full scans ~20 s. A 30 TU home time on quiet links (Linux's
// lighter setting) coincided with firmware resets on AX210, so it is not used.
// maxOutOverrideTU (boot flag itlwm_scanout=120..480) lengthens each visit so
// several passive dwells fit before returning home; the 120 TU home time stays.
// For Macs whose Wi-Fi carries little traffic. 0 keeps the 120 TU default.
inline ScanTiming scanTiming(uint32_t awayMilliseconds, bool associated,
                             bool supportsFragmentation, uint32_t maxOutOverrideTU = 0)
{
    if (!associated)
        return {0, false, 0};
    uint64_t requested = uint64_t(awayMilliseconds) * 1000 / 1024;
    if (awayMilliseconds && requested < 100 && supportsFragmentation)
        return {requested < 44 ? 44 : uint32_t(requested), true, 95};
    return {maxOutOverrideTU > 120 ? maxOutOverrideTU : 120, false, 120};
}

inline uint16_t read16(const uint8_t *p) {
    return uint16_t(p[0]) | uint16_t(p[1]) << 8;
}

inline uint32_t read32(const uint8_t *p) {
    return uint32_t(read16(p)) | uint32_t(read16(p + 2)) << 16;
}

inline bool validIEs(const uint8_t *data, size_t length) {
    if (!data || length > 2048)
        return false;
    while (length) {
        if (length < 2 || size_t(data[1]) + 2 > length)
            return false;
        size_t next = size_t(data[1]) + 2;
        data += next;
        length -= next;
    }
    return true;
}

inline bool scanUsesProbes(bool requested, bool activeRequest) {
    return requested ? activeRequest : true;
}

// Present the supported PSK option of a PSK/SAE transition network to WCL.
// This operates on the scan-message copy, never the received beacon or the
// net80211 RSN IE used to validate the four-way handshake. SAE-only, mandatory
// PMF and other AKM combinations must not be converted into WPA2 networks.
// True if the IEs carry an RSN Extension element (244) with SAE hash-to-element (bit 5).
// The driver only does H2E, so -itlwmwpa3 shows macOS the SAE AKM only when this holds.
inline bool advertisesSAEH2E(const uint8_t *ies, size_t length) {
    if (!validIEs(ies, length))
        return false;
    for (size_t offset = 0; offset < length; offset += size_t(ies[offset + 1]) + 2) {
        if (ies[offset] == 244 && ies[offset + 1] >= 1 && (ies[offset + 2] & 0x20))
            return true;
    }
    return false;
}

// True if a beacon's IEs hide the network's name: no SSID element, an empty one, or one of zero bytes only
// (the two ways access points hide it). Such a network answers only a probe that names it.
inline bool hidesSsid(const uint8_t *ies, size_t length) {
    if (!validIEs(ies, length))
        return false;
    for (size_t offset = 0; offset < length; offset += size_t(ies[offset + 1]) + 2) {
        if (ies[offset] != 0)
            continue;
        for (size_t i = 0; i < ies[offset + 1]; ++i)
            if (ies[offset + 2 + i])
                return false;
        return true;
    }
    return true;
}

inline bool zeroAddress(const uint8_t *address) {
    for (unsigned i = 0; i < 6; ++i)
        if (address[i])
            return false;
    return true;
}

// Two network names are the same and not empty.
inline bool sameSsid(const uint8_t *a, size_t aLength, const uint8_t *b, size_t bLength) {
    return aLength && aLength == bLength && aLength <= 32 && !memcmp(a, b, aLength);
}

inline size_t selectWPA2TransitionMode(uint8_t *ies, size_t length) {
    if (!validIEs(ies, length))
        return length;
    bool converted = false;
    for (size_t offset = 0; offset < length; ) {
        uint8_t *ie = ies + offset;
        size_t size = size_t(ie[1]) + 2;
        if (ie[0] != 48 || size < 10 || read16(ie + 2) != 1) {
            offset += size;
            continue;
        }
        size_t pairwiseCount = read16(ie + 8);
        if (!pairwiseCount || pairwiseCount > (size - 10) / 4) {
            offset += size;
            continue;
        }
        size_t countOffset = 10 + 4 * pairwiseCount;
        if (size - countOffset < 2) {
            offset += size;
            continue;
        }
        size_t count = read16(ie + countOffset);
        size_t suitesOffset = countOffset + 2;
        if (count < 2 || count > (size - suitesOffset) / 4) {
            offset += size;
            continue;
        }
        size_t tailOffset = suitesOffset + 4 * count;
        // PSK/SAE transition mode advertises PMF capable, but not required.
        if (size - tailOffset < 2 || (read16(ie + tailOffset) & 0xc0) != 0x80) {
            offset += size;
            continue;
        }
        bool psk = false, sae = false, other = false;
        for (size_t i = 0; i < count; ++i) {
            const uint8_t *suite = ie + suitesOffset + 4 * i;
            if (suite[0] != 0 || suite[1] != 0x0f || suite[2] != 0xac)
                other = true;
            else if (suite[3] == 2)
                psk = true;
            else if (suite[3] == 6)
                continue;      // PSK-SHA256: dropped with SAE, as long as plain PSK is offered too
            else if (suite[3] == 8 || suite[3] == 24)
                sae = true;    // SAE, and SAE with group-dependent hash
            else
                other = true;
        }
        if (!psk || !sae || other) {
            offset += size;
            continue;
        }
        const uint8_t pskSuite[] = {0, 0x0f, 0xac, 2};
        memcpy(ie + suitesOffset, pskSuite, sizeof(pskSuite));
        ie[countOffset] = 1;
        ie[countOffset + 1] = 0;
        size_t removed = 4 * (count - 1);
        // Keep RSN capabilities, PMKIDs, group-management cipher and all
        // following information elements byte-for-byte intact.
        memmove(ie + suitesOffset + 4, ie + tailOffset,
                length - offset - tailOffset);
        ie[1] -= removed;
        length -= removed;
        offset += size - removed;
        converted = true;
    }
    // The RSN Extension element only describes SAE features (H2E, protected TWT and the like). Once
    // the network is shown as WPA2-PSK, macOS must not see it either.
    if (converted) {
        for (size_t offset = 0; offset + 2 <= length; ) {
            const size_t size = size_t(ies[offset + 1]) + 2;
            if (size > length - offset)     // never past the list, whatever ran before (audit P-W01)
                break;
            if (ies[offset] == 244) {
                memmove(ies + offset, ies + offset + size, length - offset - size);
                length -= size;
            } else {
                offset += size;
            }
        }
    }
    return length;
}
inline bool probeChannel(bool active, bool passiveOnly, bool dfs) {
    return active && !passiveOnly && !dfs;
}
// iwx (UMAC scan): an active scan selects its SSID on every channel entry, passive and radar channels included,
// as iwlwifi (iwl_mvm_umac_scan_cfg_channels_v7) and OpenBSD's iwx do; the firmware itself keeps those channels
// passive until it may transmit there. Leaving the SSID off them made AX210 firmware assert (UMAC 0x20002806,
// last command SCAN_REQ_UMAC, a passive 5 GHz channel in the data word) during unassociated scans (#69,
// runmain's finding). iwm and iwn keep probeChannel: their firmware is asked per channel by the driver.
inline bool umacScanSelectsSsid(bool active) {
    return active;
}

struct ScanRequest {
    uint32_t identifier;
    uint32_t type;
    uint8_t ssid[32];
    uint32_t ssidLength;
    uint8_t bssid[6];
    uint32_t channelCount;
    uint8_t channels[32];
};

inline bool scanChannelSelected(const uint8_t *channels, bool restricted, unsigned channel) {
    return !restricted || (channel < 256 && (channels[channel / 8] & (1U << (channel % 8))));
}

inline bool decodeScan(const void *buffer, size_t length, ScanRequest &out) {
    if (!buffer || length < 0x58)
        return false;
    const uint8_t *p = static_cast<const uint8_t *>(buffer);
    uint32_t count = read32(p + 0x54), ssidLength = read32(p + 0x1c);
    uint32_t type = read32(p + 0x40);
    if (count > 400 || ssidLength > 32 || type < 1 || type > 4 ||
        length < 0x58 + size_t(count) * 12)
        return false;
    out = {};
    out.identifier = read32(p);
    out.type = type;
    out.ssidLength = ssidLength;
    out.channelCount = count;
    memcpy(out.ssid, p + 0x20, ssidLength);
    memcpy(out.bssid, p + 0x14, 6);
    // Native entries are apple80211_channel: version, channel, flags (12 bytes).
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *entry = p + 0x58 + size_t(i) * 12;
        uint32_t channel = read32(entry + 4), flags = read32(entry + 8);
        // Do not confuse 6 GHz channel numbers with overlapping 2.4 GHz ones.
        if (!channel || channel > 196 || (flags & 0x2000))
            continue;
        if (((flags & 0x8) && channel > 14) || ((flags & 0x10) && channel <= 14))
            continue;
        out.channels[channel / 8] |= 1U << (channel % 8);
    }
    return true;
}

struct JoinRequest {
    uint32_t lowerAuth;
    uint32_t upperAuth;
    uint32_t ssidLength;
    uint8_t ssid[32];
    uint32_t keyLength;
    uint32_t keyCipher;
    uint16_t keyIndex;
    /* SAE passphrase: raw bytes up to 63; PSK: 32 bytes. */
    uint8_t key[64];
    uint8_t bssid[6];
    uint16_t channelSpec;
    uint16_t rsnLength;
    uint8_t rsn[257];
};

inline bool validCipherKey(uint32_t cipher, uint32_t length, uint16_t flags,
                           uint16_t index, uint32_t rscLength) {
    // Native WCL accepts PMK/MSK for enterprise, not legacy PTK/GTK.
    (void)flags; // PTK/GTK selectors do not apply to PMK material.
    (void)index;
    return (cipher == 6 || cipher == 7 || cipher == 9) && length == 32 && rscLength <= 8;
}

inline bool validRSNOverride(const uint8_t *ie, size_t length) {
    if (!ie || length > 257) return false;
    if (!length) return true;
    if (length < 4 || size_t(ie[1]) + 2 != length) return false;
    if (ie[0] == 48) return ie[2] == 1 && ie[3] == 0;
    return length >= 8 && ie[0] == 221 && ie[2] == 0 && ie[3] == 0x50 &&
        ie[4] == 0xf2 && ie[5] == 1 && ie[6] == 1 && ie[7] == 0;
}

enum class LegacyAuth { Invalid, Open, Wep, Personal, PersonalSAE, Enterprise };
inline LegacyAuth classifyLegacyAuth(const JoinRequest &j) {
    // Values from apple80211_authtype/cipher_type, used by the WCL association request.
    if (!validRSNOverride(j.rsn, j.rsnLength)) return LegacyAuth::Invalid;
    if (j.lowerAuth != 1) return LegacyAuth::Invalid;
    if (!j.upperAuth) {
        if (!j.keyLength) return LegacyAuth::Open;
        if (j.keyIndex < 4 && ((j.keyLength == 5 && j.keyCipher == 1) ||
                              (j.keyLength == 13 && j.keyCipher == 2)))
            return LegacyAuth::Wep;
        return LegacyAuth::Invalid;
    }
    const uint32_t personal = (1u << 1) | (1u << 3) | (1u << 10);
    const uint32_t enterprise = (1u << 0) | (1u << 2) | (1u << 11);
    const uint32_t sae = 1u << 12;
    if (j.upperAuth & ~(personal | enterprise | sae)) return LegacyAuth::Invalid;
    // WPA3-Personal is its own authentication type; mixing it with WPA2 is invalid.
    if ((j.upperAuth & sae) && j.upperAuth != sae) {
        return LegacyAuth::Invalid;
    }
    if ((j.upperAuth & personal) && (j.upperAuth & enterprise)) return LegacyAuth::Invalid;
    if (j.upperAuth & personal) {
        if (j.keyLength == 32 && (j.keyCipher == 6 || j.keyCipher == 7))
            return LegacyAuth::Personal;
        // WPA3 transition networks can hand over the raw passphrase too.
        if (j.keyCipher == 10 && j.keyLength >= 8 && j.keyLength <= 63 &&
            !memchr(j.key, 0, j.keyLength)) {
            return LegacyAuth::Personal;
        }
        return LegacyAuth::Invalid;
    }
    // Native WCL carries the raw SAE password (cipher 10), not a PMK.
    if (j.upperAuth == sae) {
        if (j.keyLength < 1 || j.keyLength > 63 || j.keyCipher != 10)
            return LegacyAuth::Invalid;
        if (j.rsnLength >= 8 &&
            (j.rsn[4] != 0 || j.rsn[5] != 0x0f || j.rsn[6] != 0xac ||
             j.rsn[7] != 4)) {
            return LegacyAuth::Invalid;
        }
        return LegacyAuth::PersonalSAE;
    }
    if (j.upperAuth & enterprise)
        return (!j.keyLength || (j.keyLength == 32 && (j.keyCipher == 6 || j.keyCipher == 7))) ?
            LegacyAuth::Enterprise : LegacyAuth::Invalid;
    return LegacyAuth::Invalid;
}

inline bool decodeJoin(const void *buffer, size_t length, JoinRequest &out) {
    if (!buffer || length < 0x218)
        return false;
    const uint8_t *p = static_cast<const uint8_t *>(buffer);
    uint32_t count = read32(p + 0x214), ssidLength = read32(p + 0x1c);
    uint32_t keyLength = read32(p + 0x44);
    uint16_t rsnLength = read16(p + 0xd4);
    if (!count || count > 10 || !ssidLength || ssidLength > 32 ||
        keyLength > 64 || rsnLength > 257 || length < 0x218 + size_t(count) * 18)
        return false;
    if (p[0x21c] & 1)
        return false;
    uint8_t addressBits = 0;
    for (unsigned i = 0; i < 6; ++i)
        addressBits |= p[0x21c + i];
    if (!addressBits)
        return false;
    out = {};
    out.lowerAuth = read32(p + 0x10);
    out.upperAuth = read32(p + 0x14);
    out.ssidLength = ssidLength;
    memcpy(out.ssid, p + 0x20, ssidLength);
    out.keyLength = keyLength;
    out.keyCipher = read32(p + 0x48);
    out.keyIndex = read16(p + 0x4e);
    memcpy(out.key, p + 0x50, keyLength);
    memcpy(out.bssid, p + 0x21c, 6);
    out.channelSpec = read16(p + 0x228);
    out.rsnLength = rsnLength;
    memcpy(out.rsn, p + 0xd6, rsnLength);
    return true;
}

}
#endif
