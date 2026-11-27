// Read-only record of what the firmware says about the regulatory domain. Nothing here
// changes a channel, a country or the source of a request.
#pragma once
#include <stdint.h>
#include <stddef.h>
namespace ItlAWDL {
// The firmware's reply lists channel flags in the order of the NVM channel table.
inline bool regulatoryChannelFlags(const uint8_t *table, size_t tableCount, uint8_t channel,
                                   const uint32_t *flags, size_t flagCount, uint32_t *out) {
    if (!table || !flags || !out) return false;
    for (size_t i = 0; i < tableCount && i < flagCount; ++i) {
        if (table[i] == channel) { *out = flags[i]; return true; }
    }
    return false;
}
struct MccSample {
    uint32_t uptimeSeconds;
    uint16_t mcc;
    uint8_t source, status, state, trigger, bssChannel, reserved;
    uint32_t channel149, channel36, channel6;
};
// The firmware repeats its notice, so it's answered at most this often.
constexpr uint32_t kMccEchoIntervalSeconds = 30;
constexpr bool mccEchoDue(bool answered, uint32_t nowSeconds, uint32_t lastSeconds) {
    return !answered || nowSeconds < lastSeconds || nowSeconds - lastSeconds >= kMccEchoIntervalSeconds;
}
enum MccSampleTrigger : uint8_t { kMccRead = 0, kMccReadAfterNotice = 1, kMccBiosReply = 2, kMccEchoReply = 3, kMccPeerReply = 4 };
// A country the firmware says it learned from Wi-Fi, in two upper-case letters. The world
// domain is excluded because answering it can't unlock anything.
constexpr uint8_t kMccSourceWifi = 5;
constexpr bool countryNoticeUsable(uint16_t mcc, uint8_t source) {
    return source == kMccSourceWifi && (mcc >> 8) >= 'A' && (mcc >> 8) <= 'Z' && (mcc & 255) >= 'A' && (mcc & 255) <= 'Z' &&
        mcc != uint16_t('Z' << 8 | 'Z');
}
// Which countries nearby networks advertise, by channel. No names or addresses are kept.
struct BeaconCountry { uint8_t first, second, channel, reserved; uint32_t count; };
// True for a beacon or probe response. country is left as "--" when it carries no Country element.
inline bool beaconCountry(const uint8_t *frame, size_t captured, uint8_t country[2]) {
    if (!frame || captured < 36 + 4 || (frame[0] != 0x80 && frame[0] != 0x50)) return false;
    country[0] = country[1] = '-';
    const size_t end = captured - 4; // The capture ends with the FCS.
    for (size_t i = 36; i + 2 <= end;) {
        const size_t length = frame[i + 1];
        if (i + 2 + length > end) break;
        if (frame[i] == 7 && length >= 2) {
            country[0] = frame[i + 2];
            country[1] = frame[i + 3];
            break;
        }
        i += 2 + length;
    }
    return true;
}
inline void noteBeaconCountry(BeaconCountry *table, unsigned capacity, unsigned &count, uint32_t &overflow,
                              const uint8_t country[2], uint8_t channel) {
    for (unsigned i = 0; i < count; ++i) {
        if (table[i].first == country[0] && table[i].second == country[1] && table[i].channel == channel) {
            ++table[i].count;
            return;
        }
    }
    if (count >= capacity) { ++overflow; return; }
    table[count++] = BeaconCountry{country[0], country[1], channel, 0, 1};
}
// -itlawdlbgscan: while idle on channel 6, scan now and then until the firmware reports a
// country, then move up with a card restart. There are no idle scans on 149. A withdrawal the
// firmware reports there still moves the driver down, and the scans start again.
constexpr uint64_t kBackgroundScanFirstUS = 45000000, kBackgroundScanEveryUS = 90000000;
constexpr uint64_t kBackgroundScanLimitUS = 15000000, kChannelMoveIdleUS = 10000000;
constexpr uint64_t kChannelMoveUpEveryUS = 300000000;
struct ChannelMoveState {
    // upNoticed keeps a notice that came too soon after the last move up. The firmware doesn't
    // repeat one for a country it already reported, so dropping it could strand us on 6.
    bool wantUp = false, wantDown = false, skipStartupScan = false, upNoticed = false;
    uint64_t lastScanUS = 0, lastUpUS = 0;
    uint64_t moveStartUS = 0;
    uint32_t lastMoveMs = 0;
};
// itlawdlmovetest=N, for testing only: one forced move down, N seconds after boot if on 149 by then.
constexpr bool forcedMoveDue(unsigned seconds, bool done, unsigned channel, uint64_t nowUS) {
    return seconds && !done && channel == 149 && nowUS >= uint64_t(seconds) * 1000000;
}
constexpr bool backgroundScanDue(bool onFallbackChannel, bool busy, uint64_t nowUS, uint64_t lastScanUS, uint64_t lastDataUS) {
    return onFallbackChannel && !busy &&
        nowUS >= (lastScanUS ? lastScanUS + kBackgroundScanEveryUS : kBackgroundScanFirstUS) &&
        nowUS - lastDataUS >= kChannelMoveIdleUS;
}
// A restart while already on 149 needs no startup scan if the firmware still allows it.
// Coming up from 6 always scans, so the country gets answered and recorded.
constexpr bool startupScanNeeded(unsigned currentChannel, bool active149) {
    return !(currentChannel == 149 && active149);
}
// A usable notice on the fallback channel asks for a move up, but not more often than this,
// in case the startup scan doesn't hear the same network again.
constexpr bool channelMoveUpAllowed(uint64_t nowUS, uint64_t lastUpUS) {
    return !lastUpUS || nowUS - lastUpUS >= kChannelMoveUpEveryUS;
}
// The move itself waits until nothing's been sent or received for a while.
constexpr bool channelMoveReady(bool busy, uint64_t nowUS, uint64_t lastDataUS) {
    return !busy && nowUS - lastDataUS >= kChannelMoveIdleUS;
}
// The country a peer states in its AWDL frames: TLV type 12, bytes 2 and 3 of the value.
// frame is a validated action frame without FCS, with TLVs from byte 40. The layout comes
// from captures of one phone, so anything else is refused.
inline bool peerCountryFromAction(const uint8_t *frame, size_t length, uint16_t *country) {
    if (!frame || !country || length < 40) return false;
    for (size_t i = 40; i + 3 <= length;) {
        const size_t value = size_t(frame[i + 1]) | size_t(frame[i + 2]) << 8;
        if (i + 3 + value > length) return false;
        if (frame[i] == 12) {
            if (value < 4) return false;
            const uint16_t found = uint16_t(frame[i + 5] << 8 | frame[i + 6]);
            if (!countryNoticeUsable(found, kMccSourceWifi)) return false;
            *country = found;
            return true;
        }
        i += 3 + value;
    }
    return false;
}
// The same country has to arrive this many times in a row before it's believed.
constexpr unsigned kPeerCountryFrames = 5;
struct PeerCountryState { uint16_t candidate = 0, confirmed = 0; unsigned run = 0, changes = 0; };
inline void notePeerCountry(PeerCountryState &s, uint16_t country) {
    if (country != s.candidate) {
        if (s.candidate) ++s.changes;
        s.candidate = country;
        s.run = 0;
    }
    if (++s.run >= kPeerCountryFrames) s.confirmed = country;
}
struct MccNotice { uint32_t uptimeSeconds; uint16_t mcc; uint8_t source, reserved; };
template <typename T> inline bool regulatoryAppend(T *table, unsigned capacity, unsigned &count, const T &entry) {
    if (count >= capacity) return false;
    table[count++] = entry;
    return true;
}
}
