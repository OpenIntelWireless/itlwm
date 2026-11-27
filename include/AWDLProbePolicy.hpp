#pragma once
#include <stdint.h>
namespace ItlAWDL {
// A peer-gated train is about 173 s of airtime at the nominal 110 TU interval.
constexpr unsigned probeLimit(bool fast, bool peerGated = false) {
    return peerGated ? 1536U : fast ? 64U : 8U;
}
// Readiness waits stay slow. Only an active, unfinished, nonfailed train
// polls at the nominal 110 TU action interval. Never schedule catch-up sends.
constexpr unsigned probeDelayUS(bool fast, unsigned submitted, bool pending, bool attempted) {
    return fast && submitted && submitted < probeLimit(fast) && (pending || !attempted)
        ? 110U * 1024U : 6000000U;
}
// Transmit only while a peer is audible, so the bounded budget is spent when
// something could hear it and not during an empty stretch after boot.
constexpr bool peerRecentlyHeard(bool everHeard, uint64_t nowUS, uint64_t lastHeardUS) {
    return everHeard && nowUS >= lastHeardUS && nowUS - lastHeardUS <= 8000000U;
}
// Every 16th train frame is unicast. An 802.11 ACK comes from the receiver's own
// radio, so a completed unicast shows reception, unless the absent control also
// "succeeds", which would mean firmware status does not reflect ACKs here. The
// source variants ask whether firmware matches ACKs for the AWDL address, which
// is not the address in its MAC context. Failed probes cost retry airtime, hence
// the low rate. Index 0 is the first frame, which stays a normal broadcast.
// With elicit set, the hardware-source slots instead send a peer a Neighbor
// Solicitation and an echo request, which ask it to address a frame back to us.
enum class AckProbe : int { None = -1, PeerAWDL = 0, PeerHardware = 1, ControlAWDL = 2, ControlHardware = 3, PeerNeighbor = 4, PeerEcho = 5, PeerForeign = 6 };
// With foreign set, the first slot asks the peer to answer an address that isn't
// ours, so its replies can't be ACKed by us and should come back as retries.
constexpr AckProbe ackProbeFor(unsigned frame, bool peerKnown, bool elicit = false, bool foreign = false) {
    return frame % 4 != 1 ? AckProbe::None
        : frame % 16 == 1 ? (peerKnown ? (foreign ? AckProbe::PeerForeign : AckProbe::PeerAWDL) : AckProbe::None)
        : frame % 16 == 5 ? (peerKnown ? (elicit ? AckProbe::PeerNeighbor : AckProbe::PeerHardware) : AckProbe::None)
        : frame % 16 == 9 ? AckProbe::ControlAWDL
        : elicit ? (peerKnown ? AckProbe::PeerEcho : AckProbe::None) : AckProbe::ControlHardware;
}
// Unicast AWDL data needs real throughput, unlike probes, which stay at the lowest rate.
// Only a frame's first try counts. The driver holds a failed frame for a resend, so a peer
// that's off channel costs about one failure per absence, and many failures in a short
// run say the rate is too high.
// Steps above kLegacyRateTop are HT at 20 MHz and long guard interval: one stream, then two.
// -itlawdlht raises `top` to reach them.
constexpr unsigned kDataRateSteps = 9, kLegacyRateTop = 3, kHoldWindowsMax = 16;
constexpr unsigned dataRateMbps(unsigned step) {
    return step == 0 ? 12U : step == 1 ? 24U : step == 2 ? 36U : step == 3 ? 54U : step == 4 ? 65U :
           step == 5 ? 78U : step == 6 ? 104U : step == 7 ? 117U : 130U;
}
// The HT MCS index for a step, or -1 for a legacy rate.
constexpr int htMcsForStep(unsigned step) {
    return step <= kLegacyRateTop ? -1 : step == 4 ? 7 : int(step) + 7;
}
struct DataRateState {
    unsigned step = 1, frames = 0, failures = 0, top = kLegacyRateTop;
    // A peer may not take some HT rate at all, and retrying it every window would lose about
    // one frame in eight, so climbing back to one waits longer each time it fails. Legacy steps
    // don't wait, because every transfer starts by climbing them after idle failures.
    unsigned holdWindows = 0, holdLength = 1, failedStep = kDataRateSteps;
};
inline void noteDataResult(DataRateState &s, bool ok) {
    ++s.frames;
    if (!ok) ++s.failures;
    if (s.failures >= 8U) {
        if (s.step > kLegacyRateTop) {
            s.failedStep = s.step;
            s.holdWindows = s.holdLength;
            s.holdLength = s.holdLength * 2 > kHoldWindowsMax ? kHoldWindowsMax : s.holdLength * 2;
        }
        if (s.step) --s.step;
        s.frames = s.failures = 0;
    } else if (s.frames >= 64U) {
        if (s.failures <= 1U) {
            if (s.step >= s.failedStep) {
                // That rate works after all.
                s.holdLength = 1;
                s.failedStep = kDataRateSteps;
            }
            if (s.holdWindows) --s.holdWindows;
            const bool held = s.step + 1 > kLegacyRateTop && s.holdWindows;
            if (s.step < s.top && !held) ++s.step;
        }
        s.frames = s.failures = 0;
    }
}
// A failed unicast frame is held and sent again for a short time, so a brief absence by the
// peer looks like delay to the transport above us and not like loss.
constexpr uint64_t kResendWindowUS = 400000;
constexpr unsigned kResendMaxAttempts = 100;
struct ResendState { bool held = false, pending = false; unsigned attempts = 0; uint64_t firstUS = 0, notBeforeUS = 0; };
constexpr uint64_t resendBackoffUS(unsigned attempts) { return attempts <= 1U ? 0U : attempts == 2U ? 2000U : 5000U; }
constexpr bool resendExpired(const ResendState &s, uint64_t nowUS) {
    return nowUS < s.firstUS || nowUS - s.firstUS >= kResendWindowUS || s.attempts >= kResendMaxAttempts;
}
// After a failed try. False means the frame is given up, and the state is clear.
inline bool resendAfterFailure(ResendState &s, uint64_t nowUS) {
    if (!s.held || resendExpired(s, nowUS)) {
        s = ResendState{};
        return false;
    }
    ++s.attempts;
    s.notBeforeUS = nowUS + resendBackoffUS(s.attempts);
    s.pending = true;
    return true;
}
// With no data to send, the driver sends sync frames. These use the lowest rate and take a
// lot of air, so they need their own pace, however often the timer runs.
constexpr uint64_t kSyncIdleIntervalUS = 45000;
constexpr bool syncIdleDue(uint64_t nowUS, uint64_t lastSyncUS) {
    return nowUS < lastSyncUS || nowUS - lastSyncUS >= kSyncIdleIntervalUS;
}
// While data is moving, check for output every millisecond. Output arrives without notice,
// so a slow idle poll adds its whole delay to each round trip of a transfer.
constexpr uint64_t kDataActiveWindowUS = 1000000;
constexpr bool dataRecentlyActive(bool ever, uint64_t nowUS, uint64_t lastUS) {
    return ever && nowUS >= lastUS && nowUS - lastUS < kDataActiveWindowUS;
}
// Under continuous output a sync frame still goes about once per 110 TU, so a
// transfer can't silence the frames that keep the peer following us.
constexpr bool syncBeforeData(bool audible, uint64_t nowUS, uint64_t lastSyncUS) {
    return audible && nowUS >= lastSyncUS && nowUS - lastSyncUS >= 110U * 1024U;
}
// A firmware restart invalidates the queue, so allocate again for each generation.
// A failed allocation stays failed, so it can't become a restart loop.
constexpr bool monitorQueueShouldAllocate(bool attempted, int queue, int queueGeneration, int generation) {
    return !attempted || (queue >= 0 && queueGeneration != generation);
}
// Fixed channel choice. The firmware's regulatory answer decides: a channel it marks
// passive, DFS or no-ad-hoc is never used for transmit, and we stay on channel 6.
constexpr unsigned fixedChannelFor(bool want149, bool active149, bool restricted149) {
    return want149 && active149 && !restricted149 ? 149U : 6U;
}
// Accepts only a two-letter upper-case country; anything else keeps the world domain.
constexpr bool validCountry(const char *c) {
    return c && c[0] >= 'A' && c[0] <= 'Z' && c[1] >= 'A' && c[1] <= 'Z' && !c[2];
}
// Firmware Bluetooth coexistence mode for a test boot: 1 network, 2 Bluetooth, 3 Wi-Fi.
// Anything else keeps the driver's default of favouring Wi-Fi. Off (0) isn't offered,
// because disabling arbitration on a shared radio isn't a useful test.
constexpr uint32_t btCoexModeFor(int requested, uint32_t fallback) {
    return requested >= 1 && requested <= 3 ? uint32_t(requested) : fallback;
}
constexpr bool ackProbeIsPeer(AckProbe p) {
    return p == AckProbe::PeerAWDL || p == AckProbe::PeerHardware || p == AckProbe::PeerNeighbor || p == AckProbe::PeerEcho || p == AckProbe::PeerForeign;
}
constexpr bool ackProbeUsesHardwareSource(AckProbe p) { return p == AckProbe::PeerHardware || p == AckProbe::ControlHardware; }
constexpr unsigned peerTrainDelayUS(unsigned submitted, bool heard, bool pending, bool attempted) {
    return !submitted || submitted >= probeLimit(false, true) || (attempted && !pending) ? 6000000U
        : (heard || pending) ? 110U * 1024U : 1000000U;
}
}
