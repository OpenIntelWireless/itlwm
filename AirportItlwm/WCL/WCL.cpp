//
//  WCL.cpp
//  AirportItlwm
//
//  Created by laobamac on 2026/10/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifdef AIRPORT_WCL
#include "../AirportItlwmV2.hpp"
#include "../AirportItlwmSkywalkInterface.hpp"
#include <kern/thread_call.h>
#include <kern/clock.h>
#include <net80211/ieee80211_node.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_priv.h>
#include <crypto/sha1.h>

extern IOCommandGate *_fCommandGate;

namespace {
struct WCLTraceEntry { uint32_t ms; uint32_t id; uint32_t a; uint32_t b; char kind; };
WCLTraceEntry wclTrace[64];
volatile UInt32 wclTraceNext;
volatile UInt32 wclTraceVersion;

const char *wclMessageName(uint32_t id)
{
    switch (id) {
        case AirportWCL::FirstBeacon: return "FirstBeacon";
        case AirportWCL::ConnectComplete: return "ConnectComplete";
        case AirportWCL::JoinAbortComplete: return "JoinAbortComplete";
        case AirportWCL::ResetInterface: return "ResetInterface";
        case AirportWCL::DriverAvailable: return "DriverAvailable";
        case AirportWCL::AssocComplete: return "AssocComplete";
        case AirportWCL::LinkStatus: return "LinkStatus";
        case AirportWCL::Deauth: return "Deauth";
        case AirportWCL::ScanDone: return "ScanDone";
        default: return nullptr;
    }
}
}

void itlWCLTrace(char kind, uint32_t id, uint32_t a, uint32_t b)
{
    uint64_t now = 0, ns = 0;
    clock_get_uptime(&now);
    absolutetime_to_nanoseconds(now, &ns);
    const UInt32 slot = OSIncrementAtomic(reinterpret_cast<volatile SInt32 *>(&wclTraceNext)) % 64;
    wclTrace[slot] = {uint32_t(ns / 1000000), id, a, b, kind};
    OSIncrementAtomic(reinterpret_cast<volatile SInt32 *>(&wclTraceVersion));
}

// Oldest first. False if nothing changed since *version.
bool itlWCLTraceText(char *out, size_t size, uint32_t *version)
{
    const UInt32 current = wclTraceVersion;
    if (!out || !size || (version && *version == current))
        return false;
    if (version)
        *version = current;
    const UInt32 next = wclTraceNext;
    const UInt32 count = next < 64 ? next : 64;
    size_t used = 0;
    out[0] = 0;
    for (UInt32 i = 0; i < count && used + 1 < size; ++i) {
        const WCLTraceEntry &e = wclTrace[(next - count + i) % 64];
        const char *name = e.kind == '>' ? wclMessageName(e.id) : nullptr;
        int n = name ? snprintf(out + used, size - used, "%s%u.%03u >%s %x", used ? "; " : "",
                                e.ms / 1000, e.ms % 1000, name, e.a)
                     : snprintf(out + used, size - used, "%s%u.%03u %c%u %x %x", used ? "; " : "",
                                e.ms / 1000, e.ms % 1000, e.kind, e.id, e.a, e.b);
        if (n < 0)
            break;
        used += size_t(n) < size - used ? size_t(n) : size - used - 1;
    }
    return true;
}

// Every message to WCL goes through here; scan results and link-quality updates are too frequent to trace.
void AirportItlwmSkywalkInterface::wclPost(uint32_t id, void *data, unsigned long length, bool flag)
{
    if (id != AirportWCL::ScanResult && id != AirportWCL::LqmUpdate) {
        uint32_t first = 0;
        if (data && length >= 4)
            memcpy(&first, data, 4);
        else if (data && length >= 2)
            memcpy(&first, data, 2);
        itlWCLTrace('>', id, first, uint32_t(length));
    }
    instance->postMessage(this, id, data, length, flag);
}

struct AirportItlwmSkywalkInterface::CountryUpdate {
    AirportItlwmSkywalkInterface *interface;
    AirportItlwm *controller;
    IOCommandGate *gate;
    IO80211WorkQueue *queue;
    thread_call_t call;
};

void AirportItlwmSkywalkInterface::deferWCLCountryUpdate()
{
    auto queue = instance->getWorkQueue();
    if (wclStopping || !_fCommandGate || !queue)
        return;
    auto update = static_cast<CountryUpdate *>(IOMalloc(sizeof(CountryUpdate)));
    if (!update)
        return;
    update->call = thread_call_allocate(wclCountryUpdateThread, update);
    if (!update->call) {
        IOFree(update, sizeof(*update));
        return;
    }
    update->interface = this;
    update->controller = instance;
    update->gate = _fCommandGate;
    update->queue = queue;
    retain();
    instance->retain();
    update->gate->retain();
    queue->retain();
    thread_call_enter(update->call);
}

void AirportItlwmSkywalkInterface::wclCountryUpdateThread(void *arg, void *)
{
    auto update = static_cast<CountryUpdate *>(arg);
    // Native country notifications synchronously query WCL. Holding the gate
    // is necessary, but executing on the driver's workloop thread is forbidden.
    // While the interface is going down the gate may be held by the
    // framework, which in turn waits for the driver to finish, so the
    // notification is dropped instead of waiting for it.
    if (!update->interface->wclStopping)
        update->gate->runAction(wclCountryUpdateGated, update);
    thread_call_free(update->call);
    update->interface->release();
    update->controller->release();
    update->gate->release();
    update->queue->release();
    IOFree(update, sizeof(*update));
}

IOReturn AirportItlwmSkywalkInterface::wclCountryUpdateGated(
    OSObject *, void *arg, void *, void *, void *)
{
    auto update = static_cast<CountryUpdate *>(arg);
    if (update->interface->wclStopping)
        return kIOReturnNotReady;
    if (!update->queue->inGate() || update->queue->onThread())
        return kIOReturnNotPermitted;
    update->interface->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED, nullptr, 0, false);
    return kIOReturnSuccess;
}

bool AirportItlwmSkywalkInterface::initWCL()
{
    joinTimer = IOTimerEventSource::timerEventSource(this, wclJoinTimeout);
    if (!joinTimer)
        return false;
    return instance->getWorkQueue()->addEventSource(joinTimer) == kIOReturnSuccess;
}

bool AirportItlwmSkywalkInterface::canUseCommandGate() const
{
    return !wclStopping && _fCommandGate;
}

void AirportItlwmSkywalkInterface::stopWCL()
{
    // The flag is set before the gate is taken: a request that arrives while
    // the stop runs must fail instead of waiting for the gate, because the
    // framework holds the gate while it tears the interface down and waits
    // for the driver in return.
    wclStopping = true;
    // Pending country tasks must observe shutdown under the same gate.
    if (_fCommandGate)
        _fCommandGate->runAction(stopWCLGated, this);
    if (joinTimer) {
        joinTimer->cancelTimeout();
        if (joinTimer->getWorkLoop())
            joinTimer->getWorkLoop()->removeEventSource(joinTimer);
        OSSafeReleaseNULL(joinTimer);
    }
    if (scanSource)
        scanSource->cancelTimeout();
    scanPending = joinPending = false;
    joinDeferred = false;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    if (fHalService) {
        ieee80211com *ic = fHalService->get80211Controller();
        ic->ic_wcl_join_requested = false;
        ic->ic_wcl_scan_requested = false;
        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    }
}

IOReturn AirportItlwmSkywalkInterface::stopWCLGated(
    OSObject *, void *arg, void *, void *, void *)
{
    auto self = static_cast<AirportItlwmSkywalkInterface *>(arg);
    self->portAuthorized = false;
    self->updateWCLLinkQuality(true);
    self->wclStopping = true;
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::updateWCLLinkQuality(bool force)
{
    if (_fCommandGate)
        _fCommandGate->runAction(updateWCLLinkQualityGated, this,
                                reinterpret_cast<void *>(uintptr_t(force)));
}

IOReturn AirportItlwmSkywalkInterface::updateWCLLinkQualityGated(
    OSObject *, void *arg0, void *arg1, void *, void *)
{
    auto self = static_cast<AirportItlwmSkywalkInterface *>(arg0);
    if (self->wclStopping || !self->fHalService)
        return kIOReturnNotReady;
    auto queue = self->instance->getWorkQueue();
    if (!queue || !queue->inGate())
        return kIOReturnNotPermitted;
    auto interface = self->mExpansionData ? self->getBSDInterface() : nullptr;
    if (!interface) {
        self->wclLinkQualityInterface = nullptr;
        self->wclReportedLinkQuality = -2;
        return kIOReturnNotReady;
    }
    auto ic = self->fHalService->get80211Controller();
    int quality = -2;
    if (self->portAuthorized && self->linkState() == kIO80211NetworkLinkUp &&
        (ifnet_flags(interface) & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING) &&
        ic && ic->ic_state == IEEE80211_S_RUN && ic->ic_bss &&
        IEEE80211_ADDR_EQ(ic->ic_bss->ni_bssid, self->joinBSSID)) {
        int rssi = IWM_MIN_DBM + ic->ic_bss->ni_rssi;
        quality = rssi >= -70 ? 100 : (rssi >= -85 ? 50 : 20);
    }
    if (arg1 || quality != self->wclReportedLinkQuality ||
        interface != self->wclLinkQualityInterface) {
        self->setLQM(static_cast<unsigned long long>(static_cast<long long>(quality)));
        self->wclReportedLinkQuality = quality;
        self->wclLinkQualityInterface = interface;
    }
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::free()
{
    if (joinTimer)
        stopWCL();
    IO80211InfraProtocol::free();
}

IOReturn AirportItlwmSkywalkInterface::wclCommand(OSObject *owner, void *a0, void *a1, void *a2, void *)
{
    // Trace the join, scan, leave, key and lifecycle commands; the channel, counter and BSS copies are polled.
    const uintptr_t command = uintptr_t(a1);
    const IOReturn result = wclCommandBody(owner, a0, a1, a2);
    if (command <= 4 || (command >= 8 && command <= 12))
        itlWCLTrace('<', uint32_t(command), uint32_t(result), command == 12 ? uint32_t(uintptr_t(a2)) : 0);
    return result;
}

IOReturn AirportItlwmSkywalkInterface::wclCommandBody(OSObject *, void *a0, void *a1, void *a2)
{
    auto self = static_cast<AirportItlwmSkywalkInterface *>(a0);
    if (self->wclStopping)
        return kIOReturnNotReady;
    switch (uintptr_t(a1)) {
        case 18: self->publishEarlyBssid(); return kIOReturnSuccess;
        case 13: return self->copyWCLChannels(a2);
        case 16: {  // getWCL_VALID_CHANNEL_COUNT, under the gate (audit ST04)
            auto *count = static_cast<unsigned long *>(a2);
            *count = 0;
            ieee80211com *ic = self->fHalService->get80211Controller();
            for (unsigned i = 1; i <= IEEE80211_CHAN_MAX; ++i)
                if (isset(ic->ic_chan_active, i) && ic->ic_channels[i].ic_freq)
                    ++*count;
            return kIOReturnSuccess;
        }
        case 17: {  // getWCL_CHANNELS_INFO, under the gate (audit ST04)
            auto info = static_cast<AirportWCL::ChannelInfo *>(a2);
            bzero(info, sizeof(*info));
            ieee80211com *ic = self->fHalService->get80211Controller();
            for (unsigned i = 1; i <= IEEE80211_CHAN_MAX && info->count < 400; ++i) {
                const ieee80211_channel *channel = &ic->ic_channels[i];
                if (!isset(ic->ic_chan_active, i) || !channel->ic_freq)
                    continue;
                auto &entry = info->channels[info->count++];
                entry.channel = i;
                entry.channelSpec = uint16_t(i | (IEEE80211_IS_CHAN_5GHZ(channel) ? 0xd000 : 0x1000));
                if (channel->ic_flags & IEEE80211_CHAN_DFS)
                    entry.flags |= 2;
                if (channel->ic_flags & IEEE80211_CHAN_PASSIVE)
                    entry.flags |= 4;
            }
            apple80211_country_code_data country = {};
            if (self->instance->getCOUNTRY_CODE(static_cast<OSObject *>(self), &country) == kIOReturnSuccess)
                memcpy(info->country, country.cc, 3);
            return info->count ? kIOReturnSuccess : kIOReturnNotReady;
        }
        case 14: return self->copyWCLTrafficCounters(a2);
        case 15:
            return self->fHalService->setScanHomeAwayTime(
                AirportWCL::read32(static_cast<const uint8_t *>(a2)));
        case 12:
            self->handleWCLEvent(int(uintptr_t(a2)), nullptr);
            return kIOReturnSuccess;
        case 11: self->clearWCLPMKSA(); return kIOReturnSuccess;
        case 8: return self->installWCLKey(static_cast<apple80211_key *>(a2));
        case 9: return self->accessWCLRSN(static_cast<apple80211_rsn_ie_data *>(a2), true);
        case 10: return self->accessWCLRSN(static_cast<apple80211_rsn_ie_data *>(a2), false);
        case 0: return self->beginWCLScan(static_cast<apple80211ScanRequest *>(a2));
        case 1: return self->beginWCLJoin(static_cast<apple80211AssocCandidates *>(a2));
        case 2: return self->abortWCLJoin();
        case 3: return self->leaveWCLNetwork();
        case 6: return self->copyWCLExtendedBss(a2);
        case 7:
            if (!a2 || !self->wclBssValid || !self->wclAssociatedBeacons)
                return kIOReturnNotReady;
            memcpy(a2, self->wclBeaconInfo, sizeof(self->wclBeaconInfo));
            return kIOReturnSuccess;
        case 5:
            if (!a2 || !self->wclBssValid)
                return kIOReturnNotReady;
            memcpy(a2, self->wclBssInfo, sizeof(self->wclBssInfo));
            return kIOReturnSuccess;
        case 4:
            self->finishWCLScan(kIOReturnAborted);
            return kIOReturnSuccess;
    }
    return kIOReturnUnsupported;
}

IOReturn AirportItlwmSkywalkInterface::setWCL_SCAN_REQ(apple80211ScanRequest *request)
{
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, nullptr, request);
}

IOReturn AirportItlwmSkywalkInterface::setWCL_SCAN_ABORT(void *)
{
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(4));
}

IOReturn AirportItlwmSkywalkInterface::setWCL_ASSOCIATE(apple80211AssocCandidates *request)
{
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(1), request);
}

#if __IO80211_TARGET == __MAC_15_2
IOReturn AirportItlwmSkywalkInterface::setWCL_JOIN_ABORT(void *)
#else
IOReturn AirportItlwmSkywalkInterface::setWCL_JOIN_ABORT(apple80211_wcl_abort_join *)
#endif
{
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(2));
}

IOReturn AirportItlwmSkywalkInterface::setWCL_LEAVE_NETWORK(apple80211_leave_network *)
{
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(3));
}

// Scan diagnostic (#20, #24, #34: macOS's scans end with results=0 while beacons arrive). Counts where each
// scan request ends, published as ItlwmScanStats; ItlwmScanLast is the last refusal or completion.
static struct {
    uint32_t requests, accepted, badArg, notReady, busyPending, busyJoin, busyBgscan, busyAuth, noChannel,
        bgscanFailed, stateError, doneEvents, doneSkipped, completedOk, completedTimeout, beaconsWhilePending;
} wclScanStats;

static void wclScanPublish(IOService *service, const char *last)
{
    char text[200];
    snprintf(text, sizeof(text),
             "req=%u ok=%u badarg=%u notready=%u busy=%u/%u/%u/%u nochan=%u bgfail=%u stateerr=%u done=%u "
             "skipped=%u completed=%u timeout=%u beacons=%u",
             wclScanStats.requests, wclScanStats.accepted, wclScanStats.badArg, wclScanStats.notReady,
             wclScanStats.busyPending, wclScanStats.busyJoin, wclScanStats.busyBgscan, wclScanStats.busyAuth,
             wclScanStats.noChannel, wclScanStats.bgscanFailed, wclScanStats.stateError, wclScanStats.doneEvents,
             wclScanStats.doneSkipped, wclScanStats.completedOk, wclScanStats.completedTimeout,
             wclScanStats.beaconsWhilePending);
    service->setProperty("ItlwmScanStats", text);
    if (last)
        service->setProperty("ItlwmScanLast", last);
}
static uint32_t wclScanPreempts, wclFastLaneRequests;

IOReturn AirportItlwmSkywalkInterface::beginWCLScan(apple80211ScanRequest *request)
{
    ++wclScanStats.requests;
    IOReturn result = startWCLScan(request);
    char last[96];
    ieee80211com *ic = fHalService->get80211Controller();
    snprintf(last, sizeof(last), "request #%u -> 0x%x, state %d, pending %d, join %d, bgscan %d",
             wclScanStats.requests, result, ic->ic_state, scanPending, joinPending,
             (ic->ic_flags & IEEE80211_F_BGSCAN) ? 1 : 0);
    wclScanPublish(instance, last);
    return result;
}

IOReturn AirportItlwmSkywalkInterface::startWCLScan(apple80211ScanRequest *request)
{
    AirportWCL::ScanRequest scan;
    if (!AirportWCL::decodeScan(request, 0x1550, scan)) {
        ++wclScanStats.badArg;
        return kIOReturnBadArgument;
    }
    ieee80211com *ic = fHalService->get80211Controller();
    if (!(ic->ic_if.if_flags & IFF_RUNNING)) {
        ++wclScanStats.notReady;
        return kIOReturnNotReady;
    }
    // A new request while our own unassociated scan runs replaces it, as AppleBCMWLANScanAdapter does
    // ("Event scan is in progress, aborting...", "scan aborted by another scan"). Refusing it (tmpErr)
    // broke Instant Hotspot: airportd's directed scan for the phone's network was refused ten times in a
    // row while auto-join's 38-channel scan ran, and the join gave up (2026-11-13 10:36).
    const bool preempt = scanPending && !joinPending && ic->ic_state == IEEE80211_S_SCAN;
    if (!preempt && (scanPending || joinPending || (ic->ic_flags & IEEE80211_F_BGSCAN))) {
        ++(scanPending ? wclScanStats.busyPending : joinPending ? wclScanStats.busyJoin : wclScanStats.busyBgscan);
        return kIOReturnBusy;
    }
    if (ic->ic_state == IEEE80211_S_AUTH || ic->ic_state == IEEE80211_S_ASSOC) {
        ++wclScanStats.busyAuth;
        return kIOReturnBusy;
    }
    if (scan.channelCount) {
        bool usable = false;
        for (unsigned channel = 1; channel <= IEEE80211_CHAN_MAX; ++channel)
            if (ic->ic_channels[channel].ic_flags &&
                AirportWCL::scanChannelSelected(scan.channels, true, channel))
                usable = true;
        if (!usable) {
            ++wclScanStats.noChannel;
            return kIOReturnUnsupported;
        }
    }
    if (preempt) {
        finishWCLScan(kIOReturnAborted);
        instance->setProperty("ItlwmWCLScanPreempts", ++wclScanPreempts, 32);
    }
    scanPending = true;
    scanCompleted = false;
    // The pass already under way may have gone past channels the new request needs: it completes on the next.
    scanSkipCompletion = ic->ic_state == IEEE80211_S_SCAN &&
        (preempt || (scan.type != 2 && scan.ssidLength != 0) ||
         ic->ic_wcl_scan_ssid_length != 0 || ic->ic_des_esslen != 0);
    ic->ic_wcl_scan_requested = true;
    ic->ic_wcl_scan_active = scan.type != 2;
    ic->ic_wcl_scan_ssid_length = scan.type == 2 ? 0 : scan.ssidLength;
    memcpy(ic->ic_wcl_scan_ssid, scan.ssid, sizeof(scan.ssid));
    ic->ic_wcl_scan_restricted = scan.channelCount != 0;
    memcpy(ic->ic_wcl_scan_channels, scan.channels, sizeof(scan.channels));
    scanSource->setTimeoutMS(20000);
    if (ic->ic_state == IEEE80211_S_RUN) {
        ieee80211_begin_cache_bgscan(&ic->ic_if);
        if (!(ic->ic_flags & IEEE80211_F_BGSCAN)) {
            scanPending = false;
            ic->ic_wcl_scan_requested = false;
            scanSource->cancelTimeout();
            ++wclScanStats.bgscanFailed;
            return kIOReturnBusy;
        }
    } else if (ic->ic_state != IEEE80211_S_SCAN) {
        int error = ic->ic_newstate(ic, IEEE80211_S_SCAN, -1);
        if (error) {
            scanPending = false;
            ic->ic_wcl_scan_requested = false;
            scanSource->cancelTimeout();
            ++wclScanStats.stateError;
            return kIOReturnError;
        }
    }
    ++wclScanStats.accepted;
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::finishWCLScan(IOReturn status)
{
    if (!scanPending)
        return;
    scanPending = false;
    scanCompleted = false;
    scanSource->cancelTimeout();
    fHalService->get80211Controller()->ic_wcl_scan_requested = false;
    ++(status == kIOReturnSuccess ? wclScanStats.completedOk : wclScanStats.completedTimeout);
    char last[64];
    snprintf(last, sizeof(last), "scan done 0x%x after request #%u", status, wclScanStats.requests);
    wclScanPublish(instance, last);
    wclPost(AirportWCL::ScanDone, &status, sizeof(status), true);
}

void AirportItlwmSkywalkInterface::completeWCLScan()
{
    if (!wclStopping)
        finishWCLScan(scanCompleted ? kIOReturnSuccess : kIOReturnTimeout);
}

void AirportItlwmSkywalkInterface::publishWCLBeacon(const ieee80211_node *node, const uint8_t *ies, size_t length)
{
    if (!node || node->ni_esslen > 32 || !AirportWCL::validIEs(ies, length))
        return;
    ieee80211com *ic = fHalService->get80211Controller();
    if (!node->ni_chan || node->ni_chan == IEEE80211_CHAN_ANYC)
        return;
    unsigned channel = ieee80211_chan2ieee(ic, node->ni_chan);
    if (!channel || channel > 196)
        return;
    size_t size = sizeof(AirportWCL::BeaconMetadata) + length;
    auto metadata = static_cast<AirportWCL::BeaconMetadata *>(IOMalloc(size));
    if (!metadata)
        return;
    *metadata = {};
    metadata->ieLength = uint32_t(length);
    metadata->channelSpec = uint16_t(channel | (IEEE80211_IS_CHAN_5GHZ(node->ni_chan) ? 0xd000 : 0x1000));
    metadata->channel = channel;
    uint32_t ssidLength = node->ni_esslen;
    const uint8_t *ssid = node->ni_essid;
    if (ssidLength == 0 && wclHasHiddenSsid &&
        IEEE80211_ADDR_EQ(node->ni_bssid, wclHiddenBssid)) {
        // Hidden network: the beacon carries no name, but we know it from the
        // join request. Without the name the system neither lists the network
        // nor matches it against its preferred networks.
        ssidLength = wclHiddenSsidLength;
        ssid = wclHiddenSsid;
    }
    metadata->ssidLength = ssidLength;
    memcpy(metadata->ssid, ssid, ssidLength);
    memcpy(metadata->bssid, node->ni_bssid, 6);
    metadata->rssi = IWM_MIN_DBM + node->ni_rssi;
    metadata->interval = node->ni_intval;
    metadata->capability = node->ni_capinfo;
    metadata->flags = AirportWCL::SSIDPresent | AirportWCL::RSSIValid;
    memcpy(metadata + 1, ies, length);
    /*
     * Keep real AKMs so macOS can select SAE, but only where the AP offers hash-to-element: we
     * don't do hunting-and-pecking, so a transition network without H2E keeps joining as WPA2.
     */
    if (!ic->ic_wpa3 || !AirportWCL::advertisesSAEH2E(reinterpret_cast<const uint8_t *>(metadata + 1), length))
        metadata->ieLength = uint32_t(AirportWCL::selectWPA2TransitionMode(
            reinterpret_cast<uint8_t *>(metadata + 1), length));
    size_t messageSize = sizeof(*metadata) + metadata->ieLength;
    // The framework asks the driver for the BSS information as soon as the
    // link comes up and it gives up on the network when that fails ("Update
    // Bss fail"). The information is taken from the beacons of the network,
    // so it has to be collected while the network is still being scanned:
    // waiting for the association to be complete is too late, the scan has
    // usually finished by then and no beacon arrives any more.
    //
    // Without the information the framework never runs setCurrentBSS, so
    // neither the BSSID nor the SSID reach the 802.1X supplicant, and the
    // join ends in "join failure".
    bool bssMatches = IEEE80211_ADDR_EQ(node->ni_bssid, joinBSSID);
    // The hidden network's BSS counts only while that network is the one being joined.
    if (!bssMatches && wclHasHiddenSsid &&
        AirportWCL::sameSsid(ic->ic_des_essid, ic->ic_des_esslen, wclHiddenSsid, wclHiddenSsidLength))
        bssMatches = IEEE80211_ADDR_EQ(node->ni_bssid, wclHiddenBssid);
    if ((joinPending || assocNotified) && bssMatches) {
        wclBssValid = messageSize <= sizeof(wclBssInfo);
        if (wclBssValid) {
            bzero(wclBssInfo, sizeof(wclBssInfo));
            memcpy(wclBssInfo, metadata, messageSize);
        }
    }
    // A directed scan that was asked for by name teaches the driver the name
    // of the network it found. The beacons of a hidden network do not carry
    // that name, so without remembering it the scan results of that network
    // stay nameless and the system never lists it.
    // Only a network whose beacons really hide the name is remembered: the name came from its answer to the
    // directed scan's probe, and this frame doesn't carry it.
    if (ic->ic_wcl_scan_active &&
        AirportWCL::sameSsid(node->ni_essid, node->ni_esslen, ic->ic_wcl_scan_ssid, ic->ic_wcl_scan_ssid_length) &&
        AirportWCL::hidesSsid(ies, length)) {
        if (!AirportWCL::zeroAddress(node->ni_bssid)) {
            memcpy(wclHiddenSsid, ic->ic_wcl_scan_ssid, ic->ic_wcl_scan_ssid_length);
            wclHiddenSsidLength = ic->ic_wcl_scan_ssid_length;
            wclHasHiddenSsid = true;
            memcpy(wclHiddenBssid, node->ni_bssid, sizeof(wclHiddenBssid));
        }
    }
    wclPost(AirportWCL::ScanResult, metadata, messageSize, true);
    IOFree(metadata, size);
}

void AirportItlwmSkywalkInterface::publishEarlyBssid()
{
    if (wclStopping || !earlyBssidPending || !joinPending || assocNotified || !AirportWCL::zeroAddress(joinBSSID))
        return;
    if (AirportWCL::zeroAddress(earlyBssid)) {
        earlyBssidPending = false;
        return;
    }
    memcpy(joinBSSID, earlyBssid, sizeof(joinBSSID));
    setCurrentApAddress(reinterpret_cast<ether_addr *>(joinBSSID));
    earlyBssidPending = false;
}

void AirportItlwmSkywalkInterface::clearWCLPMKSA()
{
    auto ic = fHalService->get80211Controller();
    ieee80211_pmk *pmk;
    while ((pmk = TAILQ_FIRST(&ic->ic_pmksa))) {
        TAILQ_REMOVE(&ic->ic_pmksa, pmk, pmk_next);
        explicit_bzero(pmk, sizeof(*pmk));
        ::free(pmk);
    }
}

IOReturn AirportItlwmSkywalkInterface::setCLEAR_PMKSA_CACHE(void *)
{
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(11));
}

IOReturn AirportItlwmSkywalkInterface::installWCLKey(apple80211_key *key)
{
    static_assert(sizeof(apple80211_key) == 0x94, "WCL cipher key layout");
    if (!key || !AirportWCL::validCipherKey(key->key_cipher_type, key->key_len,
            key->key_flags, key->key_index, key->key_rsc_len))
        return kIOReturnBadArgument;
    auto ic = fHalService->get80211Controller();
    auto ni = ic->ic_bss;
    if (!ic->ic_wcl_enterprise || !ni || ic->ic_state != IEEE80211_S_RUN)
        return kIOReturnNotReady;
    if (key->key_cipher_type == APPLE80211_CIPHER_PMK ||
        key->key_cipher_type == APPLE80211_CIPHER_PMKSA ||
        key->key_cipher_type == APPLE80211_CIPHER_MSK) {
        // WCL's native user-client rejects PTK/GTK, and delivers a PMK/MSK
        // instead. Use the existing net80211 four-way/group-key handshake.
        if (!ieee80211_is_8021x_akm((enum ieee80211_akm)ni->ni_rsnakms))
            return kIOReturnBadArgument;
        uint8_t any = 0;
        for (auto byte : key->key_ea.octet) any |= byte;
        if (any && !IEEE80211_ADDR_EQ(key->key_ea.octet, ni->ni_bssid))
            return kIOReturnBadArgument;
        auto pmk = ieee80211_pmksa_add(ic, (enum ieee80211_akm)ni->ni_rsnakms,
                                     ni->ni_macaddr, key->key, 0);
        IOReturn result = pmk ? kIOReturnSuccess : kIOReturnNoMemory;
        return result;
    }
    return kIOReturnUnsupported;
}

IOReturn AirportItlwmSkywalkInterface::accessWCLRSN(apple80211_rsn_ie_data *data, bool write)
{
    if (!data) return kIOReturnBadArgument;
    auto ic = fHalService->get80211Controller();
    if (write) {
        if (!AirportWCL::validRSNOverride(data->ie, data->len))
            return kIOReturnBadArgument;
        // net80211 constructs negotiated IEs for its own key handshake.
        return kIOReturnUnsupported;

    }
    const uint8_t *ie = ic->ic_bss ? ic->ic_bss->ni_rsnie : nullptr;
    if (!ie) return kIOReturnNotReady;
    size_t length = size_t(ie[1]) + 2;
    if (length > sizeof(data->ie)) return kIOReturnBadArgument;
    bzero(data, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->len = length;
    memcpy(data->ie, ie, length);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::beginWCLJoin(apple80211AssocCandidates *request)
{
    AirportWCL::JoinRequest join;
    if (!AirportWCL::decodeJoin(request, 0x2cc, join)) {
        return kIOReturnBadArgument;
    }
    return startWCLJoin(join);
}

IOReturn AirportItlwmSkywalkInterface::startWCLJoin(AirportWCL::JoinRequest &join)
{
    auto auth = AirportWCL::classifyLegacyAuth(join);
    bool personal = auth == AirportWCL::LegacyAuth::Personal;
    bool sae = auth == AirportWCL::LegacyAuth::PersonalSAE;
    bool enterprise = auth == AirportWCL::LegacyAuth::Enterprise;
    bool supported = auth != AirportWCL::LegacyAuth::Invalid;
    ieee80211com *ic = fHalService->get80211Controller();
    // Applying a private MAC restarts firmware asynchronously. WCL can issue
    // the association before that restart has completed; keep one request
    // until the HAL reports READY rather than making the user retry it.
    if (supported && !joinPending && ic->ic_wcl_mac_reconfig &&
        (ic->ic_if.if_flags & IFF_UP)) {
        deferredJoin = join;
        memcpy(joinBSSID, join.bssid, sizeof(joinBSSID));
        explicit_bzero(&join, sizeof(join));
        joinDeferred = joinPending = true;
        joinTimer->setTimeoutMS(30000);
        itlWCLTrace('j', 0, kIOReturnSuccess, 1);
        return kIOReturnSuccess;
    }
    if (!supported || !(ic->ic_if.if_flags & IFF_RUNNING) || joinPending || scanPending) {
        explicit_bzero(&join, sizeof(join));
        return !supported ? kIOReturnUnsupported : kIOReturnBusy;
    }
    if (ic->ic_state == IEEE80211_S_RUN || ic->ic_state == IEEE80211_S_AUTH || ic->ic_state == IEEE80211_S_ASSOC)
        leaveWCLNetwork();
    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    clearWCLPMKSA();
    ic->ic_flags &= ~(IEEE80211_F_AUTO_JOIN | IEEE80211_F_PSK);
    ic->ic_wcl_enterprise = enterprise;

    /* SAE uses the WPA path with AKM SAE and a password token instead of a PSK. */
    if (personal || sae || enterprise) {
        ieee80211_wpaparams wpa = {};
        wpa.i_enabled = 1;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA_PSK))
            wpa.i_protos |= IEEE80211_WPA_PROTO_WPA1;
        if ((join.upperAuth & (APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_WPA2_PSK |
                              APPLE80211_AUTHTYPE_SHA256_PSK | APPLE80211_AUTHTYPE_SHA256_8021X)) ||
            sae)
            wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2_PSK))
            wpa.i_akms |= IEEE80211_WPA_AKM_PSK;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2))
            wpa.i_akms |= IEEE80211_WPA_AKM_8021X;
        if (join.upperAuth & APPLE80211_AUTHTYPE_SHA256_PSK) {
            wpa.i_akms |= IEEE80211_WPA_AKM_SHA256_PSK;
            wpa.i_akms |= IEEE80211_WPA_AKM_PSK;
        }
        if (join.upperAuth & APPLE80211_AUTHTYPE_SHA256_8021X)
            wpa.i_akms |= IEEE80211_WPA_AKM_SHA256_8021X;
        if (sae) {
            wpa.i_akms |= IEEE80211_WPA_AKM_SAE;
        }
        /* SAE only permits CCMP, never TKIP. */
        wpa.i_ciphers = sae ? IEEE80211_WPA_CIPHER_CCMP :
            IEEE80211_WPA_CIPHER_CCMP | IEEE80211_WPA_CIPHER_TKIP;
        if (join.rsnLength >= 8 && join.rsn[0] == IEEE80211_ELEMID_RSN &&
            join.rsn[4] == 0 && join.rsn[5] == 0x0f && join.rsn[6] == 0xac) {
            if (join.rsn[7] == 2) wpa.i_groupcipher = IEEE80211_WPA_CIPHER_TKIP;
            if (join.rsn[7] == 4) wpa.i_groupcipher = IEEE80211_WPA_CIPHER_CCMP;
        }
        int error = ieee80211_ioctl_setwpaparms(ic, &wpa);
        if (error && error != ENETRESET) {
            explicit_bzero(&join, sizeof(join));
            return kIOReturnBadArgument;
        }
        if (sae) {
            /* Derive the token from the raw SAE password; net80211 derives the PWE per peer. */
            /* Fail cleanly on invalid passphrase/SSID or a join racing the flag. */
            if (!ic->ic_wpa3 ||
                ieee80211_sae_password_to_pt(ic->ic_sae_pt, join.key,
                    join.keyLength, join.ssid, join.ssidLength) != 0) {
                ieee80211_disable_rsn(ic);
                explicit_bzero(&join, sizeof(join));
                return kIOReturnUnsupported;
            }
            ic->ic_sae_pt_valid = 1;
        } else if (personal) {
            if (join.keyCipher == 10) {
                /* A passphrase was supplied instead of a 32-byte PSK. */
                join.key[join.keyLength] = 0;
                if (pbkdf2_sha1(reinterpret_cast<const char *>(join.key),
                        join.ssid, join.ssidLength, 4096, ic->ic_psk,
                        sizeof(ic->ic_psk)) != 0) {
                    explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
                    explicit_bzero(&join, sizeof(join));
                    return kIOReturnBadArgument;
                }
            } else {
                memcpy(ic->ic_psk, join.key, sizeof(ic->ic_psk));
            }
            ic->ic_flags |= IEEE80211_F_PSK;
        } else if (join.keyLength == IEEE80211_PMK_LEN) {
            bool cached = true;
            if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2))
                cached = ieee80211_pmksa_add(ic, IEEE80211_AKM_8021X, join.bssid, join.key, 0) != nullptr;
            if (cached && (join.upperAuth & APPLE80211_AUTHTYPE_SHA256_8021X))
                cached = ieee80211_pmksa_add(ic, IEEE80211_AKM_SHA256_8021X, join.bssid, join.key, 0) != nullptr;
            if (!cached) {
                clearWCLPMKSA();
                explicit_bzero(&join, sizeof(join));
                return kIOReturnNoMemory;
            }
        }
    } else if (auth == AirportWCL::LegacyAuth::Wep) {
        ieee80211_nwkey keys = {};
        keys.i_wepon = IEEE80211_NWKEY_WEP;
        keys.i_defkid = join.keyIndex + 1;
        keys.i_key[join.keyIndex].i_keylen = join.keyLength;
        keys.i_key[join.keyIndex].i_keydat = join.key;
        int error = ieee80211_ioctl_setnwkeys(ic, &keys);
        if (error && error != ENETRESET) {
            explicit_bzero(&join, sizeof(join));
            return kIOReturnBadArgument;
        }
    }
    ic->ic_des_esslen = join.ssidLength;
    memcpy(ic->ic_des_essid, join.ssid, sizeof(ic->ic_des_essid));
    memcpy(ic->ic_des_bssid, join.bssid, 6);
    memcpy(joinBSSID, join.bssid, 6);
    ic->ic_flags |= IEEE80211_F_DESBSSID;
    ic->ic_wcl_join_requested = true;
    ic->ic_wcl_scan_requested = false;
    current_authtype_lower = join.lowerAuth;
    current_authtype_upper = join.upperAuth;
    explicit_bzero(&join, sizeof(join));
    wclBssValid = false;
    joinPending = true;
    assocNotified = firstBeaconNotified = portAuthorized = false;
    wclFirstBeaconHeld = false;
    wclAssociatedBeacons = 0;
    bzero(wclBeaconInfo, sizeof(wclBeaconInfo));
    disassocIsVoluntary = false;
    joinTimer->setTimeoutMS(30000);
    if (ic->ic_state != IEEE80211_S_SCAN && ic->ic_newstate(ic, IEEE80211_S_SCAN, -1)) {
        joinPending = false;
        joinTimer->cancelTimeout();
        ic->ic_wcl_join_requested = false;
        clearWCLPMKSA();
        ic->ic_wcl_enterprise = false;
        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
        return kIOReturnError;
    }
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::resumeWCLJoin()
{
    if (!joinDeferred || wclStopping)
        return;
    AirportWCL::JoinRequest join = deferredJoin;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    joinDeferred = joinPending = false;
    joinTimer->cancelTimeout();
    IOReturn status = startWCLJoin(join);
    explicit_bzero(&join, sizeof(join));
    itlWCLTrace('j', 1, uint32_t(status), 0);
    if (status != kIOReturnSuccess) {
        joinPending = true;
        finishWCLJoin(1, 0, status);
    }
}

void AirportItlwmSkywalkInterface::finishWCLJoin(uint16_t status, uint16_t reason, IOReturn driverStatus)
{
    if (!joinPending)
        return;
    AirportWCL::ConnectionEvent event = {};
    event.status = status;
    event.reason = reason;
    memcpy(event.peers[0].bssid, joinBSSID, 6);
    event.peers[0].driverStatus = driverStatus;
    joinPending = false;
    joinDeferred = false;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    joinTimer->cancelTimeout();
    wclPost(AirportWCL::ConnectComplete, &event, sizeof(event), true);
    if (status) {
        portAuthorized = false;
        updateWCLLinkQuality(true);
        ieee80211com *ic = fHalService->get80211Controller();
        ic->ic_wcl_join_requested = false;
        clearWCLPMKSA();
        ic->ic_wcl_enterprise = false;
        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    }
}

void AirportItlwmSkywalkInterface::wclJoinTimeout(OSObject *owner, IOTimerEventSource *)
{
    auto self = OSDynamicCast(AirportItlwmSkywalkInterface, owner);
    if (self && !self->wclStopping) {
        self->finishWCLJoin(1, 1004, kIOReturnTimeout);
        self->leaveWCLNetwork();
    }
}

IOReturn AirportItlwmSkywalkInterface::leaveWCLNetwork()
{
    ieee80211com *ic = fHalService->get80211Controller();
    portAuthorized = false;
    updateWCLLinkQuality(true);
    joinPending = false;
    joinDeferred = false;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    joinTimer->cancelTimeout();
    ic->ic_wcl_join_requested = false;
    wclAssociatedBeacons = 0;
    wclBssValid = false;
    disassocIsVoluntary = true;
    ic->ic_deauth_reason = IEEE80211_REASON_AUTH_LEAVE;
    // Tell the AP we're leaving, as setDISASSOCIATE (the non-WCL path) does. net80211's RUN -> SCAN is its
    // beacon-miss transition and sends nothing, so the AP kept this Mac associated: the next join's
    // authentication was answered with a disassociation and that attempt failed after 10 s.
    if (ic->ic_state > IEEE80211_S_AUTH && ic->ic_bss != NULL)
        IEEE80211_SEND_MGMT(ic, ic->ic_bss, IEEE80211_FC0_SUBTYPE_DEAUTH, IEEE80211_REASON_AUTH_LEAVE);
    if (ic->ic_state > IEEE80211_S_SCAN)
        ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    clearWCLPMKSA();
    ic->ic_wcl_enterprise = false;
    ic->ic_flags &= ~(IEEE80211_F_PSK | IEEE80211_F_DESBSSID);
    ic->ic_des_esslen = 0;
    bzero(ic->ic_des_essid, sizeof(ic->ic_des_essid));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::abortWCLJoin()
{
    leaveWCLNetwork();
    wclPost(AirportWCL::JoinAbortComplete, nullptr, 0, true);
    return kIOReturnSuccess;
}

// IOSkywalkNetworkInterface::reportLinkQuality(q) sets the BSD interface's link quality metric
// (ifnet_set_link_quality). configd publishes it as State:/Network/Interface/en0/LinkQuality, and apsd
// only connects push over an interface whose metric isn't "off" (-2). Nothing set it on Tahoe: the
// pre-Skywalk driver's setLinkQualityMetric(100) at link-up is commented out in the V2 path, and
// IO80211SkywalkInterface::setLQM is an empty stub, so en0 stayed "off" and push, iMessage and
// other Apple services never connected over Wi-Fi. Non-virtual, exported by IOSkywalkFamily.
extern "C" IOReturn itlReportLinkQuality(IOSkywalkNetworkInterface *, unsigned int)
    __asm__("__ZN25IOSkywalkNetworkInterface17reportLinkQualityEj");

namespace {
// The kernel's IFNET_LQM_THRESH_* values; "off" is AirportWCL::kLinkQualityOff (WCL.hpp).
constexpr int32_t kLinkQualityBad = 10, kLinkQualityPoor = 50, kLinkQualityGood = 100;
int32_t linkQualityForRSSI(int32_t rssi)
{
    if (rssi >= -70) return kLinkQualityGood;
    if (rssi >= -80) return kLinkQualityPoor;
    return kLinkQualityBad;
}
}

// WCL keeps the link's RSSI only from LqmUpdate. The beacon-driven update above rarely runs while
// associated, because the firmware filters most beacons, so WCL is left with 0 dBm: airportd then
// rates en0's link quality "off" (-2) and apsd won't use Wi-Fi, which stops push and iMessage.
// This posts an RSSI-only update every 2 s while the port is up. handleLqmUpdate stores the RSSI
// first and, with the snapshot and counter flags clear, stops there.
// On Sequoia only en0's link quality metric is reported: IO80211Family 24H241 has the same empty
// setLQM stub and no other caller of reportLinkQuality, so the same "off" rating is expected. The
// RSSI-only LqmUpdate below uses Tahoe's WCL structure layout and stays Tahoe-only.
// itlwm_lqmint=N (seconds, 1..60): post LqmUpdate only when the RSSI moved by 3 dB or more, or N
// seconds passed since the last one. Each LqmUpdate makes WCL announce RSSI_CHANGED, and with the 2 s
// timer plus every 8th beacon that was ~1.7 events a second, each followed by client queries to
// airportd. Apple's drivers report on change. Unset: every update is posted, as before.
uint32_t itlLqmMinIntervalSec;

bool AirportItlwmSkywalkInterface::wclLqmPostAllowed(int32_t rssi)
{
    if (!itlLqmMinIntervalSec)
        return true;
    uint64_t now;
    absolutetime_to_nanoseconds(mach_absolute_time(), &now);
    const int32_t delta = rssi > wclLqmLastPostRssi ? rssi - wclLqmLastPostRssi : wclLqmLastPostRssi - rssi;
    if (wclLqmLastPostNs && delta < 3 && now - wclLqmLastPostNs < uint64_t(itlLqmMinIntervalSec) * 1000000000ULL) {
        if (!(++wclLqmSuppressed % 64) && instance)
            instance->setProperty("ItlwmWCLLqmSuppressed", wclLqmSuppressed, 32);
        return false;
    }
    wclLqmLastPostNs = now;
    wclLqmLastPostRssi = rssi;
    return true;
}

void AirportItlwmSkywalkInterface::wclPostLinkQuality()
{
    if (wclStopping || !portAuthorized || !instance)
        return;
    if (++wclLqmTicks % 2)
        return;
    apple80211_rssi_data rssi = {};
    if (getRSSI(&rssi) != kIOReturnSuccess || rssi.aggregate_rssi >= 0)
        return;
    const int32_t quality = linkQualityForRSSI(rssi.aggregate_rssi);
    if (quality != wclLinkQualityReported) {
        const IOReturn result = itlReportLinkQuality(static_cast<IOSkywalkNetworkInterface *>(this), uint32_t(quality));
        if (result == kIOReturnSuccess)
            wclLinkQualityReported = quality;
        instance->setProperty("ItlwmWCLLinkQuality", uint64_t(uint32_t(quality)), 32);
        instance->setProperty("ItlwmWCLLinkQualityResult", uint64_t(uint32_t(result)), 32);
    }
#if __IO80211_TARGET != __MAC_15_2
    AirportWCL::LqmBeaconUpdate update = {};
    update.rssiValid = 1;
    update.rssi = rssi.aggregate_rssi;
    if (!wclLqmPostAllowed(rssi.aggregate_rssi))
        return;
    wclPost(AirportWCL::LqmUpdate, &update, sizeof(update), true);
    if (++wclLqmPeriodicPosts == 1 || !(wclLqmPeriodicPosts % 30)) {
        instance->setProperty("ItlwmWCLLqmPeriodicPosts", wclLqmPeriodicPosts, 32);
        instance->setProperty("ItlwmWCLLqmBeaconPosts", wclLqmBeaconPosts, 32);
        instance->setProperty("ItlwmWCLLqmLastRssi", uint64_t(uint32_t(rssi.aggregate_rssi)), 32);
    }
#endif
}

void AirportItlwmSkywalkInterface::handleWCLLink(bool up)
{
    if (wclStopping)
        return;
    portAuthorized = up;
    // The link status that was held back until the four way handshake was
    // done is reported now. The first beacon is reported as well, because
    // the beacon branch skipped it while the notification was held back.
    if (up && wclFirstBeaconHeld) {
        wclFirstBeaconHeld = false;
        firstBeaconNotified = true;
        AirportWCL::LinkStatusEvent link = {};
        memcpy(link.bssid, joinBSSID, sizeof(link.bssid));
        link.up = 1;
        link.reason = 255;
        wclLinkIndicated = true;
        wclPost(AirportWCL::LinkStatus, &link, sizeof(link), true);
        AirportWCL::FirstBeaconEvent event = {};
        memcpy(event.peer.bssid, joinBSSID, 6);
        wclPost(AirportWCL::FirstBeacon, &event, sizeof(event), true);
    }
    // itlwm_lqmint: a new link (or none) starts over, so the first update after a join is never held back.
    wclLqmLastPostNs = 0;
    if (!up)
        AirportWCL::resetLinkQuality(wclLinkQualityReported, [this](int32_t quality) {
            itlReportLinkQuality(static_cast<IOSkywalkNetworkInterface *>(this), uint32_t(quality));
        });
    if (!up && wclLinkIndicated) {
        AirportWCL::LinkStatusEvent event = {};
        memcpy(event.bssid, joinBSSID, sizeof(event.bssid));
        event.reason = 255;
        wclLinkIndicated = false;
        wclBssValid = false;
        wclPost(AirportWCL::LinkStatus, &event, sizeof(event), true);
    }
    if (up && joinPending && firstBeaconNotified)
        finishWCLJoin(0, 0, kIOReturnSuccess);
    updateWCLLinkQuality(true);
}

void AirportItlwmSkywalkInterface::handleWCLEvent(int code, void *data)
{
    if (code != IEEE80211_EVT_BEACON && code != IEEE80211_EVT_SCAN_DONE)
        itlWCLTrace('e', uint32_t(code), instance->getWorkQueue()->inGate() ? 1 : 0, wclStopping ? 1 : 0);
    if (wclStopping)
        return;
    // Firmware initialization runs on systq, outside the native PostOffice gate.
    // Serialize only lifecycle notifications; never run synchronous WCL ioctls here.
    if ((code == IEEE80211_EVT_DRIVER_RESET_BEGIN || code == IEEE80211_EVT_DRIVER_READY ||
         code == IEEE80211_EVT_DRIVER_STOPPED) && !instance->getWorkQueue()->inGate()) {
        _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(12),
                                reinterpret_cast<void *>(uintptr_t(code)));
        return;
    }
    ieee80211com *ic = fHalService->get80211Controller();
    switch (code) {
        case IEEE80211_EVT_COUNTRY_CODE_UPDATE:
            deferWCLCountryUpdate();
            break;
        case IEEE80211_EVT_DRIVER_RESET_BEGIN: {
            portAuthorized = false;
            updateWCLLinkQuality(true);
            if (ic->ic_wcl_mac_reconfig) {
                break;
            }
            uint32_t reset = 0; // Native resetInterfacesBegin.
            wclPost(AirportWCL::ResetInterface, &reset, sizeof(reset), true);
            break;
        }
        case IEEE80211_EVT_DRIVER_READY:
        case IEEE80211_EVT_DRIVER_STOPPED: {
            bool ready = code == IEEE80211_EVT_DRIVER_READY;
            if (!ready) {
                finishWCLScan(ic->ic_wcl_mac_reconfig ? kIOReturnAborted : kIOReturnOffline);
                finishWCLJoin(1, 0, kIOReturnOffline);
                portAuthorized = false;
                AirportWCL::resetLinkQuality(wclLinkQualityReported, [this](int32_t quality) {
                    itlReportLinkQuality(static_cast<IOSkywalkNetworkInterface *>(this), uint32_t(quality));
                });
                updateWCLLinkQuality(true);
                ic->ic_wcl_join_requested = false;
                clearWCLPMKSA();
                ic->ic_wcl_enterprise = false;
                explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
            }
            // An address application is requested by WCL itself, not a new
            // adapter reset. Replaying firmware-load events here rotates the
            // scan MAC again and recursively restarts the card.
            if (AirportWCL::consumeMacReconfiguration(ic->ic_wcl_mac_reconfig, ready)) {
                if (ready)
                    resumeWCLJoin();
                break;
            }
            if (ready) {
                uint32_t reset = 1; // Native resetInterfacesComplete, only after HAL success.
                wclPost(AirportWCL::ResetInterface, &reset, sizeof(reset), true);
            }
            AirportWCL::DriverAvailability event = {};
            event.version = 3;
            event.available = ready;
            event.reason = ready ? 0xe0821803 : 0xe0821804;
            wclPost(AirportWCL::DriverAvailable, &event, sizeof(event), true);
            if (ready)
                resumeWCLJoin();
            break;
        }
        case IEEE80211_EVT_BEACON: {
            auto beacon = static_cast<ieee80211_beacon_event *>(data);
            if (!beacon)
                break;
            // Retain the actual associated beacon, including its advancing TSF.
            // WCL polls BEACON_INFO to distinguish fresh reception from a stale BSS.
            if (assocNotified && (joinPending || portAuthorized) &&
                IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID) &&
                beacon->frame && beacon->frame_length >= 36 &&
                beacon->frame_length <= 0x800 &&
                (beacon->frame[0] & 0xfc) == IEEE80211_FC0_SUBTYPE_BEACON) {
                uint32_t length = uint32_t(beacon->frame_length);
                bzero(wclBeaconInfo, sizeof(wclBeaconInfo));
                memcpy(wclBeaconInfo, &length, sizeof(length));
                memcpy(wclBeaconInfo + 4, beacon->frame, length);
                ++wclAssociatedBeacons;
                ++wclLqmBeacons;
                // WCL has no legacy LQMData instance at createLQMData().
                // Send the snapshot consumed by WCL instead of legacy 227/229.
                if (portAuthorized && (wclLqmBeacons % 8 == 0)) {
#if __IO80211_TARGET == __MAC_15_2
                    apple80211_rssi_data rssi = {};
                    if (getRSSI(&rssi) == kIOReturnSuccess && wclLqmPostAllowed(rssi.aggregate_rssi)) {
                        AirportWCL::SequoiaLqmUpdate update = {};
                        update.rssiValid = 1;
                        update.rssi = rssi.aggregate_rssi;
                        wclPost(AirportWCL::LqmUpdate,
                            &update, sizeof(update), true);
                    }
#else
                    AirportWCL::LqmBeaconUpdate update;
                    apple80211_rssi_data gateRssi = {};
                    const bool gateHasRssi = getRSSI(&gateRssi) == kIOReturnSuccess && gateRssi.aggregate_rssi < 0;
                    if ((!gateHasRssi || wclLqmPostAllowed(gateRssi.aggregate_rssi)) &&
                        AirportWCL::makeBeaconUpdate(
                            wclLqmBeacons - wclLqmReportedBeacons, update)) {
                        apple80211_rssi_data rssi = {};
                        if (getRSSI(&rssi) == kIOReturnSuccess && rssi.aggregate_rssi < 0) {
                            update.rssiValid = 1;
                            update.rssi = rssi.aggregate_rssi;
#if __IO80211_TARGET == __MAC_26_0
                            // Zero means no measurement; do not invent a noise floor.
                            if (fHalService && fHalService->getDriverInfo()) {
                                int16_t noise = fHalService->getDriverInfo()->getBSSNoise();
                                if (noise > 0)
                                    noise = -noise;
                                AirportWCL::setBeaconRadio(update, rssi.aggregate_rssi, noise);
                            }
#endif
                        }
                        wclPost(AirportWCL::LqmUpdate,
                            &update, sizeof(update), true);
                        wclLqmReportedBeacons = wclLqmBeacons;
                        ++wclLqmBeaconPosts;
                    }
#endif
                    updateWCLLinkQuality();
                }
            }
            if (scanPending || joinPending || ic->ic_state == IEEE80211_S_SCAN ||
                (portAuthorized && IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID))) {
                if (scanPending)
                    ++wclScanStats.beaconsWhilePending;
                publishWCLBeacon(beacon->node, beacon->ies, beacon->length);
            }
            // A join request does not always name the BSSID of the network it
            // wants. The beacon of the network carries it, so it is taken
            // from there while the network is still being scanned.
            // Only when the join named no BSSID: one it named stays, even if another access point of the
            // same network beacons first.
            if (joinPending && !assocNotified && AirportWCL::zeroAddress(joinBSSID) &&
                AirportWCL::sameSsid(beacon->node->ni_essid, beacon->node->ni_esslen, ic->ic_des_essid,
                                     ic->ic_des_esslen)) {
                if (!AirportWCL::zeroAddress(beacon->node->ni_bssid)) {
                    memcpy(earlyBssid, beacon->node->ni_bssid, sizeof(earlyBssid));
                    earlyBssidPending = true;
                    if (instance && instance->getWorkQueue() &&
                        instance->getWorkQueue()->inGate()) {
                        publishEarlyBssid();
                    } else if (_fCommandGate) {
                        _fCommandGate->runAction(wclCommand, this,
                                                 reinterpret_cast<void *>(18));
                    }
                }
            }
            if (joinPending && assocNotified && !firstBeaconNotified &&
                IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID)) {
                AirportWCL::FirstBeaconEvent event = {};
                memcpy(event.peer.bssid, joinBSSID, 6);
                if (!wclBssValid)
                    break;
                // A personal network must not report the link up before the
                // four way handshake is done. IO80211 sometimes leaves the
                // network right away when it sees the link up, the port is
                // authorized a few milliseconds too late and the join of
                // airportd then runs into its ten second timeout. The link
                // status is therefore held back until the port is
                // authorized.
                //
                // An enterprise network needs the opposite: the link status
                // is what makes the framework run setCurrentBSS, and that
                // is the only way the BSSID and the SSID reach the 802.1X
                // supplicant. It was already sent when the association
                // completed, so nothing is held back there.
                if (!portAuthorized && !ic->ic_wcl_enterprise) {
                    wclFirstBeaconHeld = true;
                    break;
                }
                firstBeaconNotified = true;
                AirportWCL::LinkStatusEvent link = {};
                memcpy(link.bssid, joinBSSID, sizeof(link.bssid));
                link.up = 1;
                link.reason = 255;
                wclLinkIndicated = true;
                wclPost(AirportWCL::LinkStatus, &link, sizeof(link), true);
                wclPost(AirportWCL::FirstBeacon, &event, sizeof(event), true);
                if (portAuthorized)
                    finishWCLJoin(0, 0, kIOReturnSuccess);
            }
            break;
        }
        case IEEE80211_EVT_SCAN_DONE:
            ++wclScanStats.doneEvents;
            if (scanPending) {
                if (scanSkipCompletion) {
                    scanSkipCompletion = false;
                    ++wclScanStats.doneSkipped;
                }
                else {
                    scanCompleted = true;
                    scanSource->setTimeoutMS(0);
                }
            }
            break;
        case IEEE80211_EVT_STA_ASSOC_DONE:
            if (joinPending && !assocNotified) {
                AirportWCL::AssociationEvent event = {};
                event.status = ic->ic_assoc_status;
                memcpy(event.bssid, joinBSSID, 6);
                event.driverStatus = event.status ? kIOReturnError : kIOReturnSuccess;
                assocNotified = !event.status;
                wclPost(AirportWCL::AssocComplete, &event, sizeof(event), true);
                if (event.status)
                    finishWCLJoin(event.status, 0, kIOReturnError);
            }
            break;
        case IEEE80211_EVT_STA_DEAUTH: {
            portAuthorized = false;
            updateWCLLinkQuality(true);
            AirportWCL::DeauthEvent event = {};
            event.reason = ic->ic_deauth_reason;
            if (ic->ic_bss)
                memcpy(event.bssid, ic->ic_bss->ni_bssid, 6);
            wclPost(AirportWCL::Deauth, &event, sizeof(event), true);
            finishWCLJoin(1, event.reason, kIOReturnOffline);
            break;
        }
        default: break;
    }
}

IOReturn AirportItlwmSkywalkInterface::setPM_MODE(apple80211_pm_mode *data)
{
    if (!data)
        return kIOReturnBadArgument;
    // The framework sends 0x188 (392) bytes with APPLE80211_IOC_PM_MODE, but
    // the layout of the structure has never been published: only the first
    // two words are known to carry the request, the rest of the payload is
    // whatever the framework had in its buffer. The values are therefore only
    // recorded, they are not acted upon.
    //
    // The driver has no power mode of its own to switch, so accepting the
    // request only keeps the framework from reporting a failure on every join.
    pmMode = data->mode;
    pmModeFlags = data->flags;
    itlWCLTrace('P', pmMode, pmModeFlags, 0);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_FW_HOT_CHANNELS(apple80211_fw_hot_channels *data)
{
    if (!data)
        return kIOReturnBadArgument;
    // The framework builds its neighbour cache from the list of hot channels
    // the firmware reports. Intel's firmware keeps no such list for the host.
    // An empty list keeps the driver's behaviour unchanged; it only stops the
    // framework from reporting a failure on every join. IO80211's
    // WCLNeighborCacheManager::constructNeighborCacheFromFWHotChannels asks
    // with 0x14 bytes on Sequoia 24H241 and Tahoe 25G342 (checked).
    memset(data, 0, sizeof(*data));
    data->count = 0;
    itlWCLTrace('W', data->count, 0, 0);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::setPOWERSAVE(apple80211_powersave_data *data)
{
    if (!data)
        return kIOReturnBadArgument;
    // The framework tells the driver which power save level the radio should
    // use. The level is remembered here: with the power saving turned off
    // the link must not report itself as idle any more, otherwise the
    // framework keeps the radio busy although the user asked for the
    // opposite.
    wclPowersaveLevel = data->powersave_level;
    itlWCLTrace('S', wclPowersaveLevel, 0, 0);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_VALID_CHANNEL_COUNT(unsigned long *count)
{
    if (!count)
        return kIOReturnBadArgument;
    *count = 0;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    // Read under the command gate with the stop check, like its siblings (audit ST04).
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(16), count);
}

IOReturn AirportItlwmSkywalkInterface::setWCL_LINK_STATE_UPDATE(apple80211_wcl_update_link_state *data)
{
    if (!data)
        return kIOReturnBadArgument;
#if __IO80211_TARGET == __MAC_15_2
    const auto bytes = reinterpret_cast<const uint8_t *>(data);
    if (bytes[6]) {
        if (bytes[8])
            setCurrentApAddress(reinterpret_cast<ether_addr *>(data));
        if (bytes[7])
            setLinkState(kIO80211NetworkLinkUp, 0, false, 0);
    } else {
        uint32_t debounce = AirportWCL::read32(bytes + 12);
        setCurrentApAddress(nullptr);
        setLinkState(kIO80211NetworkLinkDown, 0, debounce != 0, debounce);
    }
    IOReturn status = kIOReturnSuccess;
#else
    IOReturn status = IO80211InfraInterface::setWCL_LINK_STATE_UPDATE(data);
#endif
    if (status == kIOReturnSuccess)
        updateWCLLinkQuality(true);
    return status;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_BSS_INFO(apple80211_beacon_msg *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(5), data);
}

IOReturn AirportItlwmSkywalkInterface::getWCL_EXTENDED_BSS_INFO(apple80211_extended_bss_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(6), data);
}

IOReturn AirportItlwmSkywalkInterface::copyWCLExtendedBss(void *data)
{
    ieee80211com *ic = fHalService->get80211Controller();
    // WCL's setCurrentBSS reads this right after association, before the 4-way handshake has put net80211
    // in RUN on some joins: "Fail to get EXTENDED_BSS_INFO" then "Update Bss fail" dropped the link
    // (2026-11-11 15:48, 11-12 19:51 and 21:17, 11-13 10:11). AppleBCMWLANNetAdapter::getExtendedBssInfo
    // only fails if the firmware can't give the rates; the joined node has them from ASSOC on.
    if (!data || !ic->ic_bss || (ic->ic_state != IEEE80211_S_RUN && ic->ic_state != IEEE80211_S_ASSOC))
        return kIOReturnNotReady;
    static_assert(sizeof(apple80211_rate_set_data) == 0xbc, "Extended BSS rates size");
    static_assert(sizeof(apple80211_mcs_index_set_data) == 0x10, "Extended BSS MCS size");
    auto bytes = static_cast<uint8_t *>(data);
#if __IO80211_TARGET == __MAC_15_2
    bzero(bytes, 0x1e0);
#else
    bzero(bytes, 0x214);
#endif
    {
        auto *rates = reinterpret_cast<apple80211_rate_set_data *>(bytes);
        rates->version = APPLE80211_VERSION;
        rates->num_rates = ic->ic_bss->ni_rates.rs_nrates;
        const size_t count = min(size_t(ic->ic_bss->ni_rates.rs_nrates), ARRAY_SIZE(rates->rates));
        for (size_t i = 0; i < count; ++i) {
            rates->rates[i].version = APPLE80211_VERSION;
            rates->rates[i].rate = ic->ic_bss->ni_rates.rs_rates[i];
            rates->rates[i].flags = 0;
        }
        auto *mcs = reinterpret_cast<apple80211_mcs_index_set_data *>(bytes + 0xbc);
        mcs->version = APPLE80211_VERSION;
        const size_t mcsCount = min(ARRAY_SIZE(ic->ic_bss->ni_rxmcs), ARRAY_SIZE(mcs->mcs_set_map));
        for (size_t i = 0; i < mcsCount; ++i)
            mcs->mcs_set_map[i] = ic->ic_bss->ni_rxmcs[i];
    }
    apple80211_vht_mcs_index_set_data vht = {};
    vht.version = APPLE80211_VERSION;
    vht.mcs_map = 0xffff;
    if (ic->ic_bss->ni_flags & IEEE80211_NODE_VHT)
        vht.mcs_map = ic->ic_bss->ni_vht_mcsinfo.tx_mcs_map;
    memcpy(bytes + 0xcc, &vht, sizeof(vht));
    // Native updateMCSSet uses version + a 16-bit HE MCS/NSS map (8 bytes).
    uint32_t heVersion = APPLE80211_VERSION;
    uint16_t heMap = 0xffff;
    if (ic->ic_bss->ni_flags & IEEE80211_NODE_HE) {
        bool wide = ic->ic_bss->ni_chw == IEEE80211_CHAN_WIDTH_160;
        heMap = htole16(ieee80211_he_mcs_intersection(
            le16toh(wide ? ic->ic_he_mcs_nss_supp.rx_mcs_160 : ic->ic_he_mcs_nss_supp.rx_mcs_80),
            le16toh(wide ? ic->ic_bss->ni_he_mcs_nss_supp.tx_mcs_160 : ic->ic_bss->ni_he_mcs_nss_supp.tx_mcs_80)));
    }
    memcpy(bytes + 0xd4, &heVersion, sizeof(heVersion));
    memcpy(bytes + 0xd8, &heMap, sizeof(heMap));
    if (ic->ic_flags & IEEE80211_F_RSNON)
#if __IO80211_TARGET == __MAC_15_2
        ieee80211_add_rsn(bytes + 0xdd, ic, ic->ic_bss);
#else
        ieee80211_add_rsn(bytes + 0x113, ic, ic->ic_bss);
#endif
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::setWCL_UPDATE_FAST_LANE(apple80211_fastlane *data)
{
    if (!data)
        return kIOReturnBadArgument;
    // AppleBCMWLANInfraProtocol::setWCL_UPDATE_FAST_LANE always succeeds: it records whether the AP offers
    // Fastlane (QoS) and, when both bytes are set, overrides the firmware's admission control. WCL's
    // setCurrentBSS asks for it with the AP's own Fastlane flag right after association and leaves the
    // network if the driver refuses ("Fail to set fast lane", then "Update Bss fail"): every WPA2/WPA3 join
    // to such an AP failed (2026-11-13). There is no admission control to override here.
    const auto bytes = reinterpret_cast<const uint8_t *>(data);
    if (bytes[0] || bytes[1])
        instance->setProperty("ItlwmWCLFastLaneRequests", ++wclFastLaneRequests, 32);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_LOW_LATENCY_INFO(apple80211_low_latency_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    // No low-latency or P2P session is implemented by this adapter.
    bzero(data, 4);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_CHANNELS_INFO(apple80211ChannelInfo *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    // Read under the command gate with the stop check, like its siblings (audit ST04).
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(17), data);
}

IOReturn AirportItlwmSkywalkInterface::getCHANNELS_INFO(apple80211_channels_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(13), data);
}

IOReturn AirportItlwmSkywalkInterface::copyWCLChannels(void *data)
{
    auto info = static_cast<AirportWCL::NativeChannelInfo *>(data);
    bzero(info, sizeof(*info));
    ieee80211com *ic = fHalService->get80211Controller();
    for (unsigned i = 1; i <= IEEE80211_CHAN_MAX; ++i) {
        const ieee80211_channel *channel = &ic->ic_channels[i];
        if (!isset(ic->ic_chan_active, i) || !channel->ic_freq)
            continue;
        AirportWCL::appendChannel(*info, i, IEEE80211_IS_CHAN_5GHZ(channel),
            channel->ic_flags & IEEE80211_CHAN_DFS,
            channel->ic_flags & IEEE80211_CHAN_PASSIVE,
            IEEE80211_IS_CHAN_HT40(channel) || IEEE80211_IS_CHAN_VHT40(channel),
            IEEE80211_IS_CHAN_VHT80(channel));
    }
    apple80211_country_code_data country = {};
    if (instance->getCOUNTRY_CODE(static_cast<OSObject *>(this), &country) == kIOReturnSuccess)
        memcpy(info->country, country.cc, sizeof(country.cc));
    // Diagnostic (#21): macOS picks its own AWDL 5 GHz channel (149, else 44) from this list. When it asks,
    // and what 6, 36, 44 and 149 looked like then: '-' not listed, 'a' active, 'p' passive, 'd' radar.
    static uint32_t queries;
    char last[64];
    auto state = [ic](unsigned ch) {
        const ieee80211_channel &c = ic->ic_channels[ch];
        if (!isset(ic->ic_chan_active, ch) || !c.ic_freq) return '-';
        return (c.ic_flags & IEEE80211_CHAN_DFS) ? 'd' : (c.ic_flags & IEEE80211_CHAN_PASSIVE) ? 'p' : 'a';
    };
    snprintf(last, sizeof(last), "#%u %.2s 6=%c 36=%c 44=%c 149=%c", ++queries, info->country, state(6),
             state(36), state(44), state(149));
    instance->setProperty("ItlwmChannelsInfoLast", last);
    return info->count ? kIOReturnSuccess : kIOReturnNotReady;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_TRAFFIC_COUNTERS(apple80211_wcl_traffic_counters *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(14), data);
}

IOReturn AirportItlwmSkywalkInterface::copyWCLTrafficCounters(void *data)
{
    ieee80211com *ic = fHalService->get80211Controller();
    uint64_t timestamp;
    absolutetime_to_nanoseconds(mach_absolute_time(), &timestamp);
    const auto counters = AirportWCL::makeTrafficCounters(
        ic->ic_wcl_tx_packets, ic->ic_wcl_rx_packets, timestamp);
    memcpy(data, &counters, sizeof(counters));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::setWCL_SET_SCAN_HOME_AWAY_TIME(scanHomeAndAwayTime *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(15), data);
}
#endif

#ifdef AIRPORT_WCL
IOReturn AirportItlwmSkywalkInterface::getBEACON_INFO(apple80211_beacon_info_t *data)
{
    if (!_fCommandGate || !data)
        return kIOReturnNotReady;
    if (!canUseCommandGate())
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(7), data);
}
#endif
