//
//  AirportItlwmV2.cpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#include "ItlCountedCopy.hpp"
#include "AirportItlwmV2.hpp"

// Build marker shown as ItlwmAWDLInterfaceBuild; tools/build.py sets it per macOS target.
#ifndef ITL_FORBIDDEN_BUILD
#define ITL_FORBIDDEN_BUILD "unmarked"   // tools/build.py always sets it (audit T05)
#endif

// -itlawdlsamples: raw samples of native requests, templates and packets in the registry. They can hold
// addresses and service records, and any local user can read the registry, so they are off by default.
static bool awdlRawSamples;

// read by ItlIwx's follower (-itlschedsp): macOS's requested AWDL channel sequence,
// the 16 channel numbers from setAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE. itlAWDLPlanVersion is odd while the copy
// is being written and rises by 2 per complete plan, so a reader can tell a torn copy. 0 = no plan yet. Only
// written when macOS sends 16 entries with step count 3 (one entry per extended AW), the layout the follower
// assumes.
uint8_t itlAWDLPlanChannels[16];
// -itlrxloss or itlawdlsched=3, read per second by ItlIwx.cpp: every way an AWDL data frame handed to awdl0
// can end, counted (they were silent before, apart from delivered and refused by the queue).
volatile uint32_t itlAWDLRxParseBad, itlAWDLRxNotOurs, itlAWDLRxSelf, itlAWDLRxAllocFail, itlAWDLRxPrepFail,
    itlAWDLRxCopyFail, itlAWDLRxQueueFail, itlAWDLRxDelivered, itlAWDLRxDisabled;
// Frames whose two per-frame AWDL bytes weren't macOS's defaults (3, 4), and the last such pair. They used to be
// dropped as unparseable.
volatile uint32_t itlAWDLRxMetaOther, itlAWDLRxMetaLast;
// ItlIwx.cpp: itlawdlsched=<bits>; 0x1 scheduler set (experimental, off by default), 0x2 diagnostics.
extern bool itlResFlag(const char *name, uint32_t bit);
volatile uint32_t itlAWDLPlanVersion;
// ItlIwx.cpp -itlschedmacchan: macOS's AWDL secondary master channel (0 = not set yet).
volatile uint32_t itlAWDLReqSecondaryMaster;
// -itlawdlumi, ItlIwx.cpp: 1 while a unicast MI from macOS waits to be sent; the peer manager asks for one
// (sendUnicastMI, from handleUmiTimer) when a peer is waiting for this Mac, e.g. to set up a data path.
volatile uint32_t itlAWDLUmiPending, itlAWDLUmiGo;
volatile uint64_t itlAWDLUmiAtUS;
static bool itlAWDLUmiOn()
{
    static int cached = -1;
    if (cached < 0) {
        int dummy = 0;
        cached = PE_parse_boot_argn("-itlawdlumi", &dummy, sizeof(dummy)) ? 1 : 0;
    }
    return cached == 1;
}
static uint64_t itlAWDLUptimeUS()
{
    uint64_t ns = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &ns);
    return ns / 1000;
}
// read in ItlIwx.cpp: when macOS last changed the content of its master indication (services, host
// name: every TLV type but the per-frame and schedule ones), and how often. Timing the sync frame template showed it
// carries no services. Measurement only.
volatile uint64_t itlAWDLTemplateChangeUS;
volatile uint32_t itlAWDLTemplateChanges;
static uint32_t itlAWDLMiContentHash;
// what macOS's OOB_AUTO_REQUEST asks the firmware for (IO80211AWDLPeerManager::updatePrimaryPayloadMI, 26.7.2):
// +0x0c a random send offset in us, +0x10 the MI bitmap (default 0xffffffff; 0x05050505 = slots 0, 2, 8, 10, read as one bit
// per slot over two 16-slot sequences), +0x14 options. itlAWDLForceMI (set by ItlIwx.cpp around a build) makes the next frame
// an MI; itlAWDLLastBuildMI says whether the last frame built was a broadcast MI.
volatile uint32_t itlAWDLMiBitmap = 0xffffffffU, itlAWDLMiOffsetUS, itlAWDLMiOptions, itlAWDLMiBitmapChanges;
volatile int itlAWDLForceMI, itlAWDLLastBuildMI;
static uint32_t itlAWDLMiContentHashOf(const uint8_t *tlvs, size_t length)
{
    // Types 4, 5, 12, 18, 20, 21 and 24 (sync, election, data path, channel sequence, sync tree, version) change every frame
    // or with the schedule (as the service-timing tracker); everything else is content.
    const uint32_t volatileTypes = (1u << 4) | (1u << 5) | (1u << 12) | (1u << 18) | (1u << 20) | (1u << 21) | (1u << 24);
    uint32_t h = 2166136261U;
    for (size_t i = 0; i + 3 <= length;) {
        const size_t n = size_t(tlvs[i + 1]) | size_t(tlvs[i + 2]) << 8;
        if (i + 3 + n > length)
            break;
        if (!(volatileTypes & (1u << (tlvs[i] & 31))))
            for (size_t k = 0; k < 3 + n; ++k)
                h = (h ^ tlvs[i + k]) * 16777619U;
        i += 3 + n;
    }
    return h;
}
// ItlIwx.cpp: the 16 channels the radio really follows, while the macOS-plan follower runs with
// -itlschedadvertise; false otherwise, and our frames advertise the fixed channel as before.
extern bool itlAWDLExecPlan(uint8_t *out);
// ItlIwx.cpp: our own election metric and counter, as macOS put them in the template's election v2
// TLV, for the driver's election; and the election result and clock our frames should advertise.
volatile uint32_t itlAWDLSelfMetric, itlAWDLSelfCounter, itlAWDLSelfKnown;
// our election ID (from macOS's template) and the election RSSI threshold macOS sends the chip.
volatile uint32_t itlAWDLSelfElectionId, itlAWDLSelfElectionIdKnown;
volatile int32_t itlAWDLElectionRssiFromMacOS;   // 0 = not sent yet
// -itlsvctiming, read with -itllog from the ITLAWDLLog ring: IOLog lines from this kext don't reach
// macOS's log, In testing, service-discovery timing ("ITLSVC ..." with uptime in ms). Logs which TLV types of
// macOS's master-indication template changed (not their contents), when the first MI frame carrying the change was
// built, and (ItlIwx.cpp) when a peer's service response not seen in the last 10 s arrived. Nothing else changes.
volatile uint32_t itlSvcUpdates;            // template updates that changed a non-timing TLV
volatile uint64_t itlSvcLastUpdateUS;
static int itlSvcTimingState;               // 0 not read, 1 off, 2 on
static bool itlSvcTxPending;
static uint32_t itlSvcTypeHash[32];
static uint64_t itlSvcNowUS()
{
    uint64_t uptime, ns;
    clock_get_uptime(&uptime);
    absolutetime_to_nanoseconds(uptime, &ns);
    return ns / 1000;
}
bool itlSvcTimingOn()
{
    if (!itlSvcTimingState) {
        int dummy = 0;
        itlSvcTimingState = PE_parse_boot_argn("-itlsvctiming", &dummy, sizeof(dummy)) ? 2 : 1;
    }
    return itlSvcTimingState == 2;
}
// A new template: per TLV type, a hash of its values; types 4, 5, 12, 18, 20, 21 and 24 (sync, election, data
// path, channel sequence, sync tree, version) change every frame or with the schedule and don't count.
static void itlSvcNoteTemplate(const uint8_t *tlvs, size_t length)
{
    if (!itlSvcTimingOn() || !tlvs)
        return;
    uint32_t hash[32] = {};
    uint32_t present = 0;
    for (size_t i = 0; i + 3 <= length;) {
        const size_t n = size_t(tlvs[i + 1]) | size_t(tlvs[i + 2]) << 8;
        if (i + 3 + n > length)
            break;
        const unsigned type = tlvs[i] & 31;
        uint32_t h = hash[type] ? hash[type] : 2166136261u;
        for (size_t k = 0; k < n; ++k)
            h = (h ^ tlvs[i + 3 + k]) * 16777619u;
        hash[type] = h ? h : 1;
        present |= 1u << type;
        i += 3 + n;
    }
    const uint32_t volatileTypes = (1u << 4) | (1u << 5) | (1u << 12) | (1u << 18) | (1u << 20) | (1u << 21) |
                                   (1u << 24);
    uint32_t changed = 0;
    for (unsigned t = 0; t < 32; ++t)
        if (hash[t] != itlSvcTypeHash[t])
            changed |= 1u << t;
    memcpy(itlSvcTypeHash, hash, sizeof(hash));
    changed &= ~volatileTypes;
    if (!changed)
        return;
    const uint64_t now = itlSvcNowUS();
    const uint32_t number = ++itlSvcUpdates;
    itlSvcLastUpdateUS = now;
    itlSvcTxPending = true;
    XYLog("ITLSVC %llu upd #%u changed types 0x%08x present 0x%08x len %u\n", (unsigned long long)(now / 1000),
          number, changed, present, unsigned(length));
}
// The frame builder made an MI frame (carrying the template's services).
void itlSvcNoteMiBuilt()
{
    if (!itlSvcTimingOn() || !itlSvcTxPending)
        return;
    itlSvcTxPending = false;
    const uint64_t now = itlSvcNowUS();
    XYLog("ITLSVC %llu tx #%u first MI frame +%llu ms after the update\n", (unsigned long long)(now / 1000),
          itlSvcUpdates, (unsigned long long)((now - itlSvcLastUpdateUS) / 1000));
}
// ItlIwx.cpp, -itlschedawdloff: macOS's last setAWDL_SYNC_ENABLED, 1 on, 0 off (also before the
// first request). macOS turns AWDL off when nothing uses it.
volatile uint32_t itlAWDLSyncOn;
// -itlinfrastats, off by default: report the station's traffic to IO80211's interface monitor,
// which macOS's AWDL scheduler reads (IO80211AWDLPeerManager::gatherInfraStats) to tell an idle Wi-Fi from a busy
// one. The driver never fed it, so macOS always saw 0 packets and planned "Data + Infra Idle" (24% Wi-Fi). Once a
// second, the deltas of en0's packet and byte counters go to IO80211SkywalkInterface::recordInputPacket and
// recordOutputPacket (best effort), the calls that increment those reporters. Both symbols are exported by
// IO80211Family on every target (26.7.x, 15.8.x, 14.x) and are called directly, not through the vtable.
extern IOReturn itlRecordInputPacket(IO80211SkywalkInterface *, int, int)
    __asm__("__ZN23IO80211SkywalkInterface17recordInputPacketEii");
extern IOReturn itlRecordOutputPacket(IO80211SkywalkInterface *, int, int, int)
    __asm__("__ZN23IO80211SkywalkInterface18recordOutputPacketE17apple80211_wme_acii");
static int itlInfraStatsState;   // 0 not read yet, 1 off, 2 on
static bool itlInfraStatsPrimed;
static uint64_t itlInfraLastPkIn, itlInfraLastByIn, itlInfraLastPkOut, itlInfraLastByOut;
static uint64_t itlInfraSumPkIn, itlInfraSumByIn, itlInfraSumPkOut, itlInfraSumByOut;
// unicast only. Testing showed broadcast and multicast too (about 180 packets/s at idle on a busy network),
// which put macOS in "Infra Priority" for good (threshold 50 per check). multicasts_in/_out count broadcast and
// multicast; bytes are scaled by the unicast share of packets.
static uint64_t itlInfraLastMcIn, itlInfraLastMcOut, itlInfraSumMcIn, itlInfraSumMcOut;
static uint32_t itlInfraTicks, itlInfraStatFails;
// -itlawstart, ItlIwx.cpp builds the payload: a timer on the watchdog's work loop posts
// APPLE80211_M_AWDL_AVAILABILITY_WINDOW_START on the AWDL interface at each extended AW of the follower's clock.
extern bool itlAWDLAwStart(uint8_t *out36, uint64_t *nextInUS);
extern bool itlAWDLAwEnd(uint8_t *out, size_t length);
static int itlAwStartState;   // 0 not read yet, 1 off, 2 on
static IOTimerEventSource *itlAwStartTimer;
static uint32_t itlAwStartPosted, itlAwStartIdle, itlAwStartWatch;
// -itlawdlstats: AWDL RX counts for macOS. IO80211's AWDL data-mode monitor
// (IO80211AWDLPeerManager::monitorAWDLDataMode) reads RX and TX packet counters in the AWDL peer manager's state.
// Both our AWDL RX (bypasses IO80211PeerManager::inputPacket) and our injected TX (bypasses preQueuePacket /
// getUnicastPackets) skip IO80211's peer-manager data path, so macOS saw ~0 AirDrop packets. macOS's log proved
// it: monitorAWDLDataMode saw Rx~1000/AW but Tx 0 (the earlier "TX counted natively" note was wrong). Setting the
// counters with IO80211SkywalkInterface::updateInterfaceDataStats, but that overwrites ~30 fields of the live
// accounting with our values and zeros made Mac -> iPhone sends stall, so this instead adds our RX and TX deltas to
// the two packet counters, as inputPacket / preQueuePacket's `incl` would: interface +0x120 -> +0x28 = AWDL peer
// manager, +0x18 = its state; RX at +0x79c, TX at +0x7b0 on 26.7.x (Tahoe); RX +0x78c, TX +0x7a0 on 15.8.x
// (Sequoia). From the disassembly of updateInterfaceDataStats, updateLocalCounters, inputPacket and preQueuePacket.
// Supported-builds audit (2026-11-23): the interface -> peer manager step is IO80211SkywalkInterface::getPeerManager(),
// now called directly (it differs per macOS: +0x120 -> +0x28 on Tahoe (26.7.2/26.7.3), +0x110 -> +0x28 on Sequoia (15.8/15.8.3),
// +0x110 -> +0x30 on Sonoma 14.8.9). Before, Tahoe's +0x120 was used everywhere, a wrong pointer on Sequoia. The state
// is the peer manager's +0x18 everywhere; RX/TX from IO80211PeerManager::inputPacket / preQueuePacket per build.
extern bool itlAWDLDataCounts(uint32_t *rxPkts, uint32_t *txPkts);
extern bool itlAWDLBuildVerified();
extern bool itlAWDLBuildForced();
// IO80211SkywalkInterface::getPeerManager() (exported, non-virtual; on Tahoe "mov 0x120(%rdi),%rax; mov 0x28(%rax),%rax")
// and IO80211AWDLPeerManager's vtable (exported on every build checked, 14.8.3 to 26.7.3). The counters write only
// when the returned object's vtable is that one, so a moved layout on an unverified build turns them off instead.
extern "C" void *itlSkywalkGetPeerManager(void *interface) __asm__("__ZN23IO80211SkywalkInterface14getPeerManagerEv");
extern const uintptr_t itlNativeAWDLPeerManagerVtable[] __asm__("__ZTV22IO80211AWDLPeerManager");
#if __IO80211_TARGET == __MAC_26_0
static constexpr size_t kItlAwdlPmRxOff = 0x79c, kItlAwdlPmTxOff = 0x7b0;
#elif __IO80211_TARGET == __MAC_15_2
static constexpr size_t kItlAwdlPmRxOff = 0x78c, kItlAwdlPmTxOff = 0x7a0;
#elif __IO80211_TARGET == __MAC_14_4
static constexpr size_t kItlAwdlPmRxOff = 0x77c, kItlAwdlPmTxOff = 0x790;
#else
static constexpr size_t kItlAwdlPmRxOff = 0, kItlAwdlPmTxOff = 0;
#endif
static int itlAwdlStatsState;   // 0 not read yet, 1 off, 2 on
static uint32_t itlAwdlStatsCalls, itlAwdlStatsLastRx, itlAwdlStatsAdded, itlAwdlStatsNoPath, itlAwdlStatsWrongPm;
static uint32_t itlAwdlStatsLastTx, itlAwdlStatsAddedTx;
static bool itlAwdlStatsPrimed;
static void itlReportAWDLData(AirportItlwm *self);
static void itlAwStartFire(OSObject *owner, IOTimerEventSource *sender);
#include <IOKit/acpi/IOACPIPlatformDevice.h>
#include <AWDLObservation.hpp>
#include <sys/_netstat.h>
#include <crypto/sha1.h>
#include <net80211/ieee80211_priv.h>
#include <net80211/ieee80211_var.h>

#include "AirportItlwmSkywalkInterface.hpp"
#include "IOPCIEDeviceWrapper.hpp"
#if defined(ITL_AWDL_NATIVE)
#include "AirportAWDLInterface.hpp"
#include <Airport/IO80211ManagementBuffer.h>
// The tested set, on by default from 0.7.0-alpha.2 (AWDLBuildGuard.cpp).
extern bool itlAWDLFlag(const char *name);
extern bool itlAWDLDefaults();
#include <AWDLManagementFrame.hpp>
#include <AWDLLocalSchedule.hpp>
#include <AWDLPeerProbe.hpp>
#include <AWDLElection.hpp>
// ItlIwx.cpp: the election result and clock our frames advertise; false when off.
extern bool itlAWDLClockState(ItlAWDL::ElectionAdvert *advert, ItlAWDL::Clock *clock);
#include <AWDLDataPayload.hpp>
#include <AWDLDataFrame.hpp>
#include <Airport/IOSkywalkPacketView.h>
#include <libkern/OSDebug.h>
#include <mach/vm_param.h>
#include <sys/proc.h>
#endif

#define super IO80211Controller
OSDefineMetaClassAndStructors(AirportItlwm, IO80211Controller);
OSDefineMetaClassAndStructors(CTimeout, OSObject)
#if defined(ITL_AWDL_NATIVE)
OSDefineMetaClassAndStructors(ItlAWDLInterface, IO80211AWDLProtocol)
#endif

IO80211WorkQueue *_fWorkloop;
IOCommandGate *_fCommandGate;

#if defined(ITL_AWDL_NATIVE)
IOReturn ItlAWDLInterface::getAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *data)
{
    return nativeState.getEnabled(data);
}

IOReturn ItlAWDLInterface::getAWDL_AF_SECONDARY_PAYLOAD_CAPABILITIES(apple80211_awdl_cap *data)
{
    if (!nativeState.accept)
        return unsupported("getAWDL_AF_SECONDARY_PAYLOAD_CAPABILITIES");
    if (!data)
        return kIOReturnBadArgument;
    // No secondary payload capability is claimed.
    bzero(data, sizeof(*data));
    data->version = APPLE80211_VERSION;
    return kIOReturnSuccess;
}

IOReturn ItlAWDLInterface::setAWDL_ELECTION_PARAMS(apple80211_awdl_election_params *data)
{
    if (!nativeState.accept)
        return unsupported("setAWDL_ELECTION_PARAMS");
    // Acknowledged only: there is no firmware election, and the contents aren't read.
    return data ? kIOReturnSuccess : kIOReturnBadArgument;
}

// IO80211's determineAndSetEdgeRssiThreshold (26.7.2) sends this with the threshold at +0x10 of a
// 20-byte buffer (our header's struct stops at 16): -70 dBm normally, -78 with single-stream/AirPlay services.
IOReturn ItlAWDLInterface::setAWDL_ELECTION_RSSI_THRESHOLDS(apple80211_awdl_election_rssi_thresholds *data)
{
    const IOReturn result = storeRequested(requested_AWDL_ELECTION_RSSI_THRESHOLDS, data, "AWDL_ELECTION_RSSI_THRESHOLDS");
    if (result == kIOReturnSuccess && data) {
        int32_t threshold;
        memcpy(&threshold, reinterpret_cast<const uint8_t *>(data) + 0x10, sizeof(threshold));
        if (threshold >= -100 && threshold <= -30) {
            itlAWDLElectionRssiFromMacOS = threshold;
            setProperty("ItlwmAWDLElectionRssiThreshold", uint64_t(uint32_t(threshold)), 32);
        }
    }
    return result;
}

IOReturn ItlAWDLInterface::setAWDL_PEER_TRAFFIC_REGISTRATION(apple80211_awdl_peer_traffic_registration *data)
{
    if (!nativeState.accept)
        return unsupported("setAWDL_PEER_TRAFFIC_REGISTRATION");
    // Acknowledged only. Its embedded pointer is neither read nor kept.
    return data ? kIOReturnSuccess : kIOReturnBadArgument;
}

// -itlpeercache: . IO80211 asks the driver to keep an AWDL peer in the "firmware
// peer cache" through APPLE80211_IOC_PEER_CACHE_CONTROL (IO80211P2PDataPathManager::
// sendIoctlToCachePeer, decoded from 26.7.2). On success IO80211 itself counts the peer as
// cached (_currentPeerCacheSize, the "CPC"/"Cached peer count" in its log) for an add; with
// the old "unsupported" answer the count stays 0 and the AWDL schedule keeps choosing the
// No-Cached-Peers states. The request is a 464-byte buffer IO80211 allocates: version at +0,
// opcode at +4 (0 add, 2 delete; 1 and 3 are firmware indications going the other way),
// peer address at +8. Intel firmware has no such cache, so the driver only acknowledges.
// Known gap: IO80211 lowers the count only on the firmware's delete indication, which can't
// be delivered on awdl0 (the AWDL peer manager handles that event number itself), so the count
// can rise to IO80211's cap (8) but not fall.
IOReturn ItlAWDLInterface::setPEER_CACHE_CONTROL(apple80211_peer_cache_control *data)
{
    if (!nativeState.accept || !peerCacheAccept) {
        peerCacheRefused++;
        return unsupported("setPEER_CACHE_CONTROL");
    }
    if (!data)
        return kIOReturnBadArgument;
    const uint8_t *raw = reinterpret_cast<const uint8_t *>(data);
    uint32_t version, opcode;
    memcpy(&version, raw, sizeof(version));
    memcpy(&opcode, raw + 4, sizeof(opcode));
    IOReturn result = kIOReturnSuccess;
    if (opcode == 0)
        peerCacheAdds++;
    else if (opcode == 2)
        peerCacheDeletes++;
    else {
        peerCacheOther++;
        result = kIOReturnUnsupported;
    }
    char text[160];
    // Only the last two address bytes are shown.
    snprintf(text, sizeof(text), "adds %u deletes %u other %u refused %u; last op %u ver %u peer ..:%02x:%02x",
             peerCacheAdds, peerCacheDeletes, peerCacheOther, peerCacheRefused, opcode, version, raw[12], raw[13]);
    setProperty("ITLAWDLPeerCache", text);
    return result;
}

extern bool itlAWDLBuildVerified();
extern bool itlAWDLBuildForced();

void ItlAWDLInterface::acceptNativeRequests()
{
    nativeState.accept = true;
    setProperty("ItlwmAWDLNativeUp", true);
    debugFlagsWanted = itlResFlag("-itlawdlpmdebug", 0x2);
    peerCacheAccept = itlResFlag("-itlpeercache", 0x1);
    setProperty("ITLAWDLPeerCache", peerCacheAccept ? "on, no requests yet" : "off");
    // The request carries a raw pointer at a fixed offset, a layout checked only for the verified
    // builds. On any other build the copy is off, unless -itlawdlanybuild is set (itlAWDLBuildForced): then an
    // unverified build works like a verified one (other devices list the Mac only with it), with the pointer still
    // range-checked and the copy validated (storeMasterIndication), but the layout not known to match.
    const bool wanted = itlAWDLFlag("-itlawdlmitx");
    const bool verified = itlAWDLBuildVerified();
    const bool forced = !verified && itlAWDLBuildForced();
    masterIndicationEnabled = wanted && (verified || forced);
    setProperty("ItlwmAWDLMiState", !wanted ? "off" : !masterIndicationEnabled ? "blocked: build not verified" :
                forced ? "on (unverified build, -itlawdlanybuild)" : "on");
}

#if __IO80211_TARGET != __MAC_14_4   // not a virtual on Sonoma
// wifip2pd sets a new, random address on awdl0 (it logged "Can't assign requested address" while this
// was refused, #85). The address is ours to use: the announcement, data frames and receive filtering
// all read localFrameAddress, and the firmware listener follows the address of the sync frames macOS
// builds, changing its own before it sends anything. Nothing is published but the count.
// From ann0see's diff in #85.
IOReturn ItlAWDLInterface::setMacAddress(ether_addr &address)
{
    IOLock *lock = ensureConfigurationLock();
    if (!lock)
        return kIOReturnNoMemory;
    IOLockLock(lock);
    memcpy(localFrameAddress, &address, sizeof(localFrameAddress));
    IOLockUnlock(lock);
    setProperty("ItlwmAWDLAddressSetCalls", ++addressSetCalls, 32);
    return kIOReturnSuccess;
}
#endif

IOReturn ItlAWDLInterface::getAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *data)
{
    if (!nativeState.accept)
        return unsupported("getAWDL_AF_TX_MODE");
    if (!data)
        return kIOReturnBadArgument;
    // The local struct's 64-bit mode doesn't match the native record, which holds
    // a 32-bit mode after the version. Touch only those two fields.
    data->version = APPLE80211_VERSION;
    memcpy(reinterpret_cast<uint8_t *>(data) + 4, &afTxModeValue, sizeof(afTxModeValue));
    return kIOReturnSuccess;
}

IOReturn ItlAWDLInterface::setAWDL_AF_TX_MODE(apple80211_awdl_af_tx_mode *data)
{
    if (!nativeState.accept)
        return unsupported("setAWDL_AF_TX_MODE");
    if (!data)
        return kIOReturnBadArgument;
    memcpy(&afTxModeValue, reinterpret_cast<const uint8_t *>(data) + 4, sizeof(afTxModeValue));
    setProperty("ItlwmAWDLAfTxMode", afTxModeValue, 32);
    return kIOReturnSuccess;
}

// Reports success, but nothing is sent yet: the request's format is unknown, so
// this build only records it. The sample is the fixed header before offset 0x28 only: on Tahoe and
// Sequoia the length sits at 0x28 and a raw kernel pointer at 0x30, and neither may be published.
IOReturn ItlAWDLInterface::noteOobRequest(const apple80211_awdl_oob_request *data, const char *name)
{
    if (!nativeState.accept)
        return unsupported(name);
    if (!data)
        return kIOReturnBadArgument;
    ++oobRequests;
    if (oobRequests == 1 || !(oobRequests % 16))
        setProperty("ItlwmAWDLOobRequests", oobRequests, 32);
    if (!oobSampled && awdlRawSamples) {
        oobSampled = true;
        uint16_t length;
        memcpy(&length, reinterpret_cast<const uint8_t *>(data) + 0x28, sizeof(length));
        if (auto *sample = OSData::withBytes(data, 0x28)) {
            setProperty("ItlwmAWDLOobSample", sample);
            sample->release();
        }
        setProperty("ItlwmAWDLOobFirstName", name);
        setProperty("ItlwmAWDLOobFirstLength", length, 32);
    }
    return kIOReturnSuccess;
}

IOReturn ItlAWDLInterface::setAWDL_OOB_REQUEST(apple80211_awdl_oob_request *data)
{
    const IOReturn result = noteOobRequest(data, "setAWDL_OOB_REQUEST");
    if (result == kIOReturnSuccess && itlAWDLUmiOn())
        storeUnicastMI(data);
    return result;
}

// . IO80211AWDLPeerManager::sendUnicastMI (26.7.2) fills the request: +0x04 the peer's address (6 bytes),
// +0x14 options (u16: 6, or 0xe for a peer "UMIOnDwell"), +0x16 u32 and +0x1a u16 from the peer manager, +0x28 the
// body's length (u16), +0x30 a pointer to the body, built by buildMasterIndicationTemplate(unicast) into the peer
// manager's own buffer (max 0x4b0): the same TLV layout as the AUTO request's MI template. Copied at once, checked
// like the MI template, and sent once by the sync builder to that peer.
void ItlAWDLInterface::storeUnicastMI(const apple80211_awdl_oob_request *data)
{
    const auto *raw = reinterpret_cast<const uint8_t *>(data);
    uint16_t length, options;
    const uint8_t *source;
    uint8_t peer[6];
    memcpy(peer, raw + 0x04, sizeof(peer));
    memcpy(&options, raw + 0x14, sizeof(options));
    memcpy(&length, raw + 0x28, sizeof(length));
    memcpy(&source, raw + 0x30, sizeof(source));
    ++umiRequests;
    const bool groupPeer = peer[0] & 1;
    if (reinterpret_cast<uintptr_t>(source) < 0xffffff8000000000ULL || !length || length > sizeof(umiBody) ||
        groupPeer || !ensureConfigurationLock()) {
        ++umiRejected;
        setProperty("ItlwmAWDLUmiRejected", umiRejected, 32);
        return;
    }
    auto *local = static_cast<uint8_t *>(IOMalloc(length));
    if (!local)
        return;
    memcpy(local, source, length);
    if (!ItlAWDL::masterIndicationWellFormed(local, length)) {
        IOFree(local, length);
        ++umiRejected;
        setProperty("ItlwmAWDLUmiRejected", umiRejected, 32);
        return;
    }
    if (options & 8)
        ++umiOnDwell;
    IOLockLock(configurationLock);
    if (umiLength)
        ++umiReplaced;
    memcpy(umiBody, local, length);
    umiLength = length;
    memcpy(umiPeer, peer, sizeof(umiPeer));
    umiAtUS = itlAWDLUptimeUS();
    itlAWDLUmiAtUS = umiAtUS;
    IOLockUnlock(configurationLock);
    IOFree(local, length);
    __atomic_store_n(&itlAWDLUmiPending, 1U, __ATOMIC_SEQ_CST);
}

bool ItlAWDLInterface::takeUnicastMI(uint8_t *output, size_t capacity, size_t *written, uint8_t peer[6], uint64_t nowUS)
{
    if (!configurationLock || !output || !written || !peer)
        return false;
    auto *mi = static_cast<uint8_t *>(IOMalloc(sizeof(umiBody)));
    if (!mi)
        return false;
    IOLockLock(configurationLock);
    const size_t length = umiLength;
    const uint64_t atUS = umiAtUS;
    if (length) {
        memcpy(mi, umiBody, length);
        memcpy(peer, umiPeer, 6);
    }
    umiLength = 0;
    IOLockUnlock(configurationLock);
    __atomic_store_n(&itlAWDLUmiPending, 0U, __ATOMIC_SEQ_CST);
    bool built = false;
    // macOS asks inside its AW for the peer it is waiting on; the radio holds one at most 1.1 s for the peer's AW, so
    // one older than 2.2 s (no frame went out meanwhile) is stale.
    if (length && nowUS > atUS && nowUS - atUS > 2200000ULL)
        ++umiStale;
    else if (length) {
        built = buildMITLVs(mi, length, output, capacity, written);
        if (!built)
            ++umiBuildFailed;
    }
    IOFree(mi, sizeof(umiBody));
    publishUnicastMI();
    return built;
}

void ItlAWDLInterface::noteUnicastMISent()
{
    ++umiSent;
    publishUnicastMI();
}

void ItlAWDLInterface::publishUnicastMI()
{
    char text[160];
    snprintf(text, sizeof(text), "requests %u rejected %u replaced %u sent %u stale %u build-failed %u on-dwell %u",
             umiRequests, umiRejected, umiReplaced, umiSent, umiStale, umiBuildFailed, umiOnDwell);
    setProperty("ItlwmAWDLUmi", text);
}

IOReturn ItlAWDLInterface::setAWDL_OOB_AUTO_REQUEST(apple80211_awdl_oob_request *data)
{
    const IOReturn result = noteOobRequest(data, "setAWDL_OOB_AUTO_REQUEST");
    if (result == kIOReturnSuccess && masterIndicationEnabled) {
        // the slots and offset macOS asks for, read from the request itself (layout as for the MI pointer).
        const auto *raw = reinterpret_cast<const uint8_t *>(data);
        uint32_t offset, bitmap;
        uint16_t options;
        memcpy(&offset, raw + 0x0c, sizeof(offset));
        memcpy(&bitmap, raw + 0x10, sizeof(bitmap));
        memcpy(&options, raw + 0x14, sizeof(options));
        if (bitmap != itlAWDLMiBitmap)
            ++itlAWDLMiBitmapChanges;
        itlAWDLMiBitmap = bitmap;
        itlAWDLMiOffsetUS = offset;
        itlAWDLMiOptions = options;
        char text[96];
        snprintf(text, sizeof(text), "bitmap 0x%08x offset %u us options 0x%x changes %u", bitmap, offset, options,
                 itlAWDLMiBitmapChanges);
        setProperty("ItlwmAWDLMiRequest", text);
        storeMasterIndication(data);
    }
    return result;
}

void ItlAWDLInterface::storeMasterIndication(const apple80211_awdl_oob_request *data)
{
    const auto *raw = reinterpret_cast<const uint8_t *>(data);
    uint16_t length;
    const uint8_t *source;
    memcpy(&length, raw + 0x28, sizeof(length));
    memcpy(&source, raw + 0x30, sizeof(source));
    // Only ever a kernel buffer from the peer manager, and never over its capacity.
    if (reinterpret_cast<uintptr_t>(source) < 0xffffff8000000000ULL || !length || length > sizeof(masterIndication) ||
        !ensureConfigurationLock()) {
        ++masterIndicationRejected;
        setProperty("ItlwmAWDLMiRejected", masterIndicationRejected, 32);
        return;
    }
    // Read the peer manager's buffer exactly once, into our own copy, and validate, store and sample only
    // that copy: the bytes checked are the bytes used, even if the source changes meanwhile (audit P-R05).
    auto *local = static_cast<uint8_t *>(IOMalloc(length));
    if (!local)
        return;
    memcpy(local, source, length);
    if (!ItlAWDL::masterIndicationWellFormed(local, length)) {
        IOFree(local, length);
        ++masterIndicationRejected;
        setProperty("ItlwmAWDLMiRejected", masterIndicationRejected, 32);
        return;
    }
    // The reader (copyMasterIndication) takes the same lock.
    IOLockLock(configurationLock);
    memcpy(masterIndication, local, length);
    masterIndicationLength = length;
    IOLockUnlock(configurationLock);
    ++masterIndicationUpdates;
    {   // content changes (services) timed to the first MI out
        const uint32_t h = itlAWDLMiContentHashOf(local, length);
        if (h != itlAWDLMiContentHash) {
            itlAWDLMiContentHash = h;
            itlAWDLTemplateChangeUS = itlAWDLUptimeUS();
            ++itlAWDLTemplateChanges;
        }
    }
    itlSvcNoteTemplate(local, length);
    if (masterIndicationUpdates == 1 || !(masterIndicationUpdates % 64))
        setProperty("ItlwmAWDLMiUpdates", masterIndicationUpdates, 32);
    setProperty("ItlwmAWDLMiLength", length, 32);
    // Keep the current template, since its first version is small and has no services.
    if (awdlRawSamples && masterIndicationSampledLength != length) {
        masterIndicationSampledLength = length;
        if (auto *sample = OSData::withBytes(local, length)) {
            setProperty("ItlwmAWDLMiSample", sample);
            sample->release();
        }
    }
    IOFree(local, length);
}

extern unsigned itlAWDLFixedChannel();
extern unsigned itlAWDLChannelClass();
extern bool itlAWDLBuildAllowed();
extern const char *itlAWDLBuildStatus();
// The card's own spatial streams, from the HAL's MCS set: MCS 8-15 exists only with MIMO enabled and
// two receive antennas (iwx_setup_ht_rates). 0 until the set is known. A one-antenna card (9461, 9462,
// AX101; #87) must not tell macOS or peers it has two streams.
static volatile int gItlAWDLCardStreams = 0;
int itlAWDLNoteCardStreams(const struct ieee80211com *ic)
{
    if (ic && ic->ic_sup_mcs[0])
        gItlAWDLCardStreams = ic->ic_sup_mcs[1] ? 2 : 1;
    return gItlAWDLCardStreams;
}

// With -itlawdlcaps the driver reports two HT streams and VHT to macOS; our TLV 7 says the same.
// Two streams only while the card isn't known to have one.
static bool itlAWDLTwoStreams()
{
    static int cached = -1;
    if (cached < 0) {
        int dummy = 0;
        cached = itlAWDLBuildAllowed() && itlAWDLFlag("-itlawdlcaps") &&
            !PE_parse_boot_argn("-itlawdlcapshtonly", &dummy, sizeof(dummy)) ? 1 : 0;
    }
    return cached == 1 && gItlAWDLCardStreams != 1;
}

bool ItlAWDLInterface::copyMasterIndication(uint8_t *output, size_t capacity, size_t *written)
{
    if (!masterIndicationLength || !output || !written || !capacity || !configurationLock)
        return false;
    // A consistent snapshot under the lock the setter takes (audit P-R05), then the build outside it.
    auto *mi = static_cast<uint8_t *>(IOMalloc(sizeof(masterIndication)));
    if (!mi)
        return false;
    IOLockLock(configurationLock);
    const size_t miLength = masterIndicationLength;
    memcpy(mi, masterIndication, miLength);
    IOLockUnlock(configurationLock);
    const bool ok = buildMITLVs(mi, miLength, output, capacity, written);
    IOFree(mi, sizeof(masterIndication));
    return ok;
}

// The MI TLVs for our frames from a template macOS built (its MI, or a unicast MI, -itlawdlumi).
bool ItlAWDLInterface::buildMITLVs(const uint8_t *mi, size_t miLength, uint8_t *output, size_t capacity, size_t *written)
{
    if (!mi || !miLength || !output || !written || !capacity)
        return false;
    // Built in scratch and copied only on success: a failure partway through must leave the caller's
    // buffer, which holds the ordinary frame's template, exactly as it was.
    auto *scratch = static_cast<uint8_t *>(IOMalloc(capacity));
    if (!scratch)
        return false;
    size_t length = 0;
    uint8_t execSlots[16];
    const bool exec = itlAWDLExecPlan(execSlots);
    ItlAWDL::ElectionAdvert electAdvert{};
    ItlAWDL::Clock electClock = ItlAWDL::ownClock();
    const bool elect = itlAWDLClockState(&electAdvert, &electClock);
    bool built = miLength && ItlAWDL::buildMasterIndicationTLVs(mi, miLength, localFrameAddress,
                                                          scratch, capacity, &length, uint8_t(itlAWDLFixedChannel()),
                                                          uint8_t(itlAWDLChannelClass()), itlAWDLTwoStreams(),
                                                          exec ? execSlots : nullptr, elect ? &electAdvert : nullptr);
    if (!built && (exec || elect)) {
        length = 0;
        built = miLength && ItlAWDL::buildMasterIndicationTLVs(mi, miLength, localFrameAddress,
                                                          scratch, capacity, &length, uint8_t(itlAWDLFixedChannel()),
                                                          uint8_t(itlAWDLChannelClass()), itlAWDLTwoStreams());
    }
    if (built && length <= capacity) {
        memcpy(output, scratch, length);
        *written = length;
    } else {
        setProperty("ItlwmAWDLMiBuildFailed", true);
    }
    IOFree(scratch, capacity);
    return built && length <= capacity;
}

IOReturn ItlAWDLInterface::setAWDL_SYNC_ENABLED(apple80211_awdl_sync_enabled *data)
{
    const IOReturn result = nativeState.setEnabled(data);
    if (result == kIOReturnUnsupported) {
        setProperty("ItlwmAWDLActivationBlocked", "radio-transport-unimplemented");
        return unsupported("setAWDL_SYNC_ENABLED");
    }
    if (result == kIOReturnSuccess && nativeState.accept) {
        setProperty("ItlwmAWDLSyncEnabledRequested", data->enabled, 32);
        itlAWDLSyncOn = data->enabled ? 1 : 0;
        // The peer manager exists by now. Reject reasons are behind these flags.
        if (data->enabled && debugFlagsWanted && !debugFlagsSet) {
            debugFlagsSet = true;
            setDebugFlags(~0ULL, 0);
            setProperty("ItlwmAWDLDebugFlagsSet", true);
        }
    }
    return result;
}

IOReturn ItlAWDLInterface::setAWDL_SYNC_STATE(apple80211_awdl_sync_state *data)
{
    const IOReturn result = nativeState.setState(data);
    if (result == kIOReturnUnsupported) {
        setProperty("ItlwmAWDLActivationBlocked", "radio-transport-unimplemented");
        return unsupported("setAWDL_SYNC_STATE");
    }
    if (result == kIOReturnSuccess && nativeState.accept)
        setProperty("ItlwmAWDLSyncStateRequested", data->state, 32);
    return result;
}

// macOS works out this Mac's AWDL schedule with Apple's own rules and hands it down here. The listener picks
// its channel from what it hears instead (#17, #35, #68), so these are published to compare the two:
// ItlwmAWDLReqSeqHeader (length, encoding, step and duplicate counts, fill channel), ItlwmAWDLReqSeqChannels
// (each entry's channel number), ItlwmAWDLReqSeqRaw (the whole request),
// ItlwmAWDLReqMasterChannel and ItlwmAWDLReqSecondaryMasterChannel. With -itlschedmacchan the listener
// follows the secondary master channel; otherwise they are published only.
IOReturn ItlAWDLInterface::setAWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE(apple80211_awdl_sync_channel_sequence *data)
{
    const IOReturn result = storeRequested(requested_AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE, data,
                                           "AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE");
    if (result == kIOReturnSuccess)
        publishRequestedSequence();
    return result;
}

void ItlAWDLInterface::publishRequestedSequence()
{
    // Read back our own stored copy, not the caller's buffer.
    apple80211_awdl_sync_channel_sequence copy {};
    if (readRequested(requested_AWDL_SYNCHRONIZATION_CHANNEL_SEQUENCE, &copy) != kIOReturnSuccess)
        return;
    // The header's declared 3-byte entries don't match what Tahoe sends: the first boot (25G241) showed
    // 12-byte entries, {channel, flags, a third word} as 32-bit words (149, 0x10, 1). The channel list below
    // reads that layout; the raw copy is the whole request, so another layout can be checked offline.
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&copy);
    const unsigned maxEntries = unsigned((sizeof(copy) - 16) / 12);
    const unsigned entries = copy.length < maxEntries ? copy.length : maxEntries;
    uint8_t channels[(sizeof(copy) - 16) / 12] = {};
    for (unsigned i = 0; i < entries; ++i) {
        uint32_t channel;
        memcpy(&channel, bytes + 16 + 12 * i, sizeof(channel));
        channels[i] = channel > 0xff ? 0xff : uint8_t(channel);
    }
    char header[96];
    snprintf(header, sizeof(header), "len=%u enc=%u step=%u dup=%u fill=%u", copy.length, copy.encoding,
             copy.step_count, copy.duplicate_count, copy.fill_channel);
    setProperty("ItlwmAWDLReqSeqHeader", header);
    if (auto *list = OSData::withBytes(channels, entries)) {
        setProperty("ItlwmAWDLReqSeqChannels", list);
        list->release();
    }
    if (auto *raw = OSData::withBytes(&copy, unsigned(sizeof(copy)))) {
        setProperty("ItlwmAWDLReqSeqRaw", raw);
        raw->release();
    }
    setProperty("ItlwmAWDLReqSeqSets", ++requestedSequenceSets, 32);
    if (entries == 16 && copy.step_count == 3) {   // macOS's plan hand-off
        ++itlAWDLPlanVersion;
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        memcpy(itlAWDLPlanChannels, channels, 16);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        ++itlAWDLPlanVersion;
    }
}

IOReturn ItlAWDLInterface::setAWDL_MASTER_CHANNEL(apple80211_awdl_master_channel *data)
{
    const IOReturn result = storeRequested(requested_AWDL_MASTER_CHANNEL, data, "AWDL_MASTER_CHANNEL");
    apple80211_awdl_master_channel copy {};
    if (result == kIOReturnSuccess && readRequested(requested_AWDL_MASTER_CHANNEL, &copy) == kIOReturnSuccess)
        setProperty("ItlwmAWDLReqMasterChannel", copy.master_channel, 32);
    return result;
}

IOReturn ItlAWDLInterface::setAWDL_SECONDARY_MASTER_CHANNEL(apple80211_awdl_secondary_master_channel *data)
{
    const IOReturn result = storeRequested(requested_AWDL_SECONDARY_MASTER_CHANNEL, data,
                                           "AWDL_SECONDARY_MASTER_CHANNEL");
    apple80211_awdl_secondary_master_channel copy {};
    if (result == kIOReturnSuccess &&
        readRequested(requested_AWDL_SECONDARY_MASTER_CHANNEL, &copy) == kIOReturnSuccess)
    {
        setProperty("ItlwmAWDLReqSecondaryMasterChannel", copy.secondary_master_channel, 32);
        itlAWDLReqSecondaryMaster = copy.secondary_master_channel;
    }
    return result;
}

IOReturn ItlAWDLInterface::setAWDL_SYNC_FRAME_TEMPLATE(apple80211_awdl_sync_frame_template *data)
{
    if (!data || data->version > APPLE80211_VERSION)
        return kIOReturnBadArgument;
    if (!configurationLock)
        return kIOReturnNotReady;
    // This native protocol callback receives a kernel-owned payload, already
    // marshalled by IO80211Family. Retain a bounded copy, never its pointer.
    IOLockLock(configurationLock);
    const IOReturn result = frameTemplate.set(data->payload, data->payload_len);
    IOLockUnlock(configurationLock);

    if (result == kIOReturnSuccess) {
        setProperty("ItlwmAWDLTemplateStored", data->payload_len != 0);
        setProperty("ItlwmAWDLLastStoredRequest", "AWDL_SYNC_FRAME_TEMPLATE");
    }
    return result;
}

IOReturn ItlAWDLInterface::copyFrameConfiguration(FrameConfiguration *output)
{
    if (!output) return kIOReturnBadArgument;
    if (!configurationLock || !nativeStarted) return kIOReturnNotReady;
    IOLockLock(configurationLock);
    apple80211_awdl_sync_params parameters = {};
    const IOReturn status = requested_AWDL_SYNC_PARAMS.get(&parameters);
    const size_t length = frameTemplate.size();
    if ((status != kIOReturnSuccess && status != kIOReturnNotReady) || !length) {
        IOLockUnlock(configurationLock);
        return kIOReturnNotReady;
    }
    // Both template replacement and requested settings use this same lock.
    // No borrowed native template pointer crosses the interface boundary.
    const IOReturn result = frameTemplate.copy(output->staticTLVs, sizeof(output->staticTLVs));
    if (result == kIOReturnSuccess) {
        output->parameters = parameters;
        output->hasRequestedTiming = status == kIOReturnSuccess;
        memcpy(output->address, localFrameAddress, sizeof(localFrameAddress));
        output->templateLength = length;
    }
    IOLockUnlock(configurationLock);
    return result;
}

void ItlAWDLInterface::observeDataFrame(const uint8_t *frame, size_t length)
{
    if ((!dataDeliverEnabled && (!dataCopyProbeEnabled || dataCopyAttempts >= 8)) || !nativeStarted || !rxPool ||
        !queueWorkLoop || !queueWorkLoop->inGate()) {
        ++itlAWDLRxDisabled;
        return;
    }
    ItlAWDL::DataFrameView view;
    if (ItlAWDL::parseDataFrame(frame, length, true, &view) != ItlAWDL::ParseResult::Valid) {
        ++itlAWDLRxParseBad;
        return;
    }
    // Copy only multicast or our local AWDL destination; drop self echoes.
    if (!(*view.destination & 1) && memcmp(view.destination, localFrameAddress, 6)) {
        ++itlAWDLRxNotOurs;   // e.g. sent to an address macOS rotated away from
        return;
    }
    if (!memcmp(view.source, localFrameAddress, 6)) {
        ++itlAWDLRxSelf;
        return;
    }
    if (view.ip.minExtension != 3 || view.ip.presence != 4) {
        ++itlAWDLRxMetaOther;
        itlAWDLRxMetaLast = uint32_t(view.ip.minExtension) << 8 | view.ip.presence;
    }
    ++dataCopyAttempts;
    auto *pool = reinterpret_cast<ItlSkywalkPoolView *>(rxPool);
    ItlSkywalkPacketView *packet = nullptr;
    const IOReturn allocated = pool->allocatePacket(1, &packet, 1);
    bool copied = false;
    IOReturn prepared = kIOReturnNotReady, completed = kIOReturnNotReady;
    if (allocated != kIOReturnSuccess || !packet)
        ++itlAWDLRxAllocFail;
    if (allocated == kIOReturnSuccess && packet) {
        prepared = packet->prepareWithQueue(packetQueues[2], 0, 0);
        const size_t wanted = 14 + view.ip.length;
        const bool ready = prepared == kIOReturnSuccess && packet->getPacketBufferCount() == 1 &&
            packet->setDataLength(unsigned(wanted)) == kIOReturnSuccess && packet->getDataLength() == wanted;
        if (!ready)
            ++itlAWDLRxPrepFail;
        if (ready) {
            auto *bytes = reinterpret_cast<uint8_t *>(packet->getDataVirtualAddress());
            if (bytes) {
                size_t written = 0;
                copied = ItlAWDL::copyDataEthernet(view, bytes, wanted, &written) == ItlAWDL::BuildResult::Ready &&
                    written == wanted && !memcmp(bytes, view.destination, 6) && !memcmp(bytes+6, view.source, 6) &&
                    bytes[12] == 0x86 && bytes[13] == 0xdd && !memcmp(bytes+14, view.ip.bytes, view.ip.length);
                if (!copied)
                    ++itlAWDLRxCopyFail;
                if (copied && dataDeliverEnabled) {
                    // Same framing a software Ethernet driver gives the stack.
                    IOReturn delivered = itlPacketSetHeadroom(packet, 0);
                    if (delivered == kIOReturnSuccess)
                        delivered = itlPacketSetLinkHeaderLength(packet, 14);
                    if (delivered == kIOReturnSuccess)
                        delivered = itlRxEnqueue(packetQueues[3], &packet, 1, 0);
                    if (delivered == kIOReturnSuccess) {
                        // The queue owns the packet now; don't touch or return it.
                        ++dataDelivered;
                        ++itlAWDLRxDelivered;
                        if (dataDelivered == 1 || !(dataDelivered % 16))
                            setProperty("ItlwmAWDLDataDelivered", dataDelivered, 32);
                        return;
                    }
                    ++dataDeliverFailed;
                    ++itlAWDLRxQueueFail;
                    if (dataDeliverFailed == 1 || !(dataDeliverFailed % 32))
                        noteQueueState("ItlwmAWDLQueueStateRefused");
                    setProperty("ItlwmAWDLDataDeliverFailed", dataDeliverFailed, 32);
                    setProperty("ItlwmAWDLDataDeliverLastError", delivered, 32);
                }
                bzero(bytes, wanted);
            }
        }
        const auto reset = packet->setDataLength(0);
        completed = packet->completeWithQueue(packetQueues[2], 0, 0);
        copied = copied && reset == kIOReturnSuccess && completed == kIOReturnSuccess;
        pool->deallocatePacket(packet);
    }
    if (copied) ++dataCopySuccess;
    // Unbounded delivery must not write the registry for every failed frame.
    if (dataCopyAttempts > 16 && (dataCopyAttempts % 64)) return;
    setProperty("ItlwmAWDLDataCopyAttempts", dataCopyAttempts, 32);
    setProperty("ItlwmAWDLDataCopySuccess", dataCopySuccess, 32);
    setProperty("ItlwmAWDLDataCopyLastAllocation", allocated, 32);
    setProperty("ItlwmAWDLDataCopyLastPrepare", prepared, 32);
    setProperty("ItlwmAWDLDataCopyLastComplete", completed, 32);
    // Deliberately no native RX enqueue, peer admission or data delivery.
}

IOReturn ItlAWDLInterface::receiveManagementFrame(IO80211Controller *controller,
                                                 const uint8_t *frame, size_t length,
                                                 uint32_t channel, int32_t rssi)
{
    if (!nativeStarted || !queueWorkLoop || !queueWorkLoop->inGate())
        return kIOReturnNotReady;
#if __IO80211_TARGET == __MAC_14_4
    auto *pool = itlGetInterfaceMgmtFramePool(this);   // Sonoma: the virtual interface owns the pool
#else
    auto *pool = itlGetMgmtFramePool(controller);
#endif
    if (!pool)
        return kIOReturnNotReady;
    struct Sink {
        IO80211BufferPool *pool;
        ItlAWDLInterface *interface;
        IO80211Buffer *acquire() { return pool->getBuffer(); }
        void *bytes(IO80211Buffer *p) { return p->getBytesNoCopy(); }
        size_t capacity(IO80211Buffer *p) { return p->getCapacity(); }
        void giveBack(IO80211Buffer *p) { p->returnBuffer(); }
        void setLength(IO80211Buffer *p, size_t n) { p->setLength(n); }
        void submit(IO80211Buffer *p, ItlAWDL::ManagementMetadata *metadata) {
            itlSubmitMgmtFrame(interface, p, 12, metadata, sizeof(*metadata));
        }
    } sink = {pool, this};
    const uint32_t band = channel <= 14 ? APPLE80211_C_FLAG_2GHZ : APPLE80211_C_FLAG_5GHZ;
    const IOReturn result = ItlAWDL::copyManagementFrame(sink, frame, length, channel, band, rssi);
    if (result == kIOReturnSuccess) {
        ++managementSubmissions;
        // Count submissions only. Native peer acceptance needs separate evidence.
        if (managementSubmissions == 1 || !(managementSubmissions % 100))
            setProperty("ItlwmAWDLManagementSubmissions", managementSubmissions, 32);
    }
    return result;
}

// Both flags enqueuePackets requires, per queue: IOEventSource's enabled state and
// the native flag at +0xcc, which only IOSkywalkPacketQueue::initialize sets (25G241).
void ItlAWDLInterface::noteQueueState(const char *key)
{
    char state[64];
    size_t used = 0;
    static const char *const names[] = {"txs", "txc", "rxs", "rxc"};
    for (unsigned i = 0; i < 4 && packetQueues[i]; ++i)
        used += snprintf(state + used, sizeof(state) - used, "%s %u %u; ", names[i],
                         packetQueues[i]->isEnabled() ? 1U : 0U,
                         unsigned(reinterpret_cast<const uint8_t *>(packetQueues[i])[0xcc] & 1));
    setProperty(key, state);
}

// Size of each buffer in the awdl0 packet pools (the PoolOptions in initializeNetwork use it).
static constexpr UInt32 kItlAWDLPacketBufferSize = 2048;

// The frame inside an outbound packet: one buffer, and the data offset plus length within that buffer.
// The transmit copy trusted both (audit P-A03), and the sample ignored the offset (audit D02).
static const uint8_t *itlPacketFrame(ItlSkywalkPacketView *packet, UInt32 *lengthOut)
{
    if (!packet || !lengthOut || packet->getPacketBufferCount() != 1)
        return nullptr;
    const auto *base = reinterpret_cast<const uint8_t *>(packet->getDataVirtualAddress());
    if (!base)
        return nullptr;
    const UInt32 offset = itlPacketGetDataOffset(packet);
    const UInt32 length = packet->getDataLength();
    if (!ItlCopy::frameInBuffer(offset, length, kItlAWDLPacketBufferSize))
        return nullptr;
    *lengthOut = length;
    return base + offset;
}

void ItlAWDLInterface::noteTransmit(IOSkywalkPacket *const *packets, UInt32 count)
{
    ++transmitCallbacks;
    transmitPackets += count;
    if (transmitCallbacks == 1 || !(transmitCallbacks % 64)) {
        setProperty("ItlwmAWDLTxCallbacks", transmitCallbacks, 32);
        setProperty("ItlwmAWDLTxPacketsOffered", transmitPackets, 32);
    }
    if (!awdlRawSamples || transmitSampled || !packets || !count || !packets[0]) return;
    UInt32 length = 0;
    const auto *bytes = itlPacketFrame(reinterpret_cast<ItlSkywalkPacketView *>(packets[0]), &length);
    if (!bytes || !length) return;
    transmitSampled = true;
    if (auto *sample = OSData::withBytes(bytes, min(length, 128U))) {
        setProperty("ItlwmAWDLTxSample", sample);
        sample->release();
    }
}

// Accepts every packet it can hold for completion, so the ring never stalls on the
// radio. Frames that don't fit the queue or aren't ours are dropped, like a full NIC.
UInt32 ItlAWDLInterface::acceptTransmit(IOSkywalkPacket *const *packets, UInt32 count)
{
    UInt32 accepted = 0;
    for (; accepted < count && transmitDoneCount < transmitFrameCount; ++accepted) {
        UInt32 length = 0;
        const auto *bytes = itlPacketFrame(reinterpret_cast<ItlSkywalkPacketView *>(packets[accepted]), &length);
        bool queued = false;
        if (bytes && length >= 14 && length <= sizeof(transmitFrames->bytes) && transmitFrames &&
            transmitQueued < transmitFrameCount) {
            auto &frame = transmitFrames[(transmitHead + transmitQueued) % transmitFrameCount];
            memcpy(frame.bytes, bytes, length);
            frame.length = uint16_t(length);
            ++transmitQueued;
            queued = true;
        }
        if (!queued) ++transmitDropped;
        transmitDone[transmitDoneCount++] = packets[accepted];
    }
    transmitAccepted += accepted;
    return accepted;
}

bool ItlAWDLInterface::popTransmit(uint8_t *output, size_t available, size_t *written,
                                   const uint8_t *holdPayloadFor, bool holdEverySize, const ItlAWDL::TxPassList *pass)
{
    ++transmitDepthBins[ItlAWDL::depthBin(transmitQueued + parkedQueued)];
    // Whether a peer's unicast data waits now: the one peer the radio holds (holdPayloadFor), or, while the listener
    // is on a second channel (-itlschedsecond), every peer that isn't on that channel (pass).
    auto peerHeld = [&](const uint8_t *addr) {
        return (holdPayloadFor && ItlAWDL::sameAddress(addr, holdPayloadFor)) || (pass && pass->holds(addr));
    };
    auto findParked = [&](const uint8_t *addr) -> int {
        for (unsigned i = 0; i < parkedPeerCount; ++i)
            if (ItlAWDL::sameAddress(parkedPeerTable[i].addr, addr))
                return int(i);
        return -1;
    };
    // parkedPeer names the peer whose parked frame is oldest, as it named the one parked peer before.
    auto notePeer = [&]() {
        uint32_t oldest = 0;
        for (unsigned i = 0; i < parkedPeerCount; ++i) {
            const uint32_t order = parkedFrames[parkedPeerTable[i].first].order;
            if (!i || int32_t(order - oldest) < 0) {
                oldest = order;
                memcpy(parkedPeer, parkedPeerTable[i].addr, sizeof(parkedPeer));
            }
        }
    };
    // The parked frames first: of the peers no longer held, the one whose frame was parked first, its oldest frame.
    while (parkedQueued) {
        int pick = -1;
        uint32_t oldest = 0;
        for (unsigned i = 0; i < parkedPeerCount; ++i) {
            const uint32_t order = parkedFrames[parkedPeerTable[i].first].order;
            if (!peerHeld(parkedPeerTable[i].addr) && (pick < 0 || int32_t(order - oldest) < 0)) {
                pick = int(i);
                oldest = order;
            }
        }
        if (pick < 0)
            break;
        auto &peer = parkedPeerTable[pick];
        const unsigned index = peer.first;
        auto &frame = parkedFrames[index];
        const auto result = ItlAWDL::buildDataFrameFromEthernet(frame.bytes, frame.length, localFrameAddress,
                                                                transmitSequence, output, available, written);
        peer.first = frame.next;
        if (!--peer.count) {
            parkedPeerTable[pick] = parkedPeerTable[--parkedPeerCount];
        }
        frame.length = 0;   // an empty slot until the ring's head passes it
        --parkedQueued;
        while (parkedUsed && !parkedFrames[parkedHead].length) {
            parkedHead = (parkedHead + 1) % parkedFrameCount;
            --parkedUsed;
        }
        notePeer();
        ++transmitPopped;
        if (result == ItlAWDL::BuildResult::Ready) {
            ++transmitSequence;
            return true;
        }
        ++transmitDropped;
    }
    while (transmitQueued) {
        const auto &frame = transmitFrames[transmitHead];
        const auto result = ItlAWDL::buildDataFrameFromEthernet(frame.bytes, frame.length, localFrameAddress,
                                                                transmitSequence, output, available, written);
        // Hold what is for the capped peer. With holdEverySize (iface160) that is every unicast data frame for
        // it: a short frame let past would overtake the held packets of the same QUIC connection on the
        // listener's unpaused queue, and QUIC counts overtaken packets as lost. Without it, only payload-sized
        // frames, as on iface157 to iface159. Held frames are parked, in order, so the frames behind them for
        // other peers still go; once some of its frames are parked, all of that peer's later ones join them.
        // A peer held by the pass list (another channel) waits with every size: it isn't there to hear any. Group
        // frames wait under their group address while the list is active, as the peers on the home channel would
        // miss them; they're only ever parked then, so without a list they go as before.
        const bool dataFrame = result == ItlAWDL::BuildResult::Ready && output[0] == 0x08;
        const bool unicastData = dataFrame && !(output[4] & 1);
        const bool held = (unicastData && holdPayloadFor && (holdEverySize || *written >= 1200) &&
                           ItlAWDL::sameAddress(output + 4, holdPayloadFor)) ||
            (dataFrame && pass && pass->holds(output + 4));
        const int parkedAt = dataFrame && parkedQueued ? findParked(output + 4) : -1;
        const bool behindParked = parkedAt >= 0;
        if (held || behindParked) {
            const bool shortFrame = *written < 1200;
            // A frame held only by the pass list (another channel) may use half the ring: the rest stays for the
            // home channel's own holds, so a visit can't fill it and stop awdl0 behind a held frame once home.
            const bool passOnly = !(unicastData && holdPayloadFor && ItlAWDL::sameAddress(output + 4, holdPayloadFor)) &&
                pass && pass->holds(output + 4);
            const bool roomForPass = !passOnly || parkedUsed < parkedFrameCount / 2;
            if (parkedFrames && parkedUsed < parkedFrameCount && roomForPass &&
                (behindParked || parkedPeerCount < parkedPeerMax)) {
                const unsigned index = (parkedHead + parkedUsed) % parkedFrameCount;
                auto &slot = parkedFrames[index];
                slot.length = frame.length;
                slot.next = 0xffff;
                slot.order = ++parkedSerial;
                memcpy(slot.bytes, frame.bytes, frame.length);
                if (behindParked) {
                    auto &peer = parkedPeerTable[parkedAt];
                    parkedFrames[peer.last].next = uint16_t(index);
                    peer.last = uint16_t(index);
                    ++peer.count;
                } else {
                    auto &peer = parkedPeerTable[parkedPeerCount++];
                    memcpy(peer.addr, output + 4, sizeof(peer.addr));
                    peer.first = peer.last = uint16_t(index);
                    peer.count = 1;
                }
                ++parkedUsed;
                ++parkedQueued;
                parkedPeak = max(parkedPeak, parkedQueued);
                notePeer();
                ++transmitParked;
                if (shortFrame)
                    ++transmitHeldShort;
                transmitHead = (transmitHead + 1) % transmitFrameCount;
                --transmitQueued;
                continue;
            }
            if (parkedFrames && parkedUsed < parkedFrameCount)
                ++parkedTableFull;   // room in the ring, but every peer entry is taken
            // No room to park it: it waits at the head, and what is behind it waits too, as before.
            // Once per frame, not once per attempt: the pump asks again every millisecond.
            if (shortFrame && transmitHeldMark != transmitPopped + 1) {
                transmitHeldMark = transmitPopped + 1;
                ++transmitHeldShort;
            }
            return false;
        }
        transmitHead = (transmitHead + 1) % transmitFrameCount;
        --transmitQueued;
        ++transmitPopped;
        if (result == ItlAWDL::BuildResult::Ready) {
            if (parkedQueued)
                ++transmitPassed;   // Went ahead of the held peer's frames.
            ++transmitSequence;
            return true;
        }
        ++transmitDropped;
    }
    return false;
}

bool ItlAWDLInterface::popTransmitFor(uint8_t *output, size_t available, size_t *written, const uint8_t *destination,
                                      size_t maxLength)
{
    if (!output || !written || !destination || parkedQueued || !transmitQueued)
        return false;
    const auto &frame = transmitFrames[transmitHead];
    if (frame.length < 14 || !ItlAWDL::sameAddress(frame.bytes, destination))
        return false;
    size_t length = 0;
    const auto result = ItlAWDL::buildDataFrameFromEthernet(frame.bytes, frame.length, localFrameAddress,
                                                            transmitSequence, output, available, &length);
    if (result != ItlAWDL::BuildResult::Ready || length > maxLength || output[0] != 0x08 || (output[4] & 1) ||
        !ItlAWDL::sameAddress(output + 4, destination))
        return false;   // left for popTransmit, which handles it as before (a bad one is dropped there)
    transmitHead = (transmitHead + 1) % transmitFrameCount;
    --transmitQueued;
    ++transmitPopped;
    ++transmitSequence;
    *written = length;
    return true;
}

bool ItlAWDLInterface::serviceTransmit()
{
    if (transmitDoneCount) {
        const unsigned count = min(transmitDoneCount, 32U);
        const IOReturn result = itlTxComplete(packetQueues[1], reinterpret_cast<void *const *>(transmitDone), count, 0);
        if (result == kIOReturnSuccess) {
            transmitDoneCount -= count;
            memmove(transmitDone, transmitDone + count, transmitDoneCount * sizeof(transmitDone[0]));
            transmitCompleted += count;
        } else {
            setProperty("ItlwmAWDLTxCompleteLastError", result, 32);
        }
    }
    if (transmitCompleted != transmitLastPublished) {
        transmitLastPublished = transmitCompleted;
        setProperty("ItlwmAWDLTxAccepted", transmitAccepted, 32);
        setProperty("ItlwmAWDLTxCompleted", transmitCompleted, 32);
        setProperty("ItlwmAWDLTxDropped", transmitDropped, 32);
        setProperty("ItlwmAWDLTxParked", transmitParked, 32);
        setProperty("ItlwmAWDLTxParkedPeak", parkedPeak, 32);
        setProperty("ItlwmAWDLTxParkTableFull", parkedTableFull, 32);
        setProperty("ItlwmAWDLTxPassedParked", transmitPassed, 32);
        if (auto *depths = OSData::withBytes(transmitDepthBins, sizeof(transmitDepthBins))) {
            setProperty("ItlwmAWDLTxDepthBins", depths);
            depths->release();
        }
    }
    return transmitQueued || parkedQueued || transmitDoneCount;
}

UInt32 ItlAWDLInterface::rejectTransmit(OSObject *owner, IOSkywalkTxSubmissionQueue*,
                                     IOSkywalkPacket *const *packets, UInt32 count, void*)
{
    // Native legacyDequeue interprets this as an accepted packet count and stops
    // on zero without retrying. Keep ownership with the queue until an AWDL radio
    // transport is implemented; only record that macOS tried to send.
    if (auto *interface = OSDynamicCast(ItlAWDLInterface, owner)) {
        interface->noteTransmit(packets, count);
        if (interface->dataTransmitEnabled)
            return interface->acceptTransmit(packets, count);
    }
    return 0;
}

UInt32 ItlAWDLInterface::deferReceive(OSObject *owner, IOSkywalkRxSubmissionQueue*,
                                   IOSkywalkPacket *const*, UInt32, void*)
{
    if (auto *interface = OSDynamicCast(ItlAWDLInterface, owner)) {
        ++interface->receiveSupplyCallbacks;
        if (interface->receiveSupplyCallbacks == 1 || !(interface->receiveSupplyCallbacks % 64))
            interface->setProperty("ItlwmAWDLRxSupplyCallbacks", interface->receiveSupplyCallbacks, 32);
    }
    return 0;
}

// Hands every packet still held for completion back to Skywalk, while the completion queue still
// exists. Without this, packets accepted but not yet completed stayed owned by us when the queues
// and pools were released.
void ItlAWDLInterface::drainTransmitDone()
{
    if (!transmitDoneCount)
        return;
    if (addedQueues > 1 && packetQueues[1]) {
        while (transmitDoneCount) {
            const unsigned count = min(transmitDoneCount, 32U);
            const IOReturn result = itlTxComplete(packetQueues[1], reinterpret_cast<void *const *>(transmitDone), count, 0);
            if (result != kIOReturnSuccess) {
                setProperty("ItlwmAWDLTxCompleteLastError", result, 32);
                break;
            }
            transmitDoneCount -= count;
            memmove(transmitDone, transmitDone + count, transmitDoneCount * sizeof(transmitDone[0]));
            transmitCompleted += count;
        }
    }
    // Whatever is left can't be completed any more; never hand it back later, to a new queue.
    if (transmitDoneCount)
        setProperty("ItlwmAWDLTxAbandonedAtStop", transmitDoneCount, 32);
    transmitDoneCount = 0;
}

void ItlAWDLInterface::releaseNetworkResources()
{
    // In the queues' work loop, like serviceTransmit, so the two never run at once. Always, and in one
    // action: stop accepting, disable the submission queue, then drain. Before, the drain ran only if packets
    // were held when checked outside the loop, and transmit stayed on until the queues were removed below,
    // so a callback in between parked packets nothing would complete (audit P-R03).
    if (queueWorkLoop)
        queueWorkLoop->runAction([](OSObject *owner, void*, void*, void*, void*) -> IOReturn {
            auto *self = static_cast<ItlAWDLInterface *>(owner);
            self->dataTransmitEnabled = false;
            if (self->addedQueues > 0 && self->packetQueues[0])
                self->packetQueues[0]->disable();
            self->drainTransmitDone();
            return kIOReturnSuccess;
        }, this);
    else
        dataTransmitEnabled = false;
    transmitQueued = 0;
    transmitHead = 0;
    // The held peer's copies go with the queue they came from.
    parkedQueued = 0;
    parkedHead = 0;
    parkedUsed = parkedPeerCount = 0;
    if (registrationAttempted) {
        registrationAttempted = false;
        deregisterEthernetInterface(0);
    }
    for (UInt32 i = addedQueues; i; --i) {
        packetQueues[i-1]->disable();
        queueWorkLoop->removeEventSource(packetQueues[i-1]);
    }
    addedQueues = 0;
    for (auto &queue : packetQueues)
        OSSafeReleaseNULL(queue);
    OSSafeReleaseNULL(txPool);
    OSSafeReleaseNULL(rxPool);
    OSSafeReleaseNULL(queueWorkLoop);
}

// #13: on Sequoia 15.8, awdl0 is missing although this interface carries "BSD Name" = awdl0. The
// BSD client writes that name before it creates the ifnet, so a failed start and a later detach look
// the same from outside. Each entry records the time since boot, the client's class, whether that
// client is already terminating (a detach) or still active (a failed start), the process that caused
// the call, and for closes and finalisations the unslid return addresses, which map onto the build's
// boot kernel collection. Nothing here changes behaviour.
void ItlAWDLInterface::noteClientEvent(const char *what, IOService *client, long result, bool trace)
{
    uint64_t now = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &now);
    char process[32] = {};
    proc_selfname(process, sizeof(process));
    // Open, close and the BSD attach can run on different threads: one lock for the row, the counter and
    // the published list (audit D01).
    IOLock *lock = ensureConfigurationLock();
    if (!lock)
        return;
    IOLockLock(lock);
    const char *name = client && client->getMetaClass() ? client->getMetaClass()->getClassName() : "-";
    char *entry = clientEvents[clientEventCount % clientEventCapacity];
    int used = snprintf(entry, sizeof(clientEvents[0]), "%llu ms %s %s r=%ld inactive=%d proc=%s",
                        now / 1000000ULL, what, name, result, client ? int(client->isInactive()) : -1, process);
    if (trace && used > 0 && size_t(used) < sizeof(clientEvents[0])) {
        void *frames[8] = {};
        const unsigned depth = OSBacktrace(frames, 8);
        for (unsigned i = 1; i < depth && size_t(used) < sizeof(clientEvents[0]) - 20; ++i) {
            vm_offset_t unslid = 0;
            vm_kernel_unslide_or_perm_external(vm_offset_t(frames[i]), &unslid);
            used += snprintf(entry + used, sizeof(clientEvents[0]) - size_t(used), " %lx", (unsigned long)unslid);
        }
    }
    ++clientEventCount;
    if (OSArray *list = OSArray::withCapacity(clientEventCapacity)) {
        const unsigned count = clientEventCount < clientEventCapacity ? clientEventCount : clientEventCapacity;
        for (unsigned i = clientEventCount - count; i < clientEventCount; ++i) {
            if (OSString *text = OSString::withCString(clientEvents[i % clientEventCapacity])) {
                list->setObject(text);
                text->release();
            }
        }
        setProperty("ItlwmAWDLClientEvents", list);
        list->release();
    }
    setProperty("ItlwmAWDLClientEventCount", clientEventCount, 32);
    IOLockUnlock(lock);
}

bool ItlAWDLInterface::handleOpen(IOService *client, IOOptionBits options, void *argument)
{
    const bool opened = IO80211AWDLProtocol::handleOpen(client, options, argument);
    noteClientEvent("open", client, opened ? 1 : 0, false);
    return opened;
}

void ItlAWDLInterface::handleClose(IOService *client, IOOptionBits options)
{
    noteClientEvent("close", client, long(options), true);
    IO80211AWDLProtocol::handleClose(client, options);
}

#if __IO80211_TARGET == __MAC_15_2
IOReturn ItlAWDLInterface::prepareBSDInterface(struct __ifnet *interface, unsigned int flags)
{
    const IOReturn result = IO80211AWDLProtocol::prepareBSDInterface(interface, flags);
    noteClientEvent("prepare-bsd", nullptr, long(result), false);
    return result;
}

void ItlAWDLInterface::finalizeBSDInterface(struct __ifnet *interface, unsigned int flags)
{
    noteClientEvent("finalize-bsd", nullptr, long(flags), true);
    IO80211AWDLProtocol::finalizeBSDInterface(interface, flags);
}
#endif

void ItlAWDLInterface::stop(IOService *provider)
{
    const bool started = nativeStarted;
    nativeStarted = false;
    releaseNetworkResources();
    if (started)
        IO80211AWDLProtocol::stop(provider);
}

void ItlAWDLInterface::free()
{
    if (nativeStarted)
        stop(getProvider());
    else
        releaseNetworkResources();
    if (transmitFrames) {
        IOFree(transmitFrames, transmitFramesBytes);
        transmitFrames = nullptr;
        transmitFramesBytes = 0;
    }
    if (parkedFrames) {
        IOFree(parkedFrames, sizeof(TransmitFrame) * parkedFrameCount);
        parkedFrames = nullptr;
        parkedQueued = 0;
        parkedUsed = parkedPeerCount = 0;
    }
    if (configurationLock) {
        IOLockFree(configurationLock);
        configurationLock = nullptr;
    }
    IO80211AWDLProtocol::free();
}

IOReturn ItlAWDLInterface::initializeNetwork(IO80211Controller *controller,
                                           IOWorkLoop *workLoop,
                                           const ether_addr &address)
{
    auto stage = [this, controller](const char *name) {
        setProperty("ItlwmAWDLNetworkStage", name);
        controller->setProperty("ItlwmAWDLNetworkStage", name);
    };
    auto fail = [this, controller](IOReturn result) {
        stop(controller);
        return result;
    };
    if (!controller || !workLoop || nativeStarted)
        return kIOReturnBadArgument;
    if (!ensureConfigurationLock())
        return kIOReturnNoMemory;
    static_assert(sizeof(address) == sizeof(localFrameAddress), "native AWDL address size");
    memcpy(localFrameAddress, &address, sizeof(localFrameAddress));
    int dataCopyArgument = 0;
    dataCopyProbeEnabled = PE_parse_boot_argn("-itlawdldatacopy", &dataCopyArgument, sizeof(dataCopyArgument));
    // -itlawdlcoexdata (normal Wi-Fi with the listener) needs delivery, transmit and the queues enabled too.
    const bool coexData = itlAWDLFlag("-itlawdlcoexdata");
    dataDeliverEnabled = coexData || PE_parse_boot_argn("-itlawdldatarx", &dataCopyArgument, sizeof(dataCopyArgument));
    // The copy counters belong to the -itlawdldatacopy probe; published as zeros without it, they read as a
    // failure next to working delivery (#7). ItlwmAWDLTransportReady was never set true by anything and is
    // no longer published; ItlwmAWDLDataDelivered and the TX counters show the real state.
    if (dataCopyProbeEnabled) {
        setProperty("ItlwmAWDLDataCopyAttempts", uint64_t(0), 32);
        setProperty("ItlwmAWDLDataCopySuccess", uint64_t(0), 32);
    }
    setProperty("ItlwmAWDLConfigurationMode", "requested-only");
    stage("starting");
    if (!IO80211AWDLProtocol::start(controller)) {
        stage("native-start-failed");
        return kIOReturnError;
    }
    nativeStarted = true;
    queueWorkLoop = workLoop;
    queueWorkLoop->retain();

    stage("allocating-pools");
    // iface162: the TX pool must outlast macOS's own awdl0 queue. The flowswitch copies every outgoing
    // packet into this pool before FQ-CoDel queues it (672 packets allowed), and the submission and
    // completion queues hold 64 each on top. The bring-up size (128 requested, 896 after Skywalk's
    // rounding) ran dry at the queue's peak. The flowswitch then drops the batch (ENOMEM). When FQ-CoDel
    // had not also flow-controlled the flow, QUIC's link stayed flow controlled with nothing to release
    // it: the persistent stalls of 2026-11-10 at 15:32, 15:42, 16:41 and 17:33 each began within 60 ms of
    // "skc.kmd.itlwm-awdl-tx: failed to allocate slab". itlawdltxpool=N
    // (896 to 8192) overrides the default for tests. The RX pool keeps the bring-up size.
    uint32_t txPoolPackets = 2048;
    int requestedPool = 0;
    if (PE_parse_boot_argn("itlawdltxpool", &requestedPool, sizeof(requestedPool)) &&
        requestedPool >= 896 && requestedPool <= 8192)
        txPoolPackets = uint32_t(requestedPool);
    const IOSkywalkPacketBufferPool::PoolOptions txOptions = {
        txPoolPackets, txPoolPackets, kItlAWDLPacketBufferSize, 1, 4096, 0, 0
    };
    const IOSkywalkPacketBufferPool::PoolOptions options = {
        128, 128, kItlAWDLPacketBufferSize, 1, 4096, 0, 0
    };
    // Pool type: IOSkywalkFamily turns 0 into KBIF_QUANTUM and 2 into KBIF_BUFFER_ON_DEMAND. On Sequoia
    // (XNU 11417) and Sonoma, a quantum pool gets quantum metadata, which nx_check_pp refuses for a network
    // interface (EINVAL from kern_nexus_controller_alloc_net_provider_instance), so awdl0 was never attached
    // (#7, #13, #16; found by #19 on 15.6). 1 makes a packet pool, as Apple's own drivers use. Tahoe keeps
    // the 0 every Tahoe test ran with. itlawdlpooltype=0..2 overrides it for tests.
#if __IO80211_TARGET == __MAC_15_2 || __IO80211_TARGET == __MAC_14_4
    UInt32 poolType = 1;
#else
    UInt32 poolType = 0;
#endif
    int requestedPoolType = -1;
    if (PE_parse_boot_argn("itlawdlpooltype", &requestedPoolType, sizeof(requestedPoolType)) &&
        requestedPoolType >= 0 && requestedPoolType <= 2)
        poolType = UInt32(requestedPoolType);
    setProperty("ItlwmAWDLPoolType", poolType, 32);
    txPool = IOSkywalkPacketBufferPool::withName("itlwm-awdl-tx", this, poolType, &txOptions);
    rxPool = IOSkywalkPacketBufferPool::withName("itlwm-awdl-rx", this, poolType, &options);
    setProperty("ItlwmAWDLTxPoolPackets", txPoolPackets, 32);
    if (!txPool || !rxPool)
        return fail(kIOReturnNoMemory);

    stage("allocating-queues");
    packetQueues[0] = itlMakeTxSubmission(txPool, 64, 0, this, rejectTransmit, nullptr, 0);
    packetQueues[1] = itlMakeTxCompletion(txPool, 64, 0, this, nullptr, nullptr, 0);
    packetQueues[2] = itlMakeRxSubmission(rxPool, 64, 1, 0, this, deferReceive, nullptr, 0);
    packetQueues[3] = itlMakeRxCompletion(rxPool, 64, 0, this, nullptr, nullptr, 0);
    for (auto queue : packetQueues)
        if (!queue)
            return fail(kIOReturnNoMemory);

    stage("adding-queues");
    for (auto queue : packetQueues) {
        IOReturn result = queueWorkLoop->addEventSource(queue);
        if (result != kIOReturnSuccess)
            return fail(result);
        ++addedQueues;
    }

    int poolProbe = 0;
    if (PE_parse_boot_argn("-itlawdlpoolprobe", &poolProbe, sizeof(poolProbe))) {
        auto probe = [this](IOSkywalkPacketBufferPool *nativePool, IOEventSource *queue, const char *key) {
            auto *pool = reinterpret_cast<ItlSkywalkPoolView *>(nativePool);
            ItlSkywalkPacketView *packet = nullptr;
            const IOReturn allocation = pool->allocatePacket(1, &packet, 1);
            setProperty(key, allocation, 32);
            if (allocation != kIOReturnSuccess || !packet) return;
            const IOReturn prepared = packet->prepareWithQueue(queue, 0, 0);
            const UInt32 count = packet->getPacketBufferCount();
            const UInt32 initialLength = packet->getDataLength();
            const IOReturn set = prepared == kIOReturnSuccess && count == 1 ? packet->setDataLength(56) : kIOReturnUnsupported;
            const UInt32 length = packet->getDataLength();
            bool copied = false;
            if (prepared == kIOReturnSuccess && count == 1 && set == kIOReturnSuccess && length == 56) {
                auto *bytes = reinterpret_cast<uint8_t *>(packet->getDataVirtualAddress());
                if (bytes) {
                    // Offline test vector only: never enqueue these bytes.
                    const uint8_t ip[40] = {0x60}; size_t written = 0;
                    ItlAWDL::IPv6PayloadView view;
                    copied = ItlAWDL::buildIPv6DataPayload(ip, sizeof(ip), 0x1234, bytes, 56, &written) ==
                        ItlAWDL::BuildResult::Ready && written == 56 &&
                        ItlAWDL::parseIPv6DataPayload(bytes, written, &view) == ItlAWDL::ParseResult::Valid &&
                        view.sequence == 0x1234 && view.length == sizeof(ip) && !memcmp(view.bytes, ip, sizeof(ip));
                    bzero(bytes, 56);
                }
            }
            const IOReturn reset = packet->setDataLength(0);
            const IOReturn completed = packet->completeWithQueue(queue, 0, 0);
            pool->deallocatePacket(packet);
            auto *details = OSDictionary::withCapacity(10);
            if (details) {
                auto add = [details](const char *name, UInt32 value) {
                    if (auto *number = OSNumber::withNumber(value, 32)) {
                        details->setObject(name, number); number->release();
                    }
                };
                add("allocation", allocation); add("prepareStatus", prepared); add("completeStatus", completed); add("buffers", count);
                add("initialLength", initialLength); add("setStatus", set);
                add("length", length); add("resetStatus", reset); add("returnCalled", 1); add("payloadRoundtrip", copied ? 1 : 0);
                setProperty(nativePool == txPool ? "ItlwmAWDLTxPoolDetails" : "ItlwmAWDLRxPoolDetails", details);
                details->release();
            }
            const bool ok = prepared == kIOReturnSuccess && completed == kIOReturnSuccess && count == 1 && initialLength == 0 && set == kIOReturnSuccess &&
                length == 56 && copied && reset == kIOReturnSuccess;
            setProperty(key, ok ? "lease-roundtrip-ok" : "lease-check-failed");
            setProperty("ItlwmAWDLPoolProbeBufferCount", count, 32);
            setProperty("ItlwmAWDLPoolProbeLength", length, 32);
        };
        probe(txPool, packetQueues[0], "ItlwmAWDLTxPoolProbe");
        probe(rxPool, packetQueues[2], "ItlwmAWDLRxPoolProbe");
    }


    IOSkywalkEthernetInterface::RegistrationInfo info = {};
    if (!initRegistrationInfo(&info, 1, sizeof(info)))
        return fail(kIOReturnBadArgument);
    // Offsets are from the 25G241 native AWDL registration path. The framework
    // copies this metadata; the name points to a static string in the kext.
    auto put32 = [&info](size_t offset, UInt32 value) {
        memcpy(info.bytes + offset, &value, sizeof(value));
    };
    put32(0x0c, 3);
    put32(0x14, 2);
    put32(0x24, 0x80);
    put32(0x28, 0x80);
    const char *prefix = "awdl";
    memcpy(info.bytes + 0x30, &prefix, sizeof(prefix));
    put32(0x38, 0);
    const UInt16 headroom = 0x40;
    memcpy(info.bytes + 0x3c, &headroom, sizeof(headroom));
    put32(0x40, 4);
    put32(0x48, 1428);
    put32(0x4c, 1428);
    memcpy(info.bytes + 0x108, &address, sizeof(address));
    IOSkywalkPacketQueue *queues[4];
    for (UInt32 i = 0; i < 4; ++i)
        queues[i] = reinterpret_cast<IOSkywalkPacketQueue *>(packetQueues[i]);

    stage("registering");
    registrationAttempted = true;
    IOReturn result = registerEthernetInterface(&info, queues, 4, txPool, rxPool, 0);
    if (result != kIOReturnSuccess) {
        stage("registration-failed");
        return fail(result);
    }
    setRunningState(false);
    noteQueueState("ItlwmAWDLQueueStateAtRegistration");
    int dataTransmit = 0;
    if (PE_parse_boot_argn("-itlawdldatatx", &dataTransmit, sizeof(dataTransmit)) ||
        itlAWDLFlag("-itlawdlcoexdata")) {
        // The tested set's itlawdltxqueue=4096 is the default; a value that is set still wins.
        int requestedQueue = itlAWDLDefaults() ? 4096 : 0;
        PE_parse_boot_argn("itlawdltxqueue", &requestedQueue, sizeof(requestedQueue));
        if (requestedQueue >= int(transmitFrameDefault) && requestedQueue <= int(transmitFrameCapacity))
            transmitFrameCount = unsigned(requestedQueue);
        // A second initialisation of the same object frees the first array instead of leaking it (audit D03).
        if (transmitFrames) {
            IOFree(transmitFrames, transmitFramesBytes);
            transmitFrames = nullptr;
            transmitFramesBytes = 0;
        }
        transmitFrames = static_cast<TransmitFrame *>(IOMalloc(sizeof(TransmitFrame) * transmitFrameCount));
        if (transmitFrames)
            transmitFramesBytes = sizeof(TransmitFrame) * transmitFrameCount;
        // Room to park as many frames as the FIFO holds, up to parkedFrameMax. Without it a held frame waits at
        // the head as before.
        if (parkedFrames) {
            IOFree(parkedFrames, sizeof(TransmitFrame) * parkedFrameCount);
            parkedFrames = nullptr;
        }
        parkedQueued = parkedHead = parkedUsed = parkedPeerCount = 0;
        parkedFrameCount = min(transmitFrameCount, parkedFrameMax);
        parkedFrames = static_cast<TransmitFrame *>(IOMalloc(sizeof(TransmitFrame) * parkedFrameCount));
        setProperty("ItlwmAWDLTxParkFrames", parkedFrames ? parkedFrameCount : 0, 32);
        dataTransmitEnabled = transmitFrames != nullptr;
        setProperty("ItlwmAWDLTxQueueFrames", transmitFrameCount, 32);
    }
    int queueEnable = 0;
    if (PE_parse_boot_argn("-itlawdlqueueenable", &queueEnable, sizeof(queueEnable)) ||
        itlAWDLFlag("-itlawdlcoexdata")) {
        for (auto queue : packetQueues)
            queue->enable();
        noteQueueState("ItlwmAWDLQueueStateAfterEnable");
    }
    stage("registered");
    registerService();
    return kIOReturnSuccess;
}
#endif

IO80211VirtualInterface *AirportItlwm::createVirtualInterface(ether_addr *address, UInt role)
{
#if defined(ITL_AWDL_NATIVE)
    if (awdlInterfaceTest && role == APPLE80211_VIF_AWDL) {
        setProperty("ItlwmAWDLFactoryStage", "entered");
        if (!address)
            return nullptr;
        ItlAWDLInterface *interface = new ItlAWDLInterface;
        if (!interface) {
            setProperty("ItlwmAWDLFactoryStage", "allocation-failed");
            return nullptr;
        }
        if (!interface->init(this, address, role, "awdl")) {
            setProperty("ItlwmAWDLFactoryStage", "initialization-failed");
            interface->release();
            return nullptr;
        }
        if (itlAWDLFlag("-itlawdlnativeup"))
            interface->acceptNativeRequests();
        interface->setProperty("ItlwmAWDLInterfaceBuild", ITL_FORBIDDEN_BUILD);
        setProperty("ItlwmAWDLFactoryStage", "initialized");
        return interface;
    }
#endif
    return super::createVirtualInterface(address, role);
}

void AirportItlwm::observeAWDLDataFrame(const uint8_t *frame, size_t length)
{
#if defined(ITL_AWDL_NATIVE)
    if (!awdlInterfaceTest || !_fWorkloop || !_fWorkloop->inGate() ||
        !awdlManagementInputEnabled || !fAWDLInterface) return;
    auto *interface = static_cast<ItlAWDLInterface *>(fAWDLInterface);
    interface->retain(); ++awdlManagementActive;
    interface->observeDataFrame(frame, length);
    interface->release();
    if (!--awdlManagementActive) _fWorkloop->commandWakeup(&awdlManagementActive);
#endif
}

#if defined(ITL_AWDL_NATIVE)
void itlAWDLObserveData(IOEthernetController *owner, const uint8_t *frame, size_t length)
{
    if (auto *controller = OSDynamicCast(AirportItlwm, owner)) controller->observeAWDLDataFrame(frame, length);
}
#endif

IOReturn AirportItlwm::receiveAWDLActionFrame(mbuf_t packet, size_t frameLength, uint32_t channel, int32_t rssi)
{
#if defined(ITL_AWDL_NATIVE)
    // HAL and native control share _fWorkloop. Only deliver inside its gate.
    // Stop disables new handoffs and drains this counter before native teardown.
    // This monitor-specific entry takes a normalized span excluding four FCS
    // bytes; the borrowed Intel packet itself retains those bytes.
    if (!awdlInterfaceTest || !_fWorkloop || !_fWorkloop->inGate() ||
        !awdlManagementInputEnabled || !fAWDLInterface || !packet || mbuf_next(packet) ||
        frameLength > mbuf_len(packet) || mbuf_len(packet)-frameLength != 4)
        return kIOReturnNotReady;
    auto *interface = static_cast<ItlAWDLInterface *>(fAWDLInterface);
    interface->retain();
    ++awdlManagementActive;
    const auto result = interface->receiveManagementFrame(this,
        static_cast<const uint8_t *>(mbuf_data(packet)), frameLength, channel, rssi);
    if (result != kIOReturnSuccess)
        setProperty("ItlwmAWDLManagementLastError", static_cast<uint32_t>(result), 32);
    interface->release();
    if (!--awdlManagementActive)
        _fWorkloop->commandWakeup(&awdlManagementActive);
    return result;
#else
    return kIOReturnUnsupported;
#endif
}

#if defined(ITL_AWDL_NATIVE)
IOReturn itlAWDLReceiveAction(IOEthernetController *owner, mbuf_t packet, size_t frameLength, uint32_t channel, int32_t rssi)
{
    auto *controller = OSDynamicCast(AirportItlwm, owner);
    return controller ? controller->receiveAWDLActionFrame(packet, frameLength, channel, rssi) : kIOReturnNotReady;
}
#endif

// Which sync frames were built: with macOS's MI (services, host name), PSF, or an ordinary frame in an MI
// slot because no MI was available or it failed. Counts only; no frame content is published.

IOReturn AirportItlwm::buildAWDLSyncProbe(mbuf_t *packet, uint64_t nowUS)
{
#if defined(ITL_AWDL_NATIVE)
    static uint32_t awdlSyncMIBuilt, awdlSyncPSFBuilt, awdlSyncFallbackBuilt, awdlSyncMIWanted, awdlSyncMIMissing,
        awdlSyncPeerTLVsRefused, awdlSyncFailed;
    if (!packet || *packet) return kIOReturnBadArgument;
    if (!awdlInterfaceTest || !_fWorkloop || !_fWorkloop->inGate() ||
        !awdlManagementInputEnabled || !fAWDLInterface) {
        setProperty("ItlwmAWDLSyncProbeStage", !awdlInterfaceTest ? "test-disabled" :
            !_fWorkloop ? "no-workloop" : !_fWorkloop->inGate() ? "outside-gate" :
            !awdlManagementInputEnabled ? "controller-not-ready" : "no-native-interface");
        return kIOReturnNotReady;
    }
    auto *snapshot = IONew(ItlAWDLInterface::FrameConfiguration, 1);
    if (!snapshot) {
        setProperty("ItlwmAWDLSyncProbeStage", "no-memory");
        return kIOReturnNoMemory;
    }
    auto *interface = static_cast<ItlAWDLInterface *>(fAWDLInterface);
    interface->retain();
    const auto status = interface->copyFrameConfiguration(snapshot);
    // Alternate the peer manager's service-carrying MI with sync-only PSF frames.
    // On any problem with the MI, this stays an ordinary frame.
    // a unicast MI macOS asked for goes first, to its peer, and doesn't count as the MI turn.
    uint8_t umiPeer[6] = {};
    size_t umiLength = 0;
    const bool isUMI = status == kIOReturnSuccess && itlAWDLUmiPending && itlAWDLUmiGo &&
        interface->takeUnicastMI(snapshot->staticTLVs, sizeof(snapshot->staticTLVs), &umiLength, umiPeer, nowUS);
    const bool wantMI = !isUMI && (itlAWDLForceMI || (awdlProbeSequence & 1));   // forced MI
    size_t miLength = isUMI ? umiLength : 0;
    const bool isMI = isUMI || (status == kIOReturnSuccess && wantMI &&
        interface->copyMasterIndication(snapshot->staticTLVs, sizeof(snapshot->staticTLVs), &miLength));
    const bool isPSF = !isMI && !wantMI && interface->hasMasterIndication();
    if (isMI) {
        snapshot->templateLength = miLength;
        if (!isUMI)
            itlSvcNoteMiBuilt();
    }
    if (wantMI) {
        ++awdlSyncMIWanted;
        if (!isMI)
            ++awdlSyncMIMissing;
    }
    interface->release();
    if (status != kIOReturnSuccess) {
        setProperty("ItlwmAWDLSyncProbeStage", "snapshot-not-ready");
        IODelete(snapshot, ItlAWDLInterface::FrameConfiguration, 1);
        return status;
    }
    setProperty("ItlwmAWDLSyncProbeTemplateLength", snapshot->templateLength, 32);
    setProperty("ItlwmAWDLSyncProbeStage", "snapshot-copied");
    setProperty("ItlwmAWDLRequestedTimingPresent", snapshot->hasRequestedTiming);
    setProperty("ItlwmAWDLRequestedAWLength", snapshot->parameters.availability_window_length, 32);
    setProperty("ItlwmAWDLRequestedAWPeriod", snapshot->parameters.availability_window_period, 32);
    // Reject contradictory native channel-sequence TLVs rather than claiming
    // the native requested sequence was applied to this fixed-channel test.
    bool valid = true;
    for (size_t off = 0; off < snapshot->templateLength;) {
        if (snapshot->templateLength-off < 3) { valid = false; break; }
        const size_t count = ItlAWDL::read16(snapshot->staticTLVs+off+1);
        if (count > snapshot->templateLength-off-3 || (!isMI && snapshot->staticTLVs[off] == 18)) {
            valid = false; break;
        }
        off += 3+count;
    }
    // After the check above, which still refuses a native channel-sequence TLV.
    uint8_t execSlots[16];
    bool exec = itlAWDLExecPlan(execSlots);   // the schedule the radio really follows
    // Slots that can't be encoded fall back to the fixed schedule in both TLVs, never in only one of them.
    for (unsigned i = 0; exec && i < 16; ++i)
        if (!ItlAWDL::fixedScheduleChannel(execSlots[i])) exec = false;
    // our own metric and counter for the driver's election, then its result and clock.
    {
        uint32_t selfMetric = 0, selfCounter = 0;
        if (valid && ItlAWDL::templateSelfElection(snapshot->staticTLVs, snapshot->templateLength, &selfMetric,
                                                   &selfCounter)) {
            itlAWDLSelfMetric = selfMetric;
            itlAWDLSelfCounter = selfCounter;
            itlAWDLSelfKnown = 1;
        }
        uint32_t electionId = 0;
        if (valid && ItlAWDL::templateSelfElectionId(snapshot->staticTLVs, snapshot->templateLength, &electionId)) {
            itlAWDLSelfElectionId = electionId;
            itlAWDLSelfElectionIdKnown = 1;
        }
    }
    ItlAWDL::ElectionAdvert electAdvert{};
    ItlAWDL::Clock electClock = ItlAWDL::ownClock();
    const bool elect = itlAWDLClockState(&electAdvert, &electClock);
    if (valid && !isMI && awdlExtendFrames &&
        !ItlAWDL::extendWithPeerTLVs(snapshot->staticTLVs, &snapshot->templateLength,
                                     sizeof(snapshot->staticTLVs), snapshot->address, uint8_t(itlAWDLFixedChannel()),
                                     uint8_t(itlAWDLChannelClass()), itlAWDLTwoStreams(), exec ? execSlots : nullptr,
                                     elect ? &electAdvert : nullptr))
    {
        setProperty("ItlwmAWDLPeerTLVs", "not-added");
        ++awdlSyncPeerTLVsRefused;
    }
    uint8_t sync[73]; size_t syncLength = 0;
    const uint8_t fixedChannel = uint8_t(itlAWDLFixedChannel());
    ItlAWDL::SyncPrefix settings = {fixedChannel,fixedChannel,0,0,16,110,0x1000,16,16,0,3,3,3,3,{}};
    memcpy(settings.master, elect ? electAdvert.master : snapshot->address, 6);
    // the elected clock (the master's, or our own epoch-0 clock as before).
    uint64_t clockEpochUS = 0;
    uint16_t clockInitialAW = 0;
    if (elect)
        ItlAWDL::clockEpoch(electClock, nowUS, &clockEpochUS, &clockInitialAW);
    const auto schedule = ItlAWDL::buildLocalFixedSchedule(settings, clockEpochUS, nowUS, clockInitialAW,
        sync, sizeof(sync), &syncLength, exec ? execSlots : nullptr);
    mbuf_t result = nullptr;
    // Each way a frame can fail has its own stage and return code, so one snapshot shows which.
    IOReturn error = kIOReturnBadArgument;
    const char *stage = "frame-rejected";
    if (!valid)
        stage = "template-invalid";
    else if (schedule != ItlAWDL::BuildResult::Ready) {
        stage = "schedule-rejected";
        error = kIOReturnUnsupported;
    }
    if (valid && schedule == ItlAWDL::BuildResult::Ready) {
        // A fresh getcluster allocation uses a plain mbuf without M_PKTHDR.
        // The packet allocator supplies both the header and 2 KB cluster.
        if (mbuf_getpacket(MBUF_DONTWAIT, &result) || !result) {
            error = kIOReturnNoMemory;
            stage = "no-memory";
        } else {
            error = kIOReturnError;
            ItlAWDL::LocalFrame frame = {{},{255,255,255,255,255,255},uint8_t(isPSF ? 0 : 3),uint16_t(awdlProbeSequence & 4095),
                uint32_t(nowUS),uint32_t(nowUS),sync,syncLength,
                snapshot->staticTLVs,snapshot->templateLength};
            memcpy(frame.source, snapshot->address, 6);
            if (isUMI)
                memcpy(frame.receiver, umiPeer, 6);
            size_t length = 0;
            if (ItlAWDL::buildLocalFrame(frame, static_cast<uint8_t *>(mbuf_data(result)),
                    mbuf_maxlen(result), &length) == ItlAWDL::BuildResult::Ready) {
                mbuf_setlen(result,length); mbuf_pkthdr_setlen(result,length);
                *packet = result; error = kIOReturnSuccess;
                // A unicast MI doesn't take a turn of the MI/PSF alternation (its sequence number is still new).
                awdlProbeSequence = uint16_t((awdlProbeSequence + (isUMI ? 2 : 1)) & 4095);
                if (isUMI)
                    interface->noteUnicastMISent();
                setProperty("ItlwmAWDLSyncProbeFrameLength", length, 32);
            } else mbuf_freem(result);
        }
    }
    IODelete(snapshot, ItlAWDLInterface::FrameConfiguration, 1);
    // A failed frame still moves the sequence on, so a failing MI doesn't hold the alternation on itself.
    if (error != kIOReturnSuccess)
        awdlProbeSequence = uint16_t((awdlProbeSequence + 1) & 4095);
    setProperty("ItlwmAWDLSyncProbeStage", error == kIOReturnSuccess ? "frame-built" : stage);
    itlAWDLLastBuildMI = error == kIOReturnSuccess && isMI && !isUMI;
    if (error == kIOReturnSuccess)
        ++(isMI ? awdlSyncMIBuilt : isPSF ? awdlSyncPSFBuilt : awdlSyncFallbackBuilt);
    else
        ++awdlSyncFailed;
    const uint32_t syncTotal = awdlSyncMIBuilt + awdlSyncPSFBuilt + awdlSyncFallbackBuilt + awdlSyncFailed;
    if (syncTotal <= 4 || !(syncTotal % 16)) {
        setProperty("ItlwmAWDLSyncMIBuilt", awdlSyncMIBuilt, 32);
        setProperty("ItlwmAWDLSyncPSFBuilt", awdlSyncPSFBuilt, 32);
        setProperty("ItlwmAWDLSyncFallbackBuilt", awdlSyncFallbackBuilt, 32);
        setProperty("ItlwmAWDLSyncMIWanted", awdlSyncMIWanted, 32);
        setProperty("ItlwmAWDLSyncMIMissing", awdlSyncMIMissing, 32);
        setProperty("ItlwmAWDLSyncPeerTLVsRefused", awdlSyncPeerTLVsRefused, 32);
        setProperty("ItlwmAWDLSyncFailed", awdlSyncFailed, 32);
    }
    return error;
#else
    return kIOReturnUnsupported;
#endif
}

#if defined(ITL_AWDL_NATIVE)
// Under the shared gate. The caller's sender consumes the packet.
IOReturn itlAWDLBuildTransmit(IOEthernetController *owner, mbuf_t *packet)
{
    auto *controller = OSDynamicCast(AirportItlwm, owner);
    return controller ? controller->buildAWDLTransmit(packet) : kIOReturnNotReady;
}

IOReturn itlAWDLBuildTransmit(IOEthernetController *owner, mbuf_t *packet, const uint8_t *holdPayloadFor)
{
    auto *controller = OSDynamicCast(AirportItlwm, owner);
    return controller ? controller->buildAWDLTransmit(packet, holdPayloadFor) : kIOReturnNotReady;
}

IOReturn itlAWDLBuildTransmit(IOEthernetController *owner, mbuf_t *packet, const uint8_t *holdPayloadFor,
                              bool holdEverySize)
{
    auto *controller = OSDynamicCast(AirportItlwm, owner);
    return controller ? controller->buildAWDLTransmit(packet, holdPayloadFor, holdEverySize) : kIOReturnNotReady;
}

// -itlschedsecond: as above, and while the listener is on a second channel only `pass`'s peers' unicast data goes.
IOReturn itlAWDLBuildTransmit(IOEthernetController *owner, mbuf_t *packet, const uint8_t *holdPayloadFor,
                              bool holdEverySize, const ItlAWDL::TxPassList *pass)
{
    auto *controller = OSDynamicCast(AirportItlwm, owner);
    return controller ? controller->buildAWDLTransmit(packet, holdPayloadFor, holdEverySize, pass) : kIOReturnNotReady;
}

unsigned itlAWDLTransmitHeldShort(IOEthernetController *owner)
{
    auto *controller = OSDynamicCast(AirportItlwm, owner);
    return controller ? controller->heldShortAWDLTransmit() : 0;
}

unsigned itlAWDLTransmitQueued(IOEthernetController *owner)
{
    auto *controller = OSDynamicCast(AirportItlwm, owner);
    return controller ? controller->queuedAWDLTransmit() : 0;
}

bool itlAWDLServiceTransmit(IOEthernetController *owner)
{
    auto *controller = OSDynamicCast(AirportItlwm, owner);
    return controller && controller->serviceAWDLTransmit();
}

IOReturn AirportItlwm::buildAWDLTransmit(mbuf_t *packet, const uint8_t *holdPayloadFor, bool holdEverySize,
                                         const ItlAWDL::TxPassList *pass)
{
    if (!packet || *packet || !_fWorkloop || !_fWorkloop->inGate() || !awdlManagementInputEnabled || !fAWDLInterface)
        return kIOReturnNotReady;
    mbuf_t result = nullptr;
    if (mbuf_getpacket(MBUF_DONTWAIT, &result) || !result)
        return kIOReturnNoMemory;
    size_t length = 0;
    auto *interface = static_cast<ItlAWDLInterface *>(fAWDLInterface);
    interface->retain();
    const bool ready = interface->popTransmit(static_cast<uint8_t *>(mbuf_data(result)), mbuf_maxlen(result), &length, holdPayloadFor,
                                                 holdEverySize, pass);
    interface->release();
    if (!ready) {
        mbuf_freem(result);
        return kIOReturnNotFound;
    }
    mbuf_setlen(result, length);
    mbuf_pkthdr_setlen(result, length);
    *packet = result;
    return kIOReturnSuccess;
}

IOReturn itlAWDLBuildTransmitFor(IOEthernetController *owner, mbuf_t *packet, const uint8_t *destination,
                                 size_t maxLength)
{
    auto *controller = OSDynamicCast(AirportItlwm, owner);
    return controller ? controller->buildAWDLTransmitFor(packet, destination, maxLength) : kIOReturnNotReady;
}

IOReturn AirportItlwm::buildAWDLTransmitFor(mbuf_t *packet, const uint8_t *destination, size_t maxLength)
{
    if (!packet || *packet || !destination || !_fWorkloop || !_fWorkloop->inGate() || !awdlManagementInputEnabled ||
        !fAWDLInterface)
        return kIOReturnNotReady;
    mbuf_t result = nullptr;
    if (mbuf_getpacket(MBUF_DONTWAIT, &result) || !result)
        return kIOReturnNoMemory;
    size_t length = 0;
    auto *interface = static_cast<ItlAWDLInterface *>(fAWDLInterface);
    interface->retain();
    const bool ready = interface->popTransmitFor(static_cast<uint8_t *>(mbuf_data(result)), mbuf_maxlen(result), &length,
                                                 destination, maxLength);
    interface->release();
    if (!ready) {
        mbuf_freem(result);
        return kIOReturnNotFound;
    }
    mbuf_setlen(result, length);
    mbuf_pkthdr_setlen(result, length);
    *packet = result;
    return kIOReturnSuccess;
}

// How many frames macOS has queued on awdl0 that the driver hasn't taken yet, for diagnostics only.
unsigned AirportItlwm::queuedAWDLTransmit()
{
    if (!_fWorkloop || !_fWorkloop->inGate() || !awdlManagementInputEnabled || !fAWDLInterface)
        return 0;
    return static_cast<ItlAWDLInterface *>(fAWDLInterface)->queuedTransmit();
}

unsigned AirportItlwm::heldShortAWDLTransmit()
{
    if (!_fWorkloop || !_fWorkloop->inGate() || !awdlManagementInputEnabled || !fAWDLInterface)
        return 0;
    return static_cast<ItlAWDLInterface *>(fAWDLInterface)->heldShortTransmit();
}

bool AirportItlwm::serviceAWDLTransmit()
{
    if (!_fWorkloop || !_fWorkloop->inGate() || !awdlManagementInputEnabled || !fAWDLInterface)
        return false;
    auto *interface = static_cast<ItlAWDLInterface *>(fAWDLInterface);
    interface->retain();
    const bool pending = interface->serviceTransmit();
    interface->release();
    return pending;
}

IOReturn itlAWDLBuildSyncProbe(IOEthernetController *owner, mbuf_t *packet, uint64_t nowUS)
{
    auto *controller = OSDynamicCast(AirportItlwm, owner);
    return controller ? controller->buildAWDLSyncProbe(packet, nowUS) : kIOReturnNotReady;
}
#endif

void AirportItlwm::teardownAWDLInterface()
{
    if (fAWDLInterface) {
        // terminate() needs the live native controller context and invokes our
        // stop() while dismantling the published service. Do not stop it first.
        detachVirtualInterface(fAWDLInterface, true);
#if defined(ITL_AWDL_NATIVE)
        fAWDLInterface->release();
#endif
        fAWDLInterface = nullptr;
    }
}

void AirportItlwm::releaseAll()
{
    // First, while the command gate the power calls use still exists.
    unregistPM();
    // The watchdog uses the HAL and the gate, both released below.
    if (itlAwStartTimer) {
        itlAwStartTimer->cancelTimeout();
        if (fWatchdogWorkLoop)
            fWatchdogWorkLoop->removeEventSource(itlAwStartTimer);
        OSSafeReleaseNULL(itlAwStartTimer);
    }
    if (watchdogTimer) {
        watchdogTimer->cancelTimeout();
        if (fWatchdogWorkLoop)
            fWatchdogWorkLoop->removeEventSource(watchdogTimer);
        watchdogTimer->release();
        watchdogTimer = NULL;
    }
    OSSafeReleaseNULL(fWatchdogWorkLoop);
    teardownAWDLInterface();
#ifdef AIRPORT_WCL
    if (fNetIf)
        static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->stopWCL();
    OSSafeReleaseNULL(driverFaultReporter);
    OSSafeReleaseNULL(driverCoreFaultReporter);
    OSSafeReleaseNULL(driverFaultStream);
    OSSafeReleaseNULL(driverLogger);
    // Stop only successfully started pipes, while their owner workloop exists.
    if (driverSnapshotsPipeStarted) {
        driverSnapshotsPipe->CCPipe::stopPipe();
        driverSnapshotsPipeStarted = false;
    }
    if (driverDataPathPipeStarted) {
        driverDataPathPipe->CCPipe::stopPipe();
        driverDataPathPipeStarted = false;
    }
    if (driverLogPipeStarted) {
        driverLogPipe->CCPipe::stopPipe();
        driverLogPipeStarted = false;
    }
#endif
    OSSafeReleaseNULL(driverLogPipe);
    OSSafeReleaseNULL(driverDataPathPipe);
    OSSafeReleaseNULL(driverSnapshotsPipe);
#ifndef AIRPORT_WCL
    OSSafeReleaseNULL(driverFaultReporter);
#endif
    // After detach (stop, failStart): drop the HAL's references to this controller, its work loop and
    // gate, which otherwise kept the controller alive through the wrapper's HAL (audit P-R02).
    if (fHalService) {
        fHalService->shutdown();
        fHalService->release();
        fHalService = NULL;
    }
    if (_fWorkloop) {
        if (_fCommandGate) {
//            _fCommandGate->disable();
            _fWorkloop->removeEventSource(_fCommandGate);
            _fCommandGate->release();
            _fCommandGate = NULL;
        }
        if (scanSource) {
            scanSource->cancelTimeout();
            scanSource->disable();
            _fWorkloop->removeEventSource(scanSource);
            scanSource->release();
            scanSource = NULL;
        }
        _fWorkloop->release();
        _fWorkloop = NULL;
    }
}

void AirportItlwm::
eventHandler(struct ieee80211com *ic, int msgCode, void *data)
{
    AirportItlwm *that = OSDynamicCast(AirportItlwm, ic->ic_ac.ac_if.controller);
    // In every build: the non-WCL (Sonoma) body used that without a check (audit D04).
    if (!that)
        return;
    IO80211SkywalkInterface *interface = that->fNetIf;
    if (!interface)
        return;
#ifdef AIRPORT_WCL
    static_cast<AirportItlwmSkywalkInterface *>(interface)->handleWCLEvent(msgCode, data);
#else
    switch (msgCode) {
        case IEEE80211_EVT_COUNTRY_CODE_UPDATE:
            interface->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED, NULL, 0, 0);
            break;
        case IEEE80211_EVT_STA_ASSOC_DONE:
            interface->postMessage(APPLE80211_M_ASSOC_DONE, NULL, 0, 0);
            break;
        case IEEE80211_EVT_STA_DEAUTH:
            interface->postMessage(APPLE80211_M_DEAUTH_RECEIVED, NULL, 0, 0);
            break;
        default:
            break;
    }
#endif
}

// see itlAwdlStatsState.
static void itlReportAWDLData(AirportItlwm *self)
{
    if (!itlAwdlStatsState) {
        itlAwdlStatsState = itlResFlag("-itlawdlstats", 0x1) && kItlAwdlPmRxOff ? 2 : 1;
    }
    uint32_t rx = 0, tx = 0;
    // Supported-builds audit: these offsets were checked on the verified kernel + macOS pairs. Like the master
    // indication copy, this runs there, and with -itlawdlanybuild on any other build (itlAWDLBuildForced).
    if (itlAwdlStatsState != 2 || !self || !self->fAWDLInterface || !(itlAWDLBuildVerified() || itlAWDLBuildForced()) ||
        !itlAWDLDataCounts(&rx, &tx))
        return;
    ++itlAwdlStatsCalls;
    const uint32_t rxDelta = itlAwdlStatsPrimed && rx >= itlAwdlStatsLastRx ? rx - itlAwdlStatsLastRx : 0;
    const uint32_t txDelta = itlAwdlStatsPrimed && tx >= itlAwdlStatsLastTx ? tx - itlAwdlStatsLastTx : 0;
    itlAwdlStatsPrimed = true;
    itlAwdlStatsLastRx = rx;
    itlAwdlStatsLastTx = tx;
    if (!rxDelta && !txDelta)
        return;
    // The peer manager through macOS's own accessor, and only if it is one: its vtable must be
    // IO80211AWDLPeerManager's (address point = symbol + two words). Anything else turns the counters off for good.
    auto *pm = static_cast<uint8_t *>(itlSkywalkGetPeerManager(static_cast<IO80211SkywalkInterface *>(
        static_cast<ItlAWDLInterface *>(self->fAWDLInterface))));
    if (!pm) {
        ++itlAwdlStatsNoPath;
        return;
    }
    if (reinterpret_cast<uintptr_t>(pm) < 0xffffff8000000000ULL ||
        *reinterpret_cast<const uintptr_t *>(pm) != reinterpret_cast<uintptr_t>(itlNativeAWDLPeerManagerVtable + 2)) {
        ++itlAwdlStatsWrongPm;
        itlAwdlStatsState = 1;
        self->setProperty("ITLAWDLDataStats", "off: getPeerManager() didn't return an IO80211AWDLPeerManager");
        return;
    }
    uint8_t *state = *reinterpret_cast<uint8_t **>(pm + 0x18);
    if (reinterpret_cast<uintptr_t>(state) < 0xffffff8000000000ULL) {
        ++itlAwdlStatsNoPath;
        return;
    }
    if (rxDelta) {
        __atomic_fetch_add(reinterpret_cast<uint32_t *>(state + kItlAwdlPmRxOff), rxDelta, __ATOMIC_RELAXED);
        itlAwdlStatsAdded += rxDelta;
    }
    if (txDelta) {
        __atomic_fetch_add(reinterpret_cast<uint32_t *>(state + kItlAwdlPmTxOff), txDelta, __ATOMIC_RELAXED);
        itlAwdlStatsAddedTx += txDelta;
    }
}

// see itlAwStartState.
static void itlAwStartFire(OSObject *owner, IOTimerEventSource *sender)
{
    auto self = OSDynamicCast(AirportItlwm, owner);
    if (!self || !sender)
        return;
    uint8_t ev[36];
    uint64_t next = 100000;
    if ((itlAwStartPosted + itlAwStartIdle) % 4 == 0)
        itlReportAWDLData(self);   // about 4 per second
    // close the AW that just ended before opening the next one, as the chip does.
    uint8_t end[40];
    if (self->fAWDLInterface && itlAWDLAwEnd(end, sizeof(end)))
        static_cast<ItlAWDLInterface *>(self->fAWDLInterface)->postMessage(APPLE80211_M_AWDL_AVAILABILITY_WINDOW_END, end,
                                                                          sizeof(end), false);
    if (self->fAWDLInterface && itlAWDLAwStart(ev, &next)) {
        static_cast<ItlAWDLInterface *>(self->fAWDLInterface)->postMessage(APPLE80211_M_AWDL_AVAILABILITY_WINDOW_START, ev,
                                                                          sizeof(ev), false);
        ++itlAwStartPosted;
    } else {
        ++itlAwStartIdle;
    }
    if (next < 2000)
        next = 2000;
    if (next > 200000)
        next = 200000;
    sender->setTimeoutUS(uint32_t(next));
}

// see itlInfraStatsState. Runs from the 1 s watchdog, in the gate.
void AirportItlwm::reportInfraTraffic()
{
    if (!itlInfraStatsState) {
        itlInfraStatsState = itlResFlag("-itlinfrastats", 0x1) ? 2 : 1;
    }
    if (itlInfraStatsState != 2 || !fNetIf || !bsdInterface || !fHalService)
        return;
    ifnet_t bsd = bsdInterface->getIfnet();
    struct ifnet_stats_param st;
    memset(&st, 0, sizeof(st));
    if (!bsd || ifnet_stat(bsd, &st) != 0) {
        ++itlInfraStatFails;
        return;
    }
    auto delta = [](uint64_t now, uint64_t &last) -> int {
        const uint64_t d = now >= last ? now - last : 0;   // a reset counter gives 0 once
        last = now;
        return d > 0x7fffffffULL ? 0x7fffffff : int(d);
    };
    const int allIn = delta(st.packets_in, itlInfraLastPkIn), allByIn = delta(st.bytes_in, itlInfraLastByIn);
    const int allOut = delta(st.packets_out, itlInfraLastPkOut), allByOut = delta(st.bytes_out, itlInfraLastByOut);
    const int mcIn = delta(st.multicasts_in, itlInfraLastMcIn), mcOut = delta(st.multicasts_out, itlInfraLastMcOut);
    if (!itlInfraStatsPrimed) {   // the first read only sets the baseline
        itlInfraStatsPrimed = true;
        return;
    }
    // unicast packets, and bytes in proportion (64-bit, no overflow for int inputs).
    const int pkIn = allIn > mcIn ? allIn - mcIn : 0, pkOut = allOut > mcOut ? allOut - mcOut : 0;
    const int byIn = allIn > 0 ? int((int64_t)allByIn * pkIn / allIn) : 0;
    const int byOut = allOut > 0 ? int((int64_t)allByOut * pkOut / allOut) : 0;
    itlInfraSumMcIn += mcIn;
    itlInfraSumMcOut += mcOut;
    auto netif = static_cast<IO80211SkywalkInterface *>(fNetIf);
    if (fHalService->get80211Controller()->ic_state == IEEE80211_S_RUN) {
        if (pkIn > 0)
            itlRecordInputPacket(netif, pkIn, byIn);
        if (pkOut > 0)
            itlRecordOutputPacket(netif, 0 /* APPLE80211_WME_AC_BE */, pkOut, byOut);
        itlInfraSumPkIn += pkIn;
        itlInfraSumByIn += byIn;
        itlInfraSumPkOut += pkOut;
        itlInfraSumByOut += byOut;
    }
    if (++itlInfraTicks % 5 == 0) {
        char s[220];
        snprintf(s, sizeof(s), "ticks %u fails %u; reported (unicast) in %llu pkts %llu bytes, out %llu pkts %llu bytes; "
                 "left out multicast/broadcast in %llu out %llu",
                 itlInfraTicks, itlInfraStatFails, (unsigned long long)itlInfraSumPkIn,
                 (unsigned long long)itlInfraSumByIn, (unsigned long long)itlInfraSumPkOut,
                 (unsigned long long)itlInfraSumByOut, (unsigned long long)itlInfraSumMcIn,
                 (unsigned long long)itlInfraSumMcOut);
        setProperty("ITLInfraStats", s);
    }
}

// ItlwmRxErrors: why received frames were dropped, so a report of en0 input errors (netstat -i)
// can tell decryption, replay, Block Ack reordering and association problems apart (#69).
// Every 5 s, only when something changed.
void AirportItlwm::publishRxErrors()
{
    if (++rxErrorsTick % 5)
        return;
    struct ieee80211com *ic = fHalService->get80211Controller();
    const struct ieee80211_stats &s = ic->ic_stats;
    const uint32_t inputErrors = ic->ic_ac.ac_if.netStat ? ic->ic_ac.ac_if.netStat->inputErrors : 0;
    const uint32_t sum = inputErrors + s.is_ccmp_hw_notccm + s.is_ccmp_hw_micfail + s.is_ccmp_replays +
        s.is_ccmp_decap_fail + s.is_rx_wepfail + s.is_rx_unencrypted + s.is_rx_unauth + s.is_rx_wrongbss +
        s.is_rx_notassoc + s.is_rx_tooshort + s.is_ht_rx_ba_winmiss + s.is_ht_rx_ba_dup +
        s.is_ht_rx_frame_below_ba_winstart + s.is_ht_rx_ba_unauth + s.is_ht_rx_ba_agreements;
    if (rxErrorsPublished && sum == rxErrorsLastSum)
        return;
    rxErrorsPublished = true;
    rxErrorsLastSum = sum;
    char text[480];
    snprintf(text, sizeof(text),
             "input errors %u; firmware not CCM %u, decrypt/MIC failed %u; CCMP replay %u, no key/ExtIV %u; "
             "software decrypt failed %u; unencrypted %u; port not valid %u; wrong BSS %u; not associated %u; "
             "too short %u; Block Ack window miss %u, duplicate %u, below window %u; "
             "Block Ack agreements %u, before port valid %u",
             inputErrors, s.is_ccmp_hw_notccm, s.is_ccmp_hw_micfail, s.is_ccmp_replays, s.is_ccmp_decap_fail,
             s.is_rx_wepfail, s.is_rx_unencrypted, s.is_rx_unauth, s.is_rx_wrongbss, s.is_rx_notassoc,
             s.is_rx_tooshort, s.is_ht_rx_ba_winmiss, s.is_ht_rx_ba_dup, s.is_ht_rx_frame_below_ba_winstart,
             s.is_ht_rx_ba_agreements, s.is_ht_rx_ba_unauth);
    setProperty("ItlwmRxErrors", text);
}

void AirportItlwm::watchdogAction(IOTimerEventSource *timer)
{
    if (!fHalService)
        return;
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    (*ifp->if_watchdog)(ifp);
    reportInfraTraffic();   // -itlinfrastats only
    itlReportAWDLData(this);   // -itlawdlstats only (also from the AW-start timer)
    if (!itlAwStartState) {   // started once, from the watchdog
        itlAwStartState = itlResFlag("-itlawstart", 0x1) ? 2 : 1;
        if (itlAwStartState == 2 && fWatchdogWorkLoop) {
            itlAwStartTimer = IOTimerEventSource::timerEventSource(this, itlAwStartFire);
            if (itlAwStartTimer && fWatchdogWorkLoop->addEventSource(itlAwStartTimer) == kIOReturnSuccess) {
                itlAwStartTimer->setTimeoutMS(100);
            } else {
                OSSafeReleaseNULL(itlAwStartTimer);
            }
        }
    }
    if (itlAwStartTimer && ++itlAwStartWatch % 5 == 0) {
        char aw[96];
        snprintf(aw, sizeof(aw), "posted %u idle %u", itlAwStartPosted, itlAwStartIdle);
        setProperty("ITLAWDLAwStartPosts", aw);
    }
    if (itlAwdlStatsState == 2 && itlAwStartWatch % 5 == 0) {
        char st[160];
        snprintf(st, sizeof(st), "calls %u; rx seen %u added %u; tx seen %u added %u; no path %u; not a peer manager %u%s",
                 itlAwdlStatsCalls, itlAwdlStatsLastRx, itlAwdlStatsAdded, itlAwdlStatsLastTx, itlAwdlStatsAddedTx,
                 itlAwdlStatsNoPath, itlAwdlStatsWrongPm, itlAWDLBuildVerified() ? "" : " (-itlawdlanybuild)");
        setProperty("ITLAWDLDataStats", st);
    }
    publishRxErrors();
#ifdef AIRPORT_WCL
    // ItlwmWCLTrace (WCL.cpp): once a second, only when something new was recorded.
    {
        static uint32_t traceVersion = UINT32_MAX;
        static char traceText[3072];
        if (itlWCLTraceText(traceText, sizeof(traceText), &traceVersion))
            setProperty("ItlwmWCLTrace", traceText);
    }
#endif
#ifdef AIRPORT_WCL
    if (fNetIf)
        static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->wclPostLinkQuality();
#else
    if (fNetIf)
        static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->postLinkQuality();
#endif

    watchdogTimer->setTimeoutMS(kWatchDogTimerPeriod);
}

void AirportItlwm::fakeScanDone(OSObject *owner, IOTimerEventSource *sender)
{
#ifndef AIRPORT_WCL
    UInt32 msg = 0;
#endif
    AirportItlwm *that = (AirportItlwm *)owner;
#ifdef AIRPORT_WCL
    if (that->fNetIf)
        static_cast<AirportItlwmSkywalkInterface *>(that->fNetIf)->completeWCLScan();
#else
    if (that && that->fNetIf)
        that->fNetIf->postMessage(APPLE80211_M_SCAN_DONE, &msg, 4, 0);
#endif
}

extern bool itlAWDLBuildAllowed();
extern const char *itlAWDLBuildStatus();

bool AirportItlwm::init(OSDictionary *properties)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    bool ret = super::init(properties);
    awdlSyncEnable = true;
    fAWDLInterface = nullptr;
    int awdlBootValue = 0;
    // AirDrop only starts on a macOS build whose Wi-Fi stack was verified (AWDLBuildGuard.cpp).
    awdlInterfaceTest = itlAWDLBuildAllowed() && itlAWDLFlag("-itlawdliface");
    setProperty("ItlwmAWDLBuildCheck", itlAWDLBuildStatus());
    // From 0.7.0-alpha.2: whether the tested set is on without its flags (check_compat.sh reads this).
    setProperty("ItlwmAWDLDefaults", itlAWDLDefaults() ? "on: the tested set needs no Wi-Fi flags" :
                "off (-itlawdlnodefaults): only the flags that are set count");
    awdlRawSamples = PE_parse_boot_argn("-itlawdlsamples", &awdlBootValue, sizeof(awdlBootValue));
    awdlExtendFrames = itlAWDLFlag("-itlawdlelicit");
    awdlCreateRequests = 0;
    awdlManagementInputEnabled = false;
    awdlManagementActive = 0;
    setProperty("ItlwmAWDLInterfaceBuild", ITL_FORBIDDEN_BUILD);
    setProperty("ItlwmAWDLInterfaceTestEnabled", awdlInterfaceTest ? kOSBooleanTrue : kOSBooleanFalse);
    OSNumber *requests = OSNumber::withNumber(static_cast<UInt64>(0), 64);
    if (requests) {
        setProperty("ItlwmAWDLCreateRequests", requests);
        requests->release();
    }
    power_state = 0;
    memset(geo_location_cc, 0, sizeof(geo_location_cc));
    return ret;
}

IOService* AirportItlwm::probe(IOService *provider, SInt32 *score)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    IOPCIEDeviceWrapper *wrapper = OSDynamicCast(IOPCIEDeviceWrapper, provider);
    if (!wrapper) {
        XYLog("%s Not a IOPCIEDeviceWrapper instance\n", __FUNCTION__);
        return NULL;
    }
    pciNub = wrapper->pciNub;
    // The wrapper keeps its own reference; this one is ours, released in releaseAll or free.
    ItlHalService *hal = wrapper->halForStart();
    if (fHalService != hal) {
        OSSafeReleaseNULL(fHalService);
        fHalService = hal;
        if (fHalService)
            fHalService->retain();
    }
    if (!pciNub || !fHalService) {
        XYLog("%s Not a valid IOPCIEDeviceWrapper instance\n", __FUNCTION__);
        return NULL;
    }
    return super::probe(provider, score);
}

#define LOWER32(x)  ((uint64_t)(x) & 0xffffffff)
#define HIGHER32(x) ((uint64_t)(x) >> 32)

bool AirportItlwm::
initCCLogs()
{
    CCPipeOptions driverLogOptions = { 0 };
    driverLogOptions.pipe_type = 0;
    driverLogOptions.log_data_type = 1;
    driverLogOptions.pipe_size = 0x200000;
    driverLogOptions.min_log_size_notify = 0xccccc;
    driverLogOptions.notify_threshold = 1000;
    strlcpy(driverLogOptions.file_name, "Itlwm_Logs", sizeof(driverLogOptions.file_name));
    snprintf(driverLogOptions.name, sizeof(driverLogOptions.name), "wlan%d", 0);
    strlcpy(driverLogOptions.directory_name, "WiFi", sizeof(driverLogOptions.directory_name));
    driverLogOptions.pad9 = 0x1000000;
    driverLogOptions.pad10 = 2;
    driverLogOptions.file_options = 0;
    driverLogOptions.log_policy = 0;
    driverLogPipe = CCPipe::withOwnerNameCapacity(this, "com.zxystd.AirportItlwm", "DriverLogs", &driverLogOptions);
    XYLog("%s driverLogPipeRet %d\n", __FUNCTION__, driverLogPipe != NULL);
#ifdef AIRPORT_WCL
    if (!driverLogPipe || !getWorkLoop())
        return false;
    // The factory only initializes the pipe. startPipe creates its event sources.
    // Qualify the native method: do not dispatch through the legacy CCPipe header.
    driverLogPipeStarted = driverLogPipe->CCPipe::startPipe();
    if (!driverLogPipeStarted)
        return false;
    CCStreamOptions loggerOptions = {};
    CCStream *logger = CCStream::withPipeAndName(driverLogPipe, "AirportItlwm", &loggerOptions);
    driverLogger = OSDynamicCast(CCLogStream, logger);
    if (!driverLogger) {
        OSSafeReleaseNULL(logger);
        return false;
    }
#endif

    memset(&driverLogOptions, 0, sizeof(driverLogOptions));
    driverLogOptions.pipe_type = 0;
    driverLogOptions.log_data_type = 0;
    driverLogOptions.pipe_size = 0x200000;
    driverLogOptions.min_log_size_notify = 0xccccc;
    driverLogOptions.notify_threshold = 1000;
    strlcpy(driverLogOptions.file_name, "AppleBCMWLAN_Datapath", sizeof(driverLogOptions.file_name));
    strlcpy(driverLogOptions.directory_name, "WiFi", sizeof(driverLogOptions.directory_name));
    driverLogOptions.pad9 = HIGHER32(0x202800000);
    driverLogOptions.pad10 = LOWER32(0x202800000);
    driverLogOptions.file_options = 0;
    driverLogOptions.log_policy = 0;
    driverDataPathPipe = CCPipe::withOwnerNameCapacity(this, "com.zxystd.AirportItlwm", "DatapathEvents", &driverLogOptions);
    XYLog("%s driverDataPathPipeRet %d\n", __FUNCTION__, driverDataPathPipe != NULL);
#ifdef AIRPORT_WCL
    if (!driverDataPathPipe)
        return false;
    driverDataPathPipeStarted = driverDataPathPipe->CCPipe::startPipe();
    if (!driverDataPathPipeStarted)
        return false;
#endif

    memset(&driverLogOptions, 0, sizeof(driverLogOptions));
    driverLogOptions.pipe_type = 0x200000001;
    driverLogOptions.log_data_type = 2;
    strlcpy(driverLogOptions.file_name, "StateSnapshots", sizeof(driverLogOptions.file_name));
    strlcpy(driverLogOptions.name, "0", sizeof(driverLogOptions.name));
    strlcpy(driverLogOptions.directory_name, "WiFi", sizeof(driverLogOptions.directory_name));
    driverLogOptions.pipe_size = 128;
    driverSnapshotsPipe = CCPipe::withOwnerNameCapacity(this, "com.zxystd.AirportItlwm", "StateSnapshots", &driverLogOptions);
    XYLog("%s driverSnapshotsPipeRet %d\n", __FUNCTION__, driverSnapshotsPipe != NULL);
#ifdef AIRPORT_WCL
    if (!driverSnapshotsPipe)
        return false;
    driverSnapshotsPipeStarted = driverSnapshotsPipe->CCPipe::startPipe();
    if (!driverSnapshotsPipeStarted)
        return false;
#endif

    CCStreamOptions faultReportOptions = { 0 };
    faultReportOptions.stream_type = 1;
    faultReportOptions.console_level = 0xFFFFFFFFFFFFFFFF;
#ifdef AIRPORT_WCL
    driverFaultStream = CCStream::withPipeAndName(driverSnapshotsPipe, "FaultReporter", &faultReportOptions);
    CCDataStream *dataStream = OSDynamicCast(CCDataStream, driverFaultStream);
    if (!dataStream || !_fWorkloop) {
        return false;
    }
    driverCoreFaultReporter = CCFaultReporter::withStreamWorkloop(dataStream, _fWorkloop);
    if (!driverCoreFaultReporter) {
        return false;
    }
    driverFaultReporter = IO80211FaultReporter::allocWithParams(driverCoreFaultReporter);
    if (!OSDynamicCast(CommonFaultReporter, driverFaultReporter)) {
        return false;
    }
#else
    driverFaultReporter = CCStream::withPipeAndName(driverSnapshotsPipe, "FaultReporter", &faultReportOptions);
#endif
    XYLog("%s driverFaultReporterRet %d\n", __FUNCTION__, driverFaultReporter != NULL);
    return driverLogPipe && driverDataPathPipe && driverSnapshotsPipe && driverFaultReporter;
}

#ifdef AIRPORT_WCL
extern void itlMccSetBiosCountry(uint16_t);
// With -itlmccprobe only: record what the laptop's ACPI methods for this Wi-Fi card return.
// Linux reads the country from WRDD as the BIOS source. Nothing here uses the values.
static void itlMccProbeReadBios(IOPCIDevice *pci)
{
    int dummy;
    if (!PE_parse_boot_argn("-itlmccprobe", &dummy, sizeof(dummy)))
        return;
    auto *root = IORegistryEntry::getRegistryRoot();
    auto *acpi = OSDynamicCast(IOACPIPlatformDevice, pci->getProperty("acpi-device"));
    root->setProperty("ITLMCCAcpiDevice", acpi ? "found" : "missing");
    if (!acpi)
        return;
    auto read = [&](const char *method, const char *valueKey, const char *resultKey) {
        OSObject *value = nullptr;
        const IOReturn result = acpi->evaluateObject(method, &value);
        root->setProperty(resultKey, result, 32);
        if (value) {
            root->setProperty(valueKey, value);
            value->release();
        }
    };
    read("_ADR", "ITLMCCAcpiADR", "ITLMCCAcpiADRResult");
    read("WRDD", "ITLMCCAcpiWRDD", "ITLMCCAcpiWRDDResult");
    read("WRDS", "ITLMCCAcpiWRDS", "ITLMCCAcpiWRDSResult");
    // WRDD is (revision, (domain, country)), and domain 7 means Wi-Fi.
    auto *table = OSDynamicCast(OSArray, root->getProperty("ITLMCCAcpiWRDD"));
    auto *entry = table ? OSDynamicCast(OSArray, table->getObject(1)) : nullptr;
    auto *domain = entry ? OSDynamicCast(OSNumber, entry->getObject(0)) : nullptr;
    auto *country = entry ? OSDynamicCast(OSNumber, entry->getObject(1)) : nullptr;
    if (domain && country && domain->unsigned32BitValue() == 7 && country->unsigned32BitValue() <= 0xffff)
        itlMccSetBiosCountry(uint16_t(country->unsigned32BitValue()));
}
#endif

// #14: when start fails, the controller node goes away and the driver's messages (kprintf only) are
// lost. While start runs, they also go to the log ring; a failed start copies them onto the PCI
// device, which stays, as ItlwmStartLog. A successful start removes that property again.
bool AirportItlwm::start(IOService *provider)
{
    const uint32_t mark = itlLogMark();
    itlLogStartup = true;
    const bool started = startDriver(provider);
    itlLogStartup = false;
    if (IOPCIDevice *device = pciNub) {
        if (started) {
            device->removeProperty("ItlwmStartLog");
            device->setProperty("ItlwmStartResult", "started");
        } else {
            if (OSArray *lines = itlLogCopySince(mark)) {
                device->setProperty("ItlwmStartLog", lines);
                lines->release();
            }
            device->setProperty("ItlwmStartResult", "failed");
        }
    }
    return started;
}

// Undoes, in reverse order, what startDriver has done so far (audit P-A07). Before this, each failure
// path undid its own subset: some never called releaseAll() (the CC log pipes and streams stayed), one
// never called super::stop(), and every failure after the HAL attached skipped fHalService->detach(), so
// the HAL kept its interrupt source, timers, task queue and firmware running while releaseAll() dropped
// the controller's own references. The steps are the ones stop() uses; the HAL goes first, so nothing
// interrupts or runs a task while the rest goes.
bool AirportItlwm::failStart(IOService *provider, const StartProgress &progress)
{
    XYLog("start: undoing (super %d, HAL %d, interface %d/%d)\n", progress.superStarted, progress.halAttached,
          progress.netIfAttached, progress.interfaceAttached);
    if (progress.halAttached && fHalService)
        fHalService->detach(pciNub);
    if (fNetIf) {
        if (progress.interfaceAttached)
            detachInterface(fNetIf, true);
        else if (progress.netIfAttached)
            fNetIf->detach(this);
        OSSafeReleaseNULL(fNetIf);
    }
    if (progress.superStarted)
        super::stop(provider);
    releaseAll();
    return false;
}

bool AirportItlwm::startDriver(IOService *provider)
{
    // Each kext is built for one macOS version, whose IO80211 class layouts it depends on.
    // On any other version it doesn't start, rather than risk a kernel panic.
#if __IO80211_TARGET == __MAC_15_2
    if (version_major != 24 || version_minor < 2) {
        IOLog("AirportItlwm: this kext is for macOS Sequoia; not starting on Darwin %d.%d\n", version_major, version_minor);
        return false;
    }
#elif __IO80211_TARGET == __MAC_26_0
    if (version_major != 25) {
        IOLog("AirportItlwm: this kext is for macOS Tahoe; not starting on Darwin %d.%d\n", version_major, version_minor);
        return false;
    }
#elif __IO80211_TARGET == __MAC_14_4
    // Sonoma 14.4 and later (Darwin 23.4+): the IO80211FamilyV2 API changed at 14.4.
    if (version_major != 23 || version_minor < 4) {
        IOLog("AirportItlwm: this kext is for macOS Sonoma 14.4 or later; not starting on Darwin %d.%d\n", version_major, version_minor);
        return false;
    }
#endif
    XYLog("%s\n", __PRETTY_FUNCTION__);
    struct IOSkywalkEthernetInterface::RegistrationInfo registInfo;
    int boot_value = 0;
    StartProgress progress {};

    UInt8 builtIn = 0;
    if (OSData *builtInData = OSData::withBytes(&builtIn, sizeof(builtIn))) {   // released (audit P-A07)
        setProperty("built-in", builtInData);
        builtInData->release();
    }
    setProperty("DriverKitDriver", kOSBooleanFalse);
#ifdef AIRPORT_WCL
    if (!initCCLogs()) {
        XYLog("start: CCLog init fail\n");
        return failStart(provider, progress);
    }
#endif
    if (!super::start(provider)) {
        XYLog("start: IO80211Controller::start fail\n");
        return failStart(provider, progress);
    }
    progress.superStarted = true;
    pciNub->setBusMasterEnable(true);
    pciNub->setIOEnable(true);
    pciNub->setMemoryEnable(true);
    pciNub->configWrite8(0x41, 0);
    if (pciNub->requestPowerDomainState(kIOPMPowerOn,
                                        (IOPowerConnection *) getParentEntry(gIOPowerPlane), IOPMLowestState) != IOPMNoErr) {
        XYLog("start: PCI power domain request fail\n");
        return failStart(provider, progress);
    }
    if (initPCIPowerManagment(pciNub) == false) {
        XYLog("start: PCI power management init fail\n");
        return failStart(provider, progress);
    }
    if (_fWorkloop == NULL) {
        XYLog("No _fWorkloop!!\n");
        return failStart(provider, progress);
    }
    _fCommandGate = IOCommandGate::commandGate(this, (IOCommandGate::Action)AirportItlwm::tsleepHandler);
    if (_fCommandGate == 0) {
        XYLog("No command gate!!\n");
        return failStart(provider, progress);
    }
    _fWorkloop->addEventSource(_fCommandGate);
    const IONetworkMedium *primaryMedium;
    if (!createMediumTables(&primaryMedium) ||
        !setCurrentMedium(primaryMedium) || !setSelectedMedium(primaryMedium)) {
        XYLog("setup medium fail\n");
        return failStart(provider, progress);
    }
    if (!fHalService->initWithController(this, _fWorkloop, _fCommandGate)) {
        XYLog("start: HAL init fail\n");
        return failStart(provider, progress);
    }
    fHalService->get80211Controller()->ic_event_handler = eventHandler;

    if (PE_parse_boot_argn("-novht", &boot_value, sizeof(boot_value)))
        fHalService->get80211Controller()->ic_userflags |= IEEE80211_F_NOVHT;
    if (PE_parse_boot_argn("-noht40", &boot_value, sizeof(boot_value)))
        fHalService->get80211Controller()->ic_userflags |= IEEE80211_F_NOHT40;

#ifdef AIRPORT_WCL
    itlMccProbeReadBios(pciNub);
    int he_enabled = 0;
    if (PE_parse_boot_argn("itlwm_he", &he_enabled, sizeof(he_enabled)) && he_enabled == 1)
        fHalService->get80211Controller()->ic_userflags |= IEEE80211_F_HEON;
    // itlwm_scanout=N (120..480 TU): longer visits off the home channel during full scans while
    // associated, so several passive channels are covered per visit. Out of range or unset: 120.
    {
        extern uint32_t itlScanMaxOutTU;
        uint32_t scanOut = 0;
        if (PE_parse_boot_argn("itlwm_scanout", &scanOut, sizeof(scanOut)) && scanOut >= 120 && scanOut <= 480)
            itlScanMaxOutTU = scanOut;
        setProperty("ItlwmScanMaxOutTU", itlScanMaxOutTU ? itlScanMaxOutTU : 120U, 32);
    }
    // itlwm_lqmint=N (1..60 s): link-quality updates to WCL only on a 3 dB RSSI change or every N s.
    {
        extern uint32_t itlLqmMinIntervalSec;
        uint32_t lqmInterval = 0;
        if (PE_parse_boot_argn("itlwm_lqmint", &lqmInterval, sizeof(lqmInterval)) && lqmInterval >= 1 && lqmInterval <= 60)
            itlLqmMinIntervalSec = lqmInterval;
        setProperty("ItlwmLqmMinIntervalSec", itlLqmMinIntervalSec, 32);
    }
#endif

    if (!fHalService->attach(pciNub)) {
        XYLog("attach fail\n");
        return failStart(provider, progress);
    }
    progress.halAttached = true;
    // The watchdog runs on the main work loop, so its action holds the same gate as the interrupt
    // and request paths. On a separate loop it touched driver and 802.11 state (sc_tx_timer, state
    // changes, link quality) while those ran.
    fWatchdogWorkLoop = _fWorkloop;
    if (fWatchdogWorkLoop)
        fWatchdogWorkLoop->retain();
    if (fWatchdogWorkLoop == NULL) {
        XYLog("init watchdog workloop fail\n");
        return failStart(provider, progress);
    }
    watchdogTimer = IOTimerEventSource::timerEventSource(this, OSMemberFunctionCast(IOTimerEventSource::Action, this, &AirportItlwm::watchdogAction));
    if (!watchdogTimer) {
        XYLog("init watchdog fail\n");
        return failStart(provider, progress);
    }
    fWatchdogWorkLoop->addEventSource(watchdogTimer);
    scanSource = IOTimerEventSource::timerEventSource(this, &fakeScanDone);
#ifdef AIRPORT_WCL
    if (!scanSource || _fWorkloop->addEventSource(scanSource) != kIOReturnSuccess) {
        return failStart(provider, progress);
    }
#else
    _fWorkloop->addEventSource(scanSource);
#endif
    scanSource->enable();

    fNetIf = new AirportItlwmSkywalkInterface;
#ifdef AIRPORT_WCL
    if (!fNetIf || !static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->init(this)) {
#else
    if (!fNetIf || !fNetIf->init(this)) {
#endif
        XYLog("Skywalk interface init fail\n");
        return failStart(provider, progress);
    }
    fNetIf->setInterfaceRole(1);
    fNetIf->setInterfaceId(1);

#ifndef AIRPORT_WCL
    if (!initCCLogs()) {
        XYLog("CCLog init fail\n");
        return failStart(provider, progress);
    }
#endif
    if (!fNetIf->attach(this)) {
        XYLog("attach to service fail\n");
        return failStart(provider, progress);
    }
    progress.netIfAttached = true;
    if (!attachInterface(fNetIf, this)) {
        XYLog("attach to interface fail\n");
        return failStart(provider, progress);
    }
    progress.interfaceAttached = true;
    if (!IONetworkController::attachInterface((IONetworkInterface **)&bsdInterface,
#ifdef AIRPORT_WCL
                                             false
#else
                                             true
#endif
                                             )) {
        XYLog("attach to IONetworkController interface fail\n");
        return failStart(provider, progress);
    }
    memset(&registInfo, 0, sizeof(registInfo));
    if (!fNetIf->initRegistrationInfo(&registInfo, 1, sizeof(registInfo))) {
        XYLog("initRegistrationInfo fail\n");
        return failStart(provider, progress);
    }
#ifdef AIRPORT_WCL
    fNetIf->mExpansionData->fRegistrationInfo = (struct IOSkywalkNetworkInterface::RegistrationInfo *)IOMalloc(sizeof(struct IOSkywalkNetworkInterface::RegistrationInfo));
    fNetIf->mExpansionData2->fRegistrationInfo = (struct IOSkywalkEthernetInterface::RegistrationInfo *)IOMalloc(sizeof(struct IOSkywalkEthernetInterface::RegistrationInfo));
    if (!fNetIf->mExpansionData->fRegistrationInfo || !fNetIf->mExpansionData2->fRegistrationInfo) {
        return failStart(provider, progress);
    }
    memcpy(fNetIf->mExpansionData->fRegistrationInfo, &registInfo, sizeof(registInfo));
    memcpy(fNetIf->mExpansionData2->fRegistrationInfo, &registInfo, sizeof(registInfo));
    if (fNetIf->getInterfaceRole() == 1)
        fNetIf->deferBSDAttach(true);
    if (!fNetIf->start(this)) {
        return failStart(provider, progress);
    }

#else
    if (!fNetIf->initRegistrationInfo(&registInfo, 1, sizeof(registInfo))) {
        XYLog("initRegistrationInfo fail\n");
        return failStart(provider, progress);
    }
    fNetIf->mExpansionData->fRegistrationInfo = (struct IOSkywalkNetworkInterface::RegistrationInfo *)IOMalloc(sizeof(struct IOSkywalkNetworkInterface::RegistrationInfo));
    fNetIf->mExpansionData2->fRegistrationInfo = (struct IOSkywalkEthernetInterface::RegistrationInfo *)IOMalloc(sizeof(struct IOSkywalkEthernetInterface::RegistrationInfo));
    memcpy(fNetIf->mExpansionData->fRegistrationInfo, &registInfo, sizeof(registInfo));
    memcpy(fNetIf->mExpansionData2->fRegistrationInfo, &registInfo, sizeof(registInfo));
    if (fNetIf->getInterfaceRole() == 1)
        fNetIf->deferBSDAttach(true);
    fNetIf->start(this);

#endif
    setLinkStatus(kIONetworkLinkValid);
    if (TAILQ_EMPTY(&fHalService->get80211Controller()->ic_ess))
        fHalService->get80211Controller()->ic_flags |= IEEE80211_F_AUTO_JOIN;
    // The HAL built its rate set at the first firmware load: record the card's streams for -itlawdlcaps.
    setProperty("ItlwmCardStreams", uint32_t(itlAWDLNoteCardStreams(fHalService->get80211Controller())), 32);
#ifdef AIRPORT_WCL
    awdlManagementInputEnabled = true;
    bsdInterface->registerService();
#else
    awdlManagementInputEnabled = true;
#endif
    registerService();
    return true;
}

void AirportItlwm::stop(IOService *provider)
{
#if defined(ITL_AWDL_NATIVE)
    if (_fWorkloop) {
        _fWorkloop->runAction([](OSObject *owner, void*, void*, void*, void*) -> IOReturn {
            auto *controller = static_cast<AirportItlwm *>(owner);
            controller->awdlManagementInputEnabled = false;
            // An active native callback can temporarily release the gate.
            // Track it explicitly; a single empty gated action is not a drain.
            while (controller->awdlManagementActive)
                _fWorkloop->commandSleep(&controller->awdlManagementActive, 0);
            return kIOReturnSuccess;
        }, this, nullptr, nullptr, nullptr, nullptr);
    }
    // Return native queued buffers and stop the AWDL peer manager while its
    // controller and management pool are still live, before super::stop().
    teardownAWDLInterface();
#endif
    XYLog("%s\n", __PRETTY_FUNCTION__);XYLog("%s\n", __PRETTY_FUNCTION__);
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
#ifdef AIRPORT_WCL
    if (fNetIf)
        static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->stopWCL();
#endif
    super::stop(provider);
    disableAdapter(bsdInterface);
    setLinkStatus(kIONetworkLinkValid);
    fHalService->detach(pciNub);
    ether_ifdetach(ifp);
    detachInterface(fNetIf, true);
    OSSafeReleaseNULL(fNetIf);
    releaseAll();
}

void AirportItlwm::free()
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    if (fHalService != NULL) {
        fHalService->release();
        fHalService = NULL;
    }
    if (syncFrameTemplate != NULL && syncFrameTemplateLength > 0) {
        IOFree(syncFrameTemplate, syncFrameTemplateLength);
        syncFrameTemplateLength = 0;
        syncFrameTemplate = NULL;
    }
    if (roamProfile != NULL) {
        IOFree(roamProfile, sizeof(struct apple80211_roam_profile_band_data));
        roamProfile = NULL;
    }
    if (btcProfile != NULL) {
        IOFree(btcProfile, sizeof(struct apple80211_btc_profiles_data));
        btcProfile = NULL;
    }
    super::free();
}

bool AirportItlwm::createWorkQueue()
{
    XYLog("%s %d\n", __FUNCTION__, _fWorkloop != 0);
    return _fWorkloop != 0;
}

#ifdef AIRPORT_WCL
IOWorkLoop *AirportItlwm::getWorkLoop() const
{
    return _fWorkloop;
}
#endif

IO80211WorkQueue *AirportItlwm::getWorkQueue()
#ifdef AIRPORT_WCL
const
#endif
{
    return _fWorkloop;
}

#ifdef AIRPORT_WCL
CommonFaultReporter *AirportItlwm::getFaultReporterFromDriver()
#else
void *AirportItlwm::getFaultReporterFromDriver()
#endif
{
    return driverFaultReporter;
}

IOReturn AirportItlwm::enable(IO80211SkywalkInterface *netif)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    super::enable(netif);
    if (!_fCommandGate)         // audit D05
        return kIOReturnNotReady;
    _fCommandGate->enable();
    if (power_state)
        enableAdapterWhenPowered();
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::disable(IO80211SkywalkInterface *netif)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    super::disable(netif);
    setLinkStatus(kIONetworkLinkValid);
    return kIOReturnSuccess;
}

bool AirportItlwm::configureInterface(IONetworkInterface *netif)
{
    IONetworkData *nd;
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;

    if (super::configureInterface(netif) == false) {
        XYLog("super failed\n");
        return false;
    }

    nd = netif->getParameter(kIONetworkStatsKey);
    if (!nd || !(fpNetStats = (IONetworkStats *)nd->getBuffer())) {
        XYLog("network statistics buffer unavailable?\n");
        return false;
    }
    ifp->netStat = fpNetStats;
    ether_ifattach(ifp, OSDynamicCast(IOEthernetInterface, netif));
    fpNetStats->collisions = 0;
#ifdef __PRIVATE_SPI__
#ifdef AIRPORT_WCL
    if (netif->configureOutputPullModel(fHalService->getDriverInfo()->getTxQueueSize(),
        kIONetworkWorkLoopSynchronous, 0,
        IOEthernetInterface::kOutputPacketSchedulingModelNormal, 0) != kIOReturnSuccess)
        return false;
#else
    netif->configureOutputPullModel(fHalService->getDriverInfo()->getTxQueueSize(), 0, 0, IOEthernetInterface::kOutputPacketSchedulingModelNormal, 0);
#endif
#endif

    return true;
}

IONetworkInterface *AirportItlwm::createInterface()
{
    AirportItlwmEthernetInterface *netif = new AirportItlwmEthernetInterface;
    if (!netif)
        return NULL;
    if (!netif->initWithSkywalkInterfaceAndProvider(this, fNetIf)) {
        netif->release();
        return NULL;
    }
    return netif;
}

bool AirportItlwm::createMediumTables(const IONetworkMedium **primary)
{
    IONetworkMedium    *medium;

    OSDictionary *mediumDict = OSDictionary::withCapacity(2);
    if (mediumDict == NULL) {
        XYLog("Cannot allocate OSDictionary\n");
        return false;
    }

    medium = IONetworkMedium::medium(kIOMediumIEEE80211, 54000000);
    IONetworkMedium::addMedium(mediumDict, medium);
    medium->release();
    if (primary) {
        *primary = medium;
    }
    medium = IONetworkMedium::medium(kIOMediumIEEE80211None, 0);
    IONetworkMedium::addMedium(mediumDict, medium);
    medium->release();

    bool result = publishMediumDictionary(mediumDict);
    if (!result) {
        XYLog("Cannot publish medium dictionary!\n");
    }

    mediumDict->release();
    return result;
}

IOReturn AirportItlwm::selectMedium(const IONetworkMedium *medium) {
    setSelectedMedium(medium);
    return kIOReturnSuccess;
}

bool AirportItlwm::
setLinkStatus(UInt32 status, const IONetworkMedium * activeMedium, UInt64 speed, OSData * data)
{
    struct _ifnet *ifq = &fHalService->get80211Controller()->ic_ac.ac_if;
    if (status == currentStatus) {
        return true;
    }
    bool ret = super::setLinkStatus(status, activeMedium, speed, data);
    currentStatus = status;
    if (fNetIf) {
        if (status & kIONetworkLinkActive) {
#ifdef __PRIVATE_SPI__
            bsdInterface->startOutputThread();
#endif
            getCommandGate()->runAction(setLinkStateGated, (void *)kIO80211NetworkLinkUp, (void *)0);
//            fNetIf->setLinkQualityMetric(100);
        } else if (!(status & kIONetworkLinkNoNetworkChange)) {
#ifdef __PRIVATE_SPI__
            bsdInterface->stopOutputThread();
            bsdInterface->flushOutputQueue();
#endif
            ifq_flush(&ifq->if_snd);
            mq_purge(&fHalService->get80211Controller()->ic_mgtq);
            getCommandGate()->runAction(setLinkStateGated, (void *)kIO80211NetworkLinkDown, (void *)fHalService->get80211Controller()->ic_deauth_reason);
        }
    }
    return ret;
}

IOReturn AirportItlwm::
setLinkStateGated(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3)
{
    AirportItlwm *that = OSDynamicCast(AirportItlwm, target);
#ifdef AIRPORT_WCL
    that->bsdInterface->setLinkState((IO80211LinkState)(uint64_t)arg0);
    static_cast<AirportItlwmSkywalkInterface *>(that->fNetIf)->handleWCLLink(
        (IO80211LinkState)(uint64_t)arg0 == kIO80211NetworkLinkUp);
    return kIOReturnSuccess;
#else
    IOReturn ret = that->fNetIf->setLinkState((IO80211LinkState)(uint64_t)arg0, (unsigned int)(uint64_t)arg1);
    that->fNetIf->setRunningState((IO80211LinkState)(uint64_t)arg0 == kIO80211NetworkLinkUp);
    that->fNetIf->postMessage(APPLE80211_M_LINK_CHANGED, NULL, 0, false);
    that->fNetIf->postMessage(APPLE80211_M_BSSID_CHANGED, NULL, 0, false);
    that->fNetIf->postMessage(APPLE80211_M_SSID_CHANGED, NULL, 0, false);
    if ((IO80211LinkState)(uint64_t)arg0 == kIO80211NetworkLinkUp) {
        that->fNetIf->reportLinkStatus(3, 0x80);
    } else {
        that->fNetIf->reportLinkStatus(1, 0);
    }
    that->bsdInterface->setLinkState((IO80211LinkState)(uint64_t)arg0);
    return ret;
#endif
}

#ifdef __PRIVATE_SPI__
IOReturn AirportItlwm::outputStart(IONetworkInterface *interface, IOOptionBits options)
{
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;
    mbuf_t m = NULL;
#ifdef AIRPORT_WCL
    if (!ifp->if_snd.queue)
        return kIOReturnNoResources;
    if (!ifq_empty(&ifp->if_snd))
        (*ifp->if_start)(ifp);
    const uint32_t capacity = ifp->if_snd.queue->getCapacity();
    const uint32_t queued = ifq_len(&ifp->if_snd);
    if (ifq_is_oactive(&ifp->if_snd) || queued >= capacity)
        return kIOReturnNoResources;
    const uint32_t count = MIN(32U, capacity - queued);
    if (interface->dequeueOutputPackets(count, &m) != kIOReturnSuccess || !m)
        return kIOReturnSuccess;
    while (m) {
        mbuf_t next = mbuf_nextpkt(m);
        mbuf_setnextpkt(m, NULL);
        enqueuePacket(m);
        m = next;
    }
    (*ifp->if_start)(ifp);
    if (ifq_is_oactive(&ifp->if_snd))
        return kIOReturnNoResources;
    return kIOReturnSuccess;
#else
    if (ifq_is_oactive(&ifp->if_snd))
        return kIOReturnNoResources;
    while (kIOReturnSuccess == interface->dequeueOutputPackets(1, &m)) {
        if (outputPacket(m, NULL)!= kIOReturnOutputSuccess ||
            ifq_is_oactive(&ifp->if_snd))
            return kIOReturnNoResources;
    }
    return kIOReturnSuccess;
#endif
}

IOReturn AirportItlwm::networkInterfaceNotification(
                    IONetworkInterface * interface,
                    uint32_t              type,
                    void *                  argument )
{
    XYLog("%s\n", __FUNCTION__);
    return kIOReturnSuccess;
}
#endif

extern const char* hexdump(uint8_t *buf, size_t len);

#ifdef AIRPORT_WCL
UInt32 AirportItlwm::outputPacket(mbuf_t m, void *param)
{
    IOReturn status = _fCommandGate ? _fCommandGate->runAction(outputPacketGated, m) : kIOReturnNotReady;
    if (status != kIOReturnOutputSuccess && status != kIOReturnOutputDropped) {
        if (m && mbuf_type(m) != MBUF_TYPE_FREE)
            freePacket(m);
        return kIOReturnOutputDropped;
    }
    return status;
}

IOReturn AirportItlwm::outputPacketGated(OSObject *owner, void *arg0, void *, void *, void *)
{
    auto self = static_cast<AirportItlwm *>(owner);
    UInt32 status = self->enqueuePacket(static_cast<mbuf_t>(arg0));
    auto ifp = &self->fHalService->get80211Controller()->ic_ac.ac_if;
    if (ifp->if_snd.queue)
        (*ifp->if_start)(ifp);
    return status;
}

UInt32 AirportItlwm::enqueuePacket(mbuf_t m)
{
    auto ic = fHalService->get80211Controller();
    auto ifp = &ic->ic_ac.ac_if;
    if (ic->ic_state == IEEE80211_S_RUN && ifp->if_snd.queue &&
        m && mbuf_type(m) != MBUF_TYPE_FREE && (mbuf_flags(m) & MBUF_PKTHDR) &&
        ifp->if_snd.queue->lockEnqueue(m))
        return kIOReturnOutputSuccess;
    if (ifp->netStat)
        ++ifp->netStat->outputErrors;
    if (m && mbuf_type(m) != MBUF_TYPE_FREE)
        freePacket(m);
    return kIOReturnOutputDropped;
}
#else
UInt32 AirportItlwm::outputPacket(mbuf_t m, void *param)
{
//    XYLog("%s\n", __FUNCTION__);
    IOReturn ret = kIOReturnOutputSuccess;
    struct _ifnet *ifp = &fHalService->get80211Controller()->ic_ac.ac_if;

    if (fHalService->get80211Controller()->ic_state != IEEE80211_S_RUN || ifp->if_snd.queue == NULL) {
        if (m && mbuf_type(m) != MBUF_TYPE_FREE)
            freePacket(m);
        return kIOReturnOutputDropped;
    }
    // Each bad packet returns here (audit D04): the old checks logged and carried on, so a null mbuf was
    // dereferenced and a freed one enqueued. The EAPOL hex dump is gone too: it wrote the handshake,
    // including the encrypted group key, to the log (and to ITLAWDLLog with -itllog, audit HL02).
    if (m == NULL) {
        if (ifp->netStat)
            ifp->netStat->outputErrors++;
        return kIOReturnOutputDropped;
    }
    if (mbuf_type(m) == MBUF_TYPE_FREE) {
        if (ifp->netStat)
            ifp->netStat->outputErrors++;
        return kIOReturnOutputDropped;
    }
    if (!(mbuf_flags(m) & MBUF_PKTHDR)) {
        if (ifp->netStat)
            ifp->netStat->outputErrors++;
        freePacket(m);
        return kIOReturnOutputDropped;
    }
    if (!ifp->if_snd.queue->lockEnqueue(m)) {
        freePacket(m);
        ret = kIOReturnOutputDropped;
    }
    (*ifp->if_start)(ifp);
    return ret;
}
#endif

const OSString * AirportItlwm::newVendorString() const
{
    return OSString::withCString("Apple");
}

const OSString * AirportItlwm::newModelString() const
{
    return OSString::withCString(fHalService->getDriverInfo()->getFirmwareName());
}

IOReturn AirportItlwm::getHardwareAddress(IOEthernetAddress *addrP)
{
    if (IEEE80211_ADDR_EQ(etheranyaddr, fHalService->get80211Controller()->ic_myaddr))
        return kIOReturnError;
    else {
        IEEE80211_ADDR_COPY(addrP, fHalService->get80211Controller()->ic_myaddr);
        return kIOReturnSuccess;
    }
}

IOReturn AirportItlwm::setHardwareAddress(const void *addrP, UInt32 addrBytes)
{
    if (!fNetIf || !addrP)
        return kIOReturnError;
#ifdef AIRPORT_WCL
    const UInt8 *address = static_cast<const UInt8 *>(addrP);
    auto ic = fHalService->get80211Controller();
    bool initializing = (ic->ic_if.if_flags & IFF_UP) && !(ic->ic_if.if_flags & IFF_RUNNING);
    auto update = AirportWCL::planMacUpdate(ic->ic_myaddr, address, addrBytes, initializing);
    itlWCLTrace('m', 0, uint32_t(update), (ic->ic_if.if_flags & IFF_RUNNING) ? 1 : 0);
    if (update == AirportWCL::MacUpdate::Invalid)
        return kIOReturnBadArgument;
    if (update == AirportWCL::MacUpdate::Busy) {
        return kIOReturnBusy;
    }
    if (!bsdInterface || !bsdInterface->getIfnet())
        return kIOReturnNotReady;
    // WCL calls this directly, bypassing IOEthernetInterface's normal MAC ioctl.
    // Update the BSD address used by DHCP/ARP as well as the firmware address.
    errno_t error = ifnet_set_lladdr(bsdInterface->getIfnet(), address, addrBytes);
    if (error)
        return kIOReturnError;
    bsdInterface->setProperty(kIOMACAddress, const_cast<UInt8 *>(address), addrBytes);
    // WCL replays the current address after every driver-available notification.
    // Keep BSD synchronized, but do not restart firmware for a replay.
    if (update == AirportWCL::MacUpdate::Unchanged) {
        return kIOReturnSuccess;
    }
#endif
    if_setlladdr(&fHalService->get80211Controller()->ic_ac.ac_if, (const UInt8 *)addrP);
#ifdef AIRPORT_WCL
    if (ic->ic_if.if_flags & IFF_RUNNING) {
        ic->ic_wcl_mac_reconfig = true;
#else
    if (fHalService->get80211Controller()->ic_state > IEEE80211_S_INIT) {
#endif
        fHalService->disable(bsdInterface);
        fHalService->enable(bsdInterface);
    }
    return kIOReturnSuccess;
}

UInt32 AirportItlwm::getFeatures() const
{
    return fHalService->getDriverInfo()->supportedFeatures();
}

IOReturn AirportItlwm::setPromiscuousMode(IOEnetPromiscuousMode mode)
{
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::setMulticastMode(IOEnetMulticastMode mode)
{
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::setMulticastList(IOEthernetAddress* addr, UInt32 len)
{
    return fHalService->getDriverController()->setMulticastList(addr, len);
}

IOReturn AirportItlwm::getPacketFilters(const OSSymbol *group, UInt32 *filters) const
{
    IOReturn    rtn = kIOReturnSuccess;
    if (group == gIOEthernetWakeOnLANFilterGroup && magicPacketSupported)
        *filters = kIOEthernetWakeOnMagicPacket;
    else if (group == gIONetworkFilterGroup)
        *filters = kIOPacketFilterMulticast | kIOPacketFilterPromiscuous;
    else
        rtn = IOEthernetController::getPacketFilters(group, filters);
    return rtn;
}

SInt32 AirportItlwm::
enableFeature(IO80211FeatureCode code, void *data)
{
    if (code == kIO80211Feature80211n) {
        return 0;
    }
    return 102;
}

bool AirportItlwm::getLogPipes(CCPipe**logPipe, CCPipe**eventPipe, CCPipe**snapshotsPipe)
{
    bool ret = false;
    if (logPipe) {
        *logPipe = driverLogPipe;
        ret = true;
    }
    if (eventPipe) {
        *eventPipe = driverDataPathPipe;
        ret = true;
    }
    if (snapshotsPipe) {
        *snapshotsPipe = driverSnapshotsPipe;
        ret = true;
    }
    return ret;
}

#define APPLE80211_CAPA_AWDL_FEATURE_AUTO_UNLOCK    0x00000004
#define APPLE80211_CAPA_AWDL_FEATURE_WOW            0x00000080

IOReturn AirportItlwm::
getCARD_CAPABILITIES(OSObject *object,
                                     struct apple80211_capability_data *cd)
{
    if (!cd || !fHalService)     // audit P-A07
        return kIOReturnBadArgument;
    uint32_t caps = fHalService->get80211Controller()->ic_caps;
    memset(cd, 0, sizeof(struct apple80211_capability_data));

    if (caps & IEEE80211_C_WEP)
        cd->capabilities[0] |= 1 << APPLE80211_CAP_WEP;
    if (caps & IEEE80211_C_RSN)
        cd->capabilities[0] |= 1 << APPLE80211_CAP_TKIP | 1 << APPLE80211_CAP_AES_CCM;
    // Disable not implemented capabilities
    // if (caps & IEEE80211_C_PMGT)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_PMGT;
    // if (caps & IEEE80211_C_IBSS)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_IBSS;
    // if (caps & IEEE80211_C_HOSTAP)
    //     cd->capabilities[0] |= 1 << APPLE80211_CAP_HOSTAP;
    // AES not enabled, like on Apple cards

    if (caps & IEEE80211_C_SHSLOT)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_SHSLOT - 8);
    if (caps & IEEE80211_C_SHPREAMBLE)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_SHPREAMBLE - 8);
    if (caps & IEEE80211_C_RSN)
        cd->capabilities[1] |= 1 << (APPLE80211_CAP_WPA1 - 8) | 1 << (APPLE80211_CAP_WPA2 - 8) | 1 << (APPLE80211_CAP_TKIPMIC - 8);
    // Disable not implemented capabilities
    // if (caps & IEEE80211_C_TXPMGT)
    //     cd->capabilities[1] |= 1 << (APPLE80211_CAP_TXPMGT - 8);
    // if (caps & IEEE80211_C_MONITOR)
    //     cd->capabilities[1] |= 1 << (APPLE80211_CAP_MONITOR - 8);
    // WPA not enabled, like on Apple cards

    cd->version = APPLE80211_VERSION;
#ifdef AIRPORT_WCL
    // WPA2 can use TKIP for group traffic even when unicast uses CCMP.
    // net80211 handles TKIP/MIC in software; hiding it makes Apple80211
    // reject these networks before it submits an association request.
    cd->capabilities[0] = (caps & IEEE80211_C_RSN) ?
        (1 << APPLE80211_CAP_AES_CCM) | (1 << APPLE80211_CAP_TKIP) : 0;
    cd->capabilities[1] &= ~(1 << (APPLE80211_CAP_WPA1 - 8));
    cd->capabilities[5] = 0x40; // Scan completion events.
    /* Advertise SAE only with -itlwmwpa3; Apple80211Associate2 filters SAE on MFP + SAE bits. */
    if (fHalService->get80211Controller()->ic_wpa3) {
        cd->capabilities[6] |= 0x01;
        /* WCL requires capability byte 9 bit 3 for SAE; airportd rejects otherwise. */
        cd->capabilities[9] |= 0x08;
    }
    // Tahoe wifip2pd checks raw capability byte 4, bit 0 before requesting
    // an AWDL interface (25G241, 0x1000483b5). Expose it only for bring-up.
    if (awdlInterfaceTest) {
        cd->capabilities[4] |= 0x01;
        // Native configureValidAWDLChannels tests capability byte 3 bit 5
        // (25G241, 0xffffff80021cab1e). Report physical supported bands from
        // the HAL channel table; this does not promise concurrent operation
        // or relax any regulatory/passive restrictions on those channels.
        auto *ic = fHalService->get80211Controller();
        bool band2 = false, band5 = false;
        for (unsigned i = 0; i <= IEEE80211_CHAN_MAX; ++i) {
            if (!ic->ic_channels[i].ic_freq)
                continue;
            band2 |= (ic->ic_channels[i].ic_flags & IEEE80211_CHAN_2GHZ) != 0;
            band5 |= (ic->ic_channels[i].ic_flags & IEEE80211_CHAN_5GHZ) != 0;
        }
        if (band2 && band5)
            cd->capabilities[3] |= 0x20;
    }
    cd->capabilities[2] = (1 << (APPLE80211_CAP_WME - 16)) |
        (1 << (APPLE80211_CAP_SHORT_GI_40MHZ - 16)) |
        (1 << (APPLE80211_CAP_SHORT_GI_20MHZ - 16));
    // Tahoe WCLDeviceConfiguration::isHeSupported reads byte 17, bit 7.
    // WCL uses this capability together with the BSS HE IE for PHY reporting.
    if (caps & IEEE80211_C_HE)
        cd->capabilities[17] |= 0x80;
#else
    cd->capabilities[2] = 0xFF; // BURST, WME, SHORT_GI_40MHZ, SHORT_GI_20MHZ, WOW, TSN, ?, ?
    cd->capabilities[3] = 0x2B;
    cd->capabilities[5] = 0x40;
    cd->capabilities[6] = (
//                           1 |    //MFP capable
                           0x8 |
                           0x4 |
                           0x80
                           );
    *(uint16_t *)&cd->capabilities[8] = 0x201;

    if (awdlInterfaceTest) {
        cd->capabilities[4] |= 0x01;
    }
//
//    cd->capabilities[2] |= 0x10;
//    cd->capabilities[5] |= 0x1;
//
//    cd->capabilities[2] |= 0x2;
//
//    cd->capabilities[3] |= 0x20;
//
//    cd->capabilities[0] |= 0x80;
//
//    cd->capabilities[3] |= 0x80;
//    cd->capabilities[4] |= 0x4;
//
//    cd->capabilities[4] |= 0x1;
//    cd->capabilities[3] |= 0x1;
//    cd->capabilities[6] |= 0x8;
//
//    cd->capabilities[3] |= 3;
//    cd->capabilities[4] |= 2;
//    cd->capabilities[6] |= 0x10;
//    cd->capabilities[5] |= 0x20;
//    cd->capabilities[5] |= 0x80;
//
//    if (cd->capabilities[6] & 0x20) {
//        cd->capabilities[2] |= 8;
//    }
//    cd->capabilities[5] |= 8;
//    cd->capabilities[8] |= 2;
//
//    cd->capabilities[11] |= (2 | 4 | 8 | 0x10 | 0x20 | 0x40 | 0x80);

#endif
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getDRIVER_VERSION(OSObject *object,
                                  struct apple80211_version_data *hv)
{
    if (!hv)
        return kIOReturnError;
    hv->version = APPLE80211_VERSION;
    snprintf(hv->string, sizeof(hv->string), "itlwm: %s%s fw: %s", ITLWM_VERSION, GIT_COMMIT, fHalService->getDriverInfo()->getFirmwareVersion());
    hv->string_len = strlen(hv->string);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getHARDWARE_VERSION(OSObject *object,
                                    struct apple80211_version_data *hv)
{
    if (!hv)
        return kIOReturnError;
    if (!fHalService)
        return kIOReturnNotReady;
    hv->version = APPLE80211_VERSION;
    // Terminated, and the reported length never exceeds what was copied (audit P-A07).
    const char *firmware = fHalService->getDriverInfo()->getFirmwareVersion();
    memset(hv->string, 0, sizeof(hv->string));
    strlcpy(hv->string, firmware ? firmware : "", sizeof(hv->string));
    hv->string_len = (u_int16_t)strnlen(hv->string, sizeof(hv->string) - 1);
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getCOUNTRY_CODE(OSObject *object,
                                struct apple80211_country_code_data *cd)
{
    char user_override_cc[3];
    const char *cc_fw = fHalService->getDriverInfo()->getFirmwareCountryCode();

    if (!cd)
        return kIOReturnError;
    cd->version = APPLE80211_VERSION;
    memset(user_override_cc, 0, sizeof(user_override_cc));
    PE_parse_boot_argn("itlwm_cc", user_override_cc, 3);
    /* user_override_cc > firmware_cc > geo_location_cc */
    strncpy((char*)cd->cc, user_override_cc[0] ? user_override_cc : ((cc_fw[0] == 'Z' && cc_fw[1] == 'Z' && geo_location_cc[0]) ? geo_location_cc : cc_fw), sizeof(cd->cc));
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setCOUNTRY_CODE(OSObject *object, struct apple80211_country_code_data *data)
{
#ifdef AIRPORT_WCL
    if (!data)
        return kIOReturnBadArgument;
    if (data->cc[0] != 'x' && data->cc[0] != 'X' &&
        memcmp(geo_location_cc, data->cc, sizeof(geo_location_cc)) != 0) {
        memcpy(geo_location_cc, data->cc, sizeof(geo_location_cc));
        if (fNetIf)
            static_cast<AirportItlwmSkywalkInterface *>(fNetIf)->handleWCLEvent(
                IEEE80211_EVT_COUNTRY_CODE_UPDATE, nullptr);
    }
#else
    XYLog("%s cc=%s\n", __FUNCTION__, data->cc);
    if (data && data->cc[0] != 120 && data->cc[0] != 88) {
        memcpy(geo_location_cc, data->cc, sizeof(geo_location_cc));
        fNetIf->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED, NULL, 0, 0);
    }
#endif
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
getPOWER(OSObject *object,
                         struct apple80211_power_data *pd)
{
    if (!pd)
        return kIOReturnError;
    pd->version = APPLE80211_VERSION;
    pd->num_radios = 4;
    pd->power_state[0] = power_state;
    pd->power_state[1] = power_state;
    pd->power_state[2] = power_state;
    pd->power_state[3] = power_state;
    return kIOReturnSuccess;
}

IOReturn AirportItlwm::
setPOWER(OSObject *object,
                         struct apple80211_power_data *pd)
{
#ifdef AIRPORT_WCL
    if (!pd)
        return kIOReturnError;
    IOLog("itlwm: setPOWER: num_radios[%d]  power_state(0:%u  1:%u  2:%u  3:%u)\n", pd->num_radios, pd->power_state[0], pd->power_state[1], pd->power_state[2], pd->power_state[3]);
    if (pd->num_radios > 0) {
        bool isRunning = (fHalService->get80211Controller()->ic_ac.ac_if.if_flags & IFF_RUNNING) != 0;
        if (pd->power_state[0] == 0) {
            fHalService->get80211Controller()->ic_wcl_mac_reconfig = false;
            enableAwaitingPowerOn = false;
            changePowerStateToPriv(kPowerStateOff);
            if (fHalService->get80211Controller()->ic_ac.ac_if.if_flags & (IFF_UP | IFF_RUNNING)) {
                net80211_ifstats(fHalService->get80211Controller());
                disableAdapter(bsdInterface);
            }
        } else {
            changePowerStateToPriv(kPowerStateOn);
            if (!isRunning)
                enableAdapterWhenPowered();
        }
        power_state = (pd->power_state[0]);
    }

    return kIOReturnSuccess;
#else
    if (!pd)
        return kIOReturnError;
    IOLog("itlwm: setPOWER: num_radios[%d]  power_state(0:%u  1:%u  2:%u  3:%u)\n", pd->num_radios, pd->power_state[0], pd->power_state[1], pd->power_state[2], pd->power_state[3]);
    if (pd->num_radios > 0) {
        bool isRunning = (fHalService->get80211Controller()->ic_ac.ac_if.if_flags & (IFF_UP | IFF_RUNNING)) != 0;
        if (pd->power_state[0] == 0) {
            enableAwaitingPowerOn = false;
            changePowerStateToPriv(1);
            if (isRunning) {
                net80211_ifstats(fHalService->get80211Controller());
                disableAdapter(bsdInterface);
            }
        } else {
            changePowerStateToPriv(2);
            if (!isRunning)
                enableAdapterWhenPowered();
        }
        power_state = (pd->power_state[0]);
    }

    return kIOReturnSuccess;
#endif
}

// XYLog reaches only the serial console on a normal boot, so requests that end up in these unsupported
// entries are also counted in the registry, as one snapshot: entry, command, direction where known, and
// the count. Payloads aren't read: these entries get no length or type. (Selector 127, AW AP alignment,
// doesn't come here on 25G241: IO80211Family's internal set table sends it to its own stub.)
static void noteUnhandledRequest(IOService *owner, const char *entry, unsigned cmd, unsigned request)
{
    if (ml_at_interrupt_context())
        return;
    static volatile SInt32 count;
    const SInt32 n = OSIncrementAtomic(&count) + 1;
    char snapshot[96];
    snprintf(snapshot, sizeof(snapshot), "%s cmd %u request %u count %d", entry, cmd, request, int(n));
    owner->setProperty("ItlwmUnhandledRequest", snapshot);
}

SInt32 AirportItlwm::apple80211_ioctl(IO80211SkywalkInterface *interface,unsigned long cmd,void *data, bool b1, bool b2)
{
    if (!ml_at_interrupt_context())
        XYLog("%s cmd: %s b1: %d b2: %d\n", __FUNCTION__, convertApple80211IOCTLToString((unsigned int)cmd), b1, b2);
#ifdef AIRPORT_WCL
    noteUnhandledRequest(this, "ioctl", unsigned(cmd), 0);
    return kIOReturnUnsupported;
#else
    return super::apple80211_ioctl(interface, cmd, data, b1, b2);
#endif
}

SInt32 AirportItlwm::apple80211SkywalkRequest(UInt request,int cmd,IO80211SkywalkInterface *interface,void *data)
{
    if (!ml_at_interrupt_context())
        XYLog("%s 1 cmd: %s request: %d\n", __FUNCTION__, convertApple80211IOCTLToString(cmd), request);
    noteUnhandledRequest(this, "skywalk1", unsigned(cmd), request);
    return kIOReturnUnsupported;
}

SInt32 AirportItlwm::apple80211SkywalkRequest(UInt request,int cmd,IO80211SkywalkInterface *interface,void *data,void *)
{
    if (!ml_at_interrupt_context())
        XYLog("%s 2 cmd: %s request: %d\n", __FUNCTION__, convertApple80211IOCTLToString(cmd), request);
    noteUnhandledRequest(this, "skywalk2", unsigned(cmd), request);
    return kIOReturnUnsupported;
}

IOReturn AirportItlwm::enableAdapter(IONetworkInterface *netif)
{
    // Reached from Apple's power requests; after a failed start or stop these are gone (audit D05).
    if (!fHalService || !watchdogTimer)
        return kIOReturnNotReady;
#ifdef AIRPORT_WCL
    IOReturn status = fHalService->enable(netif);
    if (status != kIOReturnSuccess)
        return status;
#else
    fHalService->enable(netif);
#endif
    watchdogTimer->setTimeoutMS(kWatchDogTimerPeriod);
    watchdogTimer->enable();
    return kIOReturnSuccess;
}

void AirportItlwm::disableAdapter(IONetworkInterface *netif)
{
    if (watchdogTimer) {        // audit D05
        watchdogTimer->cancelTimeout();
        watchdogTimer->disable();
    }
    if (fHalService)
        fHalService->disable(netif);
}

IOReturn AirportItlwm::
tsleepHandler(OSObject* owner, void* arg0, void* arg1, void* arg2, void* arg3)
{
    AirportItlwm* dev = OSDynamicCast(AirportItlwm, owner);
    if (dev == 0)
        return kIOReturnError;

    if (arg1 == 0) {
        if (_fCommandGate->commandSleep(arg0, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    } else {
        AbsoluteTime deadline;
        clock_interval_to_deadline((*(int*)arg1), kNanosecondScale, reinterpret_cast<uint64_t*> (&deadline));
        if (_fCommandGate->commandSleep(arg0, deadline, THREAD_INTERRUPTIBLE) == THREAD_AWAKENED)
            return kIOReturnSuccess;
        else
            return kIOReturnTimeout;
    }
}

bool AirportItlwm::initPCIPowerManagment(IOPCIDevice *provider)
{
    UInt16 reg16;

    reg16 = provider->configRead16(kIOPCIConfigCommand);

    reg16 |= ( kIOPCICommandBusMaster       |
               kIOPCICommandMemorySpace     |
               kIOPCICommandMemWrInvalidate );

    reg16 &= ~kIOPCICommandIOSpace;  // disable I/O space

    provider->configWrite16( kIOPCIConfigCommand, reg16 );
    provider->findPCICapability(kIOPCIPowerManagementCapability,
                                &pmPCICapPtr);
    if (pmPCICapPtr) {
        UInt16 pciPMCReg = provider->configRead32( pmPCICapPtr ) >> 16;
        if (pciPMCReg & kPCIPMCPMESupportFromD3Cold)
            magicPacketSupported = true;
        provider->configWrite16((pmPCICapPtr + 4), 0x8000 );
        IOSleep(10);
    }
    return true;
}

static IOPMPowerState powerStateArray[kPowerStateCount] =
{
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, kIOPMDeviceUsable, kIOPMPowerOn, kIOPMPowerOn, 0, 0, 0, 0, 0, 0, 0, 0}
};

void AirportItlwm::unregistPM()
{
    // A call still pending would run after stop, against a command gate that is gone. Cancel it,
    // or wait for one already running, and drop the reference setPowerState took for it.
    if (powerOffThreadCall) {
        if (thread_call_cancel_wait(powerOffThreadCall))
            release();
        thread_call_free(powerOffThreadCall);
        powerOffThreadCall = NULL;
    }
    if (powerOnThreadCall) {
        if (thread_call_cancel_wait(powerOnThreadCall))
            release();
        thread_call_free(powerOnThreadCall);
        powerOnThreadCall = NULL;
    }
}

IOReturn AirportItlwm::setPowerState(unsigned long powerStateOrdinal, IOService *policyMaker)
{
    IOReturn result = IOPMAckImplied;

    if (pmPowerState == powerStateOrdinal)
        return result;
    switch (powerStateOrdinal) {
        case kPowerStateOff:
            if (powerOffThreadCall) {
                retain();
                if (thread_call_enter(powerOffThreadCall))
                    release();
                result = 5000000;
            }
            break;
        case kPowerStateOn:
            if (powerOnThreadCall) {
                retain();
                if (thread_call_enter(powerOnThreadCall))
                    release();
                result = 5000000;
            }
            break;

        default:
            break;
    }
    return result;
}

IOReturn AirportItlwm::setWakeOnMagicPacket(bool active)
{
    magicPacketEnabled = active;
    return kIOReturnSuccess;
}

static void handleSetPowerStateOff(thread_call_param_t param0,
                             thread_call_param_t param1)
{
    AirportItlwm *self = (AirportItlwm *)param0;

    if (param1 == 0)
    {
        self->getCommandGate()->runAction((IOCommandGate::Action)
                                           handleSetPowerStateOff,
                                           (void *) 1);
    }
    else
    {
        self->setPowerStateOff();
        self->release();
    }
}

static void handleSetPowerStateOn(thread_call_param_t param0,
                            thread_call_param_t param1)
{
    AirportItlwm *self = (AirportItlwm *) param0;

    if (param1 == 0)
    {
        self->getCommandGate()->runAction((IOCommandGate::Action)
                                           handleSetPowerStateOn,
                                           (void *) 1);
    }
    else
    {
        self->setPowerStateOn();
        self->release();
    }
}

IOReturn AirportItlwm::registerWithPolicyMaker(IOService *policyMaker)
{
    IOReturn ret;

    pmPowerState = kPowerStateOn;
    pmPolicyMaker = policyMaker;

    powerOffThreadCall = thread_call_allocate(
                                            (thread_call_func_t)handleSetPowerStateOff,
                                            (thread_call_param_t)this);
    powerOnThreadCall  = thread_call_allocate(
                                            (thread_call_func_t)handleSetPowerStateOn,
                                              (thread_call_param_t)this);
    ret = pmPolicyMaker->registerPowerDriver(this,
                                             powerStateArray,
                                             kPowerStateCount);
    return ret;
}

void AirportItlwm::setPowerStateOff()
{
    XYLog("%s\n", __FUNCTION__);
    pmPowerState = kPowerStateOff;
    enableAwaitingPowerOn = false;
    disableAdapter(bsdInterface);
    pmPolicyMaker->acknowledgeSetPowerState();
}

void AirportItlwm::setPowerStateOn()
{
    XYLog("%s\n", __FUNCTION__);
    pmPowerState = kPowerStateOn;
    pmPolicyMaker->acknowledgeSetPowerState();
    // Wi-Fi was asked for while the card was still off (#38): start it now that it's powered.
    if (enableAwaitingPowerOn && power_state) {
        enableAwaitingPowerOn = false;
        XYLog("%s: starting the deferred Wi-Fi enable\n", __FUNCTION__);
        enableAdapter(bsdInterface);
    }
}

// #38: on a full wake macOS can ask for Wi-Fi (setPOWER, or the interface's enable) a few milliseconds
// before the power manager has powered the card back on (setPowerStateOn). The card then reads all-ones,
// initialization fails, and nothing retried it, so Wi-Fi stayed off until it was toggled. While the
// power state is off, remember the request instead, and start the adapter in setPowerStateOn. A power-off
// or a Wi-Fi-off request in between drops it, so a dark wake never starts Wi-Fi. Before power management
// is registered there is no power state to wait for, so Wi-Fi starts at once, as before.
void AirportItlwm::enableAdapterWhenPowered()
{
    if (pmPolicyMaker && pmPowerState != kPowerStateOn) {
        enableAwaitingPowerOn = true;
        setProperty("ItlwmEnableDeferrals", ++enableDeferrals, 32);
        XYLog("%s: power is off, starting Wi-Fi once it's on\n", __FUNCTION__);
        return;
    }
    enableAwaitingPowerOn = false;
    enableAdapter(bsdInterface);
}
