//
//  AWDLBuildGuard.cpp
//  AirportItlwm
//
//  Decides once whether AirDrop (AWDL) may start on this macOS build. Two checks must both pass:
//  1. The running kernel is one whose IO80211Family and IOSkywalkFamily were verified (AWDLBuildGuard.hpp).
//  2. Apple's IO80211AWDLProtocol virtual table, which ItlAWDLInterface subclasses slot for slot,
//     still has the expected functions at spread-out anchor slots, its own pure methods where
//     expected, and ends where expected (568 slots on Tahoe, 563 on Sequoia, 547 on Sonoma). This catches a changed
//     table on any build.
//  -itlawdlanybuild skips check 1 (never check 2), and -itlawdloff fails both. When AWDL may not start, the driver
//  behaves like plain AirportItlwm: normal Wi-Fi works and nothing AWDL-related is created or sent.
//

#include <IOKit/IOLib.h>
#include <libkern/version.h>
#include <sys/sysctl.h>
#include <AWDLBuildGuard.hpp>

// From 0.7.0-alpha.2 the tested set (docs/BOOT-FLAGS.md) is on by default. Each of its flags is still read, so
// boot-args from older releases keep working and change nothing. -itlawdlnodefaults goes back to the old rule:
// only the flags that are set count, and with none the driver behaves like AirportItlwm.
bool itlAWDLDefaults()
{
    static int cached = -1;
    if (cached < 0) {
        int dummy = 0;
        cached = PE_parse_boot_argn("-itlawdlnodefaults", &dummy, sizeof(dummy)) ? 0 : 1;
    }
    return cached == 1;
}

// One flag of the tested set: on by default, or when set. The same name with "no" after "-itlawdl" turns that one
// flag off (-itlawdlnocoexmulti for -itlawdlcoexmulti), and wins over the flag itself.
bool itlAWDLFlag(const char *name)
{
    int dummy = 0;
    static const char prefix[] = "-itlawdl";
    const size_t prefixLength = sizeof(prefix) - 1;
    if (name && !strncmp(name, prefix, prefixLength)) {
        char off[64];
        if (snprintf(off, sizeof(off), "-itlawdlno%s", name + prefixLength) < int(sizeof(off)) &&
            PE_parse_boot_argn(off, &dummy, sizeof(dummy)))
            return false;
    }
    return itlAWDLDefaults() || PE_parse_boot_argn(name, &dummy, sizeof(dummy));
}

#if !defined(ITL_AWDL_NATIVE)
// A target without the AirDrop port: the driver is plain Wi-Fi, and nothing here
// may reference Apple's AWDL classes, which this kext would then need at load time.
bool itlAWDLBuildAllowed() { return false; }
bool itlAWDLBuildVerified() { return false; }
bool itlAWDLBuildForced() { return false; }
const char *itlAWDLBuildStatus() { return "unavailable: AirDrop isn't ported to this macOS version yet"; }
#else

extern "C" {
extern const uintptr_t itlNativeAWDLProtocolVtable[] __asm__("__ZTV19IO80211AWDLProtocol");
void itlAnchorAWDLProtocolD1() __asm__("__ZN19IO80211AWDLProtocolD1Ev");
void itlAnchorWakeFlags() __asm__("__ZN25IOSkywalkNetworkInterface21getSupportedWakeFlagsEPj");
void itlAnchorInterfaceCCA() __asm__("__ZN23IO80211SkywalkInterface15setInterfaceCCAE18apple80211_channeli");
void itlAnchorStatsDump() __asm__("__ZN23IO80211SkywalkInterface9statsDumpEv");
#if defined(ITL_AWDL_GUARD_SEQUOIA) || defined(ITL_AWDL_GUARD_SONOMA)
void itlAnchorVirtualInit() __asm__("__ZN23IO80211VirtualInterface4initEP17IO80211ControllerP10ether_addrjPKc");
#else
void itlAnchorSyncDPSStats() __asm__("__ZN23IO80211SkywalkInterface12syncDPSStatsEP26apple82011_postMessage_dps");
#endif
void itlAnchorReserved15() __asm__("__ZN23IO80211VirtualInterface34_RESERVEDIO80211VirtualInterface15Ev");
void itlAnchorPureVirtual() __asm__("___cxa_pure_virtual");
}

namespace {
// Slots counted from the address point (the vtable symbol plus two words), as in the 25G241 table
// (Tahoe) and the 24H241 Kernel Debug Kit table (Sequoia).
struct Anchor { unsigned slot; uintptr_t expected; };

int gAllowed = -1;
bool gVerified = false;
bool gForced = false;   // allowed only because of -itlawdlanybuild
bool gAnyBuild = false; // -itlawdlanybuild is set
const char *gStatus = "not-checked";

bool vtableMatches()
{
    const uintptr_t *slots = itlNativeAWDLProtocolVtable + 2;
    const uintptr_t pure = reinterpret_cast<uintptr_t>(&itlAnchorPureVirtual);
#if defined(ITL_AWDL_GUARD_SONOMA)
    // From 23J631's Kernel Debug Kit: 547 slots, 62 AWDL pure virtuals from 485.
    const Anchor anchors[] = {
        {0, reinterpret_cast<uintptr_t>(&itlAnchorAWDLProtocolD1)},
        {297, reinterpret_cast<uintptr_t>(&itlAnchorWakeFlags)},
        {379, reinterpret_cast<uintptr_t>(&itlAnchorInterfaceCCA)},
        {420, reinterpret_cast<uintptr_t>(&itlAnchorStatsDump)},
        {446, reinterpret_cast<uintptr_t>(&itlAnchorVirtualInit)},
        {484, reinterpret_cast<uintptr_t>(&itlAnchorReserved15)},
        {485, pure},
        {546, pure},
        {547, 0},
    };
#elif defined(ITL_AWDL_GUARD_SEQUOIA)
    const Anchor anchors[] = {
        {0, reinterpret_cast<uintptr_t>(&itlAnchorAWDLProtocolD1)},
        {299, reinterpret_cast<uintptr_t>(&itlAnchorWakeFlags)},
        {380, reinterpret_cast<uintptr_t>(&itlAnchorInterfaceCCA)},
        {415, pure},                                   // setMacAddress, pure in IO80211SkywalkInterface here
        {420, reinterpret_cast<uintptr_t>(&itlAnchorStatsDump)},
        {460, reinterpret_cast<uintptr_t>(&itlAnchorVirtualInit)},
        {499, reinterpret_cast<uintptr_t>(&itlAnchorReserved15)},
        {500, pure},
        {562, pure},
        {563, 0},
    };
#else
    const Anchor anchors[] = {
        {0, reinterpret_cast<uintptr_t>(&itlAnchorAWDLProtocolD1)},
        {300, reinterpret_cast<uintptr_t>(&itlAnchorWakeFlags)},
        {380, reinterpret_cast<uintptr_t>(&itlAnchorInterfaceCCA)},
        {420, reinterpret_cast<uintptr_t>(&itlAnchorStatsDump)},
        {460, reinterpret_cast<uintptr_t>(&itlAnchorSyncDPSStats)},
        {504, reinterpret_cast<uintptr_t>(&itlAnchorReserved15)},
        {505, pure},
        {567, pure},
        {568, 0},
    };
#endif
    for (const auto &a : anchors)
        if (slots[a.slot] != a.expected)
            return false;
    return true;
}
}

bool itlAWDLBuildAllowed()
{
    if (gAllowed >= 0)
        return gAllowed == 1;
    int dummy = 0;
    // From 0.7.0-alpha.2: AirDrop off whatever else is set, so the driver behaves like AirportItlwm.
    if (PE_parse_boot_argn("-itlawdloff", &dummy, sizeof(dummy))) {
        gStatus = "off: -itlawdloff";
        gAllowed = 0;
        IOLog("AirportItlwm: AirDrop %s\n", gStatus);
        return false;
    }
    const bool anyBuild = PE_parse_boot_argn("-itlawdlanybuild", &dummy, sizeof(dummy));
    gAnyBuild = anyBuild;
    const ItlAWDL::BuildCheck build = ItlAWDL::checkBuild(version, nullptr);
    if (!vtableMatches()) {
        gStatus = "blocked: IO80211AWDLProtocol table differs";
        gAllowed = 0;
    } else if (build == ItlAWDL::BuildCheck::Verified) {
        gStatus = "verified";
        gAllowed = 1;
        gVerified = true;
#ifdef ITL_AWDL_GUARD_SEQUOIA
    } else if (build == ItlAWDL::BuildCheck::Expected) {
        gStatus = "expected: macOS 15.8.x kernel not checked offline";
        gAllowed = 1;
#endif
    } else if (anyBuild) {
        gStatus = "unverified build, allowed by -itlawdlanybuild";
        gAllowed = 1;
        gForced = true;
    } else {
        gStatus = "blocked: unverified macOS build";
        gAllowed = 0;
    }
    IOLog("AirportItlwm: AirDrop %s\n", gStatus);
    return gAllowed == 1;
}

// True only for a kernel on the verified list whose table matched. Code that relies on native data
// layouts the vtable anchors don't cover (such as the master indication request) needs this, not
// just itlAWDLBuildAllowed(): an "expected" or -itlawdlanybuild build stays off.
//
// gVerified only says the kernel is on the list. The macOS build must pair with it too (audit P-A08);
// kern.osversion can still be empty when the driver starts, so it's read here, when first needed (the
// peer manager's start), and the answer kept once the build is known.
// True when -itlawdlanybuild is set and AirDrop runs on a build the list doesn't verify as a pair: an unknown
// kernel (allowed only by the flag), an "expected" Sequoia kernel, or a listed kernel with an unlisted macOS build.
// The flag then makes the build behave like a verified one: the master indication copy (from 0.6.0-beta.2, unknown
// kernels only; now all three cases) and the AirDrop packet counters run too. Both keep their runtime checks: the
// copy's pointer is range-checked and the copy validated, and the counters only write once getPeerManager()
// returns a real IO80211AWDLPeerManager (its vtable). The layouts behind them are otherwise unchecked, the risk
// the flag carries (BOOT-FLAGS).
bool itlAWDLBuildVerified();
bool itlAWDLBuildForced()
{
    if (!itlAWDLBuildAllowed())
        return false;
    return gForced || (gAnyBuild && !itlAWDLBuildVerified());
}

bool itlAWDLBuildVerified()
{
    static int pairVerified = -1;
    static char statusText[96];
    if (!itlAWDLBuildAllowed() || !gVerified)
        return false;
    if (pairVerified >= 0)
        return pairVerified == 1;
    char osBuild[32] = {};
    size_t length = sizeof(osBuild) - 1;
    if (sysctlbyname("kern.osversion", osBuild, &length, nullptr, 0) != 0 || !osBuild[0])
        return false;   // not known yet: stays off, asked again next time
    pairVerified = ItlAWDL::buildPairVerified(version, osBuild) ? 1 : 0;
    if (!pairVerified) {
        snprintf(statusText, sizeof(statusText), "allowed: kernel verified, macOS build %s not verified", osBuild);
        gStatus = statusText;
        IOLog("AirportItlwm: AirDrop %s; the master indication copy and packet counters %s\n", gStatus,
              gAnyBuild ? "run anyway (-itlawdlanybuild)" : "stay off");
    }
    return pairVerified == 1;
}

const char *itlAWDLBuildStatus()
{
    itlAWDLBuildAllowed();
    return gStatus;
}
#endif
