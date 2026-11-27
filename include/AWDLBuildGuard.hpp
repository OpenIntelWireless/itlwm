#pragma once
// Which macOS builds AirDrop (AWDL) may run on. The AWDL interface subclasses Apple's IO80211 classes
// and relies on their virtual tables and on a few native data layouts, so it may only start on a
// build where those were verified. Elsewhere the driver behaves like plain AirportItlwm: normal
// Wi-Fi works and nothing AWDL-related starts. -itlawdlanybuild overrides this, for testers who
// accept the risk of a kernel panic.
//
// Each macOS version has its own kext and its own list.
// Tahoe: 25G241 on hardware; 25G229, 25G330, 25G332 and 25G342 offline, from Apple's Kernel Debug Kits
// (IOSkywalkFamily identical, IO80211Family's AWDL, interface, buffer and registration code
// instruction-identical, all virtual table slots and all kernel imports matching). 25G229 carries 25G241's
// kernel and IO80211Family; 25G330 is binary-identical to 25G332. 25G422 (26.7.4 beta, from 0.7.0-alpha.3) from a
// user's tools/check-my-mac.pl report: its IO80211Family code differs from 26.7.1's, but the six IO80211 tables'
// sizes and names, the AWDL layouts it checks and every import of the kext the user ran match.
// Sequoia: 24H23 (15.8) and 24H241 (15.8.3) offline, from their Kernel Debug Kits (identical
// IO80211Family virtual tables; the AWDL subclass audited against them). 24H32 is binary-identical to 24H23,
// and 24H230 and 24H232 carry 24H241's kernel and IO80211Family. The 15.7.x builds 24G419, 24G517 and 24G830:
// the same six IO80211 tables and AWDL, interface and buffer code as 24H23 (they differ in NAN code only),
// IOSkywalkFamily's tables identical, all imports present. Other 15.8.x kernels (xnu-11417.140.69.71x) are
// allowed as "expected": the runtime vtable check still has to pass.
// Sonoma: 23J631 (14.8.9) offline, from its Kernel Debug Kit; 23J220 (14.8.3) and 23J319 (14.8.4) the same
// way (identical tables and AWDL code; IONetworkingFamily identical). 23J520 (14.8.7), 23J620 (14.8.8) and 24G824
// (15.7.8) from their installers' kernel collections (tools/check-my-mac.pl --kc): the protocol table, the six
// IO80211 tables' sizes and names, the AWDL layouts it checks and every import match.
#include <stddef.h>
#include <string.h>

namespace ItlAWDL {

struct VerifiedBuild {
    const char *osBuild;   // kern.osversion
    const char *kernel;    // the xnu build tag inside the kernel's version string
};

#if defined(__MAC_14_4) && __IO80211_TARGET == __MAC_14_4
#define ITL_AWDL_GUARD_SONOMA 1
constexpr VerifiedBuild kVerifiedBuilds[] = {
    {"23J220", "xnu-10063.141.1.708.2~1/RELEASE_X86_64"},    // macOS 14.8.3
    {"23J319", "xnu-10063.141.1.710.3~1/RELEASE_X86_64"},    // macOS 14.8.4
    {"23J520", "xnu-10063.141.1.712.16~1/RELEASE_X86_64"},   // macOS 14.8.7 (installer's KC)
    {"23J620", "xnu-10063.141.1.713.39~1/RELEASE_X86_64"},   // macOS 14.8.8 (installer's KC; 14.8.9's kernel)
    {"23J631", "xnu-10063.141.1.713.39~1/RELEASE_X86_64"},   // macOS 14.8.9
};
#elif defined(__MAC_15_2) && __IO80211_TARGET == __MAC_15_2
#define ITL_AWDL_GUARD_SEQUOIA 1
constexpr VerifiedBuild kVerifiedBuilds[] = {
    {"24G419", "xnu-11417.140.69.705.2~1/RELEASE_X86_64"},    // macOS 15.7.3
    {"24G517", "xnu-11417.140.69.708.3~1/RELEASE_X86_64"},    // macOS 15.7.4
    {"24G824", "xnu-11417.140.69.711.44~1/RELEASE_X86_64"},   // macOS 15.7.8 (installer's KC; 15.7.9's kernel)
    {"24G830", "xnu-11417.140.69.711.44~1/RELEASE_X86_64"},   // macOS 15.7.9
    {"24H23",  "xnu-11417.140.69.712.69~1/RELEASE_X86_64"},   // macOS 15.8
    {"24H32",  "xnu-11417.140.69.712.69~1/RELEASE_X86_64"},   // macOS 15.8.1
    {"24H230", "xnu-11417.140.69.713.47~2/RELEASE_X86_64"},   // macOS 15.8.2
    {"24H232", "xnu-11417.140.69.713.47~2/RELEASE_X86_64"},   // macOS 15.8.2
    {"24H241", "xnu-11417.140.69.713.47~2/RELEASE_X86_64"},   // macOS 15.8.3
};
// Later 15.8.x updates: same kernel train, not checked offline.
constexpr const char *kExpectedKernelPrefix = "xnu-11417.140.69.71";
constexpr const char *kExpectedKernelSuffix = "/RELEASE_X86_64";
#else
constexpr VerifiedBuild kVerifiedBuilds[] = {
    {"25G229", "xnu-12377.161.15.700.19~2/RELEASE_X86_64"},   // macOS 26.7
    {"25G241", "xnu-12377.161.15.700.19~2/RELEASE_X86_64"},   // macOS 26.7.1
    {"25G330", "xnu-12377.161.15.701.48~2/RELEASE_X86_64"},   // macOS 26.7.2
    {"25G332", "xnu-12377.161.15.701.48~2/RELEASE_X86_64"},   // macOS 26.7.2
    {"25G342", "xnu-12377.161.15.701.48~2/RELEASE_X86_64"},   // macOS 26.7.3
    {"25G422", "xnu-12377.161.15.702.20~1/RELEASE_X86_64"},   // macOS 26.7.4 beta (check-my-mac report)
};
#endif

enum class BuildCheck { Verified, UnknownBuild, UnknownKernel, Expected };

inline bool containsText(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return false;
    const size_t n = strlen(needle);
    for (const char *p = haystack; *p; ++p)
        if (!strncmp(p, needle, n)) return true;
    return false;
}

// kernelVersion is the kernel's `version` string, which is always set. osBuild is `osversion`,
// which may still be empty early in boot; then the kernel alone decides. Both must match when set.
inline BuildCheck checkBuild(const char *kernelVersion, const char *osBuild) {
    bool kernelKnown = false;
    for (const auto &b : kVerifiedBuilds)
        if (containsText(kernelVersion, b.kernel)) kernelKnown = true;
#ifdef ITL_AWDL_GUARD_SEQUOIA
    if (!kernelKnown && containsText(kernelVersion, kExpectedKernelPrefix) && containsText(kernelVersion, kExpectedKernelSuffix))
        return BuildCheck::Expected;
#endif
    if (!kernelKnown) return BuildCheck::UnknownKernel;
    if (!osBuild || !*osBuild) return BuildCheck::Verified;
    for (const auto &b : kVerifiedBuilds)
        if (!strcmp(osBuild, b.osBuild) && containsText(kernelVersion, b.kernel)) return BuildCheck::Verified;
    return BuildCheck::UnknownBuild;
}

// The stronger check, for code that relies on native data layouts the vtable anchors don't cover (the
// master indication request): the macOS build itself must be on the list and pair with this kernel. A
// kernel alone isn't enough, because one kernel can ship with more than one IO80211Family (Tahoe 26.7.2
// and 26.7.3 share one), and a later update could keep the kernel and change the family (audit P-A08).
inline bool buildPairVerified(const char *kernelVersion, const char *osBuild) {
    return osBuild && *osBuild && checkBuild(kernelVersion, osBuild) == BuildCheck::Verified;
}

inline const char *buildCheckName(BuildCheck c) {
    switch (c) {
        case BuildCheck::Verified: return "verified";
        case BuildCheck::UnknownBuild: return "unknown-build";
        case BuildCheck::UnknownKernel: return "unknown-kernel";
        case BuildCheck::Expected: return "expected";   // Sequoia only
    }
    return "unknown";
}

}
