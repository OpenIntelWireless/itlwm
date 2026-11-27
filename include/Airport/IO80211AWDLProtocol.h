// Selects the native declarations for the macOS version this kext is built for.
#pragma once
#if __IO80211_TARGET == __MAC_14_4
#include "macOS14/IO80211AWDLProtocol.h"   // Sonoma 14.8.9 (23J631)
#elif __IO80211_TARGET == __MAC_15_2
#include "macOS15/IO80211AWDLProtocol.h"
#else
#include "macOS26/IO80211AWDLProtocol.h"
#endif
