// Selects the native declarations for the macOS version this kext is built for.
#pragma once
#if __IO80211_TARGET == __MAC_14_4
#include "macOS15/IOSkywalkPacketView.h"   // Sonoma 14.8.9 (23J631)
#elif __IO80211_TARGET == __MAC_15_2
#include "macOS15/IOSkywalkPacketView.h"
#else
#include "macOS26/IOSkywalkPacketView.h"
#endif
