// Which macOS targets have the native AirDrop (AWDL) interface. One switch for the driver and the HAL.
#pragma once
#include <Availability.h>
#if defined(AIRPORT_WCL) && (__IO80211_TARGET == __MAC_26_0 || __IO80211_TARGET == __MAC_15_2)
#define ITL_AWDL_NATIVE 1   // Tahoe 26.x and Sequoia 15.2+ (WCL)
#elif !defined(AIRPORT_WCL) && __IO80211_TARGET == __MAC_14_4
#define ITL_AWDL_NATIVE 1   // Sonoma 14.4+ (IO80211FamilyV2 without WCL); checked against 14.8.9 (23J631)
#endif
