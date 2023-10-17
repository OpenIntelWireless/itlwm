//
//  Apple80211.h
//  itlwm
//
//  Created by qcwap on 2020/9/4.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef Apple80211_h
#define Apple80211_h

#include "apple_private_spi.h"
#include "debug.h"
#include "IO80211WorkLoop.h"
#ifdef IO80211FAMILY_V2
#include "IO80211WorkQueue.h"
#include "IO80211ControllerV2.h"
#include "IO80211InfraInterface.h"
#include "IO80211InfraProtocol.h"
#include "IOSkywalkPacketBufferPool.h"
#include "IOSkywalkLegacyEthernetInterface.h"
#include "IO80211SkywalkInterface.h"
#else
#include "IO80211Controller.h"
#include "IO80211Interface.h"
#include "IO80211VirtualInterface.h"
#include "IO80211P2PInterface.h"
#endif /* IO80211FAMILY_V2 */

#endif /* Apple80211_h */
