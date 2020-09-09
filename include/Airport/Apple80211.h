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

#ifdef Mojave
#include "Mojave/IO80211WorkLoop.h"
#include "Mojave/IO80211Controller.h"
#include "Mojave/IO80211Interface.h"
#include "Mojave/IO80211VirtualInterface.h"
#include "Mojave/IO80211P2PInterface.h"
#endif

#ifdef Catalina
#include "Catalina/IO80211WorkLoop.h"
#include "Catalina/IO80211Controller.h"
#include "Catalina/IO80211Interface.h"
#include "Catalina/IO80211VirtualInterface.h"
#include "Catalina/IO80211P2PInterface.h"
#include "Catalina/IO80211SkywalkInterface.h"
#include "Catalina/IOSkywalkEthernetInterface.h"
#endif

#ifdef BigSur
#include "BigSur/IO80211WorkLoop.h"
#include "BigSur/IO80211Controller.h"
#include "BigSur/IO80211Interface.h"
#include "BigSur/IO80211VirtualInterface.h"
#include "BigSur/IO80211P2PInterface.h"
#include "BigSur/IO80211SkywalkInterface.h"
#include "BigSur/IOSkywalkEthernetInterface.h"
#endif

#endif /* Apple80211_h */
