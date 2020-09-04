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

#ifdef Catalina
#include "Catalina/IO80211WorkLoop.h"
#include "Catalina/IO80211Controller.h"
#include "Catalina/IO80211Interface.h"
#include "Catalina/IO80211VirtualInterface.h"
#include "Catalina/IO80211P2PInterface.h"
#include "Catalina/IO80211SkywalkInterface.h"
#include "Catalina/IOSkywalkEthernetInterface.h"
#endif

#endif /* Apple80211_h */
