//
//  apple80211.h
//  Black80211
//
//  Created by Roman Peshkov on 02/05/2018.
//  Copyright © 2018 Roman Peshkov. All rights reserved.
//

#ifndef apple80211_h
#define apple80211_h

#ifdef SIERRA
#include "apple80211/sierra/IO80211Controller.h"
#include "apple80211/sierra/IO80211WorkLoop.h"
#include "apple80211/sierra/IO80211Interface.h"
#endif

#ifdef HIGH_SIERRA
#include "apple80211/high_sierra/IO80211Controller.h"
#include "apple80211/high_sierra/IO80211WorkLoop.h"
#include "apple80211/high_sierra/IO80211Interface.h"
#endif

#ifdef CATALINA
#include "apple80211/catalina/IO80211Controller.h"
#include "apple80211/catalina/IO80211WorkLoop.h"
#include "apple80211/catalina/IO80211Interface.h"
#endif


#endif /* apple80211_h */
