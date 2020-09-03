/*
* Copyright (C) 2020  钟先耀
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*/

#ifndef IoctlId_h
#define IoctlId_h

enum IOCTL_IDS {
    IOCTL_80211_DRIVER_INFO,
    IOCTL_80211_STA_INFO,
    IOCTL_80211_POWER,
    IOCTL_80211_STATE,
    IOCTL_80211_NW_ID,
    IOCTL_80211_WPA_KEY,
    IOCTL_80211_ASSOCIATE,
    IOCTL_80211_DISASSOCIATE,
    IOCTL_80211_JOIN,
    IOCTL_80211_SCAN,
    IOCTL_80211_SCAN_RESULT,
    IOCTL_80211_TX_POWER_LEVEL,
    
    IOCTL_ID_MAX
};

#endif /* IoctlId_h */
