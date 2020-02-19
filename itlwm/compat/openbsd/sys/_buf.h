//
//  _buf.h
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/25.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef _buf_h
#define _buf_h

/* Macros to clear/set/test flags. */
#define SET(t, f)       (t) |= (f)
#define CLR(t, f)       (t) &= ~(f)
#define ISSET(t, f)     ((t) & (f))

#endif /* _buf_h */
