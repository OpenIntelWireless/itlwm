//
//  _string.h
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/30.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef _string_c
#define _string_c

#include <string.h>
#include <sys/syslog.h>
#include <IOKit/IOLib.h>

int timingsafe_bcmp(const void *b1, const void *b2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)b1, *p2 = (const unsigned char *)b2;
    int ret = 0;

    for (; n > 0; n--)
        ret |= *p1++ ^ *p2++;
    return (ret != 0);
}




#endif /* _string_c */
