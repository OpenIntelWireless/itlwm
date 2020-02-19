//
//  skbuff.h
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/22.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef skbuff_h
#define skbuff_h

#include <linux/types.h>
#include <IOKit/IOLocks.h>

struct sk_buff {
    
    void *cb;
    void *data;
};

struct sk_buff_head {
    struct sk_buff    *next;
    struct sk_buff    *prev;
    __u32        qlen;
    IOSimpleLock*    lock;
};

#endif /* skbuff_h */
