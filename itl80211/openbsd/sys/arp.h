//
//  arp.h
//  itlwm
//
//  Created by zxystd on 2023/7/1.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#ifndef arp_h
#define arp_h

#include <sys/kpi_mbuf.h>

void debug_print_arp(const char *tag, mbuf_t m);

#endif /* arp_h */
