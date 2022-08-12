//
//  _malloc.h
//  itlwm
//
//  Created by qcwap on 2020/7/24.
//  Copyright © 2020 钟先耀. All rights reserved.
//
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

#ifndef _malloc_h
#define _malloc_h

#include <IOKit/IOLib.h>

static inline void*
malloc(vm_size_t len, int type, int how)
{
    void* addr = IOMalloc(len + sizeof(vm_size_t));
    if (addr == NULL) {
        return NULL;
    }
    *((vm_size_t*) addr) = len;
    void *buf = (void*)((uint8_t*)addr + sizeof(vm_size_t));
    bzero(buf, len);
    return buf;
}

static inline void
free(void* addr)
{
    if (addr == NULL) {
        return;
    }
    void* actual_addr = (void*)((uint8_t*)addr - sizeof(vm_size_t));
    vm_size_t len = *((vm_size_t*) actual_addr);
    IOFree(actual_addr, len + sizeof(vm_size_t));
}

static inline void
free(void *addr, int type, int flags)
{
    free(addr);
}

#endif /* _malloc_h */
