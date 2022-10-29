//
//  zutil.c
//  itlwm
//
//  Created by qcwap on 2020/9/4.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include <zutil.h>
extern "C" {
typedef struct z_mem
{
    UInt32 alloc_size;
    UInt8 data[0];
} z_mem;

void *zcalloc(void *opaque, uint items, uint size)
{
    void* result = NULL;
    z_mem* zmem = NULL;
    UInt32 allocSize =  items * size + sizeof(zmem);
    
    zmem = (z_mem*)IOMalloc(allocSize);
    
    if (zmem)
    {
        zmem->alloc_size = allocSize;
        result = (void*)&(zmem->data);
    }
    
    return result;
}

void zcfree(void *opaque, void *ptr)
{
    UInt32* skipper = (UInt32 *)ptr - 1;
    z_mem* zmem = (z_mem*)skipper;
    IOFree((void*)zmem, zmem->alloc_size);
}
}
