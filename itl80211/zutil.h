//
//  zutil.h
//  itlwm
//
//  Created by qcwap on 2020/9/4.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef zutil_h
#define zutil_h

#include <IOKit/IOLib.h>
#include <IOKit/IOTypes.h>

extern "C" {
void *zcalloc(void *opaque, uint items, uint size);

void zcfree(void *opaque, void *ptr);
}

#endif /* zutil_h */
