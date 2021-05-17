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

#ifndef IOEventLock_hpp
#define IOEventLock_hpp

#include <IOKit/IOEventSource.h>

class IOEventLock : public IOEventSource {
    OSDeclareDefaultStructors(IOEventLock)
    
public:
    
    virtual void free( void ) APPLE_KEXT_OVERRIDE;
    
    bool init(OSObject *owner);
    
    void lock();
    
    void unlock();
    
public:
    
};

#endif /* IOEventLock_hpp */
