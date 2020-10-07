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

#ifndef ItlDriverInfo_h
#define ItlDriverInfo_h

class ItlDriverInfo {
    
public:
    
    virtual const char *getFirmwareVersion() = 0;
    
    virtual int16_t getBSSNoise() = 0;
    
    virtual bool is5GBandSupport() = 0;
    
    virtual int getTxNSS() = 0;
    
    virtual const char *getFirmwareName() = 0;
    
    virtual UInt32 supportedFeatures() = 0;
};

#endif /* ItlDriverInfo_h */
