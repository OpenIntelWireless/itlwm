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

#ifndef FwData_h
#define FwData_h

#include <string.h>
#include <libkern/c++/OSData.h>

struct FwDesc {
    const char *name;
    const unsigned char *var;
    const int size;
};

#define IWL_FW(fw_name, fw_var, fw_size) \
    .name = fw_name, .var = fw_var, .size = fw_size


extern const struct FwDesc fwList[];
extern const int fwNumber;

static inline OSData *getFWDescByName(const char* name) {
    for (int i = 0; i < fwNumber; i++) {
        if (strcmp(fwList[i].name, name) == 0) {
            FwDesc desc = fwList[i];
            return OSData::withBytes(desc.var, desc.size);
        }
    }
    return NULL;
}

#endif /* FwData_h */
