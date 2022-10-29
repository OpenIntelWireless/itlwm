/*
* Copyright (C) 2021  钟先耀
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

#ifndef _clock_h
#define _clock_h

#include <sys/time.h>

#define hz  100
#define ticks   \
({  \
uint64_t t; \
uint64_t k;  \
clock_get_uptime(&t);   \
absolutetime_to_nanoseconds(t, &k);  \
(int)((k * hz) / 1000000000);  \
})

#endif /* _clock_h */
