/*	$OpenBSD: timeout.h,v 1.29 2019/07/12 00:04:59 cheloha Exp $	*/
/*
 * Copyright (c) 2000-2001 Artur Grabowski <art@openbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL  DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SYS_TIMEOUT_H_
#define _SYS_TIMEOUT_H_


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/queue.h>            /* _Q_INVALIDATE */
#include <sys/sysctl.h>
#include <sys/_buf.h>
#include <sys/kernel.h>

#define _KERNEL
#include <sys/CTimeout.hpp>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOLocks.h>
#include <libkern/c++/OSObject.h>

void initTimeout(IOWorkLoop *workloop);
void releaseTimeout();
int splnet();
void splx(int s);
void timeout_set(CTimeout **t, void (*fn)(void *), void *arg);
int timeout_add_msec(CTimeout **to, int msecs);
int timeout_add_sec(CTimeout **to, int secs);
int timeout_add_usec(CTimeout **to, int usecs);
int timeout_del(CTimeout **to);
int timeout_pending(CTimeout **to);

#endif	/* _SYS_TIMEOUT_H_ */
