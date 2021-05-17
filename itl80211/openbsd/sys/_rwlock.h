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

#ifndef _rwlock_h
#define _rwlock_h

#include <IOKit/IOLocks.h>

#define RW_WRITE        0x0001UL /* exclusive lock */
#define RW_READ            0x0002UL /* shared lock */
#define RW_DOWNGRADE        0x0004UL /* downgrade exclusive to shared */
#define RW_OPMASK        0x0007UL

#define RW_INTR            0x0010UL /* interruptible sleep */
#define RW_SLEEPFAIL        0x0020UL /* fail if we slept for the lock */
#define RW_NOSLEEP        0x0040UL /* don't wait for the lock */
#define RW_RECURSEFAIL        0x0080UL /* Fail on recursion for RRW locks. */
#define RW_DUPOK        0x0100UL /* Permit duplicate lock */

/*
 * for rw_status() and rrw_status() only: exclusive lock held by
 * some other thread
 */
#define RW_WRITE_OTHER        0x0100UL

#define rw_assert_wrlock(rwl)    ((void)0)
#define rw_assert_rdlock(rwl)    ((void)0)
#define rw_assert_anylock(rwl)    ((void)0)
#define rw_assert_unlocked(rwl)    ((void)0)

struct rwlock {
    IORWLock *lock;
};

static inline void
rw_free(struct rwlock *rwl)
{
    if (rwl->lock) {
        IORWLockFree(rwl->lock);
        rwl->lock = NULL;
    }
}

static inline void
rw_init(struct rwlock *rwl, const char *name)
{
    rw_free(rwl);
    rwl->lock = IORWLockAlloc();
}

static inline void
rw_enter_read(struct rwlock *rwl)
{
    IORWLockRead(rwl->lock);
}

static inline void
rw_enter_write(struct rwlock *rwl)
{
    IORWLockWrite(rwl->lock);
}

static inline void
rw_exit_read(struct rwlock *rwl)
{
    IORWLockUnlock(rwl->lock);
}

static inline void
rw_exit_write(struct rwlock *rwl)
{
    IORWLockUnlock(rwl->lock);
}

static inline int
rw_enter(struct rwlock *rwl, int flags)
{
    if (flags & RW_WRITE)
        rw_enter_write(rwl);
    else if (flags & RW_READ)
        rw_enter_read(rwl);
    return 0;
}

static inline void
rw_exit(struct rwlock *rwl)
{
    IORWLockUnlock(rwl->lock);
}

static inline int
rw_status(struct rwlock *rwl)
{
    return 0;
}

#endif /* _rwlock_h */
