//
//  _task.cpp
//  itlwm
//
//  Created by qcwap on 2020/3/1.
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

#include <sys/_task.h>
#include <sys/proc.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOCommandGate.h>

enum ETQ_STATE {
    TQ_S_CREATED,
    TQ_S_RUNNING,
    TQ_S_DESTROYED
};

struct taskq {
    enum ETQ_STATE       tq_state;
    unsigned int         tq_running;
    unsigned int         tq_waiting;
    unsigned int         tq_nthreads;
    unsigned int         tq_flags;
    const char        *tq_name;

    IORecursiveLock *tq_mtx;
    struct task_list     tq_worklist;
};

static const char taskq_sys_name[] = "systq";

struct taskq taskq_sys = {
    TQ_S_CREATED,
    0,
    0,
    1,
    0,
    taskq_sys_name,
};

struct taskq *const systq = &taskq_sys;

int
taskq_next_work(struct taskq *tq, struct task *work)
{
    struct task *next;
    
    //    IOLog("itlwm: taskq %s lock\n", __FUNCTION__);
    IORecursiveLockLock(tq->tq_mtx);
    
    while ((next = TAILQ_FIRST(&tq->tq_worklist)) == NULL) {
        if (tq->tq_state != TQ_S_RUNNING) {
            IORecursiveLockUnlock(tq->tq_mtx);
            return (0);
        }
        IORecursiveLockSleep(tq->tq_mtx, tq, THREAD_INTERRUPTIBLE);
    }

    TAILQ_REMOVE(&tq->tq_worklist, next, t_entry);
    CLR(next->t_flags, TASK_ONQUEUE);

    *work = *next; /* copy to caller to avoid races */

    next = TAILQ_FIRST(&tq->tq_worklist);
    IORecursiveLockUnlock(tq->tq_mtx);
//    IOLog("itlwm: taskq %s unlock\n", __FUNCTION__);

    if (next != NULL && tq->tq_nthreads > 1)
        IORecursiveLockWakeup(tq->tq_mtx, tq, true);

    return (1);
}

void
taskq_thread(void *xtq)
{
    struct taskq *tq = (struct taskq *)xtq;
    struct task work;
    int last;

//    if (ISSET(tq->tq_flags, TASKQ_MPSAFE))
//        KERNEL_UNLOCK();

//    WITNESS_CHECKORDER(&tq->tq_lock_object, LOP_NEWORDER, NULL);
    
    IOLog("itlwm: taskq %s schedule task\n", __FUNCTION__);

    while (taskq_next_work(tq, &work)) {
//        WITNESS_LOCK(&tq->tq_lock_object, 0);
//        IOLog("itlwm: taskq worker thread=%lld work=%s\n", thread_tid(current_thread()), work.name);
        (*work.t_func)(work.t_arg);
//        IOLog("itlwm: taskq worker thread=%lld work=%s done", thread_tid(current_thread()), work.name);
//        WITNESS_UNLOCK(&tq->tq_lock_object, 0);
//        sched_pause(yield);
        IOSleep(1);
    }
    
    IOLog("itlwm: taskq %s schedule task done\n", __FUNCTION__);

    IORecursiveLockLock(tq->tq_mtx);
    last = (--tq->tq_running == 0);
    IORecursiveLockUnlock(tq->tq_mtx);

//    if (ISSET(tq->tq_flags, TASKQ_MPSAFE))
//        KERNEL_LOCK();

    if (last) {
        IOLog("itlwm: taskq %s schedule task wakeup\n", __FUNCTION__);
        IORecursiveLockWakeup(tq->tq_mtx, tq, false);
    }

//    kthread_exit(0);
    thread_terminate(current_thread());
}

void taskq_create_thread(void *arg)
{
    struct taskq *tq = (struct taskq *)arg;
    int rv;
    IOLog("itlwm: taskq %s lock\n", __FUNCTION__);
    IORecursiveLockLock(tq->tq_mtx);
    switch (tq->tq_state) {
        case TQ_S_DESTROYED:
            IOLog("itlwm: taskq %s unlock\n", __FUNCTION__);
            IORecursiveLockUnlock(tq->tq_mtx);
            if (tq != systq) {
                IORecursiveLockFree(tq->tq_mtx);
                IOFree(tq, sizeof(*tq));
            }
            return;

        case TQ_S_CREATED:
            tq->tq_state = TQ_S_RUNNING;
            break;

        default:
            IOLog("itlwm: unexpected %s tq state %u", tq->tq_name, tq->tq_state);
            IORecursiveLockUnlock(tq->tq_mtx);
            if (tq != systq) {
                IORecursiveLockFree(tq->tq_mtx);
                IOFree(tq, sizeof(*tq));
            }
            return;
    }

    do {
        tq->tq_running++;
        IOLog("itlwm: taskq %s unlock\n", __FUNCTION__);
        IORecursiveLockUnlock(tq->tq_mtx);

        thread_t new_thread;
        rv = kernel_thread_start((thread_continue_t)taskq_thread, tq, &new_thread);
        thread_deallocate(new_thread);

        IOLog("itlwm: taskq %s lock\n", __FUNCTION__);
        IORecursiveLockLock(tq->tq_mtx);
        if (rv != KERN_SUCCESS) {
            IOLog("itlwm: tasq unable to create thread for \"%s\" taskq\n",
                   tq->tq_name);

            tq->tq_running--;
            /* could have been destroyed during kthread_create */
            if (tq->tq_state == TQ_S_DESTROYED &&
                tq->tq_running == 0)
                IORecursiveLockWakeup(tq->tq_mtx, tq, false);
            break;
        }
    } while (tq->tq_running < tq->tq_nthreads);
    
    IOLog("itlwm: taskq %s unlock\n", __FUNCTION__);
    IORecursiveLockUnlock(tq->tq_mtx);
}

void
taskq_init(void)
{
    systq->tq_mtx = IORecursiveLockAlloc();
    TAILQ_INIT(&systq->tq_worklist);
    thread_t new_thread;
    kernel_thread_start((thread_continue_t)taskq_create_thread, systq, &new_thread);
    thread_deallocate(new_thread);
}

struct taskq *
taskq_create(const char *name, unsigned int nthreads, int ipl,
             unsigned int flags)
{
    struct taskq *tq;

    tq = (struct taskq *)IOMalloc(sizeof(*tq));
    if (tq == NULL)
        return (NULL);

    tq->tq_state = TQ_S_CREATED;
    tq->tq_running = 0;
    tq->tq_waiting = 0;
    tq->tq_nthreads = nthreads;
    tq->tq_name = name;
    tq->tq_flags = flags;
    tq->tq_mtx = IORecursiveLockAlloc();

    //    mtx_init_flags(&tq->tq_mtx, ipl, name, 0);
    TAILQ_INIT(&tq->tq_worklist);
    thread_t new_thread;
    /* try to create a thread to guarantee that tasks will be serviced */
    kernel_thread_start((thread_continue_t)taskq_create_thread, tq, &new_thread);
    thread_deallocate(new_thread);
    return (tq);
}

void
taskq_destroy(struct taskq *tq)
{
    if (!tq || !tq->tq_mtx) {
        return;
    }
    IORecursiveLockLock(tq->tq_mtx);
    switch (tq->tq_state) {
        case TQ_S_CREATED:
            /* tq is still referenced by taskq_create_thread */
            tq->tq_state = TQ_S_DESTROYED;
            IORecursiveLockUnlock(tq->tq_mtx);
            return;

        case TQ_S_RUNNING:
            tq->tq_state = TQ_S_DESTROYED;
            break;

        default:
            IOLog("itlwm: unexpected %s tq state %u", tq->tq_name, tq->tq_state);
            tq->tq_state = TQ_S_DESTROYED;
            IORecursiveLockUnlock(tq->tq_mtx);
            return;
    }

    while (tq->tq_running > 0) {
        IORecursiveLockWakeup(tq->tq_mtx, tq, false);
        IORecursiveLockSleep(tq->tq_mtx, tq, THREAD_INTERRUPTIBLE);
    }

    IORecursiveLockUnlock(tq->tq_mtx);
    IORecursiveLockFree(tq->tq_mtx);
    if (tq != systq) {
        IOFree(tq, sizeof(*tq));
    }
    
}

void
task_set(struct task *t, void (*fn)(void *), void *arg, const char *name)
{
    t->t_func = fn;
    t->t_arg = arg;
    t->t_flags = 0;
    memcpy(t->name, name, sizeof(t->name));
}

int
task_add(struct taskq *tq, struct task *w)
{
    int rv = 0;
//    IOLog("itlwm: taskq task_add %s thread: %lld\n", w->name, thread_tid(current_thread()));
    
    if (ISSET(w->t_flags, TASK_ONQUEUE))
        return (0);

    IORecursiveLockLock(tq->tq_mtx);
    if (ISSET(w->t_flags, TASK_ONQUEUE)) {
//        IOLog("itlwm: taskq task_add %s is already on queue thread: %lld\n", w->name, thread_tid(current_thread()));
        IORecursiveLockUnlock(tq->tq_mtx);
        return (0);
    }
    if (!ISSET(w->t_flags, TASK_ONQUEUE)) {
//        IOLog("itlwm: taskq task_add %s add to queue thread: %lld\n", w->name, thread_tid(current_thread()));
        rv = 1;
        SET(w->t_flags, TASK_ONQUEUE);
        TAILQ_INSERT_TAIL(&tq->tq_worklist, w, t_entry);
    }
    IORecursiveLockUnlock(tq->tq_mtx);

    if (rv)
        IORecursiveLockWakeup(tq->tq_mtx, tq, true);

    return (rv);
}

int
task_del(struct taskq *tq, struct task *w)
{
    int rv = 0;
//    IOLog("itlwm: taskq task_del %s thread: %lld\n", w->name, thread_tid(current_thread()));
    
    if (!ISSET(w->t_flags, TASK_ONQUEUE))
        return (0);

    IORecursiveLockLock(tq->tq_mtx);
    if (ISSET(w->t_flags, TASK_ONQUEUE)) {
        rv = 1;
        CLR(w->t_flags, TASK_ONQUEUE);
        TAILQ_REMOVE(&tq->tq_worklist, w, t_entry);
    }
    IORecursiveLockUnlock(tq->tq_mtx);

    return (rv);
}
