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

#include "_task.h"
#include <sys/proc.h>

#include <IOKit/IOLib.h>
#include <IOKit/IOCommandGate.h>

extern IOCommandGate *_fCommandGate;

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

    lck_grp_t         *tq_grp;
    lck_grp_attr_t    *tq_grp_attr;
    lck_attr_t        *tq_attr;
    lck_mtx_t         *tq_mtx;
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

IOReturn
taskq_run(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3)
{
    struct taskq *tq = (struct taskq *)arg0;
    struct task *work = (struct task *)arg1;
    
    (*work->t_func)(work->t_arg);
    
    return kIOReturnSuccess;
}

int
taskq_next_work(struct taskq *tq, struct task *work)
{
    struct task *next;

    lck_mtx_lock(tq->tq_mtx);
retry:
    while ((next = TAILQ_FIRST(&tq->tq_worklist)) == NULL) {
        if (tq->tq_state != TQ_S_RUNNING) {
            lck_mtx_unlock(tq->tq_mtx);
            return (0);
        }

        tq->tq_waiting++;
        msleep(tq, tq->tq_mtx, PWAIT, "bored", 0);
        tq->tq_waiting--;
    }

    if (ISSET(next->t_flags, TASK_BARRIER)) {
        /*
         * Make sure all other threads are sleeping before we
         * proceed and run the barrier task.
         */
        if (++tq->tq_waiting == tq->tq_nthreads) {
            tq->tq_waiting--;
        } else {
            msleep(tq, tq->tq_mtx, PWAIT, "tqblk", 0);
            tq->tq_waiting--;
            goto retry;
        }
    }

    TAILQ_REMOVE(&tq->tq_worklist, next, t_entry);
    CLR(next->t_flags, TASK_ONQUEUE);

    *work = *next; /* copy to caller to avoid races */

    next = TAILQ_FIRST(&tq->tq_worklist);
    lck_mtx_unlock(tq->tq_mtx);

    if (next != NULL && tq->tq_nthreads > 1)
        wakeup_one((caddr_t)tq);

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

    while (taskq_next_work(tq, &work)) {
//        WITNESS_LOCK(&tq->tq_lock_object, 0);
        IOLog("itlwm: taskq worker thread=%lld work=%lld\n", thread_tid(current_thread()), &work);
        (*work.t_func)(work.t_arg);
        IOLog("itlwm: taskq worker thread=%lld work=%lld done", thread_tid(current_thread()), &work);
//        _fCommandGate->runAction(taskq_run, tq, &work);
//        WITNESS_UNLOCK(&tq->tq_lock_object, 0);
//        sched_pause(yield);
        IODelay(1);
    }

    lck_mtx_lock(tq->tq_mtx);
    last = (--tq->tq_running == 0);
    lck_mtx_unlock(tq->tq_mtx);

//    if (ISSET(tq->tq_flags, TASKQ_MPSAFE))
//        KERNEL_LOCK();

    if (last)
        wakeup_one((caddr_t)&tq->tq_running);

//    kthread_exit(0);
    thread_terminate(current_thread());
}

void taskq_create_thread(void *arg)
{
    struct taskq *tq = (struct taskq *)arg;
    int rv;
    lck_mtx_lock(tq->tq_mtx);
    switch (tq->tq_state) {
        case TQ_S_DESTROYED:
            lck_mtx_unlock(tq->tq_mtx);
            IOFree(tq, sizeof(*tq));
            return;

        case TQ_S_CREATED:
            tq->tq_state = TQ_S_RUNNING;
            break;

        default:
            panic("unexpected %s tq state %d", tq->tq_name, tq->tq_state);
    }

    do {
        tq->tq_running++;
        lck_mtx_unlock(tq->tq_mtx);

        thread_t new_thread;
        rv = kernel_thread_start((thread_continue_t)taskq_thread, tq, &new_thread);
//        rv = kthread_create(taskq_thread, tq, NULL, tq->tq_name);

        lck_mtx_lock(tq->tq_mtx);
        if (rv != KERN_SUCCESS) {
            printf("unable to create thread for \"%s\" taskq\n",
                   tq->tq_name);

            tq->tq_running--;
            /* could have been destroyed during kthread_create */
            if (tq->tq_state == TQ_S_DESTROYED &&
                tq->tq_running == 0)
                wakeup_one((caddr_t)&tq->tq_running);
            break;
        }
    } while (tq->tq_running < tq->tq_nthreads);

    lck_mtx_unlock(tq->tq_mtx);
}

void
taskq_init(void)
{
    systq->tq_attr = lck_attr_alloc_init();
    systq->tq_grp_attr = lck_grp_attr_alloc_init();
    systq->tq_grp = lck_grp_alloc_init("systq", systq->tq_grp_attr);
    systq->tq_mtx = lck_mtx_alloc_init(systq->tq_grp, systq->tq_attr);
    TAILQ_INIT(&systq->tq_worklist);
    thread_t new_thread;
    kernel_thread_start((thread_continue_t)taskq_create_thread, systq, &new_thread);
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
    tq->tq_attr = lck_attr_alloc_init();
    tq->tq_grp_attr = lck_grp_attr_alloc_init();
    tq->tq_grp = lck_grp_alloc_init("taskq", tq->tq_grp_attr);
    tq->tq_mtx = lck_mtx_alloc_init(tq->tq_grp, tq->tq_attr);

    //    mtx_init_flags(&tq->tq_mtx, ipl, name, 0);
    TAILQ_INIT(&tq->tq_worklist);
    thread_t new_thread;
    /* try to create a thread to guarantee that tasks will be serviced */
    kernel_thread_start((thread_continue_t)taskq_create_thread, tq, &new_thread);

    return (tq);
}

void
taskq_destroy(struct taskq *tq)
{
    if (!tq) {
        return;
    }
    lck_mtx_lock(tq->tq_mtx);
    switch (tq->tq_state) {
        case TQ_S_CREATED:
            /* tq is still referenced by taskq_create_thread */
            tq->tq_state = TQ_S_DESTROYED;
            lck_mtx_unlock(tq->tq_mtx);
            return;

        case TQ_S_RUNNING:
            tq->tq_state = TQ_S_DESTROYED;
            break;

        default:
            panic("unexpected %s tq state %u", tq->tq_name, tq->tq_state);
    }

    while (tq->tq_running > 0) {
        wakeup(tq);
        msleep(&tq->tq_running, tq->tq_mtx, PWAIT, "tqdestroy", 0);
    }
    lck_mtx_unlock(tq->tq_mtx);

    lck_mtx_free(tq->tq_mtx, tq->tq_grp);
    lck_grp_attr_free(tq->tq_grp_attr);
    lck_attr_free(tq->tq_attr);
    lck_grp_free(tq->tq_grp);
    if (tq != systq) {
        IOFree(tq, sizeof(*tq));
    }
    
}

void
task_set(struct task *t, void (*fn)(void *), void *arg)
{
    t->t_func = fn;
    t->t_arg = arg;
    t->t_flags = 0;
}

int
task_add(struct taskq *tq, struct task *w)
{
    int rv = 0;
//    IOLog("itlwm: taskq task_add task=%lld\n", w);
    if (ISSET(w->t_flags, TASK_ONQUEUE)) {
        IOLog("itlwm: taskq task_add is already on /queue\n");
        return (0);
    }

    lck_mtx_lock(tq->tq_mtx);
    if (!ISSET(w->t_flags, TASK_ONQUEUE)) {
//        IOLog("itlwm: taskq task_add add to queue\n");
        rv = 1;
        SET(w->t_flags, TASK_ONQUEUE);
        TAILQ_INSERT_TAIL(&tq->tq_worklist, w, t_entry);
    }
    lck_mtx_unlock(tq->tq_mtx);

    if (rv)
        wakeup_one((caddr_t)tq);

    return (rv);
}

int
task_del(struct taskq *tq, struct task *w)
{
    int rv = 0;
//    IOLog("itlwm: taskq task_del task=%lld\n", w);
    if (!ISSET(w->t_flags, TASK_ONQUEUE))
        return (0);

    lck_mtx_lock(tq->tq_mtx);
    if (ISSET(w->t_flags, TASK_ONQUEUE)) {
        rv = 1;
        CLR(w->t_flags, TASK_ONQUEUE);
        TAILQ_REMOVE(&tq->tq_worklist, w, t_entry);
    }
    lck_mtx_unlock(tq->tq_mtx);

    return (rv);
}
