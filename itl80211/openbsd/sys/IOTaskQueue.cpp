//
//  IOTaskQueue.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/4/16.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "IOTaskQueue.hpp"

#define super IOEventSource
OSDefineMetaClassAndStructors(IOTaskQueue, IOEventSource)

IOTaskQueue *IOTaskQueue::taskQueue(OSObject *inOwner)
{
    IOTaskQueue *tq = new IOTaskQueue;
    if (!tq) {
        return NULL;
    }
    if (!tq->init(inOwner)) {
        tq->free();
        return NULL;
    }
    return tq;
}

bool IOTaskQueue::init(OSObject *inOwner)
{
    if (!super::init(inOwner))
        return false;
    entryLock = IOLockAlloc();
    if (!entryLock) {
        return false;
    }
    TAILQ_INIT(&tq_worklist);
    return true;
}

void IOTaskQueue::free()
{
    if (entryLock) {
        IOLockFree(entryLock);
        entryLock = NULL;
    }
}

bool IOTaskQueue::checkForWork()
{
    IOLog("itlwm: IOTaskQueue::%s\n", __FUNCTION__);
    if (!isEnabled()) {
        IOLog("itlwm: IOTaskQueue::%s !isEnabled()\n", __FUNCTION__);
        return false;
    }
    if (currentTask == NULL) {
        currentTask = TAILQ_FIRST(&tq_worklist);
        if (currentTask == NULL) {
            IOLog("itlwm: IOTaskQueue::%s TAILQ_FIRST currentTask == NULL\n", __FUNCTION__);
            return false;
        }
    } else {
        currentTask = TAILQ_NEXT(currentTask, entry_t);
        if (currentTask == NULL) {
            IOLog("itlwm: IOTaskQueue::%s TAILQ_NEXT currentTask == NULL\n", __FUNCTION__);
            return true;
        }
    }
    IOLog("itlwm: IOTaskQueue::%s execute\n", __FUNCTION__);
    (*(IOTaskQueueAction) currentTask->func_t)(currentTask->arg_t);
    return true;
}

kern_return_t IOTaskQueue::delTask(IOTask *task)
{
    IOLog("itlwm: IOTaskQueue::%s\n", __FUNCTION__);
    IOTakeLock(entryLock);
    if (!ISSET(task->flag, TASK_ONQUEUE)) {
        IOLog("itlwm: IOTaskQueue::delTask is already delete\n");
        IOUnlock(entryLock);
        return kIOReturnSuccess;
    }
    IOLog("itlwm: IOTaskQueue::delTask done\n");
    CLR(task->flag, TASK_ONQUEUE);
    TAILQ_REMOVE(&tq_worklist, task, entry_t);
    IOUnlock(entryLock);
    return kIOReturnSuccess;
}

kern_return_t IOTaskQueue::enqueueTask(IOTask *task)
{
    IOLog("itlwm: IOTaskQueue::%s\n", __FUNCTION__);
    IOTakeLock(entryLock);
    if (ISSET(task->flag, TASK_ONQUEUE)) {
        IOLog("itlwm: IOTaskQueue::enqueueTask is already on queue\n");
        IOUnlock(entryLock);
        signalWorkAvailable();
        return kIOReturnSuccess;
    }
    SET(task->flag, TASK_ONQUEUE);
    TAILQ_INSERT_TAIL(&tq_worklist, task, entry_t);
    IOUnlock(entryLock);
    signalWorkAvailable();
    return kIOReturnSuccess;
}
