//
//  IOTaskQueue.hpp
//  itlwm
//
//  Created by 钟先耀 on 2020/4/16.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef IOTaskQueue_hpp
#define IOTaskQueue_hpp

#include <IOKit/IOEventSource.h>
#include <IOKit/IOLocks.h>
#include <sys/queue.h>

typedef void (*IOTaskQueueAction)(void *);

#define TASK_ONQUEUE        1
#define SET(t, f)       (t) |= (f)
#define CLR(t, f)       (t) &= ~(f)
#define ISSET(t, f)     ((t) & (f))

struct IOTask {
    TAILQ_ENTRY(IOTask) entry_t;
    IOTaskQueueAction func_t;
    void *arg_t;
    unsigned int flag;
};

TAILQ_HEAD(io_task_queue, IOTask);

class IOTaskQueue : public IOEventSource {
    OSDeclareDefaultStructors(IOTaskQueue)
    
public:
    static IOTaskQueue *taskQueue(OSObject *inOwner);
    
    virtual kern_return_t enqueueTask(IOTask *task);
    
    virtual kern_return_t delTask(IOTask *task);
    
    virtual bool init(OSObject *inOwner);
    
    virtual void free() override;
    
    virtual bool checkForWork() override;
    
protected:
    
private:
    IOLock *entryLock;
    
    IOTask *currentTask;
    
    struct io_task_queue tq_worklist;
};

#endif /* IOTaskQueue_hpp */
