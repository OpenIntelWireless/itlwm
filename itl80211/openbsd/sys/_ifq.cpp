//
//  _ifq.cpp
//  itlwm
//
//  Created by zxystd on 2022/8/13.
//  Copyright © 2022 钟先耀. All rights reserved.
//

#include <sys/_ifq.h>

void ifq_init(struct _ifqueue *ifq, struct _ifnet *ifp, unsigned int maxLen)
{
    if (!ifq->queue)
        ifq->queue = IOPacketQueue::withCapacity(maxLen);
    else
        ifq->queue->setCapacity(maxLen);
    ifq->ifq_oactive = 0;
}

void ifq_destroy(struct _ifqueue *ifq)
{
    if (ifq->queue) {
        ifq->queue->release();
        ifq->queue = nullptr;
    }
}

void ifq_flush(struct _ifqueue *ifq)
{
    if (ifq->queue)
        ifq->queue->lockFlush();
}

bool ifq_empty(struct _ifqueue *ifq)
{
    return ifq->queue->getSize() == 0;
}

uint32_t ifq_len(struct _ifqueue *ifq)
{
    return ifq->queue->getSize();
}

void ifq_set_maxlen(struct _ifqueue *ifq, uint32_t maxLen)
{
    ifq->queue->setCapacity(maxLen);
}

void ifq_set_oactive(struct _ifqueue *ifq)
{
    ifq->ifq_oactive = 1;
}

unsigned int ifq_is_oactive(struct _ifqueue *ifq)
{
    return ifq->ifq_oactive;
}

void ifq_clr_oactive(struct _ifqueue *ifq)
{
    ifq->ifq_oactive = 0;
}

mbuf_t ifq_dequeue(struct _ifqueue *ifq)
{
    return ifq->queue->lockDequeue();
}

int ifq_enqueue(struct _ifqueue *ifq, mbuf_t m)
{
    ifq->queue->lockEnqueueWithDrop(m);
    return 0;
}
