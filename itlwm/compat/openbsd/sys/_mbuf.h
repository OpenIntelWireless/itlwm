//
//  mbuf.h
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/22.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef _mbuf_h
#define _mbuf_h

#include <sys/mbuf.h>
#include <sys/kpi_mbuf.h>
#include <IOKit/network/IOPacketQueue.h>

#define IPL_NET        6

#define    mtod(x,t)    ((t) mbuf_data(x))
#define    ml_len(_ml)        ((_ml)->ml_len)
#define    ml_empty(_ml)        ((_ml)->ml_len == 0)

#define MBUF_LIST_FIRST(_ml)    ((_ml)->ml_head)
#define MBUF_LIST_NEXT(_m)    (mbuf_nextpkt((_m)))

#define MBUF_LIST_FOREACH(_ml, _m)                    \
    for ((_m) = MBUF_LIST_FIRST(_ml);                \
        (_m) != NULL;                        \
        (_m) = MBUF_LIST_NEXT(_m))

#define    mq_len(_mq)        ml_len(&(_mq)->mq_list)
#define    mq_empty(_mq)        ml_empty(&(_mq)->mq_list)
#define    mq_full(_mq)        (mq_len((_mq)) >= (_mq)->mq_maxlen)
#define    mq_drops(_mq)        ((_mq)->mq_drops)
#define    mq_set_maxlen(_mq, _l)    ((_mq)->mq_maxlen = (_l))

//uipc_mbuf.c

struct mbuf_list {
    mbuf_t ml_head;
    mbuf_t ml_tail;
    u_int  ml_len;
};

struct mbuf_queue {
    IOLock*        mq_mtx;
    struct mbuf_list    mq_list;
    u_int            mq_maxlen;
    u_int            mq_drops;
};

/*
 * mbuf lists
 */

#define MBUF_LIST_INITIALIZER() { NULL, NULL, 0 }

#define MBUF_QUEUE_INITIALIZER(_maxlen, _ipl) \
{ MUTEX_INITIALIZER(_ipl), MBUF_LIST_INITIALIZER(), (_maxlen), 0 }

static inline void
ml_init(struct mbuf_list *ml)
{
    ml->ml_head = ml->ml_tail = NULL;
    ml->ml_len = 0;
}

static inline void
ml_enqueue(struct mbuf_list *ml, mbuf_t m)
{
    if (ml->ml_tail == NULL)
        ml->ml_head = ml->ml_tail = m;
    else {
        mbuf_setnextpkt(ml->ml_tail, m);
        ml->ml_tail = m;
    }

    mbuf_setnextpkt(m, NULL);
    ml->ml_len++;
}

static inline void
ml_enlist(struct mbuf_list *mla, struct mbuf_list *mlb)
{
    if (!ml_empty(mlb)) {
        if (ml_empty(mla))
            mla->ml_head = mlb->ml_head;
        else
            mbuf_setnextpkt(mla->ml_tail, mlb->ml_head);
        mla->ml_tail = mlb->ml_tail;
        mla->ml_len += mlb->ml_len;

        ml_init(mlb);
    }
}

static inline mbuf_t
ml_dequeue(struct mbuf_list *ml)
{
    mbuf_t m;

    m = ml->ml_head;
    if (m != NULL) {
        ml->ml_head = mbuf_nextpkt(m);
        if (ml->ml_head == NULL)
            ml->ml_tail = NULL;

        mbuf_setnextpkt(m, NULL);
        ml->ml_len--;
    }

    return (m);
}

static inline mbuf_t
ml_dechain(struct mbuf_list *ml)
{
    mbuf_t m0;

    m0 = ml->ml_head;

    ml_init(ml);

    return (m0);
}

static inline unsigned int
ml_purge(struct mbuf_list *ml)
{
    mbuf_t m, n;
    unsigned int len;

    for (m = ml->ml_head; m != NULL; m = n) {
        n = mbuf_nextpkt(m);
        mbuf_freem(m);
    }

    len = ml->ml_len;
    ml_init(ml);

    return (len);
}

/*
 * mbuf queues
 */

static inline void
mq_init(struct mbuf_queue *mq, u_int maxlen, int ipl)
{
    mq->mq_mtx = IOLockAlloc();
    ml_init(&mq->mq_list);
    mq->mq_maxlen = maxlen;
}

static inline int
mq_enqueue(struct mbuf_queue *mq, mbuf_t m)
{
    int dropped = 0;

    IOLockLock(mq->mq_mtx);
    
    if (mq_len(mq) < mq->mq_maxlen)
        ml_enqueue(&mq->mq_list, m);
    else {
        mq->mq_drops++;
        dropped = 1;
    }
    IOLockUnlock(mq->mq_mtx);

    if (dropped)
        mbuf_freem(m);

    return (dropped);
}

static inline mbuf_t
mq_dequeue(struct mbuf_queue *mq)
{
    mbuf_t m;

    IOLockLock(mq->mq_mtx);
    m = ml_dequeue(&mq->mq_list);
    IOLockUnlock(mq->mq_mtx);

    return (m);
}

static inline int
mq_enlist(struct mbuf_queue *mq, struct mbuf_list *ml)
{
    mbuf_t m;
    int dropped = 0;

    IOLockLock(mq->mq_mtx);
    if (mq_len(mq) < mq->mq_maxlen)
        ml_enlist(&mq->mq_list, ml);
    else {
        dropped = ml_len(ml);
        mq->mq_drops += dropped;
    }
    IOLockUnlock(mq->mq_mtx);

    if (dropped) {
        while ((m = ml_dequeue(ml)) != NULL)
            mbuf_freem(m);
    }

    return (dropped);
}

static inline void
mq_delist(struct mbuf_queue *mq, struct mbuf_list *ml)
{
    IOLockLock(mq->mq_mtx);
    *ml = mq->mq_list;
    ml_init(&mq->mq_list);
    IOLockUnlock(mq->mq_mtx);
}

static inline mbuf_t
mq_dechain(struct mbuf_queue *mq)
{
    mbuf_t m0;

    IOLockLock(mq->mq_mtx);
    m0 = ml_dechain(&mq->mq_list);
    IOLockUnlock(mq->mq_mtx);

    return (m0);
}

static inline unsigned int
mq_purge(struct mbuf_queue *mq)
{
    struct mbuf_list ml;
    
    mq_delist(mq, &ml);

    return (ml_purge(&ml));
}

/*
 * Concatenate mbuf chain n to m.
 * n might be copied into m (when n->m_len is small), therefore data portion of
 * n could be copied into an mbuf of different mbuf type.
 * Therefore both chains should be of the same type (e.g. MT_DATA).
 * Any m_pkthdr is not updated.
 */
static inline void
m_cat(mbuf_t m, mbuf_t n)
{
    while (mbuf_next(m))
        m = mbuf_next(m);
    while (n) {
        if (mbuf_len(n) > mbuf_trailingspace(m)) {
            /* just join the two chains */
            mbuf_setnext(m, n);
            return;
        }
        /* splat the data from one into the other */
        memcpy(mtod(m, caddr_t) + mbuf_len(m), mtod(n, caddr_t),
            mbuf_len(n));
        mbuf_setlen(m, mbuf_len(m) + mbuf_len(n));
        n = mbuf_free(n);
    }
}

static IOLock *inputLock = IOLockAlloc();

static inline int if_input(struct ifnet *ifq, struct mbuf_list *ml)
{
    mbuf_t m;
    uint64_t packets;
    if (ml_empty(ml))
        return (0);
    IOLockLock(inputLock);
    MBUF_LIST_FOREACH(ml, m) {
        ifq->iface->inputPacket(m);
    }
    IOLockUnlock(inputLock);
    return 0;
}

static inline int if_enqueue(struct ifnet *ifq, mbuf_t m)
{
    ifq->output_queue->enqueue(m, NULL);
    return 0;
}

#endif /* _mbuf_h */
