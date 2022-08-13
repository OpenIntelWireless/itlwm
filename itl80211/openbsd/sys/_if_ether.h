//
//  _if_ether.h
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/22.
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
/*    $OpenBSD: if_ether.h,v 1.76 2019/07/17 16:46:18 mpi Exp $    */
/*    $NetBSD: if_ether.h,v 1.22 1996/05/11 13:00:00 mycroft Exp $    */

/*
 * Copyright (c) 1982, 1986, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *    @(#)if_ether.h    8.1 (Berkeley) 6/10/93
 */

#ifndef _if_ether_h
#define _if_ether_h

#include <net/if.h>
#include <net/if_var.h>
#include <sys/queue.h>
#include <sys/CTimeout.hpp>
#include <sys/_if_media.h>
#include <sys/_ifq.h>
#include <net/if_dl.h>

#include <IOKit/network/IOPacketQueue.h>
#include <IOKit/network/IOEthernetInterface.h>

#define    ETHER_IS_MULTICAST(addr) (*(addr) & 0x01) /* is address mcast/bcast? */
#define    ETHER_IS_BROADCAST(addr) \
    (((addr)[0] & (addr)[1] & (addr)[2] & \
      (addr)[3] & (addr)[4] & (addr)[5]) == 0xff)
#define    ETHER_IS_ANYADDR(addr)        \
    (((addr)[0] | (addr)[1] | (addr)[2] | \
      (addr)[3] | (addr)[4] | (addr)[5]) == 0x00)
#define    ETHER_IS_EQ(a1, a2)    (memcmp((a1), (a2), ETHER_ADDR_LEN) == 0)

#define ETHER_ADDR_LEN 6

/*
 * Ethernet CRC32 polynomials (big- and little-endian verions).
 */
#define    ETHER_CRC_POLY_LE    0xedb88320
#define    ETHER_CRC_POLY_BE    0x04c11db6

/*
 * Values for if_link_state.
 */
#define LINK_STATE_UNKNOWN    0    /* link unknown */
#define LINK_STATE_INVALID    1    /* link invalid */
#define LINK_STATE_DOWN        2    /* link is down */
#define LINK_STATE_KALIVE_DOWN    3    /* keepalive reports down */
#define LINK_STATE_UP        4    /* link is up */
#define LINK_STATE_HALF_DUPLEX    5    /* link is up and half duplex */
#define LINK_STATE_FULL_DUPLEX    6    /* link is up and full duplex */

#define LINK_STATE_IS_UP(_s)    \
        ((_s) >= LINK_STATE_UP || (_s) == LINK_STATE_UNKNOWN)

#define splassert(x) (x)


/*
 * Status bit descriptions for the various interface types.
 */
struct if_status_description {
    u_char    ifs_type;
    u_char    ifs_state;
    const char *ifs_string;
};

#define LINK_STATE_DESC_MATCH(_ifs, _t, _s)                \
    (((_ifs)->ifs_type == (_t) || (_ifs)->ifs_type == 0) &&        \
        (_ifs)->ifs_state == (_s))


#define LINK_STATE_DESCRIPTIONS {                    \
    { IFT_ETHER, LINK_STATE_DOWN, "no carrier" },            \
                                    \
    { IFT_IEEE80211, LINK_STATE_DOWN, "no network" },        \
                                    \
    { IFT_PPP, LINK_STATE_DOWN, "no carrier" },            \
                                    \
    { IFT_CARP, LINK_STATE_DOWN, "backup" },            \
    { IFT_CARP, LINK_STATE_UP, "master" },                \
    { IFT_CARP, LINK_STATE_HALF_DUPLEX, "master" },            \
    { IFT_CARP, LINK_STATE_FULL_DUPLEX, "master" },            \
                                    \
    { 0, LINK_STATE_UP, "active" },                    \
    { 0, LINK_STATE_HALF_DUPLEX, "active" },            \
    { 0, LINK_STATE_FULL_DUPLEX, "active" },            \
                                    \
    { 0, LINK_STATE_UNKNOWN, "unknown" },                \
    { 0, LINK_STATE_INVALID, "invalid" },                \
    { 0, LINK_STATE_DOWN, "down" },                    \
    { 0, LINK_STATE_KALIVE_DOWN, "keepalive down" },        \
    { 0, 0, NULL }                            \
}

/*
 * Length of interface description, including terminating '\0'.
 */
#define    IFDESCRSIZE    64

/*
 * Ethernet multicast address structure.  There is one of these for each
 * multicast address or range of multicast addresses that we are supposed
 * to listen to on a particular interface.  They are kept in a linked list,
 * rooted in the interface's arpcom structure.  (This really has nothing to
 * do with ARP, or with the Internet address family, but this appears to be
 * the minimally-disrupting place to put it.)
 */
struct ether_multi {
    u_int8_t enm_addrlo[ETHER_ADDR_LEN]; /* low  or only address of range */
    u_int8_t enm_addrhi[ETHER_ADDR_LEN]; /* high or only address of range */
    u_int     enm_refcount;        /* no. claims to this addr/range */
    LIST_ENTRY(ether_multi) enm_list;
};

struct _ifnet {                /* and the entries */
    IOEthernetInterface *iface;
    IOEthernetController* controller;
    int if_link_state;
    void *if_softc;
//    struct    refcnt if_refcnt;
    int if_hdrlen;
    TAILQ_ENTRY(_ifnet) if_list;    /* [k] all struct ifnets are chained */
    TAILQ_HEAD(, ifaddr) if_addrlist; /* [N] list of addresses per if */
    TAILQ_HEAD(, ifmaddr) if_maddrlist; /* [N] list of multicast records */
    TAILQ_HEAD(, ifg_list) if_groups; /* [N] list of groups per if */
//    struct hook_desc_head *if_addrhooks; /* [I] address change callbacks */
//    struct hook_desc_head *if_linkstatehooks; /* [I] link change callbacks*/
//    struct hook_desc_head *if_detachhooks; /* [I] detach callbacks */
                /* [I] check or clean routes (+ or -)'d */
    void    (*if_rtrequest)(struct _ifnet *, int, struct rtentry *);
    char    if_xname[IFNAMSIZ];    /* [I] external name (name + unit) */
    int    if_pcount;        /* [k] # of promiscuous listeners */
    unsigned int if_bridgeidx;    /* [k] used by bridge ports */
    caddr_t    if_bpf;            /* packet filter structure */
    caddr_t if_switchport;        /* used by switch ports */
    caddr_t if_mcast;        /* used by multicast code */
    caddr_t if_mcast6;        /* used by IPv6 multicast code */
    caddr_t    if_pf_kif;        /* pf interface abstraction */
    
    IONetworkStats *netStat;
    ///extra
    uint32_t if_ierrors;
    uint32_t if_oerrors;
    uint32_t if_ipackets;
    uint32_t if_imcasts;
    int if_ibytes;
    
    
//    union {
//        struct srpl carp_s;    /* carp if list (used by !carp ifs) */
//        struct _ifnet *carp_d;    /* ptr to carpdev (used by carp ifs) */
//    } if_carp_ptr;
#define if_carp        if_carp_ptr.carp_s
#define if_carpdev    if_carp_ptr.carp_d
    unsigned int if_index;        /* [I] unique index for this if */
    short    if_timer;        /* time 'til if_watchdog called */
    unsigned short if_flags;    /* [N] up/down, broadcast, etc. */
    int    if_xflags;        /* [N] extra softnet flags */
    struct    if_data if_data;    /* stats and other data about if */
    struct    cpumem *if_counters;    /* per cpu stats */
    uint32_t if_hardmtu;        /* [d] maximum MTU device supports */
    char    if_description[IFDESCRSIZE]; /* [c] interface description */
    u_short    if_rtlabelid;        /* [c] next route label */
    uint8_t if_priority;        /* [c] route priority offset */
    uint8_t if_llprio;        /* [N] link layer priority */
    CTimeout* if_slowtimo;    /* [I] watchdog timeout */
//    struct    task if_watchdogtask;    /* [I] watchdog task */
//    struct    task if_linkstatetask;    /* [I] task to do route updates */
//
//    /* procedure handles */
//    SRPL_HEAD(, ifih) if_inputs;    /* [k] input routines (dequeue) */
    int    (*if_output)(struct _ifnet *, mbuf_t, struct sockaddr *,
             struct rtentry *);    /* output routine (enqueue) */
                    /* link level output function */
    int    (*if_ll_output)(struct _ifnet *, mbuf_t,
            struct sockaddr *, struct rtentry *);
    int    (*if_enqueue)(struct _ifnet *, mbuf_t);
    void    (*if_start)(struct _ifnet *);    /* initiate output */
    int    (*if_ioctl)(struct _ifnet *, u_long, caddr_t); /* ioctl hook */
    void    (*if_watchdog)(struct _ifnet *);    /* timer routine */
    int    (*if_wol)(struct _ifnet *, int);    /* WoL routine **/

    /* queues */
    struct    _ifqueue if_snd;        /* transmit queue */
    struct    _ifqueue **if_ifqs;    /* [I] pointer to an array of sndqs */
    void    (*if_qstart)(struct _ifqueue *);
    unsigned int if_nifqs;        /* [I] number of output queues */
    unsigned int if_txmit;        /* [c] txmitigation amount */

//    struct    ifiqueue if_rcv;    /* rx/input queue */
//    struct    ifiqueue **if_iqs;    /* [I] pointer to the array of iqs */
    unsigned int if_niqs;        /* [I] number of input queues */

    struct sockaddr_dl *if_sadl;    /* [N] pointer to our sockaddr_dl */

    void    *if_afdata[AF_MAX];
};

/*
 * Structure shared between the ethernet driver modules and
 * the address resolution code.  For example, each ec_softc or il_softc
 * begins with this structure.
 */
struct  arpcom {
    struct     _ifnet ac_if;            /* network-visible interface */
    u_int8_t ac_enaddr[ETHER_ADDR_LEN];    /* ethernet hardware address */
    char     ac__pad[2];            /* pad for some machines */
    LIST_HEAD(, ether_multi) ac_multiaddrs;    /* list of multicast addrs */
    int     ac_multicnt;            /* length of ac_multiaddrs */
    int     ac_multirangecnt;        /* number of mcast ranges */

    void    *ac_trunkport;
};

struct ether_multistep {
    struct ether_multi  *e_enm;
};

#define ETHER_FIRST_MULTI(step, ac, enm)    (0)
#define ETHER_NEXT_MULTI(step, enm) (0)
#define ETHER_LOOKUP_MULTI(addrlo, addrhi, ac, enm) (0)

static inline int
ether_addmulti(struct ifreq *, struct arpcom *)
{
    IOLog("TODO: %s\n", __FUNCTION__);
    return 0;
}

static inline int
ether_delmulti(struct ifreq *, struct arpcom *)
{
    IOLog("TODO: %s\n", __FUNCTION__);
    return 0;
}

static inline u_int8_t etherbroadcastaddr[ETHER_ADDR_LEN] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static inline u_int8_t etheranyaddr[ETHER_ADDR_LEN] =
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
#define senderr(e) { error = (e); goto bad;}

static inline int
if_setlladdr(struct _ifnet *ifp, const uint8_t *lladdr)
{
    memcpy(((struct arpcom *)ifp)->ac_enaddr, lladdr, ETHER_ADDR_LEN);
    return (0);
}

static inline int
if_attach(struct _ifnet *ifp)
{
    ifp->if_link_state = -1;
    return 0;
}

static inline int
if_detach(struct _ifnet *ifp)
{
    ifp->if_link_state = -1;
    return 0;
}

static inline int
ether_ifattach(struct _ifnet *ifp, IOEthernetInterface *iface)
{
    ifp->iface = iface;
}

static inline void
ether_ifdetach(struct _ifnet *ifp)
{
    ifp->iface = NULL;
}

#endif /* _if_ether_h */
