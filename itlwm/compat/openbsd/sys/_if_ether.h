//
//  _if_ether.h
//  AppleIntelWifiAdapter
//
//  Created by 钟先耀 on 2020/1/22.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef _if_ether_h
#define _if_ether_h

#include <net/if.h>
#include <net/if_var.h>
#include <sys/queue.h>
#include <sys/_if_media.h>

#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOOutputQueue.h>

#define    ETHER_IS_MULTICAST(addr) (*(addr) & 0x01) /* is address mcast/bcast? */
#define    ETHER_IS_BROADCAST(addr) \
    (((addr)[0] & (addr)[1] & (addr)[2] & \
      (addr)[3] & (addr)[4] & (addr)[5]) == 0xff)
#define    ETHER_IS_ANYADDR(addr)        \
    (((addr)[0] | (addr)[1] | (addr)[2] | \
      (addr)[3] | (addr)[4] | (addr)[5]) == 0x00)
#define    ETHER_IS_EQ(a1, a2)    (memcmp((a1), (a2), ETHER_ADDR_LEN) == 0)

#define    ETHERMTU    (ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)
#define    ETHERMIN    (ETHER_MIN_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)

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

struct ifnet {                /* and the entries */
    IOEthernetInterface *iface;
    IOOutputQueue* output_queue;
    void *if_softc;
//    struct    refcnt if_refcnt;
    int if_hdrlen;
    TAILQ_ENTRY(ifnet) if_list;    /* [k] all struct ifnets are chained */
    TAILQ_HEAD(, ifaddr) if_addrlist; /* [N] list of addresses per if */
    TAILQ_HEAD(, ifmaddr) if_maddrlist; /* [N] list of multicast records */
    TAILQ_HEAD(, ifg_list) if_groups; /* [N] list of groups per if */
//    struct hook_desc_head *if_addrhooks; /* [I] address change callbacks */
//    struct hook_desc_head *if_linkstatehooks; /* [I] link change callbacks*/
//    struct hook_desc_head *if_detachhooks; /* [I] detach callbacks */
                /* [I] check or clean routes (+ or -)'d */
    void    (*if_rtrequest)(struct ifnet *, int, struct rtentry *);
    char    if_xname[IFNAMSIZ];    /* [I] external name (name + unit) */
    int    if_pcount;        /* [k] # of promiscuous listeners */
    unsigned int if_bridgeidx;    /* [k] used by bridge ports */
    caddr_t    if_bpf;            /* packet filter structure */
    caddr_t if_switchport;        /* used by switch ports */
    caddr_t if_mcast;        /* used by multicast code */
    caddr_t if_mcast6;        /* used by IPv6 multicast code */
    caddr_t    if_pf_kif;        /* pf interface abstraction */
    
    ///extra
    uint32_t if_ierrors;
    uint32_t if_oerrors;
    uint32_t if_ipackets;
    uint32_t if_imcasts;
    int if_ibytes;
    
    
//    union {
//        struct srpl carp_s;    /* carp if list (used by !carp ifs) */
//        struct ifnet *carp_d;    /* ptr to carpdev (used by carp ifs) */
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
    int    (*if_output)(struct ifnet *, mbuf_t, struct sockaddr *,
             struct rtentry *);    /* output routine (enqueue) */
                    /* link level output function */
    int    (*if_ll_output)(struct ifnet *, mbuf_t,
            struct sockaddr *, struct rtentry *);
    int    (*if_enqueue)(struct ifnet *, mbuf_t);
    void    (*if_start)(struct ifnet *);    /* initiate output */
    int    (*if_ioctl)(struct ifnet *, u_long, caddr_t); /* ioctl hook */
    void    (*if_watchdog)(struct ifnet *);    /* timer routine */
    int    (*if_wol)(struct ifnet *, int);    /* WoL routine **/

    /* queues */
    struct    ifqueue if_snd;        /* transmit queue */
    struct    ifqueue **if_ifqs;    /* [I] pointer to an array of sndqs */
    void    (*if_qstart)(struct ifqueue *);
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
    struct     ifnet ac_if;            /* network-visible interface */
    u_int8_t ac_enaddr[ETHER_ADDR_LEN];    /* ethernet hardware address */
    char     ac__pad[2];            /* pad for some machines */
    LIST_HEAD(, ether_multi) ac_multiaddrs;    /* list of multicast addrs */
    int     ac_multicnt;            /* length of ac_multiaddrs */
    int     ac_multirangecnt;        /* number of mcast ranges */

    void    *ac_trunkport;
};

static inline u_int8_t etherbroadcastaddr[ETHER_ADDR_LEN] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static inline u_int8_t etheranyaddr[ETHER_ADDR_LEN] =
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
#define senderr(e) { error = (e); goto bad;}

#endif /* _if_ether_h */
