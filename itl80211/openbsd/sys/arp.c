//
//  arp.c
//  itlwm
//
//  Created by zxystd on 2023/7/1.
//  Copyright © 2023 钟先耀. All rights reserved.
//

#include "arp.h"

#include <netinet/if_ether.h>
#include <linux/types.h>
#include <sys/_malloc.h>

#define EXTRACT_16BITS(p) \
((u_int16_t)*((const u_int8_t *)(p) + 0) << 8 | \
(u_int16_t)*((const u_int8_t *)(p) + 1))
#define EXTRACT_32BITS(p) \
((u_int32_t)*((const u_int8_t *)(p) + 0) << 24 | \
(u_int32_t)*((const u_int8_t *)(p) + 1) << 16 | \
(u_int32_t)*((const u_int8_t *)(p) + 2) << 8 | \
(u_int32_t)*((const u_int8_t *)(p) + 3))
#define EXTRACT_24BITS(p) \
((u_int32_t)*((const u_int8_t *)(p) + 0) << 16 | \
(u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
(u_int32_t)*((const u_int8_t *)(p) + 2))
#define EXTRACT_LE_8BITS(p) (*(p))
#define EXTRACT_LE_16BITS(p) \
    ((u_int16_t)*((const u_int8_t *)(p) + 1) << 8 | \
    (u_int16_t)*((const u_int8_t *)(p) + 0))
#define EXTRACT_LE_32BITS(p) \
    ((u_int32_t)*((const u_int8_t *)(p) + 3) << 24 | \
    (u_int32_t)*((const u_int8_t *)(p) + 2) << 16 | \
    (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
    (u_int32_t)*((const u_int8_t *)(p) + 0))
#define EXTRACT_LE_64BITS(p) \
    ((u_int64_t)*((const u_int8_t *)(p) + 7) << 56 | \
    (u_int64_t)*((const u_int8_t *)(p) + 6) << 48 | \
    (u_int64_t)*((const u_int8_t *)(p) + 5) << 40 | \
    (u_int64_t)*((const u_int8_t *)(p) + 4) << 32 | \
    (u_int64_t)*((const u_int8_t *)(p) + 3) << 24 | \
    (u_int64_t)*((const u_int8_t *)(p) + 2) << 16 | \
    (u_int64_t)*((const u_int8_t *)(p) + 1) << 8 | \
    (u_int64_t)*((const u_int8_t *)(p) + 0))

#define ESRC(ep) ((ep)->ether_shost)
#define EDST(ep) ((ep)->ether_dhost)
#define SHA(ap) ((ap)->arp_sha)
#define THA(ap) ((ap)->arp_tha)
#define SPA(ap) ((ap)->arp_spa)
#define TPA(ap) ((ap)->arp_tpa)

#define HASHNAMESIZE 4096

struct hnamemem {
    u_int32_t addr;
    char *name;
    struct hnamemem *nxt;
};

struct enamemem {
    u_short e_addr0;
    u_short e_addr1;
    u_short e_addr2;
    char *e_name;
    u_char *e_nsap;            /* used only for nsaptable[] */
#define e_bs e_nsap            /* for bytestringtable */
    struct enamemem *e_nxt;
};

struct hnamemem hnametable[HASHNAMESIZE];
struct enamemem enametable[HASHNAMESIZE];

struct hnamemem *
newhnamemem(void)
{
    struct hnamemem *p;
    static struct hnamemem *ptr = NULL;
    static u_int num = 0;

    if (num  <= 0) {
        num = 64;
        ptr = (struct hnamemem *)malloc(num * sizeof (*ptr), 0, 0);
    }
    --num;
    p = ptr++;
    return (p);
}

char *
intoa(u_int32_t addr)
{
    char *cp;
    u_int byte;
    int n;
    static char buf[sizeof(".xxx.xxx.xxx.xxx")];

    NTOHL(addr);
    cp = &buf[sizeof buf];
    *--cp = '\0';

    n = 4;
    do {
        byte = addr & 0xff;
        *--cp = byte % 10 + '0';
        byte /= 10;
        if (byte > 0) {
            *--cp = byte % 10 + '0';
            byte /= 10;
            if (byte > 0)
                *--cp = byte + '0';
        }
        *--cp = '.';
        addr >>= 8;
    } while (--n > 0);

    return cp + 1;
}

char *
savestr(const char *str)
{
    size_t size;
    char *p;
    static char *strptr = NULL;
    static size_t strsize = 0;

    size = strlen(str) + 1;
    if (size > strsize) {
        strsize = 1024;
        if (strsize < size)
            strsize = size;
        strptr = (char *)malloc(strsize, 0, 0);
    }
    (void)strlcpy(strptr, str, size);
    p = strptr;
    strptr += size;
    strsize -= size;
    return (p);
}

#define HOST_NAME_MAX        255

char *
getname(const u_char *ap)
{
    char host[HOST_NAME_MAX+1];
    u_int32_t addr;
    struct hnamemem *p;

    /*
     * Extract 32 bits in network order, dealing with alignment.
     */
    switch ((intptr_t)ap & (sizeof(u_int32_t)-1)) {

    case 0:
        addr = *(u_int32_t *)ap;
        break;

    case 2:
#if BYTE_ORDER == BIG_ENDIAN
        addr = ((u_int32_t)*(u_short *)ap << 16) |
            (u_int32_t)*(u_short *)(ap + 2);
#else
        addr = ((u_int32_t)*(u_short *)(ap + 2) << 16) |
            (u_int32_t)*(u_short *)ap;
#endif
        break;

    default:
#if BYTE_ORDER == BIG_ENDIAN
        addr = ((u_int32_t)ap[0] << 24) |
            ((u_int32_t)ap[1] << 16) |
            ((u_int32_t)ap[2] << 8) |
            (u_int32_t)ap[3];
#else
        addr = ((u_int32_t)ap[3] << 24) |
            ((u_int32_t)ap[2] << 16) |
            ((u_int32_t)ap[1] << 8) |
            (u_int32_t)ap[0];
#endif
        break;
    }

    p = &hnametable[addr & (HASHNAMESIZE-1)];
    for (; p->nxt; p = p->nxt) {
        if (p->addr == addr)
            return (p->name);
    }
    p->addr = addr;
    p->nxt = newhnamemem();

    p->name = savestr(intoa(addr));
    return (p->name);
}

char *
ether_ntoa(struct ether_addr *e)
{
    static char a[] = "xx:xx:xx:xx:xx:xx";

    (void)snprintf(a, sizeof a, "%02x:%02x:%02x:%02x:%02x:%02x",
        e->ether_addr_octet[0], e->ether_addr_octet[1],
        e->ether_addr_octet[2], e->ether_addr_octet[3],
        e->ether_addr_octet[4], e->ether_addr_octet[5]);

    return (a);
}

static inline struct enamemem *
lookup_emem(const u_char *ep)
{
    u_int i, j, k;
    struct enamemem *tp;

    k = (ep[0] << 8) | ep[1];
    j = (ep[2] << 8) | ep[3];
    i = (ep[4] << 8) | ep[5];

    tp = &enametable[(i ^ j) & (HASHNAMESIZE-1)];
    while (tp->e_nxt)
        if (tp->e_addr0 == i &&
            tp->e_addr1 == j &&
            tp->e_addr2 == k)
            return tp;
        else
            tp = tp->e_nxt;
    tp->e_addr0 = i;
    tp->e_addr1 = j;
    tp->e_addr2 = k;
    tp->e_nxt = (struct enamemem *)malloc(1 * sizeof(*tp), 0, 0);

    return tp;
}

char *
etheraddr_string(const u_char *ep)
{
    struct enamemem *tp;
    struct ether_addr e;

    tp = lookup_emem(ep);
    if (tp->e_name)
        return (tp->e_name);
    memcpy(e.ether_addr_octet, ep, sizeof(e.ether_addr_octet));
    tp->e_name = savestr(ether_ntoa(&e));
    return (tp->e_name);
}

#define ipaddr_string(p) getname((const u_char *)(p))

void
debug_print_arp(const char *tag, mbuf_t m)
{
    size_t len = mbuf_len(m);
    ether_header_t *eh = (ether_header_t *)mbuf_data(m);
    if (len >= sizeof(ether_header_t) &&
        (eh->ether_type == htons(ETHERTYPE_ARP) || eh->ether_type == htons(ETHERTYPE_REVARP))) {
        u_char *p = (u_char *)eh + sizeof(ether_header);
        len -= sizeof(ether_header);
        const struct ether_arp *ap = (const struct ether_arp *)p;
        u_short pro, hrd, op;
        pro = EXTRACT_16BITS(&ap->arp_pro);
        hrd = EXTRACT_16BITS(&ap->arp_hrd);
        op = EXTRACT_16BITS(&ap->arp_op);
        if ((pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL)
            || ap->arp_hln != sizeof(SHA(ap))
            || ap->arp_pln != sizeof(SPA(ap))) {
            XYLog("%s arp-#%d for proto #%d (%d) hardware #%d (%d)\n",
                tag, op, pro, ap->arp_pln, hrd, ap->arp_hln);
        }
        if (pro == ETHERTYPE_TRAIL)
            XYLog("%s trailer-\n", tag);
        switch (op) {

        case ARPOP_REQUEST:
            XYLog("%s arp who-has %s tell %s\n", tag, ipaddr_string(TPA(ap)), ipaddr_string(SPA(ap)));
            break;

        case ARPOP_REPLY:
            XYLog("%s arp reply %s is-at %s\n", tag, ipaddr_string(SPA(ap)), etheraddr_string(SHA(ap)));
            break;

        case ARPOP_REVREQUEST:
            XYLog("%s rarp who-is %s tell %s\n", tag, etheraddr_string(THA(ap)),
            etheraddr_string(SHA(ap)));
            break;

        case ARPOP_REVREPLY:
            XYLog("%s rarp reply %s at %s\n", tag, etheraddr_string(THA(ap)),
            ipaddr_string(TPA(ap)));
            break;

        default:
            XYLog("%s arp-#%d\n", tag, op);
            break;
        }
        if (hrd != ARPHRD_ETHER)
            XYLog("%s  hardware #%d\n", tag, hrd);
    }
}
