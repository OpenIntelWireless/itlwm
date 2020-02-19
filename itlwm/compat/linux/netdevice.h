//
//  netdevice.h
//  AppleIntelWifiAdapter
//
//  Created by qcwap on 2020/1/5.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef netdevice_h
#define netdevice_h

#include "types.h"

#define ETH_ALEN    6        /* Octets in one ethernet addr     */


typedef u64 netdev_features_t;

enum {
    NETIF_F_SG_BIT,            /* Scatter/gather IO. */
    NETIF_F_IP_CSUM_BIT,        /* Can checksum TCP/UDP over IPv4. */
    __UNUSED_NETIF_F_1,
    NETIF_F_HW_CSUM_BIT,        /* Can checksum all the packets. */
    NETIF_F_IPV6_CSUM_BIT,        /* Can checksum TCP/UDP over IPV6 */
    NETIF_F_HIGHDMA_BIT,        /* Can DMA to high memory. */
    NETIF_F_FRAGLIST_BIT,        /* Scatter/gather IO. */
    NETIF_F_HW_VLAN_CTAG_TX_BIT,    /* Transmit VLAN CTAG HW acceleration */
    NETIF_F_HW_VLAN_CTAG_RX_BIT,    /* Receive VLAN CTAG HW acceleration */
    NETIF_F_HW_VLAN_CTAG_FILTER_BIT,/* Receive filtering on VLAN CTAGs */
    NETIF_F_VLAN_CHALLENGED_BIT,    /* Device cannot handle VLAN packets */
    NETIF_F_GSO_BIT,        /* Enable software GSO. */
    NETIF_F_LLTX_BIT,        /* LockLess TX - deprecated. Please */
    /* do not use LLTX in new drivers */
    NETIF_F_NETNS_LOCAL_BIT,    /* Does not change network namespaces */
    NETIF_F_GRO_BIT,        /* Generic receive offload */
    NETIF_F_LRO_BIT,        /* large receive offload */
    
    /**/NETIF_F_GSO_SHIFT,        /* keep the order of SKB_GSO_* bits */
    NETIF_F_TSO_BIT            /* ... TCPv4 segmentation */
    = NETIF_F_GSO_SHIFT,
    NETIF_F_GSO_ROBUST_BIT,        /* ... ->SKB_GSO_DODGY */
    NETIF_F_TSO_ECN_BIT,        /* ... TCP ECN support */
    NETIF_F_TSO_MANGLEID_BIT,    /* ... IPV4 ID mangling allowed */
    NETIF_F_TSO6_BIT,        /* ... TCPv6 segmentation */
    NETIF_F_FSO_BIT,        /* ... FCoE segmentation */
    NETIF_F_GSO_GRE_BIT,        /* ... GRE with TSO */
    NETIF_F_GSO_GRE_CSUM_BIT,    /* ... GRE with csum with TSO */
    NETIF_F_GSO_IPXIP4_BIT,        /* ... IP4 or IP6 over IP4 with TSO */
    NETIF_F_GSO_IPXIP6_BIT,        /* ... IP4 or IP6 over IP6 with TSO */
    NETIF_F_GSO_UDP_TUNNEL_BIT,    /* ... UDP TUNNEL with TSO */
    NETIF_F_GSO_UDP_TUNNEL_CSUM_BIT,/* ... UDP TUNNEL with TSO & CSUM */
    NETIF_F_GSO_PARTIAL_BIT,    /* ... Only segment inner-most L4
                                 *     in hardware and all other
                                 *     headers in software.
                                 */
    NETIF_F_GSO_TUNNEL_REMCSUM_BIT, /* ... TUNNEL with TSO & REMCSUM */
    NETIF_F_GSO_SCTP_BIT,        /* ... SCTP fragmentation */
    NETIF_F_GSO_ESP_BIT,        /* ... ESP with TSO */
    NETIF_F_GSO_UDP_BIT,        /* ... UFO, deprecated except tuntap */
    /**/NETIF_F_GSO_LAST =        /* last bit, see GSO_MASK */
    NETIF_F_GSO_UDP_BIT,
    
    NETIF_F_FCOE_CRC_BIT,        /* FCoE CRC32 */
    NETIF_F_SCTP_CRC_BIT,        /* SCTP checksum offload */
    NETIF_F_FCOE_MTU_BIT,        /* Supports max FCoE MTU, 2158 bytes*/
    NETIF_F_NTUPLE_BIT,        /* N-tuple filters supported */
    NETIF_F_RXHASH_BIT,        /* Receive hashing offload */
    NETIF_F_RXCSUM_BIT,        /* Receive checksumming offload */
    NETIF_F_NOCACHE_COPY_BIT,    /* Use no-cache copyfromuser */
    NETIF_F_LOOPBACK_BIT,        /* Enable loopback */
    NETIF_F_RXFCS_BIT,        /* Append FCS to skb pkt data */
    NETIF_F_RXALL_BIT,        /* Receive errored frames too */
    NETIF_F_HW_VLAN_STAG_TX_BIT,    /* Transmit VLAN STAG HW acceleration */
    NETIF_F_HW_VLAN_STAG_RX_BIT,    /* Receive VLAN STAG HW acceleration */
    NETIF_F_HW_VLAN_STAG_FILTER_BIT,/* Receive filtering on VLAN STAGs */
    NETIF_F_HW_L2FW_DOFFLOAD_BIT,    /* Allow L2 Forwarding in Hardware */
    
    NETIF_F_HW_TC_BIT,        /* Offload TC infrastructure */
    NETIF_F_HW_ESP_BIT,        /* Hardware ESP transformation offload */
    NETIF_F_HW_ESP_TX_CSUM_BIT,    /* ESP with TX checksum offload */
    NETIF_F_RX_UDP_TUNNEL_PORT_BIT, /* Offload of RX port for UDP tunnels */
    
    /*
     * Add your fresh new feature above and remember to update
     * netdev_features_strings[] in net/core/ethtool.c and maybe
     * some feature mask #defines below. Please also describe it
     * in Documentation/networking/netdev-features.txt.
     */
    
    /**/NETDEV_FEATURE_COUNT
};

/* copy'n'paste compression ;) */
#define __NETIF_F_BIT(bit)    ((netdev_features_t)1 << (bit))
#define __NETIF_F(name)        __NETIF_F_BIT(NETIF_F_##name##_BIT)

#define NETIF_F_FCOE_CRC    __NETIF_F(FCOE_CRC)
#define NETIF_F_FCOE_MTU    __NETIF_F(FCOE_MTU)
#define NETIF_F_FRAGLIST    __NETIF_F(FRAGLIST)
#define NETIF_F_FSO        __NETIF_F(FSO)
#define NETIF_F_GRO        __NETIF_F(GRO)
#define NETIF_F_GSO        __NETIF_F(GSO)
#define NETIF_F_GSO_ROBUST    __NETIF_F(GSO_ROBUST)
#define NETIF_F_HIGHDMA        __NETIF_F(HIGHDMA)
#define NETIF_F_HW_CSUM        __NETIF_F(HW_CSUM)
#define NETIF_F_HW_VLAN_CTAG_FILTER __NETIF_F(HW_VLAN_CTAG_FILTER)
#define NETIF_F_HW_VLAN_CTAG_RX    __NETIF_F(HW_VLAN_CTAG_RX)
#define NETIF_F_HW_VLAN_CTAG_TX    __NETIF_F(HW_VLAN_CTAG_TX)
#define NETIF_F_IP_CSUM        __NETIF_F(IP_CSUM)
#define NETIF_F_IPV6_CSUM    __NETIF_F(IPV6_CSUM)
#define NETIF_F_LLTX        __NETIF_F(LLTX)
#define NETIF_F_LOOPBACK    __NETIF_F(LOOPBACK)
#define NETIF_F_LRO        __NETIF_F(LRO)
#define NETIF_F_NETNS_LOCAL    __NETIF_F(NETNS_LOCAL)
#define NETIF_F_NOCACHE_COPY    __NETIF_F(NOCACHE_COPY)
#define NETIF_F_NTUPLE        __NETIF_F(NTUPLE)
#define NETIF_F_RXCSUM        __NETIF_F(RXCSUM)
#define NETIF_F_RXHASH        __NETIF_F(RXHASH)
#define NETIF_F_SCTP_CRC    __NETIF_F(SCTP_CRC)
#define NETIF_F_SG        __NETIF_F(SG)
#define NETIF_F_TSO6        __NETIF_F(TSO6)
#define NETIF_F_TSO_ECN        __NETIF_F(TSO_ECN)
#define NETIF_F_TSO        __NETIF_F(TSO)
#define NETIF_F_VLAN_CHALLENGED    __NETIF_F(VLAN_CHALLENGED)
#define NETIF_F_RXFCS        __NETIF_F(RXFCS)
#define NETIF_F_RXALL        __NETIF_F(RXALL)
#define NETIF_F_GSO_GRE        __NETIF_F(GSO_GRE)
#define NETIF_F_GSO_GRE_CSUM    __NETIF_F(GSO_GRE_CSUM)
#define NETIF_F_GSO_IPXIP4    __NETIF_F(GSO_IPXIP4)
#define NETIF_F_GSO_IPXIP6    __NETIF_F(GSO_IPXIP6)
#define NETIF_F_GSO_UDP_TUNNEL    __NETIF_F(GSO_UDP_TUNNEL)
#define NETIF_F_GSO_UDP_TUNNEL_CSUM __NETIF_F(GSO_UDP_TUNNEL_CSUM)
#define NETIF_F_TSO_MANGLEID    __NETIF_F(TSO_MANGLEID)
#define NETIF_F_GSO_PARTIAL     __NETIF_F(GSO_PARTIAL)
#define NETIF_F_GSO_TUNNEL_REMCSUM __NETIF_F(GSO_TUNNEL_REMCSUM)
#define NETIF_F_GSO_SCTP    __NETIF_F(GSO_SCTP)
#define NETIF_F_GSO_ESP        __NETIF_F(GSO_ESP)
#define NETIF_F_GSO_UDP        __NETIF_F(GSO_UDP)
#define NETIF_F_HW_VLAN_STAG_FILTER __NETIF_F(HW_VLAN_STAG_FILTER)
#define NETIF_F_HW_VLAN_STAG_RX    __NETIF_F(HW_VLAN_STAG_RX)
#define NETIF_F_HW_VLAN_STAG_TX    __NETIF_F(HW_VLAN_STAG_TX)
#define NETIF_F_HW_L2FW_DOFFLOAD    __NETIF_F(HW_L2FW_DOFFLOAD)
#define NETIF_F_HW_TC        __NETIF_F(HW_TC)
#define NETIF_F_HW_ESP        __NETIF_F(HW_ESP)
#define NETIF_F_HW_ESP_TX_CSUM    __NETIF_F(HW_ESP_TX_CSUM)
#define    NETIF_F_RX_UDP_TUNNEL_PORT  __NETIF_F(RX_UDP_TUNNEL_PORT)

/**
 * ether_addr_equal_masked - Compare two Ethernet addresses with a mask
 * @addr1: Pointer to a six-byte array containing the 1st Ethernet address
 * @addr2: Pointer to a six-byte array containing the 2nd Ethernet address
 * @mask: Pointer to a six-byte array containing the Ethernet address bitmask
 *
 * Compare two Ethernet addresses with a mask, returns true if for every bit
 * set in the bitmask the equivalent bits in the ethernet addresses are equal.
 * Using a mask with all bits set is a slower ether_addr_equal.
 */
static inline bool ether_addr_equal_masked(const u8 *addr1, const u8 *addr2,
                       const u8 *mask)
{
    int i;

    for (i = 0; i < ETH_ALEN; i++) {
        if ((addr1[i] ^ addr2[i]) & mask[i])
            return false;
    }

    return true;
}

/**
 * ether_addr_to_u64 - Convert an Ethernet address into a u64 value.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return a u64 value of the address
 */
static inline u64 ether_addr_to_u64(const u8 *addr)
{
    u64 u = 0;
    int i;

    for (i = 0; i < ETH_ALEN; i++)
        u = u << 8 | addr[i];

    return u;
}

/**
 * u64_to_ether_addr - Convert a u64 to an Ethernet address.
 * @u: u64 to convert to an Ethernet MAC address
 * @addr: Pointer to a six-byte array to contain the Ethernet address
 */
static inline void u64_to_ether_addr(u64 u, u8 *addr)
{
    int i;

    for (i = ETH_ALEN - 1; i >= 0; i--) {
        addr[i] = u & 0xff;
        u = u >> 8;
    }
}

/**
 * eth_addr_dec - Decrement the given MAC address
 *
 * @addr: Pointer to a six-byte array containing Ethernet address to decrement
 */
static inline void eth_addr_dec(u8 *addr)
{
    u64 u = ether_addr_to_u64(addr);

    u--;
    u64_to_ether_addr(u, addr);
}

/**
 * eth_addr_inc() - Increment the given MAC address.
 * @addr: Pointer to a six-byte array containing Ethernet address to increment.
 */
static inline void eth_addr_inc(u8 *addr)
{
    u64 u = ether_addr_to_u64(addr);

    u++;
    u64_to_ether_addr(u, addr);
}

/* Reserved Ethernet Addresses per IEEE 802.1Q */
static const u8 eth_reserved_addr_base[ETH_ALEN] __aligned(2) =
{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };
#define eth_stp_addr eth_reserved_addr_base

/**
 * is_link_local_ether_addr - Determine if given Ethernet address is link-local
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if address is link local reserved addr (01:80:c2:00:00:0X) per
 * IEEE 802.1Q 8.6.3 Frame filtering.
 *
 * Please note: addr must be aligned to u16.
 */
static inline bool is_link_local_ether_addr(const u8 *addr)
{
    __be16 *a = (__be16 *)addr;
    static const __be16 *b = (const __be16 *)eth_reserved_addr_base;
    static const __be16 m = cpu_to_be16(0xfff0);

#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
    return (((*(const u32 *)addr) ^ (*(const u32 *)b)) |
        (__force int)((a[2] ^ b[2]) & m)) == 0;
#else
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | ((a[2] ^ b[2]) & m)) == 0;
#endif
}

/**
 * is_zero_ether_addr - Determine if give Ethernet address is all zeros.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is all zeroes.
 *
 * Please note: addr must be aligned to u16.
 */
static inline bool is_zero_ether_addr(const u8 *addr)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
    return ((*(const u32 *)addr) | (*(const u16 *)(addr + 4))) == 0;
#else
    return (*(const u16 *)(addr + 0) |
        *(const u16 *)(addr + 2) |
        *(const u16 *)(addr + 4)) == 0;
#endif
}

/**
 * is_multicast_ether_addr - Determine if the Ethernet address is a multicast.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is a multicast address.
 * By definition the broadcast address is also a multicast address.
 */
static inline bool is_multicast_ether_addr(const u8 *addr)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
    u32 a = *(const u32 *)addr;
#else
    u16 a = *(const u16 *)addr;
#endif
#ifdef __BIG_ENDIAN
    return 0x01 & (a >> ((sizeof(a) * 8) - 8));
#else
    return 0x01 & a;
#endif
}

static inline bool is_multicast_ether_addr_64bits(const u8 addr[6+2])
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
#ifdef __BIG_ENDIAN
    return 0x01 & ((*(const u64 *)addr) >> 56);
#else
    return 0x01 & (*(const u64 *)addr);
#endif
#else
    return is_multicast_ether_addr(addr);
#endif
}

/**
 * is_local_ether_addr - Determine if the Ethernet address is locally-assigned one (IEEE 802).
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is a local address.
 */
static inline bool is_local_ether_addr(const u8 *addr)
{
    return 0x02 & addr[0];
}

/**
 * is_broadcast_ether_addr - Determine if the Ethernet address is broadcast
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is the broadcast address.
 *
 * Please note: addr must be aligned to u16.
 */
static inline bool is_broadcast_ether_addr(const u8 *addr)
{
    return (*(const u16 *)(addr + 0) &
        *(const u16 *)(addr + 2) &
        *(const u16 *)(addr + 4)) == 0xffff;
}

/**
 * is_unicast_ether_addr - Determine if the Ethernet address is unicast
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is a unicast address.
 */
static inline bool is_unicast_ether_addr(const u8 *addr)
{
    return !is_multicast_ether_addr(addr);
}

/**
 * is_valid_ether_addr - Determine if the given Ethernet address is valid
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Check that the Ethernet address (MAC) is not 00:00:00:00:00:00, is not
 * a multicast address, and is not FF:FF:FF:FF:FF:FF.
 *
 * Return true if the address is valid.
 *
 * Please note: addr must be aligned to u16.
 */
static inline bool is_valid_ether_addr(const u8 *addr)
{
    /* FF:FF:FF:FF:FF:FF is a multicast address so we don't need to
     * explicitly check for it here. */
    return !is_multicast_ether_addr(addr) && !is_zero_ether_addr(addr);
}

#endif /* netdevice_h */
