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
/*    $OpenBSD: if_iwx.c,v 1.45 2020/10/11 07:05:28 mpi Exp $    */

/*
 * Copyright (c) 2014, 2016 genua gmbh <info@genua.de>
 *   Author: Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2014 Fixup Software Ltd.
 * Copyright (c) 2017, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*-
 * Based on BSD-licensed source modules in the Linux iwlwifi driver,
 * which were used as the reference documentation for this implementation.
 *
 ******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 - 2019 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * BSD LICENSE
 *
 * Copyright(c) 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 - 2019 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************
 */

/*-
 * Copyright (c) 2007-2010 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "ItlIwx.hpp"
#include <linux/types.h>
#include <linux/kernel.h>
#include <FwData.h>
#include <crypto/sha1.h>

#include <IOKit/IOInterruptController.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/network/IONetworkMedium.h>
#include <net/ethernet.h>

#include <sys/_task.h>
#include <sys/pcireg.h>
#include <net80211/ieee80211_priv.h>

#define super ItlHalService
OSDefineMetaClassAndStructors(ItlIwx, ItlHalService)

#define DEVNAME(_s)    ((_s)->sc_dev.dv_xname)

#define IC2IFP(_ic_) (&(_ic_)->ic_if)

#define IWX_DEBUG

#ifdef IWX_DEBUG
#define DPRINTF(x)    do { if (iwx_debug > 0) XYLog x; } while (0)
#define DPRINTFN(n, x)    do { if (iwx_debug >= (n)) XYLog x; } while (0)
int iwx_debug = 1;
#else
#define DPRINTF(x)    do { ; } while (0)
#define DPRINTFN(n, x)    do { ; } while (0)
#endif

bool ItlIwx::attach(IOPCIDevice *device)
{
    pci.pa_tag = device;
    pci.workloop = getMainWorkLoop();
    if (!iwx_attach(&com, &pci)) {
        detach(device);
        releaseAll();
        return false;
    }
    return true;
}

void ItlIwx::
detach(IOPCIDevice *device)
{
    struct _ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    struct iwx_softc *sc = &com;
    
    for (int txq_i = 0; txq_i < nitems(sc->txq); txq_i++)
        iwx_free_tx_ring(sc, &sc->txq[txq_i]);
    iwx_free_rx_ring(sc, &sc->rxq);
    iwx_dma_contig_free(&sc->ict_dma);
    iwx_dma_contig_free(&com.ctxt_info_dma);
    ieee80211_ifdetach(ifp);
    taskq_destroy(systq);
    taskq_destroy(com.sc_nswq);
    releaseAll();
}

void ItlIwx::
releaseAll()
{
    pci_intr_handle *intrHandler = com.ih;
    
    if (intrHandler) {
        if (intrHandler->intr && intrHandler->workloop) {
//            intrHandler->intr->disable();
            intrHandler->workloop->removeEventSource(intrHandler->intr);
            intrHandler->intr->release();
        }
        intrHandler->intr = NULL;
        intrHandler->workloop = NULL;
        intrHandler->arg = NULL;
        intrHandler->dev = NULL;
        intrHandler->func = NULL;
        intrHandler->release();
        com.ih = NULL;
    }
    pci.pa_tag = NULL;
    pci.workloop = NULL;
}

void ItlIwx::free()
{
    XYLog("%s\n", __FUNCTION__);
    super::free();
}

ItlDriverInfo *ItlIwx::
getDriverInfo()
{
    return this;
}

ItlDriverController *ItlIwx::
getDriverController()
{
    return this;
}

IOReturn ItlIwx::enable(IONetworkInterface *netif)
{
    XYLog("%s\n", __PRETTY_FUNCTION__);
    struct _ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    if (ifp->if_flags & IFF_UP) {
        XYLog("%s already in activating state\n", __FUNCTION__);
        return kIOReturnSuccess;
    }
    ifp->if_flags |= IFF_UP;
    iwx_activate(&com, DVACT_RESUME);
    iwx_activate(&com, DVACT_WAKEUP);
    return kIOReturnSuccess;
}

IOReturn ItlIwx::disable(IONetworkInterface *netif)
{
    XYLog("%s\n", __FUNCTION__);
    struct _ifnet *ifp = &com.sc_ic.ic_ac.ac_if;
    if (!(ifp->if_flags & IFF_UP)) {
        XYLog("%s already in diactivating state\n", __FUNCTION__);
        return kIOReturnSuccess;
    }
    ifp->if_flags &= ~IFF_UP;
    iwx_activate(&com, DVACT_QUIESCE);
    return kIOReturnSuccess;
}

void ItlIwx::
clearScanningFlags()
{
    com.sc_flags &= ~(IWX_FLAG_SCANNING | IWX_FLAG_BGSCAN);
}

IOReturn ItlIwx::
setMulticastList(IOEthernetAddress *addr, int count)
{
    struct ieee80211com *ic = &com.sc_ic;
    struct iwx_mcast_filter_cmd *cmd;
    int len;
    uint8_t addr_count;
    int err;
    
    if (ic->ic_state != IEEE80211_S_RUN || ic->ic_bss == NULL)
        return kIOReturnError;
    addr_count = count;
    if (count > IWX_MAX_MCAST_FILTERING_ADDRESSES)
        addr_count = 0;
    if (addr == NULL)
        addr_count = 0;
    len = roundup(sizeof(struct iwx_mcast_filter_cmd) + addr_count * ETHER_ADDR_LEN, 4);
    XYLog("%s multicast count=%d bssid=%s\n", __FUNCTION__, count, ether_sprintf(ic->ic_bss->ni_bssid));
    cmd = (struct iwx_mcast_filter_cmd *)malloc(len, 0, 0);
    if (!cmd)
        return kIOReturnError;
    cmd->pass_all = addr_count == 0;
    cmd->count = addr_count;
    cmd->port_id = 0;
    IEEE80211_ADDR_COPY(cmd->bssid, ic->ic_bss->ni_bssid);
    if (addr_count > 0)
        memcpy(cmd->addr_list,
               addr->bytes, ETHER_ADDR_LEN * cmd->count);
    err = iwx_send_cmd_pdu(&com, IWX_MCAST_FILTER_CMD, IWX_CMD_ASYNC, len,
                     cmd);
    ::free(cmd);
    return err ? kIOReturnError : kIOReturnSuccess;
}

const char *ItlIwx::
getFirmwareVersion()
{
    return com.sc_fwver;
}

const char *ItlIwx::
getFirmwareName()
{
    return com.sc_fwname;
}

UInt32 ItlIwx::
supportedFeatures()
{
    return kIONetworkFeatureMultiPages;
}

const char *ItlIwx::
getFirmwareCountryCode()
{
    return com.sc_fw_mcc;
}

uint32_t ItlIwx::
getTxQueueSize()
{
    return com.sc_device_family >= IWX_DEVICE_FAMILY_AX210 ? IWX_TFD_QUEUE_SIZE_MAX_GEN3 : IWX_DEFAULT_QUEUE_SIZE;
}

int16_t ItlIwx::
getBSSNoise()
{
    return com.sc_noise;
}

bool ItlIwx::
is5GBandSupport()
{
    return com.sc_nvm.sku_cap_band_52GHz_enable;
}

int ItlIwx::
getTxNSS()
{
    return iwx_mimo_enabled(&com) && 
    (com.sc_ic.ic_bss != NULL && com.sc_ic.ic_bss->ni_rx_nss > 1) ? 2 : 1;
}

struct ieee80211com *ItlIwx::
get80211Controller()
{
    return &com.sc_ic;
}

#define MUL_NO_OVERFLOW    (1UL << (sizeof(size_t) * 4))

#define    M_CANFAIL    0x0004
void *ItlIwx::
mallocarray(size_t nmemb, size_t size, int type, int flags)
{
    if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
        nmemb > 0 && SIZE_MAX / nmemb < size) {
        if (flags & M_CANFAIL)
            return (NULL);
        panic("mallocarray: overflow %zu * %zu", nmemb, size);
    }
    return (malloc(size * nmemb, type, flags));
}

const uint8_t iwx_nvm_channels_8000[] = {
    /* 2.4 GHz */
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    /* 5 GHz */
    36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92,
    96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177, 181
};

static const uint8_t iwx_nvm_channels_uhb[] = {
   /* 2.4 GHz */
   1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
   /* 5 GHz */
   36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92,
   96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
   149, 153, 157, 161, 165, 169, 173, 177, 181,
#ifdef notyet
   /* 6-7 GHz */
   1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69,
   73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125, 129,
   133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181, 185,
   189, 193, 197, 201, 205, 209, 213, 217, 221, 225, 229, 233
#endif
};

#define IWX_NUM_2GHZ_CHANNELS    14
#define IWX_FIRST_2GHZ_HT_MINUS        5
#define IWX_LAST_2GHZ_HT_PLUS        9

const struct iwx_rate {
    uint16_t rate;
    uint8_t plcp;
    uint8_t ht_plcp;
} iwx_rates[] = {
    /* Legacy */        /* HT */
    {   2,    IWX_RATE_1M_PLCP,    IWX_RATE_HT_SISO_MCS_INV_PLCP  },
    {   4,    IWX_RATE_2M_PLCP,    IWX_RATE_HT_SISO_MCS_INV_PLCP },
    {  11,    IWX_RATE_5M_PLCP,    IWX_RATE_HT_SISO_MCS_INV_PLCP  },
    {  22,    IWX_RATE_11M_PLCP,    IWX_RATE_HT_SISO_MCS_INV_PLCP },
    {  12,    IWX_RATE_6M_PLCP,    IWX_RATE_HT_SISO_MCS_0_PLCP },
    {  18,    IWX_RATE_9M_PLCP,    IWX_RATE_HT_SISO_MCS_INV_PLCP  },
    {  24,    IWX_RATE_12M_PLCP,    IWX_RATE_HT_SISO_MCS_1_PLCP },
    {  26,    IWX_RATE_12M_PLCP,    IWX_RATE_HT_MIMO2_MCS_8_PLCP },
    {  36,    IWX_RATE_18M_PLCP,    IWX_RATE_HT_SISO_MCS_2_PLCP },
    {  48,    IWX_RATE_24M_PLCP,    IWX_RATE_HT_SISO_MCS_3_PLCP },
    {  52,    IWX_RATE_24M_PLCP,    IWX_RATE_HT_MIMO2_MCS_9_PLCP },
    {  72,    IWX_RATE_36M_PLCP,    IWX_RATE_HT_SISO_MCS_4_PLCP },
    {  78,    IWX_RATE_36M_PLCP,    IWX_RATE_HT_MIMO2_MCS_10_PLCP },
    {  96,    IWX_RATE_48M_PLCP,    IWX_RATE_HT_SISO_MCS_5_PLCP },
    { 104,    IWX_RATE_48M_PLCP,    IWX_RATE_HT_MIMO2_MCS_11_PLCP },
    { 108,    IWX_RATE_54M_PLCP,    IWX_RATE_HT_SISO_MCS_6_PLCP },
    { 128,    IWX_RATE_54M_PLCP,    IWX_RATE_HT_SISO_MCS_7_PLCP },
    { 156,    IWX_RATE_54M_PLCP,    IWX_RATE_HT_MIMO2_MCS_12_PLCP },
    { 208,    IWX_RATE_54M_PLCP,    IWX_RATE_HT_MIMO2_MCS_13_PLCP },
    { 234,    IWX_RATE_54M_PLCP,    IWX_RATE_HT_MIMO2_MCS_14_PLCP },
    { 260,    IWX_RATE_54M_PLCP,    IWX_RATE_HT_MIMO2_MCS_15_PLCP },
};
#define IWX_RIDX_CCK    0
#define IWX_RIDX_OFDM    4
#define IWX_RIDX_MAX    (nitems(iwx_rates)-1)
#define IWX_RIDX_IS_CCK(_i_) ((_i_) < IWX_RIDX_OFDM)
#define IWX_RIDX_IS_OFDM(_i_) ((_i_) >= IWX_RIDX_OFDM)
#define IWX_RVAL_IS_OFDM(_i_) ((_i_) >= 12 && (_i_) != 22)

/* Convert an MCS index into an iwx_rates[] index. */
const int iwx_mcs2ridx[] = {
    IWX_RATE_MCS_0_INDEX,
    IWX_RATE_MCS_1_INDEX,
    IWX_RATE_MCS_2_INDEX,
    IWX_RATE_MCS_3_INDEX,
    IWX_RATE_MCS_4_INDEX,
    IWX_RATE_MCS_5_INDEX,
    IWX_RATE_MCS_6_INDEX,
    IWX_RATE_MCS_7_INDEX,
    IWX_RATE_MCS_8_INDEX,
    IWX_RATE_MCS_9_INDEX,
    IWX_RATE_MCS_10_INDEX,
    IWX_RATE_MCS_11_INDEX,
    IWX_RATE_MCS_12_INDEX,
    IWX_RATE_MCS_13_INDEX,
    IWX_RATE_MCS_14_INDEX,
    IWX_RATE_MCS_15_INDEX,
};
#define IWX_LAST_HE_RATE IWX_RATE_MCS_11_INDEX
#define IWL_RATE_COUNT IWX_LAST_HE_RATE
#define IWX_MAX_MCS_DISPLAY_SIZE    12

#define IWL_RATE_60M_PLCP 3

enum {
    IWX_RATE_INVM_INDEX = IWX_RATE_COUNT,
    IWX_RATE_INVALID = IWX_RATE_COUNT,
};

struct iwx_rate_mcs_info {
    char    mbps[IWX_MAX_MCS_DISPLAY_SIZE];
    char    mcs[IWX_MAX_MCS_DISPLAY_SIZE];
};

/* mbps, mcs */
static const struct iwx_rate_mcs_info iwx_rate_mcs[IWX_RATE_COUNT] = {
    {  "1", "BPSK DSSS"},
    {  "2", "QPSK DSSS"},
    {"5.5", "BPSK CCK"},
    { "11", "QPSK CCK"},
    {  "6", "BPSK 1/2"},
    {  "9", "BPSK 1/2"},
    { "12", "QPSK 1/2"},
    { "18", "QPSK 3/4"},
    { "24", "16QAM 1/2"},
    { "36", "16QAM 3/4"},
    { "48", "64QAM 2/3"},
    { "54", "64QAM 3/4"},
    { "60", "64QAM 5/6"},
};

#define IWX_MCS_INDEX_PER_STREAM    (8)

static const char *iwx_rs_pretty_ant(u8 ant)
{
    static const char * const ant_name[] = {
        [IWX_ANT_NONE] = "None",
        [IWX_ANT_A]    = "A",
        [IWX_ANT_B]    = "B",
        [IWX_ANT_AB]   = "AB",
    };

    if (ant > ARRAY_SIZE(ant_name))
        return "UNKNOWN";

    return ant_name[ant];
}

static const char *iwx_rs_pretty_bw(u8 bw)
{
    static const char * const pretty_bw[] = {
        "20Mhz",
        "40Mhz",
        "80Mhz",
        "160 Mhz",
        "320Mhz",
    };

    if (bw > ARRAY_SIZE(pretty_bw))
        return "UNKNOWN";

    return pretty_bw[bw];
}

static uint8_t iwx_rs_extract_rate(uint32_t rate_n_flags)
{
    /* also works for HT because bits 7:6 are zero there */
    return (uint8_t)(rate_n_flags & IWX_RATE_LEGACY_RATE_MSK_V1);
}

static int iwx_hwrate_to_plcp_idx(uint32_t rate_n_flags)
{
    int idx = 0;

    if (rate_n_flags & IWX_RATE_MCS_HT_MSK_V1) {
        idx = rate_n_flags & IWX_RATE_HT_MCS_RATE_CODE_MSK_V1;
        idx += IWX_RATE_MCS_0_INDEX;

        /* skip 9M not supported in HT*/
        if (idx >= IWX_RATE_9M_INDEX)
            idx += 1;
        if ((idx >= IWX_FIRST_HT_RATE) && (idx <= IWX_LAST_HT_RATE))
            return idx;
    } else if (rate_n_flags & IWX_RATE_MCS_VHT_MSK_V1 ||
           rate_n_flags & IWX_RATE_MCS_HE_MSK_V1) {
        idx = rate_n_flags & IWX_RATE_VHT_MCS_RATE_CODE_MSK;
        idx += IWX_RATE_MCS_0_INDEX;

        /* skip 9M not supported in VHT*/
        if (idx >= IWX_RATE_9M_INDEX)
            idx++;
        if ((idx >= IWX_FIRST_VHT_RATE) && (idx <= IWX_LAST_VHT_RATE))
            return idx;
        if ((rate_n_flags & IWX_RATE_MCS_HE_MSK_V1) &&
            (idx <= IWX_LAST_HE_RATE))
            return idx;
    } else {
        /* legacy rate format, search for match in table */

        uint8_t legacy_rate = iwx_rs_extract_rate(rate_n_flags);
        for (idx = 0; idx < ARRAY_SIZE(iwx_rates); idx++)
            if (iwx_rates[idx].plcp == legacy_rate)
                return idx;
    }

    return IWX_RATE_INVALID;
}

static int iwx_rs_pretty_print_rate_v1(char *buf, int bufsz, const u32 rate)
{
    char *type;
    uint8_t mcs = 0, nss = 0;
    uint8_t ant = (rate & IWX_RATE_MCS_ANT_AB_MSK) >> IWX_RATE_MCS_ANT_POS;
    uint32_t bw = (rate & IWX_RATE_MCS_CHAN_WIDTH_MSK_V1) >>
        IWX_RATE_MCS_CHAN_WIDTH_POS;

    if (!(rate & IWX_RATE_MCS_HT_MSK_V1) &&
        !(rate & IWX_RATE_MCS_VHT_MSK_V1) &&
        !(rate & IWX_RATE_MCS_HE_MSK_V1)) {
        int index = iwx_hwrate_to_plcp_idx(rate);

        return snprintf(buf, bufsz, "Legacy | ANT: %s Rate: %s Mbps",
                 iwx_rs_pretty_ant(ant),
                 index == IWX_RATE_INVALID ? "BAD" :
                 iwx_rate_mcs[index].mbps);
    }

    if (rate & IWX_RATE_MCS_VHT_MSK_V1) {
        type = "VHT";
        mcs = rate & IWX_RATE_VHT_MCS_RATE_CODE_MSK;
        nss = ((rate & IWX_RATE_VHT_MCS_NSS_MSK)
               >> IWX_RATE_VHT_MCS_NSS_POS) + 1;
    } else if (rate & IWX_RATE_MCS_HT_MSK_V1) {
        type = "HT";
        mcs = rate & IWX_RATE_HT_MCS_INDEX_MSK_V1;
        nss = ((rate & IWX_RATE_HT_MCS_NSS_MSK_V1)
               >> IWX_RATE_HT_MCS_NSS_POS_V1) + 1;
    } else if (rate & IWX_RATE_MCS_HE_MSK_V1) {
        type = "HE";
        mcs = rate & IWX_RATE_VHT_MCS_RATE_CODE_MSK;
        nss = ((rate & IWX_RATE_VHT_MCS_NSS_MSK)
               >> IWX_RATE_VHT_MCS_NSS_POS) + 1;
    } else {
        type = "Unknown"; /* shouldn't happen */
    }

    return snprintf(buf, bufsz,
             "0x%x: %s | ANT: %s BW: %s MCS: %d NSS: %d %s%s%s%s%s",
             rate, type, iwx_rs_pretty_ant(ant), iwx_rs_pretty_bw(bw), mcs, nss,
             (rate & IWX_RATE_MCS_SGI_MSK_V1) ? "SGI " : "NGI ",
             (rate & IWX_RATE_MCS_STBC_MSK) ? "STBC " : "",
             (rate & IWX_RATE_MCS_LDPC_MSK_V1) ? "LDPC " : "",
             (rate & IWX_RATE_HE_DUAL_CARRIER_MODE_MSK) ? "DCM " : "",
             (rate & IWX_RATE_MCS_BF_MSK) ? "BF " : "");
}

static bool iwx_he_is_sgi(u32 rate_n_flags)
{
    u32 type = rate_n_flags & IWX_RATE_MCS_HE_TYPE_MSK;
    u32 ltf_gi = rate_n_flags & IWX_RATE_MCS_HE_GI_LTF_MSK;

    if (type == IWX_RATE_MCS_HE_TYPE_SU ||
        type == IWX_RATE_MCS_HE_TYPE_EXT_SU)
        return ltf_gi == IWX_RATE_MCS_HE_SU_4_LTF_08_GI;
    return false;
}

static int iwx_rs_pretty_print_rate(char *buf, int bufsz, const uint32_t rate)
{
    char *type;
    u8 mcs = 0, nss = 0;
    u8 ant = (rate & IWX_RATE_MCS_ANT_AB_MSK) >> IWX_RATE_MCS_ANT_POS;
    u32 bw = (rate & IWX_RATE_MCS_CHAN_WIDTH_MSK) >>
        IWX_RATE_MCS_CHAN_WIDTH_POS;
    u32 format = rate & IWX_RATE_MCS_MOD_TYPE_MSK;
    bool sgi;

    if (format == IWX_RATE_MCS_CCK_MSK ||
        format == IWX_RATE_MCS_LEGACY_OFDM_MSK) {
        int legacy_rate = rate & IWX_RATE_LEGACY_RATE_MSK;
        int index = format == IWX_RATE_MCS_CCK_MSK ?
            legacy_rate :
            legacy_rate + IWX_FIRST_OFDM_RATE;

        return snprintf(buf, bufsz, "Legacy | ANT: %s Rate: %s Mbps",
                 iwx_rs_pretty_ant(ant),
                 index == IWX_RATE_INVALID ? "BAD" :
                 iwx_rate_mcs[index].mbps);
    }

    if (format ==  IWX_RATE_MCS_VHT_MSK)
        type = "VHT";
    else if (format == IWX_RATE_MCS_HT_MSK)
        type = "HT";
    else if (format == IWX_RATE_MCS_HE_MSK)
        type = "HE";
    else if (format == IWX_RATE_MCS_EHT_MSK)
        type = "EHT";
    else
        type = "Unknown"; /* shouldn't happen */

    mcs = format == IWX_RATE_MCS_HT_MSK ?
        IWX_RATE_HT_MCS_INDEX(rate) :
        rate & IWX_RATE_MCS_CODE_MSK;
    nss = ((rate & IWX_RATE_MCS_NSS_MSK)
           >> IWX_RATE_MCS_NSS_POS) + 1;
    sgi = format == IWX_RATE_MCS_HE_MSK ?
        iwx_he_is_sgi(rate) :
        rate & IWX_RATE_MCS_SGI_MSK;

    return snprintf(buf, bufsz,
             "0x%x: %s | ANT: %s BW: %s MCS: %d NSS: %d %s%s%s%s%s",
             rate, type, iwx_rs_pretty_ant(ant), iwx_rs_pretty_bw(bw), mcs, nss,
             (sgi) ? "SGI " : "NGI ",
             (rate & IWX_RATE_MCS_STBC_MSK) ? "STBC " : "",
             (rate & IWX_RATE_MCS_LDPC_MSK) ? "LDPC " : "",
             (rate & IWX_RATE_HE_DUAL_CARRIER_MODE_MSK) ? "DCM " : "",
             (rate & IWX_RATE_MCS_BF_MSK) ? "BF " : "");
}

#if NBPFILTER > 0
void    iwx_radiotap_attach(struct iwx_softc *);
#endif

uint8_t ItlIwx::
iwx_lookup_cmd_ver(struct iwx_softc *sc, uint8_t grp, uint8_t cmd)
{
    const struct iwx_fw_cmd_version *entry;
    int i;
    
    for (i = 0; i < sc->n_cmd_versions; i++) {
        entry = &sc->cmd_versions[i];
        if (entry->group == grp && entry->cmd == cmd)
            return entry->cmd_ver;
    }
    
    return IWX_FW_CMD_VER_UNKNOWN;
}

uint8_t ItlIwx::
iwx_lookup_notif_ver(struct iwx_softc *sc, uint8_t grp, uint8_t cmd)
{
    const struct iwx_fw_cmd_version *entry;
    int i;
    
    for (i = 0; i < sc->n_cmd_versions; i++) {
        entry = &sc->cmd_versions[i];
        if (entry->group == grp && entry->cmd == cmd)
            return entry->notif_ver;
    }
    
    return IWX_FW_CMD_VER_UNKNOWN;
}

uint32_t ItlIwx::
iwx_lmac_id(struct iwx_softc *sc, ieee80211_channel *chan)
{
    if (!isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_CDB_SUPPORT) ||
        IEEE80211_IS_CHAN_2GHZ(chan))
        return IWX_LMAC_24G_INDEX;
    return IWX_LMAC_5G_INDEX;
}

int ItlIwx::
iwx_store_cscheme(struct iwx_softc *sc, uint8_t *data, size_t dlen)
{
    struct iwx_fw_cscheme_list *l = (struct iwx_fw_cscheme_list *)data;
    
    if (dlen < sizeof(*l) ||
        dlen < sizeof(l->size) + l->size * sizeof(*l->cs))
        return EINVAL;
    
    /* we don't actually store anything for now, always use s/w crypto */
    
    return 0;
}

int ItlIwx::
iwx_ctxt_info_alloc_dma(struct iwx_softc *sc,
                        const struct iwx_fw_onesect *sec, struct iwx_dma_info *dram)
{
    int err = iwx_dma_contig_alloc(sc->sc_dmat, dram, sec->fws_len, 0);
    if (err) {
        XYLog("%s: could not allocate context info DMA memory\n",
              DEVNAME(sc));
        return err;
    }
    
    memcpy(dram->vaddr, sec->fws_data, sec->fws_len);
    
    return 0;
}

void ItlIwx::
iwx_ctxt_info_free_paging(struct iwx_softc *sc)
{
    struct iwx_self_init_dram *dram = &sc->init_dram;
    int i;
    
    if (!dram->paging)
        return;
    
    /* free paging*/
    for (i = 0; i < dram->paging_cnt; i++)
        iwx_dma_contig_free(&dram->paging[i]);
    
    IOFree(dram->paging, dram->paging_cnt * sizeof(*dram->paging));
    dram->paging_cnt = 0;
    dram->paging = NULL;
}

int ItlIwx::
iwx_get_num_sections(const struct iwx_fw_sects *fws, int start)
{
    int i = 0;
    
    while (start < fws->fw_count &&
           fws->fw_sect[start].fws_devoff != IWX_CPU1_CPU2_SEPARATOR_SECTION &&
           fws->fw_sect[start].fws_devoff != IWX_PAGING_SEPARATOR_SECTION) {
        start++;
        i++;
    }
    
    return i;
}

int ItlIwx::
iwx_init_fw_sec(struct iwx_softc *sc, const struct iwx_fw_sects *fws,
                struct iwx_context_info_dram *ctxt_dram)
{
    struct iwx_self_init_dram *dram = &sc->init_dram;
    int i, ret, fw_cnt = 0;
    
    KASSERT(dram->paging == NULL, "dram->paging == NULL");
    
    dram->lmac_cnt = iwx_get_num_sections(fws, 0);
    /* add 1 due to separator */
    dram->umac_cnt = iwx_get_num_sections(fws, dram->lmac_cnt + 1);
    /* add 2 due to separators */
    dram->paging_cnt = iwx_get_num_sections(fws,
    dram->lmac_cnt + dram->umac_cnt + 2);
    
    dram->fw = (struct iwx_dma_info *)kcalloc(dram->umac_cnt + dram->lmac_cnt, sizeof(*dram->fw));
    if (!dram->fw) {
        XYLog("%s: could not allocate memory for firmware sections\n",
        DEVNAME(sc));
        return ENOMEM;
    }
    dram->paging = (struct iwx_dma_info *)kcalloc(dram->paging_cnt, sizeof(*dram->paging));
    if (!dram->paging) {
        XYLog("%s: could not allocate memory for firmware paging\n",
        DEVNAME(sc));
        return ENOMEM;
    }
    
    /* initialize lmac sections */
    for (i = 0; i < dram->lmac_cnt; i++) {
        ret = iwx_ctxt_info_alloc_dma(sc, &fws->fw_sect[i],
                           &dram->fw[fw_cnt]);
        if (ret)
            return ret;
        ctxt_dram->lmac_img[i] =
            htole64(dram->fw[fw_cnt].paddr);
        DPRINTFN(3, ("%s: firmware LMAC section %d at 0x%llx size %lld\n", __func__, i,
            (unsigned long long)dram->fw[fw_cnt].paddr,
            (unsigned long long)dram->fw[fw_cnt].size));
        fw_cnt++;
    }

    /* initialize umac sections */
    for (i = 0; i < dram->umac_cnt; i++) {
        /* access FW with +1 to make up for lmac separator */
        ret = iwx_ctxt_info_alloc_dma(sc,
            &fws->fw_sect[fw_cnt + 1], &dram->fw[fw_cnt]);
        if (ret)
            return ret;
        ctxt_dram->umac_img[i] =
            htole64(dram->fw[fw_cnt].paddr);
        DPRINTFN(3, ("%s: firmware UMAC section %d at 0x%llx size %lld\n", __func__, i,
            (unsigned long long)dram->fw[fw_cnt].paddr,
            (unsigned long long)dram->fw[fw_cnt].size));
        fw_cnt++;
    }

    /*
     * Initialize paging.
     * Paging memory isn't stored in dram->fw as the umac and lmac - it is
     * stored separately.
     * This is since the timing of its release is different -
     * while fw memory can be released on alive, the paging memory can be
     * freed only when the device goes down.
     * Given that, the logic here in accessing the fw image is a bit
     * different - fw_cnt isn't changing so loop counter is added to it.
     */
    for (i = 0; i < dram->paging_cnt; i++) {
        /* access FW with +2 to make up for lmac & umac separators */
        int fw_idx = fw_cnt + i + 2;

        ret = iwx_ctxt_info_alloc_dma(sc,
            &fws->fw_sect[fw_idx], &dram->paging[i]);
        if (ret)
            return ret;

        ctxt_dram->virtual_img[i] = htole64(dram->paging[i].paddr);
        DPRINTFN(3, ("%s: firmware paging section %d at 0x%llx size %lld\n", __func__, i,
            (unsigned long long)dram->paging[i].paddr,
            (unsigned long long)dram->paging[i].size));
    }

    return 0;
}

void ItlIwx::
iwx_fw_version_str(char *buf, size_t bufsize,
                   uint32_t major, uint32_t minor, uint32_t api)
{
    /*
     * Starting with major version 35 the Linux driver prints the minor
     * version in hexadecimal.
     */
    if (major >= 35)
        snprintf(buf, bufsize, "%u.%08x.%u", major, minor, api);
    else
        snprintf(buf, bufsize, "%u.%u.%u", major, minor, api);
}

int ItlIwx::
iwx_alloc_fw_monitor_block(struct iwx_softc *sc, uint8_t max_power,
                           uint8_t min_power)
{
    struct iwx_dma_info *fw_mon = &sc->fw_mon;
    uint32_t size = 0;
    uint8_t power;
    int err = 0;
    
    if (fw_mon->size)
        return 0;
    
    for (power = max_power; power >= min_power; power--) {
        size = (1 << power);
        
        err = iwx_dma_contig_alloc(sc->sc_dmat, fw_mon, size, 0);
        if (err)
            continue;
        
        DPRINTF(("%s: allocated 0x%08x bytes for firmware monitor.\n",
                 DEVNAME(sc), size));
        break;
    }
    
    if (err) {
        fw_mon->size = 0;
        return err;
    }
    
    if (power != max_power)
        DPRINTF(("%s: Sorry - debug buffer is only %luK while you requested %luK\n",
                 DEVNAME(sc), (unsigned long)(1 << (power - 10)),
                 (unsigned long)(1 << (max_power - 10))));
    
    return 0;
}

int ItlIwx::
iwx_alloc_fw_monitor(struct iwx_softc *sc, uint8_t max_power)
{
    if (!max_power) {
        /* default max_power is maximum */
        max_power = 26;
    } else {
        max_power += 11;
    }
    
    if (max_power > 26) {
        DPRINTF(("%s: External buffer size for monitor is too big %d, "
                 "check the FW TLV\n", DEVNAME(sc), max_power));
        return 0;
    }
    
    if (sc->fw_mon.size)
        return 0;
    
    return iwx_alloc_fw_monitor_block(sc, max_power, 11);
}

int ItlIwx::
iwx_apply_debug_destination(struct iwx_softc *sc)
{
    struct iwx_fw_dbg_dest_tlv_v1 *dest_v1;
    int i, err;
    uint8_t mon_mode, size_power, base_shift, end_shift;
    uint32_t base_reg, end_reg;
    
    dest_v1 = sc->sc_fw.dbg_dest_tlv_v1;
    mon_mode = dest_v1->monitor_mode;
    size_power = dest_v1->size_power;
    base_reg = le32toh(dest_v1->base_reg);
    end_reg = le32toh(dest_v1->end_reg);
    base_shift = dest_v1->base_shift;
    end_shift = dest_v1->end_shift;
    
    DPRINTF(("%s: applying debug destination %d\n", DEVNAME(sc), mon_mode));
    
    if (mon_mode == EXTERNAL_MODE) {
        err = iwx_alloc_fw_monitor(sc, size_power);
        if (err)
            return err;
    }
    
    if (!iwx_nic_lock(sc))
        return EBUSY;
    
    for (i = 0; i < sc->sc_fw.n_dest_reg; i++) {
        uint32_t addr, val;
        uint8_t op;
        
        addr = le32toh(dest_v1->reg_ops[i].addr);
        val = le32toh(dest_v1->reg_ops[i].val);
        op = dest_v1->reg_ops[i].op;
        
        DPRINTF(("%s: op=%u addr=%u val=%u\n", __func__, op, addr, val));
        switch (op) {
            case CSR_ASSIGN:
                IWX_WRITE(sc, addr, val);
                break;
            case CSR_SETBIT:
                IWX_SETBITS(sc, addr, (1 << val));
                break;
            case CSR_CLEARBIT:
                IWX_CLRBITS(sc, addr, (1 << val));
                break;
            case PRPH_ASSIGN:
                iwx_write_prph(sc, addr, val);
                break;
            case PRPH_SETBIT:
                iwx_set_bits_prph(sc, addr, (1 << val));
                break;
            case PRPH_CLEARBIT:
                iwx_clear_bits_prph(sc, addr, (1 << val));
                break;
            case PRPH_BLOCKBIT:
                if (iwx_read_prph(sc, addr) & (1 << val))
                    goto monitor;
                break;
            default:
                DPRINTF(("%s: FW debug - unknown OP %d\n",
                         DEVNAME(sc), op));
                break;
        }
    }
    
monitor:
    if (mon_mode == EXTERNAL_MODE && sc->fw_mon.size) {
        iwx_write_prph(sc, le32toh(base_reg),
                       sc->fw_mon.paddr >> base_shift);
        iwx_write_prph(sc, end_reg,
                       (sc->fw_mon.paddr + sc->fw_mon.size - 256)
                       >> end_shift);
    }
    
    iwx_nic_unlock(sc);
    return 0;
}

void ItlIwx::
iwx_set_ltr(struct iwx_softc *sc)
{
    uint32_t ltr_val = IWX_CSR_LTR_LONG_VAL_AD_NO_SNOOP_REQ |
                    u32_encode_bits(IWX_CSR_LTR_LONG_VAL_AD_SCALE_USEC,
                    IWX_CSR_LTR_LONG_VAL_AD_NO_SNOOP_SCALE) |
                    u32_encode_bits(250,
                    IWX_CSR_LTR_LONG_VAL_AD_NO_SNOOP_VAL) |
                    IWX_CSR_LTR_LONG_VAL_AD_SNOOP_REQ |
                    u32_encode_bits(IWX_CSR_LTR_LONG_VAL_AD_SCALE_USEC,
                    IWX_CSR_LTR_LONG_VAL_AD_SNOOP_SCALE) |
                    u32_encode_bits(250, IWX_CSR_LTR_LONG_VAL_AD_SNOOP_VAL);
    
    /*
     * To workaround hardware latency issues during the boot process,
     * initialize the LTR to ~250 usec (see ltr_val above).
     * The firmware initializes this again later (to a smaller value).
     */
    if ((sc->sc_device_family == IWX_DEVICE_FAMILY_AX210 ||
         sc->sc_device_family == IWX_DEVICE_FAMILY_22000) &&
        !sc->sc_integrated) {
        IWX_WRITE(sc, IWX_CSR_LTR_LONG_VAL_AD, ltr_val);
    } else if (sc->sc_integrated &&
           sc->sc_device_family == IWX_DEVICE_FAMILY_22000) {
        if (iwx_nic_lock(sc)) {
            iwx_write_prph(sc, IWX_HPM_MAC_LTR_CSR, IWX_HPM_MAC_LRT_ENABLE_ALL);
            iwx_write_prph(sc, IWX_HPM_UMAC_LTR, ltr_val);
            iwx_nic_unlock(sc);
        }
    }
}

int ItlIwx::
iwx_ctxt_info_init(struct iwx_softc *sc, const struct iwx_fw_sects *fws)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_context_info *ctxt_info;
    struct iwx_context_info_rbd_cfg *rx_cfg;
    uint32_t control_flags = 0, rb_size;
    int err;
    
    ctxt_info = (struct iwx_context_info *)sc->ctxt_info_dma.vaddr;
    
    ctxt_info->version.version = 0;
    ctxt_info->version.mac_id =
    htole16((uint16_t)IWX_READ(sc, IWX_CSR_HW_REV));
    /* size is in DWs */
    ctxt_info->version.size = htole16(sizeof(*ctxt_info) / 4);
    
    rb_size = IWX_CTXT_INFO_RB_SIZE_4K;
    
    KASSERT(IWX_RX_QUEUE_CB_SIZE(IWX_MQ_RX_TABLE_SIZE) < 0xF, "IWX_RX_QUEUE_CB_SIZE(IWX_MQ_RX_TABLE_SIZE) < 0xF");
    control_flags = IWX_CTXT_INFO_TFD_FORMAT_LONG |
    (IWX_RX_QUEUE_CB_SIZE(IWX_MQ_RX_TABLE_SIZE) <<
     IWX_CTXT_INFO_RB_CB_SIZE_POS) |
    (rb_size << IWX_CTXT_INFO_RB_SIZE_POS);
    ctxt_info->control.control_flags = htole32(control_flags);
    
    /* initialize RX default queue */
    rx_cfg = &ctxt_info->rbd_cfg;
    rx_cfg->free_rbd_addr = htole64(sc->rxq.free_desc_dma.paddr);
    rx_cfg->used_rbd_addr = htole64(sc->rxq.used_desc_dma.paddr);
    rx_cfg->status_wr_ptr = htole64(sc->rxq.stat_dma.paddr);
    
    /* initialize TX command queue */
    ctxt_info->hcmd_cfg.cmd_queue_addr =
    htole64(sc->txq[IWX_DQA_CMD_QUEUE].desc_dma.paddr);
    ctxt_info->hcmd_cfg.cmd_queue_size =
    IWX_TFD_QUEUE_CB_SIZE(IWX_CMD_QUEUE_SIZE);
    
    /* allocate ucode sections in dram and set addresses */
    err = iwx_init_fw_sec(sc, fws, &ctxt_info->dram);
    if (err) {
        iwx_ctxt_info_free_fw_img(sc);
        return err;
    }
    
    //zxystd: I don't know if it is necessary, but it is also works without the debug info, comment it to avoid DMA memory leak
#if 0
    /* Configure debug, if exists */
    if (sc->sc_fw.dbg_dest_tlv_v1) {
        err = iwx_apply_debug_destination(sc);
        if (err) {
            iwx_ctxt_info_free_fw_img(sc);
            return err;
        }
    }
#endif
    
    iwx_enable_fwload_interrupt(sc);
    
    IWX_WRITE64(sc, IWX_CSR_CTXT_INFO_BA, sc->ctxt_info_dma.paddr);
    
    iwx_set_ltr(sc);
    
    /* kick FW self load */
    if (!iwx_nic_lock(sc)) {
        iwx_ctxt_info_free_fw_img(sc);
        return EBUSY;
    }
    iwx_write_prph(sc, IWX_UREG_CPU_INIT_RUN, 1);
    iwx_nic_unlock(sc);
    
    /* Context info will be released upon alive or failure to get one */
    
    return 0;
}

int ItlIwx::
iwx_ctxt_info_gen3_init(struct iwx_softc *sc, const struct iwx_fw_sects *fws)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_context_info_gen3 *ctxt_info_gen3;
    struct iwx_prph_scratch *prph_scratch;
    struct iwx_prph_scratch_ctrl_cfg *prph_sc_ctrl;
    uint32_t control_flags = 0;
    int err;
    
    /* Allocate prph scratch. */
    err = iwx_dma_contig_alloc(sc->sc_dmat, &sc->prph_scratch_dma,
                               sizeof(struct iwx_prph_scratch), 0);
    if (err) {
        XYLog("%s: could not allocate prph scratch\n", DEVNAME(sc));
        return false;
    }
    
    prph_scratch = (struct iwx_prph_scratch *)sc->prph_scratch_dma.vaddr;
    
    prph_sc_ctrl = &prph_scratch->ctrl_cfg;
    prph_sc_ctrl->version.version = 0;
    prph_sc_ctrl->version.mac_id =
        htole16((uint16_t)IWX_READ(sc, IWX_CSR_HW_REV));
    prph_sc_ctrl->version.size = htole16(sizeof(*prph_scratch) / 4);
    
    control_flags = IWX_PRPH_SCRATCH_RB_SIZE_4K;
    control_flags |= IWX_PRPH_SCRATCH_MTR_MODE;
    control_flags |= IWX_PRPH_MTR_FORMAT_256B & IWX_PRPH_SCRATCH_MTR_FORMAT;
    
    /* initialize RX default queue */
    prph_sc_ctrl->rbd_cfg.free_rbd_addr =
        htole64(sc->rxq.free_desc_dma.paddr);
    
    prph_sc_ctrl->control.control_flags = htole32(control_flags);
    
    /* allocate ucode sections in dram and set addresses */
    err = iwx_init_fw_sec(sc, fws, &prph_scratch->dram);
    if (err) {
        iwx_ctxt_info_free_fw_img(sc);
        return err;
    }
    
    /* Allocate prph information. */
    err = iwx_dma_contig_alloc(sc->sc_dmat, &sc->prph_info_dma,
                               PAGE_SIZE, 0);
    if (err) {
        XYLog("%s: could not allocate prph information\n", DEVNAME(sc));
        goto fail0;
    }
    
    ctxt_info_gen3 = (struct iwx_context_info_gen3 *)sc->ctxt_info_dma.vaddr;
    
    ctxt_info_gen3->prph_info_base_addr =
        htole64(sc->prph_info_dma.paddr);
    ctxt_info_gen3->prph_scratch_base_addr =
        htole64(sc->prph_scratch_dma.paddr);
    ctxt_info_gen3->prph_scratch_size =
        htole32(sizeof(*prph_scratch));
    ctxt_info_gen3->cr_head_idx_arr_base_addr =
        htole64(sc->rxq.stat_dma.paddr);
    ctxt_info_gen3->tr_tail_idx_arr_base_addr =
        htole64((uint8_t *)sc->prph_info_dma.paddr + PAGE_SIZE / 2);
    ctxt_info_gen3->cr_tail_idx_arr_base_addr =
        htole64((uint8_t *)sc->prph_info_dma.paddr + 3 * PAGE_SIZE / 4);
    ctxt_info_gen3->mtr_base_addr =
        htole64(sc->txq[IWX_DQA_CMD_QUEUE].desc_dma.paddr);
    ctxt_info_gen3->mcr_base_addr =
        htole64(sc->rxq.used_desc_dma.paddr);
    ctxt_info_gen3->mtr_size =
        htole16(IWX_TFD_QUEUE_CB_SIZE(IWX_CMD_QUEUE_SIZE_GEN3));
    ctxt_info_gen3->mcr_size =
        htole16(IWX_RX_QUEUE_CB_SIZE(IWX_RX_MQ_RING_COUNT));
    
    /* Allocate IML. */
    err = iwx_dma_contig_alloc(sc->sc_dmat, &sc->iml_dma,
                               IWX_IML_MAX_LEN, 0);
    if (err) {
        XYLog("%s: could not allocate IML\n", DEVNAME(sc));
        goto fail1;
    }
    
    memcpy(sc->iml_dma.vaddr, sc->sc_iml, sc->sc_iml_len);
    
    iwx_enable_fwload_interrupt(sc);
    
    /* kick FW self load */
    IWX_WRITE64(sc, IWX_CSR_CTXT_INFO_ADDR,
            sc->ctxt_info_dma.paddr);
    IWX_WRITE64(sc, IWX_CSR_IML_DATA_ADDR,
            sc->iml_dma.paddr);
    IWX_WRITE(sc, IWX_CSR_IML_SIZE_ADDR, sc->sc_iml_len);

    IWX_SETBITS(sc, IWX_CSR_CTXT_INFO_BOOT_CTRL,
            IWX_CSR_AUTO_FUNC_BOOT_ENA);
    
    iwx_set_ltr(sc);
    
    if (!iwx_nic_lock(sc))
        return EBUSY;
    iwx_write_umac_prph(sc, IWX_UREG_CPU_INIT_RUN, 1);
    iwx_nic_unlock(sc);
    
    return 0;
    
fail1:
    iwx_dma_contig_free(&sc->iml_dma);
fail0:
    iwx_dma_contig_free(&sc->prph_info_dma);
    iwx_dma_contig_free(&sc->prph_scratch_dma);
    return ENOMEM;
}

void ItlIwx::
iwx_force_power_gating(struct iwx_softc *sc)
{
   iwx_set_bits_prph(sc, IWX_HPM_HIPM_GEN_CFG,
       IWX_HPM_HIPM_GEN_CFG_CR_FORCE_ACTIVE);
   DELAY(20);
   iwx_set_bits_prph(sc, IWX_HPM_HIPM_GEN_CFG,
       IWX_HPM_HIPM_GEN_CFG_CR_PG_EN |
       IWX_HPM_HIPM_GEN_CFG_CR_SLP_EN);
   DELAY(20);
   iwx_clear_bits_prph(sc, IWX_HPM_HIPM_GEN_CFG,
       IWX_HPM_HIPM_GEN_CFG_CR_FORCE_ACTIVE);
}

void ItlIwx::
iwx_clear_persistence_bit(struct iwx_softc *sc)
{
    uint32_t hpm, wprot;
    
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
        return;
    
    wprot = IWX_PREG_PRPH_WPROT_22000;
    hpm = iwx_read_prph_unlocked(sc, IWX_HPM_DEBUG);
    if (hpm != 0xa5a5a5a0 && (hpm & IWX_PERSISTENCE_BIT)) {
        uint32_t wprot_val = iwx_read_prph_unlocked(sc, wprot);
        
        if (wprot_val & IWX_PREG_WFPM_ACCESS) {
            XYLog("Error, can not clear persistence bit\n");
            return;
        }
        iwx_write_prph_unlocked(sc, IWX_HPM_DEBUG,
                                hpm & ~IWX_PERSISTENCE_BIT);
    }
}

void ItlIwx::
iwx_ctxt_info_free_fw_img(struct iwx_softc *sc)
{
    struct iwx_self_init_dram *dram = &sc->init_dram;
    int i;
    
    if (!dram->fw)
        return;

    for (i = 0; i < dram->lmac_cnt + dram->umac_cnt; i++)
        iwx_dma_contig_free(&dram->fw[i]);

    IOFree(dram->fw,
        (dram->lmac_cnt + dram->umac_cnt) * sizeof(*dram->fw));
    dram->lmac_cnt = 0;
    dram->umac_cnt = 0;
    dram->fw = NULL;
}

int ItlIwx::
iwx_firmware_store_section(struct iwx_softc *sc, enum iwx_ucode_type type,
                           uint8_t *data, size_t dlen)
{
    struct iwx_fw_sects *fws;
    struct iwx_fw_onesect *fwone;
    
    if (type >= IWX_UCODE_TYPE_MAX)
        return EINVAL;
    if (dlen < sizeof(uint32_t))
        return EINVAL;
    
    fws = &sc->sc_fw.fw_sects[type];
    DPRINTFN(3, ("%s: ucode type %d section %d\n", DEVNAME(sc), type, fws->fw_count));
    if (fws->fw_count >= IWX_UCODE_SECT_MAX)
        return EINVAL;
    
    fwone = &fws->fw_sect[fws->fw_count];
    
    /* first 32bit are device load offset */
    memcpy(&fwone->fws_devoff, data, sizeof(uint32_t));
    
    /* rest is data */
    fwone->fws_data = data + sizeof(uint32_t);
    fwone->fws_len = dlen - sizeof(uint32_t);
    
    fws->fw_count++;
    fws->fw_totlen += fwone->fws_len;
    
    return 0;
}

#define IWX_DEFAULT_SCAN_CHANNELS    40
/* Newer firmware might support more channels. Raise this value if needed. */
#define IWX_MAX_SCAN_CHANNELS        256 /* as of 8265-34 firmware image */
#define IWX_STATION_COUNT_MAX        16

struct iwx_tlv_calib_data {
    uint32_t ucode_type;
    struct iwx_tlv_calib_ctrl calib;
} __packed;

int ItlIwx::
iwx_set_default_calib(struct iwx_softc *sc, const void *data)
{
    const struct iwx_tlv_calib_data *def_calib = (const struct iwx_tlv_calib_data *)data;
    uint32_t ucode_type = le32toh(def_calib->ucode_type);
    
    if (ucode_type >= IWX_UCODE_TYPE_MAX)
        return EINVAL;
    
    sc->sc_default_calib[ucode_type].flow_trigger =
    def_calib->calib.flow_trigger;
    sc->sc_default_calib[ucode_type].event_trigger =
    def_calib->calib.event_trigger;
    
    return 0;
}

void ItlIwx::
iwx_fw_info_free(struct iwx_fw_info *fw)
{
    ::free(fw->fw_rawdata);
    fw->fw_rawdata = NULL;
    fw->fw_rawsize = 0;
    /* don't touch fw->fw_status */
    memset(fw->fw_sects, 0, sizeof(fw->fw_sects));
}

void ItlIwx::
iwx_pnvm_free(struct iwx_fw_info *fw)
{
    if (fw->pnvm_rawdata) {
        ::free(fw->pnvm_rawdata);
        fw->pnvm_rawdata = NULL;
        fw->pnvm_rawsize = 0;
    }
}

#define IWX_FW_ADDR_CACHE_CONTROL 0xC0000000

//void ItlIwx::
//onLoadFW(OSKextRequestTag requestTag, OSReturn result, const void *resourceData, uint32_t resourceDataLength, void *context)
//{
//    XYLog("onLoadFW callback ret=0x%08x length=%d", result, resourceDataLength);
//    ResourceCallbackContext *resourceContxt = (ResourceCallbackContext*)context;
//    IOLockLock(resourceContxt->context->_fwLoadLock);
//    if (resourceDataLength > 0) {
//        XYLog("onLoadFW return success");
//        resourceContxt->resource = OSData::withBytes(resourceData, resourceDataLength);
//    }
//    IOLockUnlock(resourceContxt->context->_fwLoadLock);
//    IOLockWakeup(resourceContxt->context->_fwLoadLock, resourceContxt->context, false);
//    XYLog("onLoadFW wakeupOn");
//}

int ItlIwx::
iwx_read_firmware(struct iwx_softc *sc)
{
    struct iwx_fw_info *fw = &sc->sc_fw;
    struct iwx_tlv_ucode_header *uhdr;
    struct iwx_ucode_tlv tlv;
    uint32_t tlv_type = 0;
    uint8_t *data;
    int err = 0;
    size_t len;
    OSData *fwData = NULL;
    
    if (fw->fw_status == IWX_FW_STATUS_DONE)
        return 0;
    
    while (fw->fw_status == IWX_FW_STATUS_INPROGRESS)
        tsleep_nsec(&sc->sc_fw, 0, "iwxfwp", INFSLP);
    fw->fw_status = IWX_FW_STATUS_INPROGRESS;
    
    if (fw->fw_rawdata != NULL)
        iwx_fw_info_free(fw);
    
//    IOLockLock(_fwLoadLock);
//    ResourceCallbackContext context =
//    {
//        .context = this,
//        .resource = NULL
//    };
//
//    //here leaks
//    IOReturn ret = OSKextRequestResource(OSKextGetCurrentIdentifier(), sc->sc_fwname, onLoadFW, &context, NULL);
//    IOLockSleep(_fwLoadLock, this, 0);
//    IOLockUnlock(_fwLoadLock);
//    if (context.resource == NULL) {
//        XYLog("%s resource load fail.\n", sc->sc_fwname);
//        goto out;
//    }
//    fw->fw_rawdata = malloc(context.resource->getLength(), 1, 1);
//    memcpy(fw->fw_rawdata, context.resource->getBytesNoCopy(), context.resource->getLength());
//    fw->fw_rawsize = context.resource->getLength();
    fwData = getFWDescByName(sc->sc_fwname);
    if (fwData == NULL) {
        err = EINVAL;
        XYLog("%s resource load fail.\n", sc->sc_fwname);
        goto out;
    }
    fw->fw_rawsize = fwData->getLength() * 4;
    fw->fw_rawdata = malloc(fw->fw_rawsize, 1, 1);
    uncompressFirmware((u_char *)fw->fw_rawdata, (uint *)&fw->fw_rawsize, (u_char *)fwData->getBytesNoCopy(), fwData->getLength());
    XYLog("load firmware %s done\n", sc->sc_fwname);
    
    sc->sc_capaflags = 0;
    sc->sc_capa_n_scan_channels = IWX_DEFAULT_SCAN_CHANNELS;
    memset(sc->sc_enabled_capa, 0, sizeof(sc->sc_enabled_capa));
    memset(sc->sc_ucode_api, 0, sizeof(sc->sc_ucode_api));
    sc->n_cmd_versions = 0;
    memcpy(sc->sc_fw_mcc, "ZZ", sizeof(sc->sc_fw_mcc));
    sc->sc_fw_mcc_int = 0x3030;
    
    uhdr = (struct iwx_tlv_ucode_header *)fw->fw_rawdata;
    if (*(uint32_t *)fw->fw_rawdata != 0
        || le32toh(uhdr->magic) != IWX_TLV_UCODE_MAGIC) {
        XYLog("%s: invalid firmware %s\n",
              DEVNAME(sc), sc->sc_fwname);
        err = EINVAL;
        goto out;
    }
    
    iwx_fw_version_str(sc->sc_fwver, sizeof(sc->sc_fwver),
             IWX_UCODE_MAJOR(le32toh(uhdr->ver)),
             IWX_UCODE_MINOR(le32toh(uhdr->ver)),
             IWX_UCODE_API(le32toh(uhdr->ver)));
    data = uhdr->data;
    len = fw->fw_rawsize - sizeof(*uhdr);
    
    XYLog("parsing firmware %s\n", sc->sc_fwname);
    while (len >= sizeof(tlv)) {
        size_t tlv_len;
        void *tlv_data;
        
        memcpy(&tlv, data, sizeof(tlv));
        tlv_len = le32toh(tlv.length);
        tlv_type = le32toh(tlv.type);
        
        len -= sizeof(tlv);
        data += sizeof(tlv);
        tlv_data = data;
        
        if (len < tlv_len) {
            XYLog("%s: firmware too short: %zu bytes\n",
                  DEVNAME(sc), len);
            err = EINVAL;
            goto parse_out;
        }
        
        switch (tlv_type) {
            case IWX_UCODE_TLV_PROBE_MAX_LEN:
                if (tlv_len < sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                sc->sc_capa_max_probe_len
                = le32toh(*(uint32_t *)tlv_data);
                if (sc->sc_capa_max_probe_len >
                    IWX_SCAN_OFFLOAD_PROBE_REQ_SIZE) {
                    err = EINVAL;
                    goto parse_out;
                }
                break;
            case IWX_UCODE_TLV_PAN:
                if (tlv_len) {
                    err = EINVAL;
                    goto parse_out;
                }
                sc->sc_capaflags |= IWX_UCODE_TLV_FLAGS_PAN;
                break;
            case IWX_UCODE_TLV_FLAGS:
                if (tlv_len < sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                /*
                 * Apparently there can be many flags, but Linux driver
                 * parses only the first one, and so do we.
                 *
                 * XXX: why does this override IWX_UCODE_TLV_PAN?
                 * Intentional or a bug?  Observations from
                 * current firmware file:
                 *  1) TLV_PAN is parsed first
                 *  2) TLV_FLAGS contains TLV_FLAGS_PAN
                 * ==> this resets TLV_PAN to itself... hnnnk
                 */
                sc->sc_capaflags = le32toh(*(uint32_t *)tlv_data);
                break;
            case IWX_UCODE_TLV_CSCHEME:
                err = iwx_store_cscheme(sc, (uint8_t *)tlv_data, tlv_len);
                if (err)
                    goto parse_out;
                break;
            case IWX_UCODE_TLV_NUM_OF_CPU: {
                uint32_t num_cpu;
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                num_cpu = le32toh(*(uint32_t *)tlv_data);
                if (num_cpu < 1 || num_cpu > 2) {
                    err = EINVAL;
                    goto parse_out;
                }
                break;
            }
            case IWX_UCODE_TLV_SEC_RT:
                err = iwx_firmware_store_section(sc,
                                                 IWX_UCODE_TYPE_REGULAR, (uint8_t *)tlv_data, tlv_len);
                if (err)
                    goto parse_out;
                break;
            case IWX_UCODE_TLV_SEC_INIT:
                err = iwx_firmware_store_section(sc,
                                                 IWX_UCODE_TYPE_INIT, (uint8_t *)tlv_data, tlv_len);
                if (err)
                    goto parse_out;
                break;
            case IWX_UCODE_TLV_SEC_WOWLAN:
                err = iwx_firmware_store_section(sc,
                                                 IWX_UCODE_TYPE_WOW, (uint8_t *)tlv_data, tlv_len);
                if (err)
                    goto parse_out;
                break;
            case IWX_UCODE_TLV_DEF_CALIB:
                if (tlv_len != sizeof(struct iwx_tlv_calib_data)) {
                    err = EINVAL;
                    goto parse_out;
                }
                err = iwx_set_default_calib(sc, tlv_data);
                if (err)
                    goto parse_out;
                break;
            case IWX_UCODE_TLV_PHY_SKU:
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                sc->sc_fw_phy_config = le32toh(*(uint32_t *)tlv_data);
                break;
                
            case IWX_UCODE_TLV_API_CHANGES_SET: {
                struct iwx_ucode_api *api;
                int idx, i;
                if (tlv_len != sizeof(*api)) {
                    err = EINVAL;
                    goto parse_out;
                }
                api = (struct iwx_ucode_api *)tlv_data;
                idx = le32toh(api->api_index);
                if (idx >= howmany(IWX_NUM_UCODE_TLV_API, 32)) {
                    err = EINVAL;
                    goto parse_out;
                }
                for (i = 0; i < 32; i++) {
                    if ((le32toh(api->api_flags) & (1 << i)) == 0)
                        continue;
                    setbit(sc->sc_ucode_api, i + (32 * idx));
                }
                break;
            }
                
            case IWX_UCODE_TLV_ENABLED_CAPABILITIES: {
                struct iwx_ucode_capa *capa;
                int idx, i;
                if (tlv_len != sizeof(*capa)) {
                    err = EINVAL;
                    goto parse_out;
                }
                capa = (struct iwx_ucode_capa *)tlv_data;
                idx = le32toh(capa->api_index);
                if (idx >= howmany(IWX_NUM_UCODE_TLV_CAPA, 32)) {
                    goto parse_out;
                }
                for (i = 0; i < 32; i++) {
                    if ((le32toh(capa->api_capa) & (1 << i)) == 0)
                        continue;
                    setbit(sc->sc_enabled_capa, i + (32 * idx));
                }
                break;
            }
                
            case IWX_UCODE_TLV_SDIO_ADMA_ADDR:
            case IWX_UCODE_TLV_FW_GSCAN_CAPA:
                /* ignore, not used by current driver */
                break;
                
            case IWX_UCODE_TLV_SEC_RT_USNIFFER:
                err = iwx_firmware_store_section(sc,
                                                 IWX_UCODE_TYPE_REGULAR_USNIFFER, (uint8_t *)tlv_data,
                                                 tlv_len);
                if (err)
                    goto parse_out;
                break;
                
            case IWX_UCODE_TLV_PAGING:
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                break;
                
            case IWX_UCODE_TLV_N_SCAN_CHANNELS:
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                sc->sc_capa_n_scan_channels =
                le32toh(*(uint32_t *)tlv_data);
                if (sc->sc_capa_n_scan_channels > IWX_MAX_SCAN_CHANNELS) {
                    err = ERANGE;
                    goto parse_out;
                }
                break;
                
            case IWX_UCODE_TLV_FW_VERSION:
                if (tlv_len != sizeof(uint32_t) * 3) {
                    err = EINVAL;
                    goto parse_out;
                }
                iwx_fw_version_str(sc->sc_fwver, sizeof(sc->sc_fwver),
                         le32toh(((uint32_t *)tlv_data)[0]),
                         le32toh(((uint32_t *)tlv_data)[1]),
                         le32toh(((uint32_t *)tlv_data)[2]));
                break;
                
            case IWX_UCODE_TLV_FW_DBG_DEST: {
                struct iwx_fw_dbg_dest_tlv_v1 *dest_v1 = NULL;
                
                fw->dbg_dest_ver = (uint8_t *)tlv_data;
                if (*fw->dbg_dest_ver != 0) {
                    err = EINVAL;
                    goto parse_out;
                }
                
                if (fw->dbg_dest_tlv_init)
                    break;
                fw->dbg_dest_tlv_init = true;
                
                dest_v1 = (struct iwx_fw_dbg_dest_tlv_v1 *)tlv_data;
                fw->dbg_dest_tlv_v1 = dest_v1;
                fw->n_dest_reg = tlv_len -
                offsetof(struct iwx_fw_dbg_dest_tlv_v1, reg_ops);
                fw->n_dest_reg /= sizeof(dest_v1->reg_ops[0]);
                DPRINTF(("%s: found debug dest; n_dest_reg=%d\n", __func__, fw->n_dest_reg));
                break;
            }
                
            case IWX_UCODE_TLV_FW_DBG_CONF: {
                struct iwx_fw_dbg_conf_tlv *conf = (struct iwx_fw_dbg_conf_tlv *)tlv_data;
                
                if (!fw->dbg_dest_tlv_init ||
                    conf->id >= nitems(fw->dbg_conf_tlv) ||
                    fw->dbg_conf_tlv[conf->id] != NULL)
                    break;
                
                DPRINTF(("Found debug configuration: %d\n", conf->id));
                fw->dbg_conf_tlv[conf->id] = conf;
                fw->dbg_conf_tlv_len[conf->id] = tlv_len;
                break;
            }
                
            case IWX_UCODE_TLV_UMAC_DEBUG_ADDRS: {
                struct iwx_umac_debug_addrs *dbg_ptrs =
                (struct iwx_umac_debug_addrs *)tlv_data;
                
                if (tlv_len != sizeof(*dbg_ptrs)) {
                    err = EINVAL;
                    goto parse_out;
                }
                if (sc->sc_device_family < IWX_DEVICE_FAMILY_22000)
                    break;
                sc->sc_uc.uc_umac_error_event_table =
                le32toh(dbg_ptrs->error_info_addr) &
                ~IWX_FW_ADDR_CACHE_CONTROL;
                sc->sc_uc.error_event_table_tlv_status |=
                IWX_ERROR_EVENT_TABLE_UMAC;
                break;
            }
                
            case IWX_UCODE_TLV_LMAC_DEBUG_ADDRS: {
                struct iwx_lmac_debug_addrs *dbg_ptrs =
                (struct iwx_lmac_debug_addrs *)tlv_data;
                
                if (tlv_len != sizeof(*dbg_ptrs)) {
                    err = EINVAL;
                    goto parse_out;
                }
                if (sc->sc_device_family < IWX_DEVICE_FAMILY_22000)
                    break;
                sc->sc_uc.uc_lmac_error_event_table[0] =
                le32toh(dbg_ptrs->error_event_table_ptr) &
                ~IWX_FW_ADDR_CACHE_CONTROL;
                sc->sc_uc.error_event_table_tlv_status |=
                IWX_ERROR_EVENT_TABLE_LMAC1;
                break;
            }
                
            case IWX_UCODE_TLV_FW_MEM_SEG:
                break;
                
            case IWX_UCODE_TLV_IML:
                if (sizeof(sc->sc_iml) < tlv_len) {
                    XYLog("IML max len mismatch. len1: %zu len2: %zu\n", sizeof(sc->sc_iml), tlv_len);
                    err = EINVAL;
                    goto parse_out;
                }
                sc->sc_iml_len = (uint32_t)tlv_len;
                memcpy(sc->sc_iml, tlv_data, sc->sc_iml_len);
                break;
                
            case IWX_UCODE_TLV_CMD_VERSIONS:
                if (tlv_len % sizeof(struct iwx_fw_cmd_version)) {
                    tlv_len /= sizeof(struct iwx_fw_cmd_version);
                    tlv_len *= sizeof(struct iwx_fw_cmd_version);
                }
                if (sc->n_cmd_versions != 0) {
                    err = EINVAL;
                    goto parse_out;
                }
                if (tlv_len > sizeof(sc->cmd_versions)) {
                    err = EINVAL;
                    goto parse_out;
                }
                memcpy(&sc->cmd_versions[0], tlv_data, tlv_len);
                sc->n_cmd_versions = tlv_len / sizeof(struct iwx_fw_cmd_version);
                break;
                
            case IWX_UCODE_TLV_FW_RECOVERY_INFO:
                break;
                
            case IWX_UCODE_TLV_FW_FSEQ_VERSION: {
                struct sfseq_ver {
                    uint8_t version[32];
                    uint8_t sha1[20];
                };
                sfseq_ver *seq_ver = (sfseq_ver *)tlv_data;
                if (tlv_len != sizeof(struct sfseq_ver)) {
                    err = EINVAL;
                    goto parse_out;
                }
                XYLog("TLV_FW_FSEQ_VERSION: %s\n", seq_ver->version);
            }
                break;
                
            case IWX_UCODE_PHY_INTEGRATION_VERSION:
                break;
            case IWX_UCODE_TLV_FW_NUM_STATIONS:
                if (tlv_len != sizeof(uint32_t)) {
                    err = EINVAL;
                    goto parse_out;
                }
                sc->sc_capa_num_stations = le32toh(*(uint32_t *)tlv_data);
                if (sc->sc_capa_num_stations > IWX_STATION_COUNT_MAX) {
                    XYLog("%d is an invalid number of station\n",
                          sc->sc_capa_num_stations);
                    err = EINVAL;
                    goto parse_out;
                }
                break;
                
                /* undocumented TLVs found in iwx-cc-a0-48 image */
            case 58:
            case 0x1000003:
            case 0x1000004:
                break;
                
                /* undocumented TLVs found in iwx-cc-a0-48 image */
            case 0x1000000:
            case 0x1000002:
            case IWX_UCODE_TLV_TYPE_DEBUG_INFO:
            case IWX_UCODE_TLV_TYPE_BUFFER_ALLOCATION:
            case IWX_UCODE_TLV_TYPE_HCMD:
            case IWX_UCODE_TLV_TYPE_REGIONS:
            case IWX_UCODE_TLV_TYPE_TRIGGERS:
            case IWX_UCODE_TLV_TYPE_CONF_SET:
                break;

                /* undocumented TLV found in iwx-cc-a0-67 image */
            case 0x100000b:
                break;
                
            default:
                //            err = EINVAL;
                //            goto parse_out;
                XYLog("%s unhandle section type= %d\n", __FUNCTION__, tlv_type);
                break;
        }
        
        /*
         * Check for size_t overflow and ignore missing padding at
         * end of firmware file.
         */
        if (roundup(tlv_len, 4) > len)
            break;
        
        len -= roundup(tlv_len, 4);
        data += roundup(tlv_len, 4);
    }
    
    KASSERT(err == 0, "err == 0");
    
    XYLog("firmware parse done\n");
    
parse_out:
    if (err) {
        XYLog("%s: firmware parse error %d, "
              "section type %d\n", DEVNAME(sc), err, tlv_type);
    }
    
out:
    if (err) {
        fw->fw_status = IWX_FW_STATUS_NONE;
        if (fw->fw_rawdata != NULL)
            iwx_fw_info_free(fw);
    } else
        fw->fw_status = IWX_FW_STATUS_DONE;
    wakeupOn(&sc->sc_fw);

    OSSafeReleaseNULL(fwData);
    
    return err;
}

struct iwx_pnvm_section {
    uint32_t offset;
    const uint8_t data[];
} __packed;

int ItlIwx::
iwx_pnvm_handle_section(struct iwx_softc *sc, const uint8_t *data, size_t len)
{
    struct iwx_ucode_tlv *tlv;
    uint32_t sha1 = 0;
    uint16_t mac_type = 0, rf_id = 0;
    uint8_t *pnvm_data = NULL, *tmp;
    bool hw_match = false;
    uint32_t size = 0;
    int err = 0;
    struct iwx_prph_scratch_ctrl_cfg *prph_sc_ctrl;
    
    XYLog("Handling PNVM section\n");
    
    while (len >= sizeof(*tlv)) {
        uint32_t tlv_len, tlv_type;
        
        len -= sizeof(*tlv);
        tlv = (struct iwx_ucode_tlv *)data;
        
        tlv_len = le32toh(tlv->length);
        tlv_type = le32toh(tlv->type);
        
        if (len < tlv_len) {
            XYLog("invalid TLV len: %zd/%u\n",
                  len, tlv_len);
            err = -EINVAL;
            goto out;
        }
        
        data += sizeof(*tlv);
        
        switch (tlv_type) {
            case IWX_UCODE_TLV_PNVM_VERSION:
                if (tlv_len < sizeof(__le32)) {
                    XYLog("Invalid size for IWL_UCODE_TLV_PNVM_VERSION (expected %zd, got %d)\n",
                          sizeof(__le32), tlv_len);
                    break;
                }
                
                sha1 = le32_to_cpup((__le32 *)data);
                
                XYLog("Got IWL_UCODE_TLV_PNVM_VERSION %0x\n",
                      sha1);
                break;
            case IWX_UCODE_TLV_HW_TYPE:
                if (tlv_len < 2 * sizeof(__le16)) {
                    XYLog("Invalid size for IWL_UCODE_TLV_HW_TYPE (expected %zd, got %d)\n",
                          2 * sizeof(__le16), tlv_len);
                    break;
                }
                
                if (hw_match)
                    break;

                mac_type = le16_to_cpup((__le16 *)data);
                rf_id = le16_to_cpup((__le16 *)(data + sizeof(__le16)));
                
                XYLog("Got IWL_UCODE_TLV_HW_TYPE mac_type 0x%0x rf_id 0x%0x\n",
                      mac_type, rf_id);
                
                if (mac_type == CSR_HW_REV_TYPE(sc->sc_hw_rev) &&
                    rf_id == CSR_HW_RFID_TYPE(sc->sc_hw_rf_id))
                    hw_match = true;
                break;
            case IWX_UCODE_TLV_SEC_RT: {
                struct iwx_pnvm_section *section = (struct iwx_pnvm_section *)data;
                u32 data_len = tlv_len - sizeof(*section);
                
                XYLog("Got IWL_UCODE_TLV_SEC_RT len %d\n",
                      tlv_len);
                
                /* TODO: remove, this is a deprecated separator */
                if (le32_to_cpup((__le32 *)data) == 0xddddeeee) {
                    XYLog("Ignoring separator.\n");
                    break;
                }
                
                XYLog("Adding data (size %d)\n",
                      data_len);
                
                tmp = (uint8_t *)malloc(size + data_len, 0, 0);
                if (!tmp) {
                    XYLog("Couldn't allocate (more) pnvm_data\n");
                    
                    err = -ENOMEM;
                    goto out;
                }
                if (pnvm_data && size > 0) {
                    memcpy(tmp, pnvm_data, size);
                    ::free(pnvm_data);
                }
                
                pnvm_data = tmp;
                
                memcpy(pnvm_data + size, section->data, data_len);
                
                size += data_len;
                
                break;
            }
            case IWX_UCODE_TLV_PNVM_SKU:
                XYLog("New PNVM section started, stop parsing.\n");
                goto done;
            default:
                XYLog("Found TLV 0x%0x, len %d\n",
                      tlv_type, tlv_len);
                break;
        }
        
        if (roundup(tlv_len, 4) > len)
            break;
        
        len -= roundup(tlv_len, 4);
        data += roundup(tlv_len, 4);
    }
    
done:
    if (!hw_match) {
        XYLog("HW mismatch, skipping PNVM section (need mac_type 0x%x rf_id 0x%x)\n",
                 CSR_HW_REV_TYPE(sc->sc_hw_rev),
                 CSR_HW_RFID_TYPE(sc->sc_hw_rf_id));
        err = -ENOENT;
        goto out;
    }

    if (!size) {
        XYLog("Empty PNVM, skipping.\n");
        err = -ENOENT;
        goto out;
    }
    
    XYLog("loaded PNVM version %08x\n", sha1);
    
    prph_sc_ctrl = &((struct iwx_prph_scratch *)sc->prph_scratch_dma.vaddr)->ctrl_cfg;
    
    iwx_dma_contig_free(&sc->pnvm_dram);
    err = iwx_dma_contig_alloc(sc->sc_dmat, &sc->pnvm_dram, size, 0);
    if (err) {
        XYLog("%s: could not allocate context info DMA memory\n",
              DEVNAME(sc));
        goto out;
    }
    
    memcpy(sc->pnvm_dram.vaddr, pnvm_data, size);
    
    prph_sc_ctrl->pnvm_cfg.pnvm_base_addr =
        htole64(sc->pnvm_dram.paddr);
    prph_sc_ctrl->pnvm_cfg.pnvm_size =
        htole32(sc->pnvm_dram.size);
    
out:
    ::free(pnvm_data);
    
    return err;
}

int ItlIwx::
iwx_read_pnvm(struct iwx_softc *sc)
{
    int err = 0;
    OSData *fwData = NULL;
    struct iwx_fw_info *fw = &sc->sc_fw;
    char fwname_copy[64];
    char pnvm_name[64];
    struct iwx_ucode_tlv *tlv;
    uint8_t *data;
    size_t len;
    const char *find;
    
    if (fw->pnvm_rawdata != NULL)
        iwx_pnvm_free(fw);
    /*
     * The prefix unfortunately includes a hyphen at the end, so
     * don't add the dot here...
     */
    memcpy(fwname_copy, sc->sc_fwname, sizeof(fwname_copy));
    find = strrchr(sc->sc_fwname, '-');
    if (!find)
        goto out;
    if (find - sc->sc_fwname - 1 <= 0)
        goto out;
    fwname_copy[find - sc->sc_fwname - 1] = '\0';
    
    snprintf(pnvm_name, sizeof(pnvm_name), "%s.pnvm",
         fwname_copy);
    
    fwData = getFWDescByName(pnvm_name);

    if (fwData == NULL) {
        err = EINVAL;
        XYLog("%s resource load fail.\n", pnvm_name);
        goto out;
    }
    fw->pnvm_rawsize = fwData->getLength() * 20;
    fw->pnvm_rawdata = malloc(fw->pnvm_rawsize, 1, 1);
    uncompressFirmware((u_char *)fw->pnvm_rawdata, (uint *)&fw->pnvm_rawsize, (u_char *)fwData->getBytesNoCopy(), fwData->getLength());
    XYLog("load firmware %s done %zu\n", pnvm_name, fw->pnvm_rawsize);
    
    XYLog("Parsing PNVM file\n");
    
    data = (uint8_t *)fw->pnvm_rawdata;
    len = fw->pnvm_rawsize;
    
    while (len >= sizeof(*tlv)) {
        uint32_t tlv_len, tlv_type;

        len -= sizeof(*tlv);
        tlv = (struct iwx_ucode_tlv *)data;

        tlv_len = le32toh(tlv->length);
        tlv_type = le32toh(tlv->type);

        if (len < tlv_len || roundup(tlv_len, 4) > len) {
            XYLog("invalid TLV len: %zd/%u\n",
                len, tlv_len);
            err = -EINVAL;
            goto out;
        }

        if (tlv_type == IWX_UCODE_TLV_PNVM_SKU) {
            struct iwx_sku_id *sku_id =
                (struct iwx_sku_id *)(data + sizeof(*tlv));

            XYLog("Got IWL_UCODE_TLV_PNVM_SKU len %d\n",
                     tlv_len);
            XYLog("sku_id 0x%0x 0x%0x 0x%0x\n",
                     le32toh(sku_id->data[0]),
                     le32toh(sku_id->data[1]),
                     le32toh(sku_id->data[2]));

            data += sizeof(*tlv) + roundup(tlv_len, 4);
            len -= roundup(tlv_len, 4);

            if (sc->sku_id[0] == le32toh(sku_id->data[0]) &&
                sc->sku_id[1] == le32toh(sku_id->data[1]) &&
                sc->sku_id[2] == le32toh(sku_id->data[2])) {

                err = iwx_pnvm_handle_section(sc, data, len);
                if (!err)
                    goto out;
            } else {
                XYLog("SKU ID didn't match!\n");
            }
        } else {
            data += sizeof(*tlv) + roundup(tlv_len, 4);
            len -= roundup(tlv_len, 4);
        }
    }
    
    XYLog("PNVM parse done\n");
    
out:
    OSSafeReleaseNULL(fwData);
    
    return err;
}

int ItlIwx::
iwx_load_pnvm(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int err;
    
    /* if the SKU_ID is empty, there's nothing to do */
    if (!sc->sku_id[0] && !sc->sku_id[1] && !sc->sku_id[2])
        return 0;
    
    if (!iwx_read_pnvm(sc)) {
        goto out;
    };
    
out:
    /* kick the doorbell */
    if (iwx_nic_lock(sc)) {
        iwx_write_umac_prph(sc, IWX_UREG_DOORBELL_TO_ISR6,
        IWX_UREG_DOORBELL_TO_ISR6_PNVM);
        iwx_nic_unlock(sc);
    }
    
    err = tsleep_nsec(&sc->sc_init_complete, 0, "iwxinit", SEC_TO_NSEC(2));
    
    iwx_pnvm_free(&sc->sc_fw);
    
    return err;
}

static uint32_t iwx_prph_msk(struct iwx_softc *sc)
{
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
        return 0x00FFFFFF;
    else
        return 0x000FFFFF;
}

uint32_t ItlIwx::
iwx_read_prph_unlocked(struct iwx_softc *sc, uint32_t addr)
{
    IWX_WRITE(sc,
              IWX_HBUS_TARG_PRPH_RADDR, ((addr & iwx_prph_msk(sc)) | (3 << 24)));
    IWX_BARRIER_READ_WRITE(sc);
    return IWX_READ(sc, IWX_HBUS_TARG_PRPH_RDAT);
}

uint32_t ItlIwx::
iwx_read_prph(struct iwx_softc *sc, uint32_t addr)
{
    iwx_nic_assert_locked(sc);
    return iwx_read_prph_unlocked(sc, addr);
}

uint32_t ItlIwx::
iwx_read_umac_prph(struct iwx_softc *sc, uint32_t addr)
{
    int off = 0;
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
        off = GEN3_UMAC_PRPH_OFFSET;
    return iwx_read_prph(sc, off + addr);
}

void ItlIwx::
iwx_write_prph_unlocked(struct iwx_softc *sc, uint32_t addr, uint32_t val)
{
    IWX_WRITE(sc,
              IWX_HBUS_TARG_PRPH_WADDR, ((addr & iwx_prph_msk(sc)) | (3 << 24)));
    IWX_BARRIER_WRITE(sc);
    IWX_WRITE(sc, IWX_HBUS_TARG_PRPH_WDAT, val);
}

void ItlIwx::
iwx_write_umac_prph(struct iwx_softc *sc, uint32_t addr, uint32_t val)
{
    int off = 0;
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
        off = GEN3_UMAC_PRPH_OFFSET;
    iwx_write_prph(sc, off + addr, val);
}

void ItlIwx::
iwx_write_prph(struct iwx_softc *sc, uint32_t addr, uint32_t val)
{
    iwx_nic_assert_locked(sc);
    iwx_write_prph_unlocked(sc, addr, val);
}

void ItlIwx::
iwx_write_prph64(struct iwx_softc *sc, uint64_t addr, uint64_t val)
{
    iwx_write_prph(sc, (uint32_t)addr, val & 0xffffffff);
    iwx_write_prph(sc, (uint32_t)addr + 4, val >> 32);
}

int ItlIwx::
iwx_read_mem(struct iwx_softc *sc, uint32_t addr, void *buf, int dwords)
{
    int offs, err = 0;
    uint32_t *vals = (uint32_t *)buf;
    
    if (iwx_nic_lock(sc)) {
        IWX_WRITE(sc, IWX_HBUS_TARG_MEM_RADDR, addr);
        for (offs = 0; offs < dwords; offs++)
            vals[offs] = le32toh(IWX_READ(sc, IWX_HBUS_TARG_MEM_RDAT));
        iwx_nic_unlock(sc);
    } else {
        err = EBUSY;
    }
    return err;
}

int ItlIwx::
iwx_write_mem(struct iwx_softc *sc, uint32_t addr, const void *buf, int dwords)
{
    int offs;
    const uint32_t *vals = (const uint32_t *)buf;
    
    if (iwx_nic_lock(sc)) {
        IWX_WRITE(sc, IWX_HBUS_TARG_MEM_WADDR, addr);
        /* WADDR auto-increments */
        for (offs = 0; offs < dwords; offs++) {
            uint32_t val = vals ? vals[offs] : 0;
            IWX_WRITE(sc, IWX_HBUS_TARG_MEM_WDAT, val);
        }
        iwx_nic_unlock(sc);
    } else {
        return EBUSY;
    }
    return 0;
}

int ItlIwx::
iwx_write_mem32(struct iwx_softc *sc, uint32_t addr, uint32_t val)
{
    return iwx_write_mem(sc, addr, &val, 1);
}

int ItlIwx::
iwx_poll_bit(struct iwx_softc *sc, int reg, uint32_t bits, uint32_t mask,
             int timo)
{
    for (;;) {
        if ((IWX_READ(sc, reg) & mask) == (bits & mask)) {
            return 1;
        }
        if (timo < 10) {
            return 0;
        }
        timo -= 10;
        DELAY(10);
    }
}

int ItlIwx::
iwx_nic_lock(struct iwx_softc *sc)
{
    if (sc->sc_nic_locks > 0) {
        iwx_nic_assert_locked(sc);
        sc->sc_nic_locks++;
        return 1; /* already locked */
    }
    
    IWX_SETBITS(sc, IWX_CSR_GP_CNTRL,
                IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
    
    DELAY(2);
    
    if (iwx_poll_bit(sc, IWX_CSR_GP_CNTRL,
                     IWX_CSR_GP_CNTRL_REG_VAL_MAC_ACCESS_EN,
                     IWX_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY
                     | IWX_CSR_GP_CNTRL_REG_FLAG_GOING_TO_SLEEP, 150000)) {
        sc->sc_nic_locks++;
        return 1;
    }
    
    XYLog("%s: acquiring device failed\n", DEVNAME(sc));
    return 0;
}

void ItlIwx::
iwx_nic_assert_locked(struct iwx_softc *sc)
{
    if (sc->sc_nic_locks <= 0)
        panic("%s: nic locks counter %d", DEVNAME(sc), sc->sc_nic_locks);
}

void ItlIwx::
iwx_nic_unlock(struct iwx_softc *sc)
{
    if (sc->sc_nic_locks > 0) {
        if (--sc->sc_nic_locks == 0)
            IWX_CLRBITS(sc, IWX_CSR_GP_CNTRL,
                        IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
    } else
        XYLog("%s: NIC already unlocked\n", DEVNAME(sc));
}

void ItlIwx::
iwx_set_bits_mask_prph(struct iwx_softc *sc, uint32_t reg, uint32_t bits,
                       uint32_t mask)
{
    uint32_t val;
    
    /* XXX: no error path? */
    if (iwx_nic_lock(sc)) {
        val = iwx_read_prph(sc, reg) & mask;
        val |= bits;
        iwx_write_prph(sc, reg, val);
        iwx_nic_unlock(sc);
    }
}

void ItlIwx::
iwx_set_bits_prph(struct iwx_softc *sc, uint32_t reg, uint32_t bits)
{
    iwx_set_bits_mask_prph(sc, reg, bits, ~0);
}

void ItlIwx::
iwx_clear_bits_prph(struct iwx_softc *sc, uint32_t reg, uint32_t bits)
{
    iwx_set_bits_mask_prph(sc, reg, 0, ~bits);
}

bool allocDmaMemory2(struct iwx_dma_info *dma, size_t size, int alignment)
{
    IOBufferMemoryDescriptor *bmd;
    IODMACommand::Segment64 seg;
    UInt64 ofs = 0;
    UInt32 numSegs = 1;
    
    bmd = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(kernel_task, kIODirectionInOut | kIOMemoryPhysicallyContiguous | kIOMapInhibitCache, size, DMA_BIT_MASK(64));
    
    if (bmd == NULL) {
        XYLog("%s alloc DMA memory failed.\n", __FUNCTION__);
        return false;
    }
    
    if (bmd->prepare() != kIOReturnSuccess) {
        XYLog("%s prepare DMA memory failed.\n", __FUNCTION__);
        bmd->release();
        bmd = NULL;
        return false;
    }
    IODMACommand *cmd = IODMACommand::withSpecification(kIODMACommandOutputHost64, 64, 0, IODMACommand::kMapped, 0, alignment);
    
    if (cmd == NULL) {
        XYLog("%s alloc IODMACommand memory failed.\n", __FUNCTION__);
        bmd->complete();
        bmd->release();
        return false;
    }

    if (cmd->setMemoryDescriptor(bmd) != kIOReturnSuccess
        || cmd->gen64IOVMSegments(&ofs, &seg, &numSegs) != kIOReturnSuccess) {
        cmd->release();
        cmd = NULL;
        bmd->complete();
        bmd->release();
        bmd = NULL;
        return false;
    }
    dma->paddr = seg.fIOVMAddr;
    dma->vaddr = bmd->getBytesNoCopy();
    dma->size = size;
    dma->buffer = bmd;
    dma->cmd = cmd;
    memset(dma->vaddr, 0, dma->size);
    return true;
}

int ItlIwx::
iwx_dma_contig_alloc(bus_dma_tag_t tag, struct iwx_dma_info *dma,
                     bus_size_t size, bus_size_t alignment)
{
    if (!allocDmaMemory2(dma, size, alignment)) {
        return 1;
    }
    
    return 0;
}

void ItlIwx::
iwx_dma_contig_free(struct iwx_dma_info *dma)
{
    if (dma == NULL || dma->cmd == NULL)
        return;
    if (dma->vaddr == NULL)
        return;
    dma->cmd->clearMemoryDescriptor();
    dma->cmd->release();
    dma->cmd = NULL;
    dma->buffer->complete();
    dma->buffer->release();
    dma->buffer = NULL;
    dma->vaddr = NULL;
}

/**
 * struct iwl_rx_transfer_desc - transfer descriptor
 * @addr: ptr to free buffer start address
 * @rbid: unique tag of the buffer
 * @reserved: reserved
 */
struct iwx_rx_transfer_desc {
    uint16_t rbid;
    uint16_t reserved[3];
    uint64_t addr;
} __packed;

int ItlIwx::
iwx_alloc_rx_ring(struct iwx_softc *sc, struct iwx_rx_ring *ring)
{
    bus_size_t size;
    int i, err;
    int rb_stts_size = sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210 ? sizeof(uint16_t) : sizeof(iwx_rb_status);
    int rb_stts_align = sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210 ? 0 : 16;
    
    ring->cur = 0;
    
    /* Allocate RX descriptors (256-byte aligned). */
    size = IWX_RX_MQ_RING_COUNT * (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210 ? sizeof(struct iwx_rx_transfer_desc) : sizeof(uint64_t));
    err = iwx_dma_contig_alloc(sc->sc_dmat, &ring->free_desc_dma, size, 256);
    if (err) {
        XYLog("%s: could not allocate RX ring DMA memory\n",
              DEVNAME(sc));
        goto fail;
    }
    ring->desc = ring->free_desc_dma.vaddr;
    
    /* Allocate RX status area (16-byte aligned). */
    err = iwx_dma_contig_alloc(sc->sc_dmat, &ring->stat_dma,
                               rb_stts_size, rb_stts_align);
    if (err) {
        XYLog("%s: could not allocate RX status DMA memory\n",
              DEVNAME(sc));
        goto fail;
    }
    ring->stat = ring->stat_dma.vaddr;
    
    size = IWX_RX_MQ_RING_COUNT * (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210 ? sizeof(struct iwx_rx_completion_desc) : sizeof(uint32_t));
    err = iwx_dma_contig_alloc(sc->sc_dmat, &ring->used_desc_dma,
                               size, 256);
    if (err) {
        XYLog("%s: could not allocate RX ring DMA memory\n",
              DEVNAME(sc));
        goto fail;
    }
    
    for (i = 0; i < IWX_RX_MQ_RING_COUNT; i++) {
        struct iwx_rx_data *data = &ring->data[i];
        
        memset(data, 0, sizeof(*data));
        err = bus_dmamap_create(sc->sc_dmat, IWX_RBUF_SIZE, 1,
                                IWX_RBUF_SIZE, 0, BUS_DMA_NOWAIT,
                                &data->map);
        if (err) {
            XYLog("%s: could not create RX buf DMA map\n",
                  DEVNAME(sc));
            goto fail;
        }
        
        err = iwx_rx_addbuf(sc, IWX_RBUF_SIZE, i);
        if (err)
            goto fail;
    }
    return 0;
    
fail:    iwx_free_rx_ring(sc, ring);
    return err;
}

void ItlIwx::
iwx_disable_rx_dma(struct iwx_softc *sc)
{
    int ntries;
    
    if (iwx_nic_lock(sc)) {
        if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210) {
            iwx_write_umac_prph(sc, IWX_RFH_RXF_DMA_CFG_GEN3, 0);
            for (ntries = 0; ntries < 1000; ntries++) {
                if (iwx_read_umac_prph(sc, IWX_RFH_GEN_STATUS_GEN3) &
                    IWX_RXF_DMA_IDLE)
                    break;
                DELAY(10);
            }
        } else {
            iwx_write_prph(sc, IWX_RFH_RXF_DMA_CFG, 0);
            for (ntries = 0; ntries < 1000; ntries++) {
                if (iwx_read_prph(sc, IWX_RFH_GEN_STATUS) &
                    IWX_RXF_DMA_IDLE)
                    break;
                DELAY(10);
            }
        }
        iwx_nic_unlock(sc);
    }
}

void ItlIwx::
iwx_reset_rx_ring(struct iwx_softc *sc, struct iwx_rx_ring *ring)
{
    ring->cur = 0;
    //    bus_dmamap_sync(sc->sc_dmat, ring->stat_dma.map, 0,
    //        ring->stat_dma.size, BUS_DMASYNC_PREWRITE);
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
        memset(ring->stat, 0, sizeof(uint16_t));
    else
        memset(ring->stat, 0, sizeof(struct iwx_rb_status));
    //    bus_dmamap_sync(sc->sc_dmat, ring->stat_dma.map, 0,
    //        ring->stat_dma.size, BUS_DMASYNC_POSTWRITE);
    
}

void ItlIwx::
iwx_free_rx_ring(struct iwx_softc *sc, struct iwx_rx_ring *ring)
{
    int i;
    
    iwx_dma_contig_free(&ring->free_desc_dma);
    iwx_dma_contig_free(&ring->stat_dma);
    iwx_dma_contig_free(&ring->used_desc_dma);
    
    for (i = 0; i < IWX_RX_MQ_RING_COUNT; i++) {
        struct iwx_rx_data *data = &ring->data[i];
        
        if (data->m != NULL) {
            //            bus_dmamap_sync(sc->sc_dmat, data->map, 0,
            //                data->map->dm_mapsize, BUS_DMASYNC_POSTREAD);
            //            bus_dmamap_unload(sc->sc_dmat, data->map);
            mbuf_freem(data->m);
            data->m = NULL;
        }
        if (data->map != NULL) {
            bus_dmamap_destroy(sc->sc_dmat, data->map);
            data->map = NULL;
        }
    }
}

void ItlIwx::
iwx_tx_ring_init(struct iwx_softc *sc, struct iwx_tx_ring *ring, int size)
{
    int low_mark, high_mark;

    ring->ring_count = size;
    low_mark = ring->ring_count / 4;
    if (low_mark < 4)
        low_mark = 4;
    ring->low_mark = ring->ring_count - low_mark;

    high_mark = ring->ring_count / 8;
    if (high_mark < 2)
        high_mark = 2;
    ring->hi_mark = ring->ring_count - high_mark;
    ring->queued = 0;
    ring->cur = 0;
    ring->tail = 0;
}

int ItlIwx::
iwx_alloc_tx_ring(struct iwx_softc *sc, struct iwx_tx_ring *ring, int qid)
{
    bus_addr_t paddr;
    bus_size_t size;
    int i, err;

    /* 0:CMD 2:MGMT */
    if (qid > IWX_QID_MGMT) {
        ring->qid = IWX_INVALID_QUEUE;
        return 0;
    }
    
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210) {
        if (qid == IWX_DQA_CMD_QUEUE)
            size = IWX_CMD_QUEUE_SIZE_GEN3;
        else
            size = IWX_MIN_256_BA_QUEUE_SIZE_GEN3;
    }
    else {
        if (qid == IWX_DQA_CMD_QUEUE)
            size = IWX_CMD_QUEUE_SIZE;
        else
            size = IWX_DEFAULT_QUEUE_SIZE;
    }
    iwx_tx_ring_init(sc, ring, size);
    ring->qid = qid;
    /* Allocate TX descriptors (256-byte aligned). */
    size = ring->ring_count * sizeof (struct iwx_tfh_tfd);
    err = iwx_dma_contig_alloc(sc->sc_dmat, &ring->desc_dma, size, 256);
    if (err) {
        XYLog("%s: could not allocate TX ring DMA memory\n",
              DEVNAME(sc));
        goto fail;
    }
    ring->desc = (struct iwx_tfh_tfd*)ring->desc_dma.vaddr;

    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
        err = iwx_dma_contig_alloc(sc->sc_dmat, &ring->bc_tbl,
                                   sizeof(struct iwx_gen3_bc_tbl), 0);
    else
        err = iwx_dma_contig_alloc(sc->sc_dmat, &ring->bc_tbl,
                                   sizeof(struct iwx_agn_scd_bc_tbl), 0);
    if (err) {
        XYLog("%s: could not allocate byte count table DMA memory\n",
              DEVNAME(sc));
        goto fail;
    }
    
    size = ring->ring_count * sizeof(struct iwx_device_cmd);
    err = iwx_dma_contig_alloc(sc->sc_dmat, &ring->cmd_dma, size,
                               IWX_FIRST_TB_SIZE_ALIGN);
    if (err) {
        XYLog("%s: could not allocate cmd DMA memory\n", DEVNAME(sc));
        goto fail;
    }
    ring->cmd = (struct iwx_device_cmd*)ring->cmd_dma.vaddr;
    
    paddr = ring->cmd_dma.paddr;
    for (i = 0; i < ring->ring_count; i++) {
        struct iwx_tx_data *data = &ring->data[i];
        size_t mapsize;
        
        data->cmd_paddr = paddr;
        paddr += sizeof(struct iwx_device_cmd);
        
        /* FW commands may require more mapped space than packets. */
        if (qid == IWX_DQA_CMD_QUEUE)
            mapsize = (sizeof(struct iwx_cmd_header) +
                       IWX_MAX_CMD_PAYLOAD_SIZE);
        else
            mapsize = MCLBYTES;
        err = bus_dmamap_create(sc->sc_dmat, mapsize,
                                IWX_TFH_NUM_TBS - 2, mapsize, 0, BUS_DMA_NOWAIT,
                                &data->map);
        if (err) {
            XYLog("%s: could not create TX buf DMA map\n",
                  DEVNAME(sc));
            goto fail;
        }
    }
    KASSERT(paddr == ring->cmd_dma.paddr + size, "paddr == ring->cmd_dma.paddr + size");
    return 0;
    
fail:    iwx_free_tx_ring(sc, ring);
    return err;
}

void ItlIwx::
iwx_reset_tx_ring(struct iwx_softc *sc, struct iwx_tx_ring *ring)
{
    int i;
    
    for (i = 0; i < ring->ring_count; i++) {
        struct iwx_tx_data *data = &ring->data[i];
        
        if (data->m != NULL) {
            //            bus_dmamap_sync(sc->sc_dmat, data->map, 0,
            //                data->map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
            //            bus_dmamap_unload(sc->sc_dmat, data->map);
            mbuf_freem(data->m);
            data->m = NULL;
        }
    }

    if (ring->qid == IWX_INVALID_QUEUE || !ring->desc) {
        return;
    }
    
    /* Clear byte count table. */
    memset(ring->bc_tbl.vaddr, 0, ring->bc_tbl.size);
    
    /* Clear TX descriptors. */
    memset(ring->desc, 0, ring->desc_dma.size);
    //    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map, 0,
    //        ring->desc_dma.size, BUS_DMASYNC_PREWRITE);
    sc->qfullmsk &= ~(1 << ring->qid);
    ring->queued = 0;
    ring->cur = 0;
    ring->tail = 0;
}

void ItlIwx::
iwx_free_tx_ring(struct iwx_softc *sc, struct iwx_tx_ring *ring)
{
    int i;
    
    iwx_dma_contig_free(&ring->desc_dma);
    iwx_dma_contig_free(&ring->cmd_dma);
    iwx_dma_contig_free(&ring->bc_tbl);
    
    for (i = 0; i < ring->ring_count; i++) {
        struct iwx_tx_data *data = &ring->data[i];
        
        if (data->m != NULL) {
            //            bus_dmamap_sync(sc->sc_dmat, data->map, 0,
            //                data->map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
            //            bus_dmamap_unload(sc->sc_dmat, data->map);
            mbuf_freem(data->m);
            data->m = NULL;
        }
        if (data->map != NULL) {
            bus_dmamap_destroy(sc->sc_dmat, data->map);
            data->map = NULL;
        }
    }
    ring->qid = IWX_INVALID_QUEUE;
    ring->hi_mark = 0;
    ring->low_mark = 0;
    ring->ring_count = 0;
}

void ItlIwx::
iwx_enable_rfkill_int(struct iwx_softc *sc)
{
    if (!sc->sc_msix) {
        sc->sc_intmask = IWX_CSR_INT_BIT_RF_KILL;
        IWX_WRITE(sc, IWX_CSR_INT_MASK, sc->sc_intmask);
    } else {
        IWX_WRITE(sc, IWX_CSR_MSIX_FH_INT_MASK_AD,
                  sc->sc_fh_init_mask);
        IWX_WRITE(sc, IWX_CSR_MSIX_HW_INT_MASK_AD,
                  ~IWX_MSIX_HW_INT_CAUSES_REG_RF_KILL);
        sc->sc_hw_mask = IWX_MSIX_HW_INT_CAUSES_REG_RF_KILL;
    }
    
    IWX_SETBITS(sc, IWX_CSR_GP_CNTRL,
                IWX_CSR_GP_CNTRL_REG_FLAG_RFKILL_WAKE_L1A_EN);
}

int ItlIwx::
iwx_check_rfkill(struct iwx_softc *sc)
{
    uint32_t v;
    int s;
    int rv;
    
    s = splnet();
    
    /*
     * "documentation" is not really helpful here:
     *  27:    HW_RF_KILL_SW
     *    Indicates state of (platform's) hardware RF-Kill switch
     *
     * But apparently when it's off, it's on ...
     */
    v = IWX_READ(sc, IWX_CSR_GP_CNTRL);
    rv = (v & IWX_CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW) == 0;
    if (rv) {
        sc->sc_flags |= IWX_FLAG_RFKILL;
    } else {
        sc->sc_flags &= ~IWX_FLAG_RFKILL;
    }
    
    XYLog("%s RF_KILL hw: %d\n", __FUNCTION__, rv);

    splx(s);
    return rv;
}

void ItlIwx::
iwx_enable_interrupts(struct iwx_softc *sc)
{
    if (!sc->sc_msix) {
        sc->sc_intmask = IWX_CSR_INI_SET_MASK;
        IWX_WRITE(sc, IWX_CSR_INT_MASK, sc->sc_intmask);
    } else {
        /*
         * fh/hw_mask keeps all the unmasked causes.
         * Unlike msi, in msix cause is enabled when it is unset.
         */
        sc->sc_hw_mask = sc->sc_hw_init_mask;
        sc->sc_fh_mask = sc->sc_fh_init_mask;
        IWX_WRITE(sc, IWX_CSR_MSIX_FH_INT_MASK_AD,
                  ~sc->sc_fh_mask);
        IWX_WRITE(sc, IWX_CSR_MSIX_HW_INT_MASK_AD,
                  ~sc->sc_hw_mask);
    }
}

void ItlIwx::
iwx_enable_fwload_interrupt(struct iwx_softc *sc)
{
    
    XYLog("%s\n", __FUNCTION__);
    if (!sc->sc_msix) {
        sc->sc_intmask = IWX_CSR_INT_BIT_ALIVE | IWX_CSR_INT_BIT_FH_RX;
        IWX_WRITE(sc, IWX_CSR_INT_MASK, sc->sc_intmask);
    } else {
        IWX_WRITE(sc, IWX_CSR_MSIX_HW_INT_MASK_AD,
                  ~IWX_MSIX_HW_INT_CAUSES_REG_ALIVE);
        sc->sc_hw_mask = IWX_MSIX_HW_INT_CAUSES_REG_ALIVE;
        /*
         * Leave all the FH causes enabled to get the ALIVE
         * notification.
         */
        IWX_WRITE(sc, IWX_CSR_MSIX_FH_INT_MASK_AD,
                  ~sc->sc_fh_init_mask);
        sc->sc_fh_mask = sc->sc_fh_init_mask;
    }
}

void ItlIwx::
iwx_restore_interrupts(struct iwx_softc *sc)
{
    IWX_WRITE(sc, IWX_CSR_INT_MASK, sc->sc_intmask);
}

void ItlIwx::
iwx_disable_interrupts(struct iwx_softc *sc)
{
    int s = splnet();
    
    if (!sc->sc_msix) {
        IWX_WRITE(sc, IWX_CSR_INT_MASK, 0);
        
        /* acknowledge all interrupts */
        IWX_WRITE(sc, IWX_CSR_INT, ~0);
        IWX_WRITE(sc, IWX_CSR_FH_INT_STATUS, ~0);
    } else {
        IWX_WRITE(sc, IWX_CSR_MSIX_FH_INT_MASK_AD,
                  sc->sc_fh_init_mask);
        IWX_WRITE(sc, IWX_CSR_MSIX_HW_INT_MASK_AD,
                  sc->sc_hw_init_mask);
    }
    
    splx(s);
}

void ItlIwx::
iwx_ict_reset(struct iwx_softc *sc)
{
    iwx_disable_interrupts(sc);
    
    memset(sc->ict_dma.vaddr, 0, IWX_ICT_SIZE);
    sc->ict_cur = 0;
    
    /* Set physical address of ICT (4KB aligned). */
    IWX_WRITE(sc, IWX_CSR_DRAM_INT_TBL_REG,
              IWX_CSR_DRAM_INT_TBL_ENABLE
              | IWX_CSR_DRAM_INIT_TBL_WRAP_CHECK
              | IWX_CSR_DRAM_INIT_TBL_WRITE_POINTER
              | sc->ict_dma.paddr >> IWX_ICT_PADDR_SHIFT);
    
    /* Switch to ICT interrupt mode in driver. */
    sc->sc_flags |= IWX_FLAG_USE_ICT;
    
    IWX_WRITE(sc, IWX_CSR_INT, sc->sc_intmask);
    iwx_enable_interrupts(sc);
}

#define IWX_HW_READY_TIMEOUT 50
int ItlIwx::
iwx_set_hw_ready(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int ready;
    
    IWX_SETBITS(sc, IWX_CSR_HW_IF_CONFIG_REG,
                IWX_CSR_HW_IF_CONFIG_REG_BIT_NIC_READY);
    
    ready = iwx_poll_bit(sc, IWX_CSR_HW_IF_CONFIG_REG,
                         IWX_CSR_HW_IF_CONFIG_REG_BIT_NIC_READY,
                         IWX_CSR_HW_IF_CONFIG_REG_BIT_NIC_READY,
                         IWX_HW_READY_TIMEOUT);
    if (ready)
        IWX_SETBITS(sc, IWX_CSR_MBOX_SET_REG,
                    IWX_CSR_MBOX_SET_REG_OS_ALIVE);
    
    return ready;
}
#undef IWX_HW_READY_TIMEOUT

int ItlIwx::
iwx_prepare_card_hw(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int t = 0;
    int ntries;
    
    if (iwx_set_hw_ready(sc))
        return 0;
    
    IWX_SETBITS(sc, IWX_CSR_DBG_LINK_PWR_MGMT_REG,
                IWX_CSR_RESET_LINK_PWR_MGMT_DISABLED);
    DELAY(1000);
    
    
    for (ntries = 0; ntries < 10; ntries++) {
        /* If HW is not ready, prepare the conditions to check again */
        IWX_SETBITS(sc, IWX_CSR_HW_IF_CONFIG_REG,
                    IWX_CSR_HW_IF_CONFIG_REG_PREPARE);
        
        do {
            if (iwx_set_hw_ready(sc))
                return 0;
            DELAY(200);
            t += 200;
        } while (t < 150000);
        DELAY(25000);
    }
    
    return ETIMEDOUT;
}

void ItlIwx::
iwx_apm_config(struct iwx_softc *sc)
{
    pcireg_t lctl, cap;
    
    /*
     * L0S states have been found to be unstable with our devices
     * and in newer hardware they are not officially supported at
     * all, so we must always set the L0S_DISABLED bit.
     */
    IWX_SETBITS(sc, IWX_CSR_GIO_REG, IWX_CSR_GIO_REG_VAL_L0S_DISABLED);
    lctl = pci_conf_read(sc->sc_pct, sc->sc_pcitag,
                         sc->sc_cap_off + PCI_PCIE_LCSR);
    /*
     * Disable L0s and L1s in PCIE register because we don't support ASPM now.
     */
    lctl &= ~(PCI_PCIE_LCSR_ASPM_L0S | PCI_PCIE_LCSR_ASPM_L1);
    pci_conf_write(sc->sc_pct, sc->sc_pcitag, sc->sc_cap_off + PCI_PCIE_LCSR, lctl);
    lctl = pci_conf_read(sc->sc_pct, sc->sc_pcitag, sc->sc_cap_off + PCI_PCIE_LCSR);
    
    cap = pci_conf_read(sc->sc_pct, sc->sc_pcitag,
                        sc->sc_cap_off + PCI_PCIE_DCSR2);
    sc->sc_ltr_enabled = (cap & PCI_PCIE_DCSR2_LTREN) ? 1 : 0;
    DPRINTF(("%s: L1 %sabled - LTR %sabled\n",
             DEVNAME(sc),
             (lctl & PCI_PCIE_LCSR_ASPM_L1) ? "En" : "Dis",
             sc->sc_ltr_enabled ? "En" : "Dis"));
}

/*
 * Start up NIC's basic functionality after it has been reset
 * e.g. after platform boot or shutdown.
 * NOTE:  This does not load uCode nor start the embedded processor
 */
int ItlIwx::
iwx_apm_init(struct iwx_softc *sc)
{
    int err = 0;
    
    /*
     * Disable L0s without affecting L1;
     *  don't wait for ICH L0s (ICH bug W/A)
     */
    IWX_SETBITS(sc, IWX_CSR_GIO_CHICKEN_BITS,
                IWX_CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX);
    
    /* Set FH wait threshold to maximum (HW error during stress W/A) */
    IWX_SETBITS(sc, IWX_CSR_DBG_HPET_MEM_REG, IWX_CSR_DBG_HPET_MEM_REG_VAL);
    
    /*
     * Enable HAP INTA (interrupt from management bus) to
     * wake device's PCI Express link L1a -> L0s
     */
    IWX_SETBITS(sc, IWX_CSR_HW_IF_CONFIG_REG,
                IWX_CSR_HW_IF_CONFIG_REG_BIT_HAP_WAKE_L1A);
    
    iwx_apm_config(sc);
    
    /*
     * Set "initialization complete" bit to move adapter from
     * D0U* --> D0A* (powered-up active) state.
     */
    IWX_SETBITS(sc, IWX_CSR_GP_CNTRL, IWX_CSR_GP_CNTRL_REG_FLAG_INIT_DONE);
    
    /*
     * Wait for clock stabilization; once stabilized, access to
     * device-internal resources is supported, e.g. iwx_write_prph()
     * and accesses to uCode SRAM.
     */
    if (!iwx_poll_bit(sc, IWX_CSR_GP_CNTRL,
                      IWX_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
                      IWX_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY, 25000)) {
        XYLog("%s: timeout waiting for clock stabilization\n",
              DEVNAME(sc));
        err = ETIMEDOUT;
        goto out;
    }
out:
    if (err)
        XYLog("%s: apm init error %d\n", DEVNAME(sc), err);
    return err;
}

void ItlIwx::
iwx_apm_stop(struct iwx_softc *sc)
{
    IWX_SETBITS(sc, IWX_CSR_DBG_LINK_PWR_MGMT_REG,
                IWX_CSR_RESET_LINK_PWR_MGMT_DISABLED);
    IWX_SETBITS(sc, IWX_CSR_HW_IF_CONFIG_REG,
                IWX_CSR_HW_IF_CONFIG_REG_PREPARE |
                IWX_CSR_HW_IF_CONFIG_REG_ENABLE_PME);
    DELAY(1000);
    IWX_CLRBITS(sc, IWX_CSR_DBG_LINK_PWR_MGMT_REG,
                IWX_CSR_RESET_LINK_PWR_MGMT_DISABLED);
    DELAY(5000);
    
    /* stop device's busmaster DMA activity */
    IWX_SETBITS(sc, IWX_CSR_RESET, IWX_CSR_RESET_REG_FLAG_STOP_MASTER);
    
    if (!iwx_poll_bit(sc, IWX_CSR_RESET,
                      IWX_CSR_RESET_REG_FLAG_MASTER_DISABLED,
                      IWX_CSR_RESET_REG_FLAG_MASTER_DISABLED, 100))
        XYLog("%s: timeout waiting for master\n", DEVNAME(sc));
    
    /*
     * Clear "initialization complete" bit to move adapter from
     * D0A* (powered-up Active) --> D0U* (Uninitialized) state.
     */
    IWX_CLRBITS(sc, IWX_CSR_GP_CNTRL,
                IWX_CSR_GP_CNTRL_REG_FLAG_INIT_DONE);
}

void ItlIwx::
iwx_init_msix_hw(struct iwx_softc *sc)
{
    iwx_conf_msix_hw(sc, 0);
    
    if (!sc->sc_msix)
        return;
    
    sc->sc_fh_init_mask = ~IWX_READ(sc, IWX_CSR_MSIX_FH_INT_MASK_AD);
    sc->sc_fh_mask = sc->sc_fh_init_mask;
    sc->sc_hw_init_mask = ~IWX_READ(sc, IWX_CSR_MSIX_HW_INT_MASK_AD);
    sc->sc_hw_mask = sc->sc_hw_init_mask;
}

void ItlIwx::
iwx_conf_msix_hw(struct iwx_softc *sc, int stopped)
{
    int vector = 0;
    
    if (!sc->sc_msix) {
        /* Newer chips default to MSIX. */
        if (!stopped && iwx_nic_lock(sc)) {
            iwx_write_umac_prph(sc, IWX_UREG_CHICK,
                           IWX_UREG_CHICK_MSI_ENABLE);
            iwx_nic_unlock(sc);
        }
        return;
    }
    
    if (!stopped && iwx_nic_lock(sc)) {
        iwx_write_umac_prph(sc, IWX_UREG_CHICK, IWX_UREG_CHICK_MSIX_ENABLE);
        iwx_nic_unlock(sc);
    }
    
    /* Disable all interrupts */
    IWX_WRITE(sc, IWX_CSR_MSIX_FH_INT_MASK_AD, ~0);
    IWX_WRITE(sc, IWX_CSR_MSIX_HW_INT_MASK_AD, ~0);
    
    /* Map fallback-queue (command/mgmt) to a single vector */
    IWX_WRITE_1(sc, IWX_CSR_MSIX_RX_IVAR(0),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    /* Map RSS queue (data) to the same vector */
    IWX_WRITE_1(sc, IWX_CSR_MSIX_RX_IVAR(1),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    
    /* Enable the RX queues cause interrupts */
    IWX_CLRBITS(sc, IWX_CSR_MSIX_FH_INT_MASK_AD,
                IWX_MSIX_FH_INT_CAUSES_Q0 | IWX_MSIX_FH_INT_CAUSES_Q1);
    
    /* Map non-RX causes to the same vector */
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_D2S_CH0_NUM),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_D2S_CH1_NUM),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_S2D),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_FH_ERR),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_REG_ALIVE),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_REG_WAKEUP),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_REG_IML),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_REG_CT_KILL),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_REG_RF_KILL),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_REG_PERIODIC),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_REG_SW_ERR),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_REG_SCD),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_REG_FH_TX),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_REG_HW_ERR),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWX_WRITE_1(sc, IWX_CSR_MSIX_IVAR(IWX_MSIX_IVAR_CAUSE_REG_HAP),
                vector | IWX_MSIX_NON_AUTO_CLEAR_CAUSE);
    
    /* Enable non-RX causes interrupts */
    IWX_CLRBITS(sc, IWX_CSR_MSIX_FH_INT_MASK_AD,
                IWX_MSIX_FH_INT_CAUSES_D2S_CH0_NUM |
                IWX_MSIX_FH_INT_CAUSES_D2S_CH1_NUM |
                IWX_MSIX_FH_INT_CAUSES_S2D |
                IWX_MSIX_FH_INT_CAUSES_FH_ERR);
    IWX_CLRBITS(sc, IWX_CSR_MSIX_HW_INT_MASK_AD,
                IWX_MSIX_HW_INT_CAUSES_REG_ALIVE |
                IWX_MSIX_HW_INT_CAUSES_REG_WAKEUP |
                IWX_MSIX_HW_INT_CAUSES_REG_IML |
                IWX_MSIX_HW_INT_CAUSES_REG_CT_KILL |
                IWX_MSIX_HW_INT_CAUSES_REG_RF_KILL |
                IWX_MSIX_HW_INT_CAUSES_REG_PERIODIC |
                IWX_MSIX_HW_INT_CAUSES_REG_SW_ERR |
                IWX_MSIX_HW_INT_CAUSES_REG_SCD |
                IWX_MSIX_HW_INT_CAUSES_REG_FH_TX |
                IWX_MSIX_HW_INT_CAUSES_REG_HW_ERR |
                IWX_MSIX_HW_INT_CAUSES_REG_HAP);
}

int ItlIwx::
iwx_start_hw(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int err;
    
    err = iwx_prepare_card_hw(sc);
    if (err)
        return err;
    
    iwx_clear_persistence_bit(sc);
    
    /* Reset the entire device */
    IWX_SETBITS(sc, IWX_CSR_RESET, IWX_CSR_RESET_REG_FLAG_SW_RESET);
    DELAY(5000);
    
    if (sc->sc_device_family == IWX_DEVICE_FAMILY_22000 && sc->sc_integrated) {
        IWX_SETBITS(sc, IWX_CSR_GP_CNTRL,
                    IWX_CSR_GP_CNTRL_REG_FLAG_INIT_DONE);
        DELAY(20);
        if (!iwx_poll_bit(sc, IWX_CSR_GP_CNTRL,
                          IWX_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
                          IWX_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY, 25000)) {
            XYLog("%s: timeout waiting for clock stabilization\n",
                  DEVNAME(sc));
            return ETIMEDOUT;
        }
        
        iwx_force_power_gating(sc);
        
        /* Reset the entire device */
        IWX_SETBITS(sc, IWX_CSR_RESET, IWX_CSR_RESET_REG_FLAG_SW_RESET);
        DELAY(5000);
    }
    
    err = iwx_apm_init(sc);
    if (err)
        return err;
    
    iwx_init_msix_hw(sc);
    
    iwx_enable_rfkill_int(sc);
    iwx_check_rfkill(sc);
    
    return 0;
}


void ItlIwx::
iwx_stop_device(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int qid;
    
    iwx_disable_interrupts(sc);
    sc->sc_flags &= ~IWX_FLAG_USE_ICT;
    
    iwx_disable_rx_dma(sc);
    iwx_reset_rx_ring(sc, &sc->rxq);
    for (qid = 0; qid < nitems(sc->txq); qid++)
        iwx_reset_tx_ring(sc, &sc->txq[qid]);
    
    /* Make sure (redundant) we've released our request to stay awake */
    IWX_CLRBITS(sc, IWX_CSR_GP_CNTRL,
                IWX_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
    if (sc->sc_nic_locks > 0)
        XYLog("%s: %d active NIC locks forcefully cleared\n",
              DEVNAME(sc), sc->sc_nic_locks);
    sc->sc_nic_locks = 0;
    
    /* Stop the device, and put it in low power state */
    iwx_apm_stop(sc);
    
    /* Reset the on-board processor. */
    IWX_SETBITS(sc, IWX_CSR_RESET, IWX_CSR_RESET_REG_FLAG_SW_RESET);
    DELAY(5000);
    
    /*
     * Upon stop, the IVAR table gets erased, so msi-x won't
     * work. This causes a bug in RF-KILL flows, since the interrupt
     * that enables radio won't fire on the correct irq, and the
     * driver won't be able to handle the interrupt.
     * Configure the IVAR table again after reset.
     */
    iwx_conf_msix_hw(sc, 1);
    
    /*
     * Upon stop, the APM issues an interrupt if HW RF kill is set.
     * Clear the interrupt again.
     */
    iwx_disable_interrupts(sc);
    
    /* Even though we stop the HW we still want the RF kill interrupt. */
    iwx_enable_rfkill_int(sc);
    iwx_check_rfkill(sc);
    
    iwx_prepare_card_hw(sc);
    
    iwx_ctxt_info_free_paging(sc);
    /* free gen3 devices related firmware DMA resource */
    iwx_dma_contig_free(&sc->prph_info_dma);
    iwx_dma_contig_free(&sc->prph_scratch_dma);
    iwx_dma_contig_free(&sc->iml_dma);
    iwx_dma_contig_free(&sc->pnvm_dram);
}

void ItlIwx::
iwx_nic_config(struct iwx_softc *sc)
{
    uint8_t radio_cfg_type, radio_cfg_step, radio_cfg_dash;
    uint32_t mask, val, reg_val = 0;
    
    radio_cfg_type = (sc->sc_fw_phy_config & IWX_FW_PHY_CFG_RADIO_TYPE) >>
    IWX_FW_PHY_CFG_RADIO_TYPE_POS;
    radio_cfg_step = (sc->sc_fw_phy_config & IWX_FW_PHY_CFG_RADIO_STEP) >>
    IWX_FW_PHY_CFG_RADIO_STEP_POS;
    radio_cfg_dash = (sc->sc_fw_phy_config & IWX_FW_PHY_CFG_RADIO_DASH) >>
    IWX_FW_PHY_CFG_RADIO_DASH_POS;
    
    reg_val |= IWX_CSR_HW_REV_STEP(sc->sc_hw_rev) <<
    IWX_CSR_HW_IF_CONFIG_REG_POS_MAC_STEP;
    reg_val |= IWX_CSR_HW_REV_DASH(sc->sc_hw_rev) <<
    IWX_CSR_HW_IF_CONFIG_REG_POS_MAC_DASH;
    
    /* radio configuration */
    reg_val |= radio_cfg_type << IWX_CSR_HW_IF_CONFIG_REG_POS_PHY_TYPE;
    reg_val |= radio_cfg_step << IWX_CSR_HW_IF_CONFIG_REG_POS_PHY_STEP;
    reg_val |= radio_cfg_dash << IWX_CSR_HW_IF_CONFIG_REG_POS_PHY_DASH;
    
    mask = IWX_CSR_HW_IF_CONFIG_REG_MSK_MAC_DASH |
    IWX_CSR_HW_IF_CONFIG_REG_MSK_MAC_STEP |
    IWX_CSR_HW_IF_CONFIG_REG_MSK_PHY_STEP |
    IWX_CSR_HW_IF_CONFIG_REG_MSK_PHY_DASH |
    IWX_CSR_HW_IF_CONFIG_REG_MSK_PHY_TYPE |
    IWX_CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI |
    IWX_CSR_HW_IF_CONFIG_REG_BIT_MAC_SI;
    
    val = IWX_READ(sc, IWX_CSR_HW_IF_CONFIG_REG);
    val &= ~mask;
    val |= reg_val;
    IWX_WRITE(sc, IWX_CSR_HW_IF_CONFIG_REG, val);
    
    XYLog("%s Radio type=0x%x-0x%x-0x%x\n", __FUNCTION__, radio_cfg_type,
          radio_cfg_step, radio_cfg_dash);
}

int ItlIwx::
iwx_nic_rx_init(struct iwx_softc *sc)
{
    IWX_WRITE_1(sc, IWX_CSR_INT_COALESCING, IWX_HOST_INT_TIMEOUT_DEF);
    
    /*
     * We don't configure the RFH; the firmware will do that.
     * Rx descriptors are set when firmware sends an ALIVE interrupt.
     */
    return 0;
}

int ItlIwx::
iwx_nic_init(struct iwx_softc *sc)
{
    int err;
    
    iwx_apm_init(sc);
    iwx_nic_config(sc);
    
    err = iwx_nic_rx_init(sc);
    if (err)
        return err;
    
    IWX_SETBITS(sc, IWX_CSR_MAC_SHADOW_REG_CTRL, 0x800fffff);
    
    return 0;
}

/* Map ieee80211_edca_ac categories to firmware Tx FIFO. */
const uint8_t iwx_ac_to_tx_fifo[] = {
    IWX_GEN2_EDCA_TX_FIFO_BE,
    IWX_GEN2_EDCA_TX_FIFO_BK,
    IWX_GEN2_EDCA_TX_FIFO_VI,
    IWX_GEN2_EDCA_TX_FIFO_VO,
};

int ItlIwx::
iwx_enable_txq(struct iwx_softc *sc, int sta_id, int qid, int tid,
               int num_slots)
{
    
    XYLog("%s\n", __FUNCTION__);
    struct iwx_tx_queue_cfg_cmd cmd;
    struct iwx_rx_packet *pkt;
    struct iwx_tx_queue_cfg_rsp *resp;
    struct iwx_host_cmd hcmd = {
        .id = IWX_SCD_QUEUE_CFG,
        .flags = IWX_CMD_WANT_RESP,
        .resp_pkt_len = sizeof(*pkt) + sizeof(*resp),
    };
    struct iwx_tx_ring *ring = &sc->txq[qid];
    int err, fwqid;
    uint32_t wr_idx;
    size_t resp_len;
    
    iwx_reset_tx_ring(sc, ring);
    
    memset(&cmd, 0, sizeof(cmd));
    cmd.sta_id = sta_id;
    cmd.tid = tid;
    cmd.flags = htole16(IWX_TX_QUEUE_CFG_ENABLE_QUEUE);
    cmd.cb_size = htole32(IWX_TFD_QUEUE_CB_SIZE(num_slots));
    cmd.byte_cnt_addr = htole64(ring->bc_tbl.paddr);
    cmd.tfdq_addr = htole64(ring->desc_dma.paddr);
    
    hcmd.data[0] = &cmd;
    hcmd.len[0] = sizeof(cmd);
    
    err = iwx_send_cmd(sc, &hcmd);
    if (err)
        return err;
    
    pkt = hcmd.resp_pkt;
    if (!pkt || (pkt->hdr.group_id & IWX_CMD_FAILED_MSK)) {
        DPRINTF(("SCD_QUEUE_CFG command failed\n"));
        err = EIO;
        goto out;
    }
    
    resp_len = iwx_rx_packet_payload_len(pkt);
    if (resp_len != sizeof(*resp)) {
        DPRINTF(("SCD_QUEUE_CFG returned %zu bytes, expected %zu bytes\n", resp_len, sizeof(*resp)));
        err = EIO;
        goto out;
    }
    
    resp = (struct iwx_tx_queue_cfg_rsp *)pkt->data;
    fwqid = le16toh(resp->queue_number);
    wr_idx = le16toh(resp->write_pointer);
    
    /* Unlike iwlwifi, we do not support dynamic queue ID assignment. */
    if (fwqid != qid) {
        DPRINTF(("requested qid %d but %d was assigned\n", qid, fwqid));
        err = EIO;
        goto out;
    }
    
    if (wr_idx != ring->cur) {
        DPRINTF(("fw write index is %d but ring is %d\n", wr_idx, ring->cur));
        err = EIO;
        goto out;
    }
out:
    iwx_free_resp(sc, &hcmd);
    return err;
}

int ItlIwx::
iwx_tvqm_alloc_txq(struct iwx_softc *sc, int tid, int ssn)
{
    int queue;
    //TODO: Here is a bug, for gen3 devices which support 256 frame aggregate into 1 A-MPDU like ax210, if the TfDs count larger than 256 than it would trigger system freeze on macOS, don't know why but Linux can do this. Still need to dig deep into the code or optimize the DMA memory allocation, here I just limit the size to 256 as the temporary solution.
#ifdef notyet
    int size = sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210 ? IWX_MIN_256_BA_QUEUE_SIZE_GEN3 : IWX_DEFAULT_QUEUE_SIZE;
#else
    int size = IWX_DEFAULT_QUEUE_SIZE;
#endif
    
    do {
        queue = iwx_tvqm_enable_txq(sc, tid, ssn, size);
        if (queue < 0)
            XYLog("Failed allocating TXQ of size %d for sta %d tid %d, ret: %d\n",
                  size, IWX_STATION_ID, tid, queue);
        size /= 2;
    } while (queue < 0 && size >= 16);
    
    if (queue < 0)
        return queue;
    sc->sc_tid_data[tid].qid = queue;
    return queue;
}

int ItlIwx::
iwx_tvqm_enable_txq(struct iwx_softc *sc, int tid, int ssn, uint32_t size)
{
    int err = -1;
    int i = 0;
    bus_addr_t paddr;
    int fwqid;
    uint32_t wr_idx;
    size_t resp_len;
    struct iwx_tx_queue_cfg_cmd cmd = {
        .flags = htole16(IWX_TX_QUEUE_CFG_ENABLE_QUEUE),
        .sta_id = IWX_STATION_ID,
        .tid = (uint8_t)tid,
    };
    struct iwx_rx_packet *pkt;
    struct iwx_tx_queue_cfg_rsp *resp;
    struct iwx_host_cmd hcmd = {
        .id = IWX_SCD_QUEUE_CFG,
        .flags = IWX_CMD_WANT_RESP,
        .resp_pkt_len = sizeof(*pkt) + sizeof(*resp),
    };
    struct iwx_tx_ring *ring = &sc->sc_tvqm_ring;
    
    memset(ring, 0, sizeof(*ring));
    iwx_tx_ring_init(sc, ring, size);
    /* Allocate TX descriptors (256-byte aligned). */
    err = iwx_dma_contig_alloc(sc->sc_dmat, &ring->desc_dma, ring->ring_count * sizeof (struct iwx_tfh_tfd), 256);
    if (err) {
        XYLog("%s: could not allocate TX ring DMA memory\n",
              DEVNAME(sc));
        err = -ENOMEM;
        goto fail;
    }
    ring->desc = (struct iwx_tfh_tfd*)ring->desc_dma.vaddr;
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
        err = iwx_dma_contig_alloc(sc->sc_dmat, &ring->bc_tbl,
                                   sizeof(struct iwx_gen3_bc_tbl), 0);
    else
        err = iwx_dma_contig_alloc(sc->sc_dmat, &ring->bc_tbl,
                                   sizeof(struct iwx_agn_scd_bc_tbl), 0);
    if (err) {
        XYLog("%s: could not allocate byte count table DMA memory\n",
              DEVNAME(sc));
        err = -ENOMEM;
        goto fail;
    }

    err = iwx_dma_contig_alloc(sc->sc_dmat, &ring->cmd_dma, ring->ring_count * sizeof(struct iwx_device_cmd), IWX_FIRST_TB_SIZE_ALIGN);
    if (err) {
        XYLog("%s: could not allocate cmd DMA memory\n", DEVNAME(sc));
        err = -ENOMEM;
        goto fail;
    }
    ring->cmd = (struct iwx_device_cmd*)ring->cmd_dma.vaddr;

    paddr = ring->cmd_dma.paddr;
    for (i = 0; i < ring->ring_count; i++) {
        struct iwx_tx_data *data = &ring->data[i];

        data->cmd_paddr = paddr;
        paddr += sizeof(struct iwx_device_cmd);
        err = bus_dmamap_create(sc->sc_dmat, MCLBYTES,
                                IWX_TFH_NUM_TBS - 2, MCLBYTES, 0, BUS_DMA_NOWAIT,
                                &data->map);
        if (err) {
            XYLog("%s: could not create TX buf DMA map\n",
                  DEVNAME(sc));
            err = -EIO;
            goto fail;
        }
    }
    cmd.cb_size = htole32(IWX_TFD_QUEUE_CB_SIZE(ring->ring_count));
    cmd.byte_cnt_addr = htole64(ring->bc_tbl.paddr);
    cmd.tfdq_addr = htole64(ring->desc_dma.paddr);

    hcmd.data[0] = &cmd;
    hcmd.len[0] = sizeof(cmd);

    err = iwx_send_cmd(sc, &hcmd);
    if (err)
        return err;

    pkt = hcmd.resp_pkt;
    if (!pkt || (pkt->hdr.group_id & IWX_CMD_FAILED_MSK)) {
        XYLog("SCD_QUEUE_CFG command failed\n");
        err = -EIO;
        goto fail;
    }

    resp_len = iwx_rx_packet_payload_len(pkt);
    if (resp_len != sizeof(*resp)) {
        XYLog("SCD_QUEUE_CFG returned %zu bytes, expected %zu bytes\n", resp_len, sizeof(*resp));
        err = -EIO;
        goto fail;
    }

    resp = (struct iwx_tx_queue_cfg_rsp *)pkt->data;
    fwqid = le16toh(resp->queue_number);
    wr_idx = le16toh(resp->write_pointer);
    if (fwqid >= ARRAY_SIZE(sc->txq)) {
        XYLog("queue index %d unsupported", fwqid);
        err = -EIO;
        goto fail;
    }
    ring->cur = wr_idx;
    ring->qid = fwqid;
    iwx_reset_tx_ring(sc, &sc->txq[fwqid]);
    iwx_free_tx_ring(sc, &sc->txq[fwqid]);
    memcpy(&sc->txq[fwqid], ring, sizeof(*ring));
    return fwqid;
fail:
    iwx_reset_tx_ring(sc, ring);
    iwx_free_tx_ring(sc, ring);
    return err;
}

void ItlIwx::
iwx_post_alive(struct iwx_softc *sc)
{
    
    XYLog("%s\n", __FUNCTION__);
    iwx_ict_reset(sc);
    
    /*
     * Re-enable all the interrupts, including the RF-Kill one, now that
     * the firmware is alive.
     */
    iwx_enable_interrupts(sc);
}

/*
 * For the high priority TE use a time event type that has similar priority to
 * the FW's action scan priority.
 */
#define IWX_ROC_TE_TYPE_NORMAL IWX_TE_P2P_DEVICE_DISCOVERABLE
#define IWX_ROC_TE_TYPE_MGMT_TX IWX_TE_P2P_CLIENT_ASSOC

int ItlIwx::
iwx_send_time_event_cmd(struct iwx_softc *sc,
                        const struct iwx_time_event_cmd *cmd)
{
    struct iwx_rx_packet *pkt;
    struct iwx_time_event_resp *resp;
    struct iwx_host_cmd hcmd = {
        .id = IWX_TIME_EVENT_CMD,
        .flags = IWX_CMD_WANT_RESP,
        .resp_pkt_len = sizeof(*pkt) + sizeof(*resp),
    };
    uint32_t resp_len;
    int err;
    
    hcmd.data[0] = cmd;
    hcmd.len[0] = sizeof(*cmd);
    err = iwx_send_cmd(sc, &hcmd);
    if (err)
        return err;
    
    pkt = hcmd.resp_pkt;
    if (!pkt || (pkt->hdr.group_id & IWX_CMD_FAILED_MSK)) {
        err = EIO;
        goto out;
    }
    
    resp_len = iwx_rx_packet_payload_len(pkt);
    if (resp_len != sizeof(*resp)) {
        err = EIO;
        goto out;
    }
    
    resp = (struct iwx_time_event_resp *)pkt->data;
    if (le32toh(resp->status) == 0)
        sc->sc_time_event_uid = le32toh(resp->unique_id);
    else
        err = EIO;
out:
    iwx_free_resp(sc, &hcmd);
    return err;
}

void ItlIwx::
iwx_protect_session(struct iwx_softc *sc, struct iwx_node *in,
                    uint32_t duration, uint32_t max_delay)
{
    struct iwx_time_event_cmd time_cmd;
    
    /* Do nothing if a time event is already scheduled. */
    if (sc->sc_flags & IWX_FLAG_TE_ACTIVE)
        return;
    
    memset(&time_cmd, 0, sizeof(time_cmd));
    
    time_cmd.action = htole32(IWX_FW_CTXT_ACTION_ADD);
    time_cmd.id_and_color =
    htole32(IWX_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    time_cmd.id = htole32(IWX_TE_BSS_STA_AGGRESSIVE_ASSOC);
    
    time_cmd.apply_time = htole32(0);
    
    time_cmd.max_frags = IWX_TE_V2_FRAG_NONE;
    time_cmd.max_delay = htole32(max_delay);
    /* TODO: why do we need to interval = bi if it is not periodic? */
    time_cmd.interval = htole32(1);
    time_cmd.duration = htole32(duration);
    time_cmd.repeat = 1;
    time_cmd.policy
    = htole16(IWX_TE_V2_NOTIF_HOST_EVENT_START |
              IWX_TE_V2_NOTIF_HOST_EVENT_END |
              IWX_T2_V2_START_IMMEDIATELY);
    
    if (iwx_send_time_event_cmd(sc, &time_cmd) == 0)
        sc->sc_flags |= IWX_FLAG_TE_ACTIVE;
    
    DELAY(100);
}

int ItlIwx::
iwx_schedule_protect_session(struct iwx_softc *sc, struct iwx_node *in,
                    uint32_t duration)
{
    struct iwx_session_prot_cmd cmd = {
        .id_and_color =
            htole32(IWX_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color)),
        .action = htole32(IWX_FW_CTXT_ACTION_ADD),
        .duration_tu = htole32(duration * IEEE80211_DUR_TU),
    };
    int err;
    
    cmd.conf_id = IWX_SESSION_PROTECT_CONF_ASSOC;
    
    DPRINTFN(1, ("Add new session protection, duration %d TU\n",
             htole32(cmd.duration_tu)));
    
    err = iwx_send_cmd_pdu(sc, iwx_cmd_id(IWX_SESSION_PROTECTION_CMD, IWX_MAC_CONF_GROUP, 0), 0, sizeof(cmd), &cmd);
    if (err)
        XYLog("Couldn't send the SESSION_PROTECTION_CMD %d\n", err);
    return err;
}

int ItlIwx::
iwx_cancel_session_protection(struct iwx_softc *sc, struct iwx_node *in)
{
    struct iwx_session_prot_cmd cmd = {
        .id_and_color =
            htole32(IWX_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color)),
        .action = htole32(IWX_FW_CTXT_ACTION_REMOVE),
        .conf_id = IWX_SESSION_PROTECT_CONF_ASSOC,
    };
    int err;
    
    DPRINTFN(1, ("Remove session protection\n"));
    
    err = iwx_send_cmd_pdu(sc, iwx_cmd_id(IWX_SESSION_PROTECTION_CMD, IWX_MAC_CONF_GROUP, 0), 0, sizeof(cmd), &cmd);
    if (err)
        XYLog("Couldn't send the Cancel SESSION_PROTECTION_CMD %d\n", err);
    return err;
}

void ItlIwx::
iwx_unprotect_session(struct iwx_softc *sc, struct iwx_node *in)
{
    struct iwx_time_event_cmd time_cmd;
    
    /* Do nothing if the time event has already ended. */
    if ((sc->sc_flags & IWX_FLAG_TE_ACTIVE) == 0)
        return;
    
    memset(&time_cmd, 0, sizeof(time_cmd));
    
    time_cmd.action = htole32(IWX_FW_CTXT_ACTION_REMOVE);
    time_cmd.id_and_color =
    htole32(IWX_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    time_cmd.id = htole32(sc->sc_time_event_uid);
    
    if (iwx_send_time_event_cmd(sc, &time_cmd) == 0)
        sc->sc_flags &= ~IWX_FLAG_TE_ACTIVE;
    
    DELAY(100);
}

/*
 * NVM read access and content parsing.  We do not support
 * external NVM or writing NVM.
 */

uint8_t ItlIwx::
iwx_fw_valid_tx_ant(struct iwx_softc *sc)
{
    uint8_t tx_ant;
    
    tx_ant = ((sc->sc_fw_phy_config & IWX_FW_PHY_CFG_TX_CHAIN)
              >> IWX_FW_PHY_CFG_TX_CHAIN_POS);
    
    if (sc->sc_nvm.valid_tx_ant)
        tx_ant &= sc->sc_nvm.valid_tx_ant;
    
    return tx_ant;
}

uint8_t ItlIwx::
iwx_fw_valid_rx_ant(struct iwx_softc *sc)
{
    uint8_t rx_ant;
    
    rx_ant = ((sc->sc_fw_phy_config & IWX_FW_PHY_CFG_RX_CHAIN)
              >> IWX_FW_PHY_CFG_RX_CHAIN_POS);
    
    if (sc->sc_nvm.valid_rx_ant)
        rx_ant &= sc->sc_nvm.valid_rx_ant;
    
    return rx_ant;
}

void ItlIwx::
iwx_init_channel_map(struct iwx_softc *sc, uint16_t *channel_profile_v3,
uint32_t *channel_profile_v4, int nchan_profile)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_nvm_data *data = &sc->sc_nvm;
    int ch_idx;
    struct ieee80211_channel *channel;
    uint32_t ch_flags;
    int is_5ghz;
    int flags, hw_value;
    int nchan;
    const uint8_t *nvm_channels;

    if (sc->sc_uhb_supported) {
        nchan = nitems(iwx_nvm_channels_uhb);
        nvm_channels = iwx_nvm_channels_uhb;
    } else {
        nchan = nitems(iwx_nvm_channels_8000);
        nvm_channels = iwx_nvm_channels_8000;
    }

    for (ch_idx = 0; ch_idx < nchan && ch_idx < nchan_profile; ch_idx++) {
        if (channel_profile_v4)
            ch_flags = le32_to_cpup(channel_profile_v4 + ch_idx);
        else
            ch_flags = le16_to_cpup(channel_profile_v3 + ch_idx);

        is_5ghz = ch_idx >= IWX_NUM_2GHZ_CHANNELS;
        if (is_5ghz && !data->sku_cap_band_52GHz_enable)
            ch_flags &= ~IWX_NVM_CHANNEL_VALID;
        
        if (ch_flags & IWX_NVM_CHANNEL_160MHZ)
            data->vht160_supported = true;

        hw_value = nvm_channels[ch_idx];
        channel = &ic->ic_channels[hw_value];

        if (!(ch_flags & IWX_NVM_CHANNEL_VALID)) {
            channel->ic_freq = 0;
            channel->ic_flags = 0;
            continue;
        }

        if (!is_5ghz) {
            flags = IEEE80211_CHAN_2GHZ;
            channel->ic_flags
                = IEEE80211_CHAN_CCK
                | IEEE80211_CHAN_OFDM
                | IEEE80211_CHAN_DYN
                | IEEE80211_CHAN_2GHZ;
        } else {
            flags = IEEE80211_CHAN_5GHZ;
            channel->ic_flags =
                IEEE80211_CHAN_A;
        }

        if (!(ch_flags & IWX_NVM_CHANNEL_ACTIVE))
            channel->ic_flags |= IEEE80211_CHAN_PASSIVE;

        if (data->sku_cap_11n_enable)
            channel->ic_flags |= IEEE80211_CHAN_HT20;

        if (!is_5ghz && (ch_flags & IWX_NVM_CHANNEL_40MHZ)) {
            if (hw_value <= IWX_LAST_2GHZ_HT_PLUS) {
                channel->ic_flags |= IEEE80211_CHAN_HT40U;
            }
            if (hw_value >= IWX_FIRST_2GHZ_HT_MINUS) {
                channel->ic_flags |= IEEE80211_CHAN_HT40D;
            }
        } else if (ch_flags & IWX_NVM_CHANNEL_40MHZ) {
            if ((ch_idx - IWX_NUM_2GHZ_CHANNELS) % 2 == 0) {
                channel->ic_flags |= IEEE80211_CHAN_HT40U;
            } else {
                channel->ic_flags |= IEEE80211_CHAN_HT40D;
            }
        }

        if (data->sku_cap_11ac_enable) {
            if (ch_flags & IWX_NVM_CHANNEL_80MHZ) {
                channel->ic_flags |= IEEE80211_CHAN_VHT80;
            }
            if (ch_flags & IWX_NVM_CHANNEL_160MHZ) {
                channel->ic_flags |= IEEE80211_CHAN_VHT160;
            }
        }

        if (ch_flags & IWX_NVM_CHANNEL_DFS) {
            channel->ic_flags |= IEEE80211_CHAN_DFS;
        }

        channel->ic_freq = ieee80211_ieee2mhz(hw_value, flags);
        
        DPRINTFN(3, ("Ch. %d Flags %x [%sGHz] - No traffic\n",
              hw_value,
              channel->ic_flags,
              (!IEEE80211_IS_CHAN_2GHZ(channel)) ? "5.2" : "2.4"));
    }
}

int ItlIwx::
iwx_mimo_enabled(struct iwx_softc *sc)
{
   struct ieee80211com *ic = &sc->sc_ic;

   return !sc->sc_nvm.sku_cap_mimo_disable &&
       (ic->ic_userflags & IEEE80211_F_NOMIMO) == 0;
}

void ItlIwx::
iwx_setup_ht_rates(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    uint8_t rx_ant;
    
    /* TX is supported with the same MCS as RX. */
    ic->ic_tx_mcs_set = IEEE80211_TX_MCS_SET_DEFINED;
    
    memset(ic->ic_sup_mcs, 0, sizeof(ic->ic_sup_mcs));
    ic->ic_sup_mcs[0] = 0xff;        /* MCS 0-7 */
    
    if (!iwx_mimo_enabled(sc))
        return;
    
    rx_ant = iwx_fw_valid_rx_ant(sc);
    if ((rx_ant & IWX_ANT_AB) == IWX_ANT_AB ||
        (rx_ant & IWX_ANT_BC) == IWX_ANT_BC)
        ic->ic_sup_mcs[1] = 0xff;    /* MCS 8-15 */
}

void ItlIwx::
iwx_init_reorder_buffer(struct iwx_reorder_buffer *reorder_buf,
                        uint16_t ssn, uint16_t buf_size)
{
    reorder_buf->head_sn = ssn;
    reorder_buf->num_stored = 0;
    reorder_buf->buf_size = buf_size;
    reorder_buf->last_amsdu = 0;
    reorder_buf->last_sub_index = 0;
    reorder_buf->removed = 0;
    reorder_buf->valid = 0;
    reorder_buf->consec_oldsn_drops = 0;
    reorder_buf->consec_oldsn_ampdu_gp2 = 0;
    reorder_buf->consec_oldsn_prev_drop = 0;
}

void ItlIwx::
iwx_clear_reorder_buffer(struct iwx_softc *sc, struct iwx_rxba_data *rxba)
{
    int i;
    struct iwx_reorder_buffer *reorder_buf = &rxba->reorder_buf;
    struct iwx_reorder_buf_entry *entry;
    
    for (i = 0; i < reorder_buf->buf_size; i++) {
        entry = &rxba->entries[i];
        ml_purge(&entry->frames);
        timerclear(&entry->reorder_time);
    }
    
    reorder_buf->removed = 1;
    timeout_del(&reorder_buf->reorder_timer);
    timeout_free(&reorder_buf->reorder_timer);
    timerclear(&rxba->last_rx);
    timeout_del(&rxba->session_timer);
    timeout_free(&rxba->session_timer);
    rxba->baid = IWX_RX_REORDER_DATA_INVALID_BAID;
}

#define RX_REORDER_BUF_TIMEOUT_MQ_USEC (100000ULL)

void ItlIwx::
iwx_rx_ba_session_expired(void *arg)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_rxba_data *rxba = (struct iwx_rxba_data *)arg;
    struct iwx_softc *sc = rxba->sc;
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    struct timeval now, timeout, expiry;
    int s;
    
    s = splnet();
    if ((sc->sc_flags & IWX_FLAG_SHUTDOWN) == 0 &&
        ic->ic_state == IEEE80211_S_RUN &&
        rxba->baid != IWX_RX_REORDER_DATA_INVALID_BAID) {
        getmicrouptime(&now);
        USEC_TO_TIMEVAL(RX_REORDER_BUF_TIMEOUT_MQ_USEC, &timeout);
        timeradd(&rxba->last_rx, &timeout, &expiry);
        if (timercmp(&now, &expiry, <)) {
            timeout_add_usec(&rxba->session_timer, rxba->timeout);
        } else {
            ic->ic_stats.is_ht_rx_ba_timeout++;
            ieee80211_delba_request(ic, ni,
                                    IEEE80211_REASON_TIMEOUT, 0, rxba->tid);
        }
    }
    splx(s);
}

void ItlIwx::
iwx_reorder_timer_expired(void *arg)
{
    XYLog("%s\n", __FUNCTION__);
    struct mbuf_list ml = MBUF_LIST_INITIALIZER();
    struct iwx_reorder_buffer *buf = (struct iwx_reorder_buffer *)arg;
    struct iwx_rxba_data *rxba = iwx_rxba_data_from_reorder_buf(buf);
    struct iwx_reorder_buf_entry *entries = &rxba->entries[0];
    struct iwx_softc *sc = rxba->sc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    int i, s;
    uint16_t sn = 0, index = 0;
    int expired = 0;
    int cont = 0;
    struct timeval now, timeout, expiry;
    
    if (!buf->num_stored || buf->removed)
        return;
    
    s = splnet();
    getmicrouptime(&now);
    USEC_TO_TIMEVAL(RX_REORDER_BUF_TIMEOUT_MQ_USEC, &timeout);
    
    for (i = 0; i < buf->buf_size ; i++) {
        index = (buf->head_sn + i) % buf->buf_size;
        
        if (ml_empty(&entries[index].frames)) {
            /*
             * If there is a hole and the next frame didn't expire
             * we want to break and not advance SN.
             */
            cont = 0;
            continue;
        }
        timeradd(&entries[index].reorder_time, &timeout, &expiry);
        if (!cont && timercmp(&now, &expiry, <))
            break;
        
        expired = 1;
        /* continue until next hole after this expired frame */
        cont = 1;
        sn = (buf->head_sn + (i + 1)) & 0xfff;
    }
    
    if (expired) {
        /* SN is set to the last expired frame + 1 */
        that->iwx_release_frames(sc, ni, rxba, buf, sn, &ml);
        if_input(&sc->sc_ic.ic_if, &ml);
        ic->ic_stats.is_ht_rx_ba_window_gap_timeout++;
    } else {
        /*
         * If no frame expired and there are stored frames, index is now
         * pointing to the first unexpired frame - modify reorder timeout
         * accordingly.
         */
        timeout_add_usec(&buf->reorder_timer,
                         RX_REORDER_BUF_TIMEOUT_MQ_USEC);
    }
    
    splx(s);
}

static inline uint8_t iwx_num_of_ant(uint8_t mask)
{
    return  !!((mask) & IWX_ANT_A) +
        !!((mask) & IWX_ANT_B) +
        !!((mask) & IWX_ANT_C);
}

void ItlIwx::
iwx_setup_vht_rates(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    uint8_t rx_ant, tx_ant;
    unsigned int max_ampdu_exponent = IEEE80211_VHTCAP_MAX_AMPDU_1024K;
    
    if (ic->ic_userflags & IEEE80211_F_NOVHT)
        return;
    
    /* enable 11ac support */
    ic->ic_flags |= IEEE80211_F_VHTON;
    
    rx_ant = iwx_num_of_ant(iwx_fw_valid_rx_ant(sc));
    tx_ant = iwx_num_of_ant(iwx_fw_valid_tx_ant(sc));
    
    ic->ic_vhtcaps = IEEE80211_VHTCAP_SHORT_GI_80 |
    IEEE80211_VHTCAP_RXSTBC_1 |
    IEEE80211_VHTCAP_SU_BEAMFORMEE_CAPABLE | 
    3 << IEEE80211_VHTCAP_BEAMFORMEE_STS_SHIFT |
    max_ampdu_exponent << IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT |
    IEEE80211_VHTCAP_MU_BEAMFORMEE_CAPABLE;
    
    if (sc->sc_nvm.vht160_supported)
        ic->ic_vhtcaps |= IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_160MHZ |
                IEEE80211_VHTCAP_SHORT_GI_160;
    
    if (!iwx_mimo_enabled(sc)) {
        rx_ant = 1;
        tx_ant = 1;
    }
    
    ic->ic_vhtcaps |= IEEE80211_VHTCAP_RXLDPC;
    if (tx_ant > 1)
        ic->ic_vhtcaps |= IEEE80211_VHTCAP_TXSTBC;
    else
        ic->ic_vhtcaps |= IEEE80211_VHTCAP_TX_ANTENNA_PATTERN;
    
    ic->ic_vht_rx_mcs_map =
        htole16(IEEE80211_VHT_MCS_SUPPORT_0_9 << 0 |
                IEEE80211_VHT_MCS_SUPPORT_0_9 << 2 |
                IEEE80211_VHT_MCS_NOT_SUPPORTED << 4 |
                IEEE80211_VHT_MCS_NOT_SUPPORTED << 6 |
                IEEE80211_VHT_MCS_NOT_SUPPORTED << 8 |
                IEEE80211_VHT_MCS_NOT_SUPPORTED << 10 |
                IEEE80211_VHT_MCS_NOT_SUPPORTED << 12 |
                IEEE80211_VHT_MCS_NOT_SUPPORTED << 14);
    if (rx_ant == 1) {
        ic->ic_vhtcaps |= IEEE80211_VHTCAP_RX_ANTENNA_PATTERN;
        /* this works because NOT_SUPPORTED == 3 */
        ic->ic_vht_rx_mcs_map |=
            htole16(IEEE80211_VHT_MCS_NOT_SUPPORTED << 2);
    }
    ic->ic_vht_tx_mcs_map = ic->ic_vht_rx_mcs_map;

    ic->ic_vht_tx_highest |=
        htole16(IEEE80211_VHT_EXT_NSS_BW_CAPABLE);
    ic->ic_vht_rx_highest = 0;
    
    memset(ic->ic_vht_sup_mcs, 0, sizeof(ic->ic_vht_sup_mcs));
    ic->ic_vht_sup_mcs[0] = 0x03FF;        /* MCS 0-9 */
    
    if (!iwx_mimo_enabled(sc))
        return;
    
    ic->ic_vht_sup_mcs[1] = 0x03FF;         /* MCS 0-9 */
}

void ItlIwx::
iwx_setup_he_rates(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    
    /* enable 11ax support */
//    ic->ic_flags |= IEEE80211_F_HEON;
    
    ic->ic_he_cap_elem = {
        .mac_cap_info[0] =
            IEEE80211_HE_MAC_CAP0_HTC_HE |
            IEEE80211_HE_MAC_CAP0_TWT_REQ,
        .mac_cap_info[1] =
            IEEE80211_HE_MAC_CAP1_TF_MAC_PAD_DUR_16US |
            IEEE80211_HE_MAC_CAP1_MULTI_TID_AGG_RX_QOS_8,
        .mac_cap_info[2] =
            IEEE80211_HE_MAC_CAP2_32BIT_BA_BITMAP,
        .mac_cap_info[3] =
            IEEE80211_HE_MAC_CAP3_OMI_CONTROL |
            IEEE80211_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_VHT_2,
        .mac_cap_info[4] =
            IEEE80211_HE_MAC_CAP4_AMDSU_IN_AMPDU |
            IEEE80211_HE_MAC_CAP4_MULTI_TID_AGG_TX_QOS_B39,
        .mac_cap_info[5] =
            IEEE80211_HE_MAC_CAP5_MULTI_TID_AGG_TX_QOS_B40 |
            IEEE80211_HE_MAC_CAP5_MULTI_TID_AGG_TX_QOS_B41 |
            IEEE80211_HE_MAC_CAP5_UL_2x996_TONE_RU |
            IEEE80211_HE_MAC_CAP5_HE_DYNAMIC_SM_PS |
            IEEE80211_HE_MAC_CAP5_HT_VHT_TRIG_FRAME_RX,
        .phy_cap_info[1] =
            IEEE80211_HE_PHY_CAP1_PREAMBLE_PUNC_RX_MASK |
            IEEE80211_HE_PHY_CAP1_DEVICE_CLASS_A |
            IEEE80211_HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD,
        .phy_cap_info[2] =
            IEEE80211_HE_PHY_CAP2_NDP_4x_LTF_AND_3_2US,
        .phy_cap_info[3] =
            IEEE80211_HE_PHY_CAP3_DCM_MAX_CONST_TX_NO_DCM |
            IEEE80211_HE_PHY_CAP3_DCM_MAX_TX_NSS_1 |
            IEEE80211_HE_PHY_CAP3_DCM_MAX_CONST_RX_NO_DCM |
            IEEE80211_HE_PHY_CAP3_DCM_MAX_RX_NSS_1,
        .phy_cap_info[4] =
            IEEE80211_HE_PHY_CAP4_SU_BEAMFORMEE |
            IEEE80211_HE_PHY_CAP4_BEAMFORMEE_MAX_STS_ABOVE_80MHZ_8 |
            IEEE80211_HE_PHY_CAP4_BEAMFORMEE_MAX_STS_UNDER_80MHZ_8,
        .phy_cap_info[5] =
            IEEE80211_HE_PHY_CAP5_BEAMFORMEE_NUM_SND_DIM_UNDER_80MHZ_2 |
            IEEE80211_HE_PHY_CAP5_BEAMFORMEE_NUM_SND_DIM_ABOVE_80MHZ_2,
        .phy_cap_info[6] =
            IEEE80211_HE_PHY_CAP6_TRIG_SU_BEAMFORMER_FB |
            IEEE80211_HE_PHY_CAP6_TRIG_MU_BEAMFORMER_FB |
            IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT,
        .phy_cap_info[7] =
            IEEE80211_HE_PHY_CAP7_POWER_BOOST_FACTOR_AR |
            IEEE80211_HE_PHY_CAP7_HE_SU_MU_PPDU_4XLTF_AND_08_US_GI |
            IEEE80211_HE_PHY_CAP7_MAX_NC_1,
        .phy_cap_info[8] =
            IEEE80211_HE_PHY_CAP8_HE_ER_SU_PPDU_4XLTF_AND_08_US_GI |
            IEEE80211_HE_PHY_CAP8_20MHZ_IN_40MHZ_HE_PPDU_IN_2G |
            IEEE80211_HE_PHY_CAP8_20MHZ_IN_160MHZ_HE_PPDU |
            IEEE80211_HE_PHY_CAP8_80MHZ_IN_160MHZ_HE_PPDU |
            IEEE80211_HE_PHY_CAP8_DCM_MAX_RU_2x996,
        .phy_cap_info[9] =
            IEEE80211_HE_PHY_CAP9_NON_TRIGGERED_CQI_FEEDBACK |
            IEEE80211_HE_PHY_CAP9_RX_FULL_BW_SU_USING_MU_WITH_COMP_SIGB |
            IEEE80211_HE_PHY_CAP9_RX_FULL_BW_SU_USING_MU_WITH_NON_COMP_SIGB |
            IEEE80211_HE_PHY_CAP9_NOMIMAL_PKT_PADDING_RESERVED,
    };
    
    /*
     * Set default Tx/Rx HE MCS NSS Support field.
     * Indicate support for up to 2 spatial streams and all
     * MCS, without any special cases
     */
    ic->ic_he_mcs_nss_supp = {
        .rx_mcs_80 = htole16(0xfffa),
        .tx_mcs_80 = htole16(0xfffa),
        .rx_mcs_160 = htole16(0xfffa),
        .tx_mcs_160 = htole16(0xfffa),
        .rx_mcs_80p80 = htole16(0xffff),
        .tx_mcs_80p80 = htole16(0xffff),
    };
    
    /*
     * Set default PPE thresholds, with PPET16 set to 0,
     * PPET8 set to 7
     */
    uint8_t ppe_thres[] = {0x61, 0x1c, 0xc7, 0x71};
    memcpy(ic->ic_ppe_thres, ppe_thres, sizeof(ic->ic_ppe_thres));
}

#define IWX_MAX_RX_BA_SESSIONS 16

void ItlIwx::
iwx_sta_rx_agg(struct iwx_softc *sc, struct ieee80211_node *ni, uint8_t tid,
               uint16_t ssn, uint16_t winsize, int timeout_val, int start)
{
    XYLog("%s start=%d tid=%d ssn=%d winsize=%d\n", __FUNCTION__, start, tid, ssn, winsize);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_add_sta_cmd cmd;
    struct iwx_node *in = (struct iwx_node *)ni;
    int err, s;
    uint32_t status;
    struct iwx_rxba_data *rxba = NULL;
    uint8_t baid = 0;
    
    s = splnet();
    
    if (start && sc->sc_rx_ba_sessions >= IWX_MAX_RX_BA_SESSIONS) {
        ieee80211_addba_req_refuse(ic, ni, tid);
        splx(s);
        return;
    }
    
    memset(&cmd, 0, sizeof(cmd));
    
    cmd.sta_id = IWX_STATION_ID;
    cmd.mac_id_n_color
    = htole32(IWX_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    cmd.add_modify = IWX_STA_MODE_MODIFY;
    
    if (start) {
        cmd.add_immediate_ba_tid = (uint8_t)tid;
        cmd.add_immediate_ba_ssn = htole16(ssn);
        cmd.rx_ba_window = htole16(winsize);
    } else {
        cmd.remove_immediate_ba_tid = (uint8_t)tid;
    }
    cmd.modify_mask = start ? IWX_STA_MODIFY_ADD_BA_TID :
    IWX_STA_MODIFY_REMOVE_BA_TID;
    
    status = IWX_ADD_STA_SUCCESS;
    err = iwx_send_cmd_pdu_status(sc, IWX_ADD_STA, sizeof(cmd), &cmd,
                                  &status);
    
    if (err || (status & IWX_ADD_STA_STATUS_MASK) != IWX_ADD_STA_SUCCESS) {
        if (start)
            ieee80211_addba_req_refuse(ic, ni, tid);
        splx(s);
        return;
    }
    
    /* Deaggregation is done in hardware. */
    if (start) {
        if (!(status & IWX_ADD_STA_BAID_VALID_MASK)) {
            ieee80211_addba_req_refuse(ic, ni, tid);
            splx(s);
            return;
        }
        baid = (status & IWX_ADD_STA_BAID_MASK) >>
        IWX_ADD_STA_BAID_SHIFT;
        if (baid == IWX_RX_REORDER_DATA_INVALID_BAID ||
            baid >= nitems(sc->sc_rxba_data)) {
            ieee80211_addba_req_refuse(ic, ni, tid);
            splx(s);
            return;
        }
        rxba = &sc->sc_rxba_data[baid];
        if (rxba->baid != IWX_RX_REORDER_DATA_INVALID_BAID) {
            ieee80211_addba_req_refuse(ic, ni, tid);
            splx(s);
            return;
        }
        rxba->sta_id = IWX_STATION_ID;
        rxba->tid = tid;
        rxba->baid = baid;
        rxba->timeout = timeout_val;
        getmicrouptime(&rxba->last_rx);
        iwx_init_reorder_buffer(&rxba->reorder_buf, ssn,
                                winsize);
        if (timeout_val != 0) {
            struct ieee80211_rx_ba *ba;
            timeout_add_usec(&rxba->session_timer,
                             timeout_val);
            /* XXX disable net80211's BA timeout handler */
            ba = &ni->ni_rx_ba[tid];
            ba->ba_timeout_val = 0;
        }
    } else {
        int i;
        for (i = 0; i < nitems(sc->sc_rxba_data); i++) {
            rxba = &sc->sc_rxba_data[i];
            if (rxba->baid ==
                IWX_RX_REORDER_DATA_INVALID_BAID)
                continue;
            if (rxba->tid != tid)
                continue;
            iwx_clear_reorder_buffer(sc, rxba);
            break;
        }
    }
    
    if (start) {
        sc->sc_rx_ba_sessions++;
        ieee80211_addba_req_accept(ic, ni, tid);
    } else if (sc->sc_rx_ba_sessions > 0)
        sc->sc_rx_ba_sessions--;

    splx(s);
}

void ItlIwx::
iwx_mac_ctxt_task(void *arg)
{
    struct iwx_softc *sc = (struct iwx_softc *)arg;
    struct ieee80211com *ic = &sc->sc_ic;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    struct iwx_node *in = (struct iwx_node *)ic->ic_bss;
    int err, s = splnet();
    
    if (sc->sc_flags & IWX_FLAG_SHUTDOWN ||
        ic->ic_state != IEEE80211_S_RUN ||
        in->in_phyctxt == NULL) {
        //        refcnt_rele_wake(&sc->task_refs);
        splx(s);
        return;
    }
    
    err = that->iwx_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_MODIFY, 1);
    if (err)
        printf("%s: failed to update MAC\n", DEVNAME(sc));
    
    if (!isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD))
        that->iwx_unprotect_session(sc, in);
    
    //    refcnt_rele_wake(&sc->task_refs);
    splx(s);
}

void ItlIwx::
iwx_chan_ctxt_task(void *arg)
{
    struct iwx_softc *sc = (struct iwx_softc *)arg;
    struct ieee80211com *ic = &sc->sc_ic;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    struct iwx_node *in = (struct iwx_node *)ic->ic_bss;
    int chains = that->iwx_mimo_enabled(sc) ? 2 : 1;
    int err, s = splnet();
    
    if (sc->sc_flags & IWX_FLAG_SHUTDOWN ||
        ic->ic_state != IEEE80211_S_RUN ||
        in->in_phyctxt == NULL) {
        //        refcnt_rele_wake(&sc->task_refs);
        splx(s);
        return;
    }
    
    err = that->iwx_phy_ctxt_update(sc, in->in_phyctxt,
                                    in->in_phyctxt->channel, chains, chains, 0);
    if (err) {
        XYLog("%s: failed to update PHY (error %d)\n",
              __FUNCTION__, err);
        //        refcnt_rele_wake(&sc->task_refs);
        splx(s);
        return;
    }
    err = that->iwx_rs_init(sc, in, true);
    if (err) {
        XYLog("%s: could not update rate scaling (error %d)\n",
              __FUNCTION__, err);
        //        refcnt_rele_wake(&sc->task_refs);
        splx(s);
        return;
    }
    
    //    refcnt_rele_wake(&sc->task_refs);
    splx(s);
}

void ItlIwx::
iwx_update_chw(struct ieee80211com *ic)
{
    struct iwx_softc *sc = (struct iwx_softc *)ic->ic_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    
    if (ic->ic_state == IEEE80211_S_RUN && (sc->sc_flags & IWX_FLAG_STA_ACTIVE))
        that->iwx_add_task(sc, systq, &sc->chan_ctxt_task);
}

void ItlIwx::
iwx_updateprot(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_softc *sc = (struct iwx_softc *)ic->ic_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    
    if (ic->ic_state == IEEE80211_S_RUN && (sc->sc_flags & IWX_FLAG_STA_ACTIVE))
        that->iwx_add_task(sc, systq, &sc->mac_ctxt_task);
}

void ItlIwx::
iwx_updateslot(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_softc *sc = (struct iwx_softc *)ic->ic_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    
    if (ic->ic_state == IEEE80211_S_RUN && (sc->sc_flags & IWX_FLAG_STA_ACTIVE))
        that->iwx_add_task(sc, systq, &sc->mac_ctxt_task);
}

void ItlIwx::
iwx_updateedca(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_softc *sc = (struct iwx_softc *)ic->ic_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    
    if (ic->ic_state == IEEE80211_S_RUN && (sc->sc_flags & IWX_FLAG_STA_ACTIVE))
        that->iwx_add_task(sc, systq, &sc->mac_ctxt_task);
}

void ItlIwx::
iwx_updatedtim(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_softc *sc = (struct iwx_softc *)ic->ic_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    
    if (ic->ic_state == IEEE80211_S_RUN && (sc->sc_flags & IWX_FLAG_STA_ACTIVE))
        that->iwx_add_task(sc, systq, &sc->mac_ctxt_task);
}

void ItlIwx::
iwx_ba_task(void *arg)
{
    struct iwx_softc *sc = (struct iwx_softc *)arg;
    struct ieee80211com *ic = &sc->sc_ic;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    struct ieee80211_node *ni = ic->ic_bss;
    struct ieee80211_tx_ba *ba;
    struct iwx_tx_ring *ring;
    int s = splnet();
    int err = 0;
    int qid = 0;
    int tid;
    
    if (sc->sc_flags & IWX_FLAG_SHUTDOWN) {
        //        refcnt_rele_wake(&sc->task_refs);
        splx(s);
        return;
    }

    for (tid = 0; tid < IWX_MAX_TID_COUNT; tid++) {
        if (sc->sc_flags & IWX_FLAG_SHUTDOWN)
            break;
        if (sc->ba_rx.start_tidmask & (1 << tid)) {
            struct ieee80211_rx_ba *ba = &ni->ni_rx_ba[tid];
            XYLog("%s ba_rx_start tid=%d, ssn=%d\n", __FUNCTION__, tid, ba->ba_winstart);
            that->iwx_sta_rx_agg(sc, ni, tid, ba->ba_winstart,
                                 ba->ba_winsize, ba->ba_timeout_val, 1);
            sc->ba_rx.start_tidmask &= ~(1 << tid);
        } else if (sc->ba_rx.stop_tidmask & (1 << tid)) {
            that->iwx_sta_rx_agg(sc, ni, tid, 0, 0, 0, 0);
            sc->ba_rx.stop_tidmask &= ~(1 << tid);
        }
    }
    
    for (tid = 0; tid < IWX_MAX_TID_COUNT; tid++) {
        if (sc->sc_flags & IWX_FLAG_SHUTDOWN)
            break;
        if (sc->ba_tx.start_tidmask & (1 << tid)) {
            ba = &ni->ni_tx_ba[tid];
            XYLog("%s ba_tx_start tid=%d, ssn=%d\n", __FUNCTION__, tid, ba->ba_winstart);
            if (!that->iwx_nic_lock(sc)) {
                err = -1;
                goto out;
            }
            if ((qid = that->iwx_tvqm_alloc_txq(sc, tid, ba->ba_winstart)) < 0) {
                err = -1;
                goto out;
            }
            ring = &sc->txq[qid];
            ba->ba_winstart = IWX_AGG_SSN_TO_TXQ_IDX(ring->cur, ring->ring_count);
            ba->ba_winend = (ba->ba_winstart + ba->ba_winsize - 1) & 0xfff;
            ba->ba_timeout_val = 0;
            ieee80211_addba_resp_accept(ic, ni, tid);
            XYLog("%s tx queue alloc succeed qid=%d ssn=%d\n", __FUNCTION__, qid, ba->ba_winstart);
        out:
            that->iwx_nic_unlock(sc);
            if (err)
                ieee80211_addba_resp_refuse(ic, ni, tid,
                                            IEEE80211_STATUS_UNSPECIFIED);
            sc->ba_tx.start_tidmask &= ~(1 << tid);
        }
    }
    
    //    refcnt_rele_wake(&sc->task_refs);
    splx(s);
}

/*
 * This function is called by upper layer when an ADDBA request is received
 * from another STA and before the ADDBA response is sent.
 */
int ItlIwx::
iwx_ampdu_rx_start(struct ieee80211com *ic, struct ieee80211_node *ni,
                   uint8_t tid)
{
    struct iwx_softc *sc = (struct iwx_softc *)IC2IFP(ic)->if_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    
    if (sc->sc_rx_ba_sessions >= IWX_MAX_RX_BA_SESSIONS ||
        tid >= IWX_MAX_TID_COUNT)
        return ENOSPC;
    
    if (ic->ic_state != IEEE80211_S_RUN)
        return ENOSPC;
    
    if (sc->ba_rx.start_tidmask & (1 << tid))
        return EBUSY;

    sc->ba_rx.start_tidmask |= (1 << tid);
    that->iwx_add_task(sc, systq, &sc->ba_task);
    
    return EBUSY;
}

/*
 * This function is called by upper layer on teardown of an HT-immediate
 * Block Ack agreement (eg. upon receipt of a DELBA frame).
 */
void ItlIwx::
iwx_ampdu_rx_stop(struct ieee80211com *ic, struct ieee80211_node *ni,
                  uint8_t tid)
{
    struct iwx_softc *sc = (struct iwx_softc *)IC2IFP(ic)->if_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    
    if (tid >= IWX_MAX_TID_COUNT || sc->ba_rx.stop_tidmask & (1 << tid))
        return;
    
    if (ic->ic_state != IEEE80211_S_RUN)
        return;

    sc->ba_rx.stop_tidmask |= (1 << tid);
    that->iwx_add_task(sc, systq, &sc->ba_task);
}

int ItlIwx::
iwx_ampdu_tx_start(struct ieee80211com *ic, struct ieee80211_node *ni, uint8_t tid)
{
    struct ieee80211_tx_ba *ba = &ni->ni_tx_ba[tid];
    struct iwx_softc *sc = (struct iwx_softc *)ic->ic_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);

    XYLog("%s tid=%d ssn=%d\n", __FUNCTION__, tid, ba->ba_winstart);

    if (tid < 0 || tid >= IWX_MAX_TID_COUNT) {
        XYLog("%s tx agg refused. tid=%d\n", __FUNCTION__, tid);
        return ENOSPC;
    }
    
    if (sc->ba_tx.start_tidmask & (1 << tid)) {
        XYLog("%s tid %d is pending to agg\n", __FUNCTION__, tid);
        return EBUSY;
    }
    
    sc->ba_tx.start_tidmask |= (1 << tid);
    that->iwx_add_task(sc, systq, &sc->ba_task);
    return EBUSY;
}

void ItlIwx::
iwx_ampdu_tx_stop(struct ieee80211com *ic, struct ieee80211_node *ni, uint8_t tid)
{
    struct ieee80211_tx_ba *ba = &ni->ni_tx_ba[tid];
    struct iwx_softc *sc = (struct iwx_softc *)IC2IFP(ic)->if_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);

    XYLog("%s tid=%d\n", __FUNCTION__, tid);

    if (ba->ba_state != IEEE80211_BA_AGREED) {
        return;
    }

    sc->sc_tid_data[tid].qid = IWX_INVALID_QUEUE;
    ic->ic_stats.is_ht_tx_ba_agreements--;
}

static void iwx_flip_hw_address(uint32_t mac_addr0, uint32_t mac_addr1, uint8_t *dest)
{
    const u8 *hw_addr;

    hw_addr = (const u8 *)&mac_addr0;
    dest[0] = hw_addr[3];
    dest[1] = hw_addr[2];
    dest[2] = hw_addr[1];
    dest[3] = hw_addr[0];

    hw_addr = (const u8 *)&mac_addr1;
    dest[4] = hw_addr[1];
    dest[5] = hw_addr[0];
}

int ItlIwx::
iwx_set_mac_addr_from_csr(struct iwx_softc *sc, struct iwx_nvm_data *data)
{
    uint32_t mac_addr0, mac_addr1;
    
    if (!iwx_nic_lock(sc))
        return EBUSY;
    
    mac_addr0 = htole32(IWX_READ(sc, IWX_CSR_MAC_ADDR0_STRAP));
    mac_addr1 = htole32(IWX_READ(sc, IWX_CSR_MAC_ADDR1_STRAP));
    
    iwx_flip_hw_address(mac_addr0, mac_addr1, data->hw_addr);
    
    /*
     * If the OEM fused a valid address, use it instead of the one in the
     * OTP
     */
    if (iwx_is_valid_mac_addr(data->hw_addr))
        goto done;
    
    mac_addr0 = htole32(IWX_READ(sc, IWX_CSR_MAC_ADDR0_OTP));
    mac_addr1 = htole32(IWX_READ(sc, IWX_CSR_MAC_ADDR1_OTP));
    
    iwx_flip_hw_address(mac_addr0, mac_addr1, data->hw_addr);
    
done:
    
    iwx_nic_unlock(sc);
    return 0;
}

int ItlIwx::
iwx_is_valid_mac_addr(const uint8_t *addr)
{
    return (memcmp(etherbroadcastaddr, addr, sizeof(etherbroadcastaddr)) != 0 &&
            memcmp(etheranyaddr, addr, sizeof(etheranyaddr)) != 0 &&
            !ETHER_IS_MULTICAST(addr));
}

int ItlIwx::
iwx_nvm_get(struct iwx_softc *sc)
{
    struct iwx_nvm_get_info cmd = {};
    struct iwx_nvm_data *nvm = &sc->sc_nvm;
    struct iwx_host_cmd hcmd = {
        .flags = IWX_CMD_WANT_RESP | IWX_CMD_SEND_IN_RFKILL,
        .data = { &cmd, },
        .len = { sizeof(cmd) },
        .id = IWX_WIDE_ID(IWX_REGULATORY_AND_NVM_GROUP,
                          IWX_NVM_GET_INFO)
    };
    int err;
    uint32_t mac_flags;
    /*
     * All the values in iwx_nvm_get_info_rsp v4 are the same as
     * in v3, except for the channel profile part of the
     * regulatory.  So we can just access the new struct, with the
     * exception of the latter.
     */
    struct iwx_nvm_get_info_rsp *rsp;
    struct iwx_nvm_get_info_rsp_v3 *rsp_v3;
    int v4 = isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_REGULATORY_NVM_INFO);
    size_t resp_len = v4 ? sizeof(*rsp) : sizeof(*rsp_v3);
    
    hcmd.resp_pkt_len = sizeof(struct iwx_rx_packet) + resp_len;
    err = iwx_send_cmd(sc, &hcmd);
    if (err)
        return err;
    
    if (iwx_rx_packet_payload_len(hcmd.resp_pkt) != resp_len) {
        err = EIO;
        goto out;
    }
    
    memset(nvm, 0, sizeof(*nvm));
    
    iwx_set_mac_addr_from_csr(sc, nvm);
    if (!iwx_is_valid_mac_addr(nvm->hw_addr)) {
        XYLog("%s: no valid mac address was found\n", DEVNAME(sc));
        err = EINVAL;
        goto out;
    }
    
    rsp = (struct iwx_nvm_get_info_rsp *)hcmd.resp_pkt->data;
    
    /* Initialize general data */
    nvm->nvm_version = le16toh(rsp->general.nvm_version);
    nvm->n_hw_addrs = rsp->general.n_hw_addrs;
    
    /* Initialize MAC sku data */
    mac_flags = le32toh(rsp->mac_sku.mac_sku_flags);
    nvm->sku_cap_11ac_enable =
    !!(mac_flags & IWX_NVM_MAC_SKU_FLAGS_802_11AC_ENABLED);
    nvm->sku_cap_11n_enable =
    !!(mac_flags & IWX_NVM_MAC_SKU_FLAGS_802_11N_ENABLED);
    nvm->sku_cap_11ax_enable =
    !!(mac_flags & IWX_NVM_MAC_SKU_FLAGS_802_11AX_ENABLED);
    nvm->sku_cap_band_24GHz_enable =
    !!(mac_flags & IWX_NVM_MAC_SKU_FLAGS_BAND_2_4_ENABLED);
    nvm->sku_cap_band_52GHz_enable =
    !!(mac_flags & IWX_NVM_MAC_SKU_FLAGS_BAND_5_2_ENABLED);
    nvm->sku_cap_mimo_disable =
    !!(mac_flags & IWX_NVM_MAC_SKU_FLAGS_MIMO_DISABLED);
    
    /* Initialize PHY sku data */
    nvm->valid_tx_ant = (uint8_t)le32toh(rsp->phy_sku.tx_chains);
    nvm->valid_rx_ant = (uint8_t)le32toh(rsp->phy_sku.rx_chains);
    
    if (le32toh(rsp->regulatory.lar_enabled) &&
        isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_LAR_SUPPORT)) {
        nvm->lar_enabled = 1;
    }
    
    if (v4) {
        iwx_init_channel_map(sc, NULL,
                             rsp->regulatory.channel_profile, IWX_NUM_CHANNELS);
    } else {
        rsp_v3 = (struct iwx_nvm_get_info_rsp_v3 *)rsp;
        iwx_init_channel_map(sc, rsp_v3->regulatory.channel_profile,
                             NULL, IWX_NUM_CHANNELS_V1);
    }
out:
    iwx_free_resp(sc, &hcmd);
    return err;
}

int ItlIwx::
iwx_load_firmware(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_fw_sects *fws;
    int err/*, w*/;

    sc->sc_uc.uc_intr = 0;
    
    fws = &sc->sc_fw.fw_sects[IWX_UCODE_TYPE_REGULAR];
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
        err = iwx_ctxt_info_gen3_init(sc, fws);
    else
        err = iwx_ctxt_info_init(sc, fws);
    if (err) {
        XYLog("%s: could not init context info\n", DEVNAME(sc));
        return err;
    }
    
    /* wait for the firmware to load */
//    for (w = 0; !sc->sc_uc.uc_intr && w < 10; w++) {
//        err = tsleep_nsec(&sc->sc_uc, 0, "iwxuc", MSEC_TO_NSEC(100));
//    }
    err = tsleep_nsec(&sc->sc_uc, 0, "iwxuc", SEC_TO_NSEC(1));
    if (err || !sc->sc_uc.uc_ok) {
        if (iwx_nic_lock(sc)) {
            XYLog("SecBoot CPU1 Status: 0x%x, CPU2 Status: 0x%x\n",
                  iwx_read_umac_prph(sc, IWX_UMAG_SB_CPU_1_STATUS),
                  iwx_read_umac_prph(sc, IWX_UMAG_SB_CPU_2_STATUS));
            XYLog("UMAC PC: 0x%x\n",
                  iwx_read_umac_prph(sc,
                                     IWX_UREG_UMAC_CURRENT_PC));
            XYLog("LMAC PC: 0x%x\n",
                  iwx_read_umac_prph(sc,
                                     IWX_UREG_LMAC1_CURRENT_PC));
            iwx_nic_unlock(sc);
        }
        iwx_ctxt_info_free_paging(sc);
        XYLog("%s: could not load firmware\n", DEVNAME(sc));
    }
    
    iwx_ctxt_info_free_fw_img(sc);
    
    iwx_dma_contig_free(&sc->iml_dma);
    
    if (!sc->sc_uc.uc_ok)
        return EINVAL;
    
    XYLog("%s: load firmware ok\n", DEVNAME(sc));
    
    return err;
}

int ItlIwx::
iwx_start_fw(struct iwx_softc *sc)
{
    
    XYLog("%s\n", __FUNCTION__);
    int err;
    
    err = iwx_prepare_card_hw(sc);
    if (err) {
        XYLog("%s: could not initialize hardware\n", DEVNAME(sc));
        return err;
    }
    
    iwx_enable_rfkill_int(sc);
    
    IWX_WRITE(sc, IWX_CSR_INT, 0xFFFFFFFF);
    
    iwx_disable_interrupts(sc);
    
    /* make sure rfkill handshake bits are cleared */
    IWX_WRITE(sc, IWX_CSR_UCODE_DRV_GP1_CLR, IWX_CSR_UCODE_SW_BIT_RFKILL);
    IWX_WRITE(sc, IWX_CSR_UCODE_DRV_GP1_CLR,
              IWX_CSR_UCODE_DRV_GP1_BIT_CMD_BLOCKED);
    
    /* clear (again), then enable firwmare load interrupt */
    IWX_WRITE(sc, IWX_CSR_INT, ~0);
    
    err = iwx_nic_init(sc);
    if (err) {
        XYLog("%s: unable to init nic\n", DEVNAME(sc));
        return err;
    }
    
    return iwx_load_firmware(sc);
}

int ItlIwx::
iwx_send_tx_ant_cfg(struct iwx_softc *sc, uint8_t valid_tx_ant)
{
    struct iwx_tx_ant_cfg_cmd tx_ant_cmd = {
        .valid = htole32(valid_tx_ant),
    };
    
    XYLog("%s select valid tx ant: %u\n", __FUNCTION__, valid_tx_ant);
    return iwx_send_cmd_pdu(sc, IWX_TX_ANT_CONFIGURATION_CMD,
                            0, sizeof(tx_ant_cmd), &tx_ant_cmd);
}

int ItlIwx::
iwx_send_phy_cfg_cmd(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_phy_cfg_cmd_v3 phy_cfg_cmd;
    uint8_t cmdver;
    
    phy_cfg_cmd.phy_cfg = htole32(sc->sc_fw_phy_config);
    phy_cfg_cmd.calib_control.event_trigger =
    sc->sc_default_calib[IWX_UCODE_TYPE_REGULAR].event_trigger;
    phy_cfg_cmd.calib_control.flow_trigger =
    sc->sc_default_calib[IWX_UCODE_TYPE_REGULAR].flow_trigger;
    
    cmdver = iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_PHY_CONFIGURATION_CMD);
    
    return iwx_send_cmd_pdu(sc, IWX_PHY_CONFIGURATION_CMD, 0,
                            (cmdver == 3) ? sizeof(struct iwx_phy_cfg_cmd_v3) :
                            sizeof(struct iwx_phy_cfg_cmd_v1), &phy_cfg_cmd);
}

int ItlIwx::
iwx_send_dqa_cmd(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_dqa_enable_cmd dqa_cmd = {
        .cmd_queue = htole32(IWX_DQA_CMD_QUEUE),
    };
    uint32_t cmd_id;
    
    cmd_id = iwx_cmd_id(IWX_DQA_ENABLE_CMD, IWX_DATA_PATH_GROUP, 0);
    return iwx_send_cmd_pdu(sc, cmd_id, 0, sizeof(dqa_cmd), &dqa_cmd);
}

int ItlIwx::
iwx_load_ucode_wait_alive(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int err;
    
    err = iwx_read_firmware(sc);
    if (err)
        return err;
    
    err = iwx_start_fw(sc);
    if (err)
        return err;
    
    err = iwx_load_pnvm(sc);
    if (err)
        return err;
    
    iwx_post_alive(sc);
    
    return 0;
}

int ItlIwx::
iwx_run_init_mvm_ucode(struct iwx_softc *sc, int readnvm)
{
    XYLog("%s\n", __FUNCTION__);
    const int wait_flags = IWX_INIT_COMPLETE;
    struct iwx_nvm_access_complete_cmd nvm_complete = {};
    struct iwx_init_extended_cfg_cmd init_cfg = {
        .init_flags = htole32(IWX_INIT_NVM),
    };
    int err;

    if ((sc->sc_flags & IWX_FLAG_RFKILL) && !readnvm) {
        XYLog("%s: radio is disabled by hardware switch\n",
            DEVNAME(sc));
        return EPERM;
    }

    sc->sc_init_complete = 0;
    err = iwx_load_ucode_wait_alive(sc);
    if (err) {
        XYLog("%s: failed to load init firmware\n", DEVNAME(sc));
        return err;
    }
    
    if (sc->sc_tx_with_siso_diversity)
        init_cfg.init_flags |= htole32(IWX_INIT_PHY);

    /*
     * Send init config command to mark that we are sending NVM
     * access commands
     */
    err = iwx_send_cmd_pdu(sc, IWX_WIDE_ID(IWX_SYSTEM_GROUP,
                                           IWX_INIT_EXTENDED_CFG_CMD), IWX_CMD_SEND_IN_RFKILL, sizeof(init_cfg), &init_cfg);
    if (err)
        return err;

    err = iwx_send_cmd_pdu(sc, IWX_WIDE_ID(IWX_REGULATORY_AND_NVM_GROUP,
                                           IWX_NVM_ACCESS_COMPLETE), IWX_CMD_SEND_IN_RFKILL, sizeof(nvm_complete), &nvm_complete);
    if (err)
        return err;

    /* Wait for the init complete notification from the firmware. */
//    while ((sc->sc_init_complete & wait_flags) != wait_flags) {
//        err = tsleep_nsec(&sc->sc_init_complete, 0, "iwxinit",
//            SEC_TO_NSEC(2));
//        if (err)
//            return err;
//    }
    err = tsleep_nsec(&sc->sc_init_complete, 0, "iwxinit", SEC_TO_NSEC(2));
    if (err) {
        return err;
    }

    if (readnvm) {
        err = iwx_nvm_get(sc);
        if (err) {
            XYLog("%s: failed to read nvm\n", DEVNAME(sc));
            return err;
        }
        if (IEEE80211_ADDR_EQ(etheranyaddr, sc->sc_ic.ic_myaddr))
            IEEE80211_ADDR_COPY(sc->sc_ic.ic_myaddr,
                sc->sc_nvm.hw_addr);
        
    }
    return 0;
}

int ItlIwx::
iwx_config_ltr(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_ltr_config_cmd cmd = {
        .flags = htole32(IWX_LTR_CFG_FLAG_FEATURE_ENABLE),
    };
    
    if (!sc->sc_ltr_enabled)
        return 0;
    
    return iwx_send_cmd_pdu(sc, IWX_LTR_CONFIG, 0, sizeof(cmd), &cmd);
}

void ItlIwx::
iwx_update_rx_desc(struct iwx_softc *sc, struct iwx_rx_ring *ring, int idx)
{
    struct iwx_rx_data *data = &ring->data[idx];
    
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210) {
        struct iwx_rx_transfer_desc *bd = (struct iwx_rx_transfer_desc *)ring->desc;
        
        bd[idx].addr = htole64(data->map->dm_segs[0].location);
        bd[idx].rbid = htole16(idx & 0x0fff);
    } else
        ((uint64_t *)ring->desc)[idx] =
        htole64(data->map->dm_segs[0].location | (idx & 0x0fff));
    //    bus_dmamap_sync(sc->sc_dmat, ring->free_desc_dma.map,
    //        idx * sizeof(uint64_t), sizeof(uint64_t),
    //        BUS_DMASYNC_PREWRITE);
}

int ItlIwx::
iwx_rx_addbuf(struct iwx_softc *sc, int size, int idx)
{
    struct iwx_rx_ring *ring = &sc->rxq;
    struct iwx_rx_data *data = &ring->data[idx];
    mbuf_t m;
    int err;
    int fatal = 0;
    
    m = getController()->allocatePacket(size);
    
    //    m = m_gethdr(M_DONTWAIT, MT_DATA);
    //    if (m == NULL)
    //        return ENOBUFS;
    //
    //    if (size <= MCLBYTES) {
    //        MCLGET(m, M_DONTWAIT);
    //    } else {
    //        MCLGETI(m, M_DONTWAIT, NULL, IWX_RBUF_SIZE);
    //    }
    //    if ((m->m_flags & M_EXT) == 0) {
    //        m_freem(m);
    //        return ENOBUFS;
    //    }
    //
    //    if (data->m != NULL) {
    //        bus_dmamap_unload(sc->sc_dmat, data->map);
    //        fatal = 1;
    //    }
    //
    //    m->m_len = m->m_pkthdr.len = m->m_ext.ext_size;
    //    err = bus_dmamap_load_mbuf(sc->sc_dmat, data->map, m,
    //        BUS_DMA_READ|BUS_DMA_NOWAIT);
    if (m == NULL) {
        XYLog("could not allocate RX mbuf\n");
        return ENOMEM;
    }
    data->map->dm_nsegs = data->map->cursor->getPhysicalSegments(m, &data->map->dm_segs[0], 1);
    if (data->map->dm_nsegs == 0) {
        /* XXX */
        if (fatal)
            panic("%s: could not load RX mbuf", DEVNAME(sc));
        mbuf_freem(m);
        return ENOMEM;
    }
    data->m = m;
    //    bus_dmamap_sync(sc->sc_dmat, data->map, 0, size, BUS_DMASYNC_PREREAD);
    
    /* Update RX descriptor. */
    iwx_update_rx_desc(sc, ring, idx);
    
    return 0;
}

int ItlIwx::
iwx_rxmq_get_signal_strength(struct iwx_softc *sc,
                             struct iwx_rx_mpdu_desc *desc)
{
    int energy_a, energy_b;
    
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210) {
        energy_a = desc->v3.energy_a;
        energy_b = desc->v3.energy_b;
    } else {
        energy_a = desc->v1.energy_a;
        energy_b = desc->v1.energy_b;
    }
    energy_a = energy_a ? -energy_a : -256;
    energy_b = energy_b ? -energy_b : -256;
    return MAX(energy_a, energy_b);
}

void ItlIwx::
iwx_rx_rx_phy_cmd(struct iwx_softc *sc, struct iwx_rx_packet *pkt,
                  struct iwx_rx_data *data)
{
    struct iwx_rx_phy_info *phy_info = (struct iwx_rx_phy_info *)pkt->data;
    
    //    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*pkt),
    //        sizeof(*phy_info), BUS_DMASYNC_POSTREAD);
    
    memcpy(&sc->sc_last_phy_info, phy_info, sizeof(sc->sc_last_phy_info));
}

/*
 * Retrieve the average noise (in dBm) among receivers.
 */
int ItlIwx::
iwx_get_noise(const uint8_t *beacon_silence_rssi)
{
    int i, total, nbant, noise;
    
    total = nbant = noise = 0;
    for (i = 0; i < 3; i++) {
        noise = letoh32(beacon_silence_rssi[i]) & 0xff;
        if (noise) {
            total += noise;
            nbant++;
        }
    }
    
    /* There should be at least one antenna but check anyway. */
    return (nbant == 0) ? -127 : (total / nbant) - 107;
}

int ItlIwx::
iwx_ccmp_decap(struct iwx_softc *sc, mbuf_t m, struct ieee80211_node *ni,
    struct ieee80211_rxinfo *rxi)
{
   struct ieee80211com *ic = &sc->sc_ic;
   struct ieee80211_key *k;
   struct ieee80211_frame *wh;
   uint64_t pn, *prsc;
   uint8_t *ivp;
   uint8_t tid;
   int hdrlen, hasqos;

   wh = mtod(m, struct ieee80211_frame *);
   hdrlen = ieee80211_get_hdrlen(wh);
   ivp = (uint8_t *)wh + hdrlen;
    
   /* find key for decryption */
   k = ieee80211_get_rxkey(ic, m, ni);
   if (k == NULL || k->k_cipher != IEEE80211_CIPHER_CCMP)
       return 1;

   /* Check that ExtIV bit is be set. */
   if (!(ivp[3] & IEEE80211_WEP_EXTIV))
       return 1;

   hasqos = ieee80211_has_qos(wh);
   tid = hasqos ? ieee80211_get_qos(wh) & IEEE80211_QOS_TID : 0;
   prsc = &k->k_rsc[tid];

   /* Extract the 48-bit PN from the CCMP header. */
   pn = (uint64_t)ivp[0]       |
        (uint64_t)ivp[1] <<  8 |
        (uint64_t)ivp[4] << 16 |
        (uint64_t)ivp[5] << 24 |
        (uint64_t)ivp[6] << 32 |
        (uint64_t)ivp[7] << 40;
    if (rxi->rxi_flags & IEEE80211_RXI_HWDEC_SAME_PN) {
        if (pn < *prsc) {
            ic->ic_stats.is_ccmp_replays++;
            return 1;
        }
    } else if (pn <= *prsc) {
       ic->ic_stats.is_ccmp_replays++;
       return 1;
   }
   /* Last seen packet number is updated in ieee80211_inputm(). */

   /*
    * Some firmware versions strip the MIC, and some don't. It is not
    * clear which of the capability flags could tell us what to expect.
    * For now, keep things simple and just leave the MIC in place if
    * it is present.
    *
    * The IV will be stripped by ieee80211_inputm().
    */
   return 0;
}

int ItlIwx::
iwx_rx_hwdecrypt(struct iwx_softc *sc, mbuf_t m, uint32_t rx_pkt_status,
                 struct ieee80211_rxinfo *rxi)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = IC2IFP(ic);
    struct ieee80211_frame *wh;
    struct ieee80211_node *ni;
    int ret = 0;
    uint8_t type, subtype;
    
    wh = mtod(m, struct ieee80211_frame *);
    
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    if (type == IEEE80211_FC0_TYPE_CTL)
        return 0;
    
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    if (ieee80211_has_qos(wh) && (subtype & IEEE80211_FC0_SUBTYPE_NODATA))
        return 0;
    
    ni = ieee80211_find_rxnode(ic, wh);
    /* Handle hardware decryption. */
    if (((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_CTL)
        && (wh->i_fc[1] & IEEE80211_FC1_PROTECTED) &&
        (ni->ni_flags & IEEE80211_NODE_RXPROT) &&
        ((!IEEE80211_IS_MULTICAST(wh->i_addr1) &&
          ni->ni_rsncipher == IEEE80211_CIPHER_CCMP) ||
         (IEEE80211_IS_MULTICAST(wh->i_addr1) &&
          ni->ni_rsngroupcipher == IEEE80211_CIPHER_CCMP))) {
        if ((rx_pkt_status & IWX_RX_MPDU_RES_STATUS_SEC_ENC_MSK) !=
            IWX_RX_MPDU_RES_STATUS_SEC_CCM_ENC) {
            ic->ic_stats.is_ccmp_dec_errs++;
            ret = 1;
            goto out;
        }
        /* Check whether decryption was successful or not. */
        if ((rx_pkt_status &
             (IWX_RX_MPDU_RES_STATUS_DEC_DONE |
              IWX_RX_MPDU_RES_STATUS_MIC_OK)) !=
            (IWX_RX_MPDU_RES_STATUS_DEC_DONE |
             IWX_RX_MPDU_RES_STATUS_MIC_OK)) {
            ic->ic_stats.is_ccmp_dec_errs++;
            ret = 1;
            goto out;
        }
        rxi->rxi_flags |= IEEE80211_RXI_HWDEC;
    }
out:
    if (ret)
        ifp->netStat->inputErrors++;
    ieee80211_release_node(ic, ni);
    return ret;
}

void ItlIwx::
iwx_rx_frame(struct iwx_softc *sc, mbuf_t m, int chanidx,
             uint32_t rx_pkt_status, int is_shortpre, int rate_n_flags,
             uint32_t device_timestamp, struct ieee80211_rxinfo *rxi,
             struct mbuf_list *ml)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_frame *wh;
    struct ieee80211_node *ni;
    struct _ifnet *ifp = IC2IFP(ic);
    
    if (chanidx < 0 || chanidx >= nitems(ic->ic_channels))
        chanidx = ieee80211_chan2ieee(ic, ic->ic_ibss_chan);
    
    wh = mtod(m, struct ieee80211_frame *);
    ni = ieee80211_find_rxnode(ic, wh);
    if ((rxi->rxi_flags & IEEE80211_RXI_HWDEC) &&
        iwx_ccmp_decap(sc, m, ni, rxi) != 0) {
        ifp->netStat->inputErrors++;
        mbuf_freem(m);
        ieee80211_release_node(ic, ni);
        return;
    }
    
#if NBPFILTER > 0
    if (sc->sc_drvbpf != NULL) {
        struct iwx_rx_radiotap_header *tap = &sc->sc_rxtap;
        uint16_t chan_flags;
        
        tap->wr_flags = 0;
        if (is_shortpre)
            tap->wr_flags |= IEEE80211_RADIOTAP_F_SHORTPRE;
        tap->wr_chan_freq =
        htole16(ic->ic_channels[chanidx].ic_freq);
        chan_flags = ic->ic_channels[chanidx].ic_flags;
        if (ic->ic_curmode != IEEE80211_MODE_11N)
            chan_flags &= ~IEEE80211_CHAN_HT;
        tap->wr_chan_flags = htole16(chan_flags);
        tap->wr_dbm_antsignal = (int8_t)rxi->rxi_rssi;
        tap->wr_dbm_antnoise = (int8_t)sc->sc_noise;
        tap->wr_tsft = device_timestamp;
        if (rate_n_flags & IWX_RATE_MCS_HT_MSK) {
            uint8_t mcs = (rate_n_flags &
                           (IWX_RATE_HT_MCS_RATE_CODE_MSK |
                            IWX_RATE_HT_MCS_NSS_MSK));
            tap->wr_rate = (0x80 | mcs);
        } else {
            uint8_t rate = (rate_n_flags &
                            IWX_RATE_LEGACY_RATE_MSK);
            switch (rate) {
                    /* CCK rates. */
                case  10: tap->wr_rate =   2; break;
                case  20: tap->wr_rate =   4; break;
                case  55: tap->wr_rate =  11; break;
                case 110: tap->wr_rate =  22; break;
                    /* OFDM rates. */
                case 0xd: tap->wr_rate =  12; break;
                case 0xf: tap->wr_rate =  18; break;
                case 0x5: tap->wr_rate =  24; break;
                case 0x7: tap->wr_rate =  36; break;
                case 0x9: tap->wr_rate =  48; break;
                case 0xb: tap->wr_rate =  72; break;
                case 0x1: tap->wr_rate =  96; break;
                case 0x3: tap->wr_rate = 108; break;
                    /* Unknown rate: should not happen. */
                default:  tap->wr_rate =   0;
            }
        }
        
        bpf_mtap_hdr(sc->sc_drvbpf, tap, sc->sc_rxtap_len,
                     m, BPF_DIRECTION_IN);
    }
#endif
    ieee80211_inputm(IC2IFP(ic), m, ni, rxi, ml);
    ieee80211_release_node(ic, ni);
}

void ItlIwx::
iwx_flip_address(uint8_t *addr)
{
    int i;
    uint8_t mac_addr[ETHER_ADDR_LEN];

    for (i = 0; i < ETHER_ADDR_LEN; i++)
        mac_addr[i] = addr[ETHER_ADDR_LEN - i - 1];
    IEEE80211_ADDR_COPY(addr, mac_addr);
}

/*
 * Drop duplicate 802.11 retransmissions
 * (IEEE 802.11-2012: 9.3.2.10 "Duplicate detection and recovery")
 * and handle pseudo-duplicate frames which result from deaggregation
 * of A-MSDU frames in hardware.
 */
int ItlIwx::
iwx_detect_duplicate(struct iwx_softc *sc, mbuf_t m,
    struct iwx_rx_mpdu_desc *desc, struct ieee80211_rxinfo *rxi)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_node *in = (struct iwx_node *)ic->ic_bss;
    struct iwx_rxq_dup_data *dup_data = &in->dup_data;
    uint8_t tid = IWX_MAX_TID_COUNT, subframe_idx;
    struct ieee80211_frame *wh = mtod(m, struct ieee80211_frame *);
    uint8_t type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    uint8_t subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    int hasqos = ieee80211_has_qos(wh);
    uint16_t seq;

    if (type == IEEE80211_FC0_TYPE_CTL ||
        (hasqos && (subtype & IEEE80211_FC0_SUBTYPE_NODATA)) ||
        IEEE80211_IS_MULTICAST(wh->i_addr1))
        return 0;

    if (hasqos) {
        tid = (ieee80211_get_qos(wh) & IEEE80211_QOS_TID);
        if (tid > IWX_MAX_TID_COUNT)
            tid = IWX_MAX_TID_COUNT;
    }

    /* If this wasn't a part of an A-MSDU the sub-frame index will be 0 */
    subframe_idx = desc->amsdu_info &
        IWX_RX_MPDU_AMSDU_SUBFRAME_IDX_MASK;

    seq = letoh16(*(u_int16_t *)wh->i_seq) >> IEEE80211_SEQ_SEQ_SHIFT;
    if ((wh->i_fc[1] & IEEE80211_FC1_RETRY) &&
        dup_data->last_seq[tid] == seq &&
        dup_data->last_sub_frame[tid] >= subframe_idx)
        return 1;

    /*
     * Allow the same frame sequence number for all A-MSDU subframes
     * following the first subframe.
     * Otherwise these subframes would be discarded as replays.
     */
    if (dup_data->last_seq[tid] == seq &&
        subframe_idx > dup_data->last_sub_frame[tid] &&
        (desc->mac_flags2 & IWX_RX_MPDU_MFLG2_AMSDU)) {
        rxi->rxi_flags |= IEEE80211_RXI_SAME_SEQ;
    }

    dup_data->last_seq[tid] = seq;
    dup_data->last_sub_frame[tid] = subframe_idx;

    return 0;
}

/*
 * Returns true if sn2 - buffer_size < sn1 < sn2.
 * To be used only in order to compare reorder buffer head with NSSN.
 * We fully trust NSSN unless it is behind us due to reorder timeout.
 * Reorder timeout can only bring us up to buffer_size SNs ahead of NSSN.
 */
int ItlIwx::
iwx_is_sn_less(uint16_t sn1, uint16_t sn2, uint16_t buffer_size)
{
    return SEQ_LT(sn1, sn2) && !SEQ_LT(sn1, sn2 - buffer_size);
}

void ItlIwx::
iwx_release_frames(struct iwx_softc *sc, struct ieee80211_node *ni,
    struct iwx_rxba_data *rxba, struct iwx_reorder_buffer *reorder_buf,
    uint16_t nssn, struct mbuf_list *ml)
{
    struct iwx_reorder_buf_entry *entries = &rxba->entries[0];
    uint16_t ssn = reorder_buf->head_sn;

    /* ignore nssn smaller than head sn - this can happen due to timeout */
    if (iwx_is_sn_less(nssn, ssn, reorder_buf->buf_size))
        goto set_timer;

    while (iwx_is_sn_less(ssn, nssn, reorder_buf->buf_size)) {
        int index = ssn % reorder_buf->buf_size;
        mbuf_t m;
        int chanidx, is_shortpre;
        uint32_t rx_pkt_status, rate_n_flags, device_timestamp;
        struct ieee80211_rxinfo *rxi;

        /* This data is the same for all A-MSDU subframes. */
        chanidx = entries[index].chanidx;
        rx_pkt_status = entries[index].rx_pkt_status;
        is_shortpre = entries[index].is_shortpre;
        rate_n_flags = entries[index].rate_n_flags;
        device_timestamp = entries[index].device_timestamp;
        rxi = &entries[index].rxi;

        /*
         * Empty the list. Will have more than one frame for A-MSDU.
         * Empty list is valid as well since nssn indicates frames were
         * received.
         */
        while ((m = ml_dequeue(&entries[index].frames)) != NULL) {
            iwx_rx_frame(sc, m, chanidx, rx_pkt_status, is_shortpre,
                rate_n_flags, device_timestamp, rxi, ml);
            reorder_buf->num_stored--;

            /*
             * Allow the same frame sequence number and CCMP PN for
             * all A-MSDU subframes following the first subframe.
             * Otherwise they would be discarded as replays.
             */
            rxi->rxi_flags |= IEEE80211_RXI_SAME_SEQ;
            rxi->rxi_flags |= IEEE80211_RXI_HWDEC_SAME_PN;
        }

        ssn = (ssn + 1) & 0xfff;
    }
    reorder_buf->head_sn = nssn;

set_timer:
    if (reorder_buf->num_stored && !reorder_buf->removed) {
        timeout_add_usec(&reorder_buf->reorder_timer,
            RX_REORDER_BUF_TIMEOUT_MQ_USEC);
    } else
        timeout_del(&reorder_buf->reorder_timer);
}

int ItlIwx::
iwx_oldsn_workaround(struct iwx_softc *sc, struct ieee80211_node *ni, int tid,
    struct iwx_reorder_buffer *buffer, uint32_t reorder_data, uint32_t gp2)
{
    struct ieee80211com *ic = &sc->sc_ic;

    if (gp2 != buffer->consec_oldsn_ampdu_gp2) {
        /* we have a new (A-)MPDU ... */

        /*
         * reset counter to 0 if we didn't have any oldsn in
         * the last A-MPDU (as detected by GP2 being identical)
         */
        if (!buffer->consec_oldsn_prev_drop)
            buffer->consec_oldsn_drops = 0;

        /* either way, update our tracking state */
        buffer->consec_oldsn_ampdu_gp2 = gp2;
    } else if (buffer->consec_oldsn_prev_drop) {
        /*
         * tracking state didn't change, and we had an old SN
         * indication before - do nothing in this case, we
         * already noted this one down and are waiting for the
         * next A-MPDU (by GP2)
         */
        return 0;
    }

    /* return unless this MPDU has old SN */
    if (!(reorder_data & IWX_RX_MPDU_REORDER_BA_OLD_SN))
        return 0;

    /* update state */
    buffer->consec_oldsn_prev_drop = 1;
    buffer->consec_oldsn_drops++;

    /* if limit is reached, send del BA and reset state */
    if (buffer->consec_oldsn_drops == IWX_AMPDU_CONSEC_DROPS_DELBA) {
        XYLog("reached %d old SN frames, stopping BA session on TID %d\n",
              IWX_AMPDU_CONSEC_DROPS_DELBA, tid);
        ieee80211_delba_request(ic, ni, IEEE80211_REASON_UNSPECIFIED,
            0, tid);
        buffer->consec_oldsn_prev_drop = 0;
        buffer->consec_oldsn_drops = 0;
        return 1;
    }

    return 0;
}

/*
 * Handle re-ordering of frames which were de-aggregated in hardware.
 * Returns 1 if the MPDU was consumed (buffered or dropped).
 * Returns 0 if the MPDU should be passed to upper layer.
 */
int ItlIwx::
iwx_rx_reorder(struct iwx_softc *sc, mbuf_t m, int chanidx,
    struct iwx_rx_mpdu_desc *desc, int is_shortpre, int rate_n_flags,
    uint32_t device_timestamp, struct ieee80211_rxinfo *rxi,
    struct mbuf_list *ml)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_frame *wh;
    struct ieee80211_node *ni;
    struct iwx_rxba_data *rxba;
    struct iwx_reorder_buffer *buffer;
    uint32_t reorder_data = le32toh(desc->reorder_data);
    int is_amsdu = (desc->mac_flags2 & IWX_RX_MPDU_MFLG2_AMSDU);
    int last_subframe =
        (desc->amsdu_info & IWX_RX_MPDU_AMSDU_LAST_SUBFRAME);
    uint8_t tid;
    uint8_t subframe_idx = (desc->amsdu_info &
        IWX_RX_MPDU_AMSDU_SUBFRAME_IDX_MASK);
    struct iwx_reorder_buf_entry *entries;
    int index;
    uint16_t nssn, sn;
    uint8_t baid, type, subtype;
    int hasqos;

    wh = mtod(m, struct ieee80211_frame *);
    hasqos = ieee80211_has_qos(wh);
    tid = hasqos ? ieee80211_get_qos(wh) & IEEE80211_QOS_TID : 0;

    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;

    /*
     * We are only interested in Block Ack requests and unicast QoS data.
     */
    if (IEEE80211_IS_MULTICAST(wh->i_addr1))
        return 0;
    if (hasqos) {
        if (subtype & IEEE80211_FC0_SUBTYPE_NODATA)
            return 0;
    } else {
        if (type != IEEE80211_FC0_TYPE_CTL ||
            subtype != IEEE80211_FC0_SUBTYPE_BAR)
            return 0;
    }

    baid = (reorder_data & IWX_RX_MPDU_REORDER_BAID_MASK) >>
    IWX_RX_MPDU_REORDER_BAID_SHIFT;
    if (baid == IWX_RX_REORDER_DATA_INVALID_BAID ||
        baid >= nitems(sc->sc_rxba_data))
        return 0;

    rxba = &sc->sc_rxba_data[baid];
    if (rxba->reorder_buf.buf_size == 0 || tid != rxba->tid || rxba->sta_id != IWX_STATION_ID)
        return 0;
    
    if (rxba->timeout != 0)
        getmicrouptime(&rxba->last_rx);

    /* Bypass A-MPDU re-ordering in net80211. */
    rxi->rxi_flags |= IEEE80211_RXI_AMPDU_DONE;

    nssn = reorder_data & IWX_RX_MPDU_REORDER_NSSN_MASK;
    sn = (reorder_data & IWX_RX_MPDU_REORDER_SN_MASK) >>
        IWX_RX_MPDU_REORDER_SN_SHIFT;

    buffer = &rxba->reorder_buf;
    entries = &rxba->entries[0];

    if (!buffer->valid) {
        if (reorder_data & IWX_RX_MPDU_REORDER_BA_OLD_SN)
            return 0;
        buffer->valid = 1;
    }

    ni = ieee80211_find_rxnode(ic, wh);
    if (type == IEEE80211_FC0_TYPE_CTL &&
        subtype == IEEE80211_FC0_SUBTYPE_BAR) {
        iwx_release_frames(sc, ni, rxba, buffer, nssn, ml);
        goto drop;
    }

    /*
     * If there was a significant jump in the nssn - adjust.
     * If the SN is smaller than the NSSN it might need to first go into
     * the reorder buffer, in which case we just release up to it and the
     * rest of the function will take care of storing it and releasing up to
     * the nssn.
     */
    if (!iwx_is_sn_less(nssn, buffer->head_sn + buffer->buf_size,
        buffer->buf_size) ||
        !SEQ_LT(sn, buffer->head_sn + buffer->buf_size)) {
        uint16_t min_sn = SEQ_LT(sn, nssn) ? sn : nssn;
        ic->ic_stats.is_ht_rx_frame_above_ba_winend++;
        iwx_release_frames(sc, ni, rxba, buffer, min_sn, ml);
    }

    if (iwx_oldsn_workaround(sc, ni, tid, buffer, reorder_data,
        device_timestamp)) {
         /* BA session will be torn down. */
        ic->ic_stats.is_ht_rx_ba_window_jump++;
        goto drop;

    }

    /* drop any outdated packets */
    if (SEQ_LT(sn, buffer->head_sn)) {
        ic->ic_stats.is_ht_rx_frame_below_ba_winstart++;
        goto drop;
    }

    /* release immediately if allowed by nssn and no stored frames */
    if (!buffer->num_stored && SEQ_LT(sn, nssn)) {
        if (iwx_is_sn_less(buffer->head_sn, nssn, buffer->buf_size) &&
           (!is_amsdu || last_subframe))
            buffer->head_sn = nssn;
        ieee80211_release_node(ic, ni);
        return 0;
    }

    /*
     * release immediately if there are no stored frames, and the sn is
     * equal to the head.
     * This can happen due to reorder timer, where NSSN is behind head_sn.
     * When we released everything, and we got the next frame in the
     * sequence, according to the NSSN we can't release immediately,
     * while technically there is no hole and we can move forward.
     */
    if (!buffer->num_stored && sn == buffer->head_sn) {
        if (!is_amsdu || last_subframe)
            buffer->head_sn = (buffer->head_sn + 1) & 0xfff;
        ieee80211_release_node(ic, ni);
        return 0;
    }

    index = sn % buffer->buf_size;

    /*
     * Check if we already stored this frame
     * As AMSDU is either received or not as whole, logic is simple:
     * If we have frames in that position in the buffer and the last frame
     * originated from AMSDU had a different SN then it is a retransmission.
     * If it is the same SN then if the subframe index is incrementing it
     * is the same AMSDU - otherwise it is a retransmission.
     */
    if (!ml_empty(&entries[index].frames)) {
        if (!is_amsdu) {
            ic->ic_stats.is_ht_rx_ba_no_buf++;
            goto drop;
        } else if (sn != buffer->last_amsdu ||
            buffer->last_sub_index >= subframe_idx) {
            ic->ic_stats.is_ht_rx_ba_no_buf++;
            goto drop;
        }
    } else {
        /* This data is the same for all A-MSDU subframes. */
        entries[index].chanidx = chanidx;
        entries[index].is_shortpre = is_shortpre;
        entries[index].rate_n_flags = rate_n_flags;
        entries[index].device_timestamp = device_timestamp;
        memcpy(&entries[index].rxi, rxi, sizeof(entries[index].rxi));
    }

    /* put in reorder buffer */
    ml_enqueue(&entries[index].frames, m);
    buffer->num_stored++;
    getmicrouptime(&entries[index].reorder_time);

    if (is_amsdu) {
        buffer->last_amsdu = sn;
        buffer->last_sub_index = subframe_idx;
    }

    /*
     * We cannot trust NSSN for AMSDU sub-frames that are not the last.
     * The reason is that NSSN advances on the first sub-frame, and may
     * cause the reorder buffer to advance before all the sub-frames arrive.
     * Example: reorder buffer contains SN 0 & 2, and we receive AMSDU with
     * SN 1. NSSN for first sub frame will be 3 with the result of driver
     * releasing SN 0,1, 2. When sub-frame 1 arrives - reorder buffer is
     * already ahead and it will be dropped.
     * If the last sub-frame is not on this queue - we will get frame
     * release notification with up to date NSSN.
     */
    if (!is_amsdu || last_subframe)
        iwx_release_frames(sc, ni, rxba, buffer, nssn, ml);

    ieee80211_release_node(ic, ni);
    return 1;

drop:
    mbuf_freem(m);
    ieee80211_release_node(ic, ni);
    return 1;
}

void ItlIwx::
iwx_rx_mpdu_mq(struct iwx_softc *sc, mbuf_t m, void *pktdata,
               size_t maxlen, struct mbuf_list *ml)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_rxinfo rxi;
    struct iwx_rx_mpdu_desc *desc;
    uint32_t len, hdrlen, rate_n_flags, device_timestamp;
    int rssi;
    uint8_t chanidx;
    uint16_t phy_info;
    size_t desc_size;
    
    desc = (struct iwx_rx_mpdu_desc *)pktdata;
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
        desc_size = sizeof(struct iwx_rx_mpdu_desc);
    else
        desc_size = IWX_RX_DESC_SIZE_V1;
    
    if (!(desc->status & htole16(IWX_RX_MPDU_RES_STATUS_CRC_OK)) ||
        !(desc->status & htole16(IWX_RX_MPDU_RES_STATUS_OVERRUN_OK))) {
        mbuf_freem(m);
        return; /* drop */
    }
    
    len = le16toh(desc->mpdu_len);
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        /* Allow control frames in monitor mode. */
        if (len < sizeof(struct ieee80211_frame_cts)) {
            ic->ic_stats.is_rx_tooshort++;
            IC2IFP(ic)->netStat->inputErrors++;
            mbuf_freem(m);
            return;
        }
    } else if (len < sizeof(struct ieee80211_frame)) {
        ic->ic_stats.is_rx_tooshort++;
        IC2IFP(ic)->netStat->inputErrors++;
        mbuf_freem(m);
        return;
    }
    if (len > maxlen - desc_size) {
        IC2IFP(ic)->netStat->inputErrors++;
        mbuf_freem(m);
        return;
    }
    
    //    m->m_data = pktdata + sizeof(*desc);
    //    m->m_pkthdr.len = m->m_len = len;
    mbuf_setdata(m, (uint8_t*)pktdata + desc_size, len);
    mbuf_pkthdr_setlen(m, len);
    mbuf_setlen(m, len);
    
    /* Account for padding following the frame header. */
    if (desc->mac_flags2 & IWX_RX_MPDU_MFLG2_PAD) {
        struct ieee80211_frame *wh = mtod(m, struct ieee80211_frame *);
        int type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
        if (type == IEEE80211_FC0_TYPE_CTL) {
            switch (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) {
                case IEEE80211_FC0_SUBTYPE_CTS:
                    hdrlen = sizeof(struct ieee80211_frame_cts);
                    break;
                case IEEE80211_FC0_SUBTYPE_ACK:
                    hdrlen = sizeof(struct ieee80211_frame_ack);
                    break;
                default:
                    hdrlen = sizeof(struct ieee80211_frame_min);
                    break;
            }
        } else
            hdrlen = ieee80211_get_hdrlen(wh);
        
        if ((le16toh(desc->status) &
             IWX_RX_MPDU_RES_STATUS_SEC_ENC_MSK) ==
            IWX_RX_MPDU_RES_STATUS_SEC_CCM_ENC) {
            /* Padding is inserted after the IV. */
            hdrlen += IEEE80211_CCMP_HDRLEN;
        }
        
        //        memmove(m->m_data + 2, m->m_data, hdrlen);
        memmove((uint8_t*)mbuf_data(m) + 2, mbuf_data(m), hdrlen);
        mbuf_adj(m, 2);
    }
    
    memset(&rxi, 0, sizeof(rxi));
    
    /*
     * Hardware de-aggregates A-MSDUs and copies the same MAC header
     * in place for each subframe. But it leaves the 'A-MSDU present'
     * bit set in the frame header. We need to clear this bit ourselves.
     * (XXX This workaround is not required on AX200/AX201 devices that
     * have been tested by me, but it's unclear when this problem was
     * fixed in the hardware. It definitely affects the 9k generation.
     * Leaving this in place for now since some 9k/AX200 hybrids seem
     * to exist that we may eventually add support for.)
     *
     * And we must allow the same CCMP PN for subframes following the
     * first subframe. Otherwise they would be discarded as replays.
     */
    if (desc->mac_flags2 & IWX_RX_MPDU_MFLG2_AMSDU) {
        struct ieee80211_frame *wh = mtod(m, struct ieee80211_frame *);
        uint8_t subframe_idx = (desc->amsdu_info &
                                IWX_RX_MPDU_AMSDU_SUBFRAME_IDX_MASK);
        if (subframe_idx > 0)
            rxi.rxi_flags |= IEEE80211_RXI_HWDEC_SAME_PN;
        if (ieee80211_has_qos(wh) && ieee80211_has_addr4(wh) &&
            mbuf_len(m) >= sizeof(struct ieee80211_qosframe_addr4)) {
            struct ieee80211_qosframe_addr4 *qwh4 = mtod(m,
                                                         struct ieee80211_qosframe_addr4 *);
            qwh4->i_qos[0] &= htole16(~IEEE80211_QOS_AMSDU);
        } else if (ieee80211_has_qos(wh) &&
                   mbuf_len(m) >= sizeof(struct ieee80211_qosframe)) {
            struct ieee80211_qosframe *qwh = mtod(m,
                                                  struct ieee80211_qosframe *);
            qwh->i_qos[0] &= htole16(~IEEE80211_QOS_AMSDU);
        }    
    }
    
    /*
     * Verify decryption before duplicate detection. The latter uses
     * the TID supplied in QoS frame headers and this TID is implicitly
     * verified as part of the CCMP nonce.
     */
    if (iwx_rx_hwdecrypt(sc, m, le16toh(desc->status), &rxi)) {
        mbuf_freem(m);
        return;
    }
    
    if (iwx_detect_duplicate(sc, m, desc, &rxi)) {
        mbuf_freem(m);
        return;
    }
    
    rssi = iwx_rxmq_get_signal_strength(sc, desc);
    rssi = (0 - IWX_MIN_DBM) + rssi;    /* normalize */
    rssi = MIN(rssi, ic->ic_max_rssi);    /* clip to max. 100% */
    
    rxi.rxi_rssi = rssi;
    
    phy_info = le16toh(desc->phy_info);
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210) {
        rate_n_flags = le32toh(desc->v3.rate_n_flags);
        chanidx = desc->v3.channel;
        device_timestamp = desc->v3.gp2_on_air_rise;
        rxi.rxi_tstamp = (uint32_t)le64toh(desc->v3.tsf_on_air_rise);
    } else {
        rate_n_flags = le32toh(desc->v1.rate_n_flags);
        chanidx = desc->v1.channel;
        device_timestamp = desc->v1.gp2_on_air_rise;
        rxi.rxi_tstamp = (uint32_t)le64toh(desc->v1.tsf_on_air_rise);
    }
    rxi.rxi_chan = chanidx;
    
    if (iwx_rx_reorder(sc, m, chanidx, desc,
                       (phy_info & IWX_RX_MPDU_PHY_SHORT_PREAMBLE),
                       rate_n_flags, device_timestamp, &rxi, ml))
        return;
    
    iwx_rx_frame(sc, m, chanidx, le16toh(desc->status),
                 (phy_info & IWX_RX_MPDU_PHY_SHORT_PREAMBLE),
                 rate_n_flags, device_timestamp, &rxi, ml);
}

void ItlIwx::
iwx_rx_tx_cmd_single(struct iwx_softc *sc, struct iwx_rx_packet *pkt,
                     struct iwx_tx_data *txd)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = IC2IFP(ic);
    struct iwx_tx_resp *tx_resp = (struct iwx_tx_resp *)pkt->data;
    int status = le16toh(tx_resp->status.status) & IWX_TX_STATUS_MSK;
    int txfail;
    
    KASSERT(tx_resp->frame_count == 1, "tx_resp->frame_count == 1");
    
    txfail = (status != IWX_TX_STATUS_SUCCESS);
    
    if (txfail) {
        XYLog("%s %d OUTPUT_ERROR type=%d status=%d\n", __FUNCTION__, __LINE__, txd->type, status);
        ifp->netStat->outputErrors++;
        if (txd->type == IEEE80211_FC0_TYPE_MGT)
            iwx_toggle_tx_ant(sc, &sc->sc_mgmt_last_antenna_idx);
    }
}

void
iwx_clear_tx_desc(struct iwx_softc *sc, struct iwx_tx_ring *ring, int idx)
{
    struct iwx_tfh_tfd *desc = &ring->desc[idx];
    uint8_t num_tbs = le16toh(desc->num_tbs) & 0x1f;
    int i;
    
    /* First TB is never cleared - it is bidirectional DMA data. */
    for (i = 1; i < num_tbs; i++) {
        struct iwx_tfh_tb *tb = &desc->tbs[i];
        memset(tb, 0, sizeof(*tb));
    }
    desc->num_tbs = 0;
    
//    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map,
//                    (char *)(void *)desc - (char *)(void *)ring->desc_dma.vaddr,
//                    sizeof(*desc), BUS_DMASYNC_PREWRITE);
}

void ItlIwx::
iwx_txd_done(struct iwx_softc *sc, struct iwx_tx_data *txd)
{
    struct ieee80211com *ic = &sc->sc_ic;
    
    //    bus_dmamap_sync(sc->sc_dmat, txd->map, 0, txd->map->dm_mapsize,
    //        BUS_DMASYNC_POSTWRITE);
    //    bus_dmamap_unload(sc->sc_dmat, txd->map);
    mbuf_freem(txd->m);
    txd->m = NULL;
    
    KASSERT(txd->in, "txd->in");
    ieee80211_release_node(ic, &txd->in->in_ni);
    txd->in = NULL;
}

void ItlIwx::
iwx_clear_oactive(struct iwx_softc *sc, struct iwx_tx_ring *ring)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = &ic->ic_if;

    if (ring->queued < ring->low_mark) {
        sc->qfullmsk &= ~(1 << ring->qid);
        if (sc->qfullmsk == 0 && ifq_is_oactive(&ifp->if_snd)) {
            ifq_clr_oactive(&ifp->if_snd);
            (*ifp->if_start)(ifp);
        }
#ifdef __PRIVATE_SPI__
        ifp->iface->signalOutputThread();
#endif
    }
}

void ItlIwx::
iwx_rx_tx_ba_notif(struct iwx_softc *sc, struct iwx_rx_packet *pkt, struct iwx_rx_data *data)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_compressed_ba_notif *ba_res = (struct iwx_compressed_ba_notif *)pkt->data;
    uint8_t tid;
    uint8_t qid;
    int i;
    struct iwx_tx_ring *ring;

    sc->sc_tx_timer = 0;

    if (le32toh(ba_res->flags) != IWX_BA_RESP_TX_BAR && le32toh(ba_res->flags) != IWX_BA_RESP_TX_AGG){
        DPRINTFN(3, ("BA_NOTIFICATION flags %x, sent:%d, acked:%d, tfd_cnt:%d, query_frame_cnt:%d, retry_cnt:%d\n",
              le32toh(ba_res->flags),
              le16toh(ba_res->txed),
              le16toh(ba_res->done),
                     le16toh(ba_res->tfd_cnt),
              ba_res->query_frame_cnt,
              ba_res->retry_cnt));
    }

    if (ic->ic_state != IEEE80211_S_RUN)
        return;

    if (!le16toh(ba_res->tfd_cnt))
        return;

    /* Free per TID */
    for (i = 0; i < le16toh(ba_res->tfd_cnt); i++) {
        struct iwx_compressed_ba_tfd *ba_tfd = &ba_res->tfd[i];

        tid = ba_tfd->tid;

        qid = le16toh(ba_tfd->q_num);
        ring = &sc->txq[qid];

        sc->sc_tx_timer = 0;

        iwx_ampdu_txq_advance(sc, ring, IWX_AGG_SSN_TO_TXQ_IDX(le16toh(ba_tfd->tfd_index), ring->ring_count));
        iwx_clear_oactive(sc, ring);
    }
}

void ItlIwx::
iwx_ampdu_txq_advance(struct iwx_softc *sc, struct iwx_tx_ring *ring, int idx)
{
    struct iwx_tx_data *txd;

    while (ring->tail != idx) {
        txd = &ring->data[ring->tail];
        if (txd->m != NULL) {
            iwx_txd_done(sc, txd);
            iwx_clear_tx_desc(sc, ring, ring->tail);
            ring->queued--;
        }
        ring->tail = (ring->tail + 1) % ring->ring_count;
    }
}

#define IWX_AGG_TX_STATE_(x) case IWX_AGG_TX_STATE_ ## x: return #x
static const char *iwx_get_agg_tx_status(uint16_t status)
{
    switch (status & IWX_AGG_TX_STATE_STATUS_MSK) {
            IWX_AGG_TX_STATE_(TRANSMITTED);
            IWX_AGG_TX_STATE_(UNDERRUN);
            IWX_AGG_TX_STATE_(BT_PRIO);
            IWX_AGG_TX_STATE_(FEW_BYTES);
            IWX_AGG_TX_STATE_(ABORT);
            IWX_AGG_TX_STATE_(TX_ON_AIR_DROP);
            IWX_AGG_TX_STATE_(LAST_SENT_TRY_CNT);
            IWX_AGG_TX_STATE_(LAST_SENT_BT_KILL);
            IWX_AGG_TX_STATE_(SCD_QUERY);
            IWX_AGG_TX_STATE_(TEST_BAD_CRC32);
            IWX_AGG_TX_STATE_(RESPONSE);
            IWX_AGG_TX_STATE_(DUMP_TX);
            IWX_AGG_TX_STATE_(DELAY_TX);
    }

    return "UNKNOWN";
}

void ItlIwx::
iwx_rx_tx_cmd(struct iwx_softc *sc, struct iwx_rx_packet *pkt,
              struct iwx_rx_data *data)
{
    uint32_t ssn;
    int idx;
    int tid;
    struct iwx_tx_resp *tx_resp = (struct iwx_tx_resp *)pkt->data;
    int qid = tx_resp->tx_queue;
    struct iwx_tx_ring *ring = &sc->txq[qid];
    struct iwx_tx_data *txd;

    bus_dmamap_sync(sc->sc_dmat, data->map, 0, IWX_RBUF_SIZE,
                    BUS_DMASYNC_POSTREAD);
    
    sc->sc_tx_timer = 0;

    if (tx_resp->frame_count > 1) {
        for (int i = 0; i < tx_resp->frame_count; i++) {
            uint16_t fstatus = le16_to_cpu((&tx_resp->status)[i].status);

            XYLog("status %s (0x%04x), try-count (%d) qid (%d) seq (0x%x)\n",
                         iwx_get_agg_tx_status(fstatus),
                         fstatus & IWX_AGG_TX_STATE_STATUS_MSK,
                         (fstatus & IWX_AGG_TX_STATE_TRY_CNT_MSK) >>
                         IWX_AGG_TX_STATE_TRY_CNT_POS,
                         qid,
                         le16_to_cpu((&tx_resp->status)[i].sequence));
        }
    } else {
        tid = tx_resp->ra_tid & 0x0f;
        memcpy(&ssn, &tx_resp->status + tx_resp->frame_count, sizeof(ssn));
        ssn = le32toh(ssn) & 0xfff;
        idx = IWX_AGG_SSN_TO_TXQ_IDX(ssn, ring->ring_count);
        txd = &ring->data[idx];
        iwx_rx_tx_cmd_single(sc, pkt, txd);
        DPRINTFN(3, ("%s tid=%d ssn=%d idx=%d\n", __FUNCTION__, tid, ssn, idx));
        iwx_ampdu_txq_advance(sc, ring, idx);
        iwx_clear_oactive(sc, ring);
    }
}

void ItlIwx::
iwx_rx_bmiss(struct iwx_softc *sc, struct iwx_rx_packet *pkt,
             struct iwx_rx_data *data)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_missed_beacons_notif *mbn = (struct iwx_missed_beacons_notif *)pkt->data;
    uint32_t missed;
    
    if ((ic->ic_opmode != IEEE80211_M_STA) ||
        (ic->ic_state != IEEE80211_S_RUN))
        return;
    
    //    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*pkt),
    //        sizeof(*mbn), BUS_DMASYNC_POSTREAD);
    
    missed = le32toh(mbn->consec_missed_beacons_since_last_rx);
    if (missed > ic->ic_bmissthres && ic->ic_mgt_timer == 0) {
        if (ic->ic_if.if_flags & IFF_DEBUG) {
            XYLog("%s: receiving no beacons from %s; checking if "
                  "this AP is still responding to probe requests\n",
                  DEVNAME(sc), ether_sprintf(ic->ic_bss->ni_macaddr));
            /* Dump driver status (TX and RX rings) while we're here. */
            XYLog("%s driver queue status:\n", __FUNCTION__);
            for (int i = 0; i < IWX_MAX_QUEUES; i++) {
                struct iwx_tx_ring *ring = &sc->txq[i];
                XYLog("  tx ring %2d: qid=%-2d cur=%-3d "
                      "queued=%-3d\n",
                      i, ring->qid, ring->cur, ring->queued);
            }
            XYLog("  rx ring: cur=%d\n", sc->rxq.cur);
            XYLog("  802.11 state %s\n",
                  ieee80211_state_name[sc->sc_ic.ic_state]);
        }
        /*
         * Rather than go directly to scan state, try to send a
         * directed probe request first. If that fails then the
         * state machine will drop us into scanning after timing
         * out waiting for a probe response.
         */
        IEEE80211_SEND_MGMT(ic, ic->ic_bss,
                            IEEE80211_FC0_SUBTYPE_PROBE_REQ, 0);
    }
    
}

int ItlIwx::
iwx_binding_cmd(struct iwx_softc *sc, struct iwx_node *in, uint32_t action)
{
    struct iwx_binding_cmd cmd;
    struct iwx_phy_ctxt *phyctxt = in->in_phyctxt;
    uint32_t mac_id = IWX_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color);
    int i, err, active = (sc->sc_flags & IWX_FLAG_BINDING_ACTIVE);
    uint32_t status;
    
    if (action == IWX_FW_CTXT_ACTION_ADD && active) {
        XYLog("binding already added\n");
        return 0;
    }
    if (action == IWX_FW_CTXT_ACTION_REMOVE && !active) {
        XYLog("binding already removed\n");
        return 0;
    }
    
    if (phyctxt == NULL) /* XXX race with iwx_stop() */
        return EINVAL;
    
    memset(&cmd, 0, sizeof(cmd));
    
    cmd.id_and_color
    = htole32(IWX_FW_CMD_ID_AND_COLOR(phyctxt->id, phyctxt->color));
    cmd.action = htole32(action);
    cmd.phy = htole32(IWX_FW_CMD_ID_AND_COLOR(phyctxt->id, phyctxt->color));
    
    cmd.macs[0] = htole32(mac_id);
    for (i = 1; i < IWX_MAX_MACS_IN_BINDING; i++)
        cmd.macs[i] = htole32(IWX_FW_CTXT_INVALID);
    
    if (IEEE80211_IS_CHAN_2GHZ(phyctxt->channel) ||
        !isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_CDB_SUPPORT))
        cmd.lmac_id = htole32(IWX_LMAC_24G_INDEX);
    else
        cmd.lmac_id = htole32(IWX_LMAC_5G_INDEX);
    
    status = 0;
    err = iwx_send_cmd_pdu_status(sc, IWX_BINDING_CONTEXT_CMD, sizeof(cmd),
                                  &cmd, &status);
    if (err == 0 && status != 0)
        err = EIO;
    
    return err;
}

static uint8_t
iwx_get_channel_width(struct ieee80211com *ic, struct ieee80211_channel *c)
{
    uint8_t ret = IWX_PHY_VHT_CHANNEL_MODE20;
    if (ic->ic_bss == NULL || ic->ic_state < IEEE80211_S_ASSOC) {
        return ret;
    }
    switch (ic->ic_bss->ni_chw) {
        case IEEE80211_CHAN_WIDTH_20_NOHT:
        case IEEE80211_CHAN_WIDTH_20:
            return IWX_PHY_VHT_CHANNEL_MODE20;
        case IEEE80211_CHAN_WIDTH_40:
            return IWX_PHY_VHT_CHANNEL_MODE40;
        case IEEE80211_CHAN_WIDTH_80:
            return IWX_PHY_VHT_CHANNEL_MODE80;
        case IEEE80211_CHAN_WIDTH_160:
            return IWX_PHY_VHT_CHANNEL_MODE160;
        default:
            XYLog("Invalid channel width=%u\n", ic->ic_bss->ni_chw);
            return ret;
    }
}

static uint8_t
iwx_get_ctrl_pos(struct ieee80211com *ic, struct ieee80211_channel *c)
{
    if (ic->ic_bss == NULL || ic->ic_state < IEEE80211_S_ASSOC || iwx_get_channel_width(ic, c) == IWX_PHY_VHT_CHANNEL_MODE20)
        return IWX_PHY_VHT_CTRL_POS_1_BELOW;

    signed int offset = ic->ic_bss->ni_chan->ic_freq - ic->ic_bss->ni_chan->ic_center_freq1;
    switch (offset) {
        case -70:
            return IWX_PHY_VHT_CTRL_POS_4_BELOW;
        case -50:
            return IWX_PHY_VHT_CTRL_POS_3_BELOW;
        case -30:
            return IWX_PHY_VHT_CTRL_POS_2_BELOW;
        case -10:
            return IWX_PHY_VHT_CTRL_POS_1_BELOW;
        case  10:
            return IWX_PHY_VHT_CTRL_POS_1_ABOVE;
        case  30:
            return IWX_PHY_VHT_CTRL_POS_2_ABOVE;
        case  50:
            return IWX_PHY_VHT_CTRL_POS_3_ABOVE;
        case  70:
            return IWX_PHY_VHT_CTRL_POS_4_ABOVE;
        default:
            XYLog("Invalid channel definition freq=%d %d\n", ic->ic_bss->ni_chan->ic_freq, offset);
            /* fall through */
        case 0:
            /*
             * The FW is expected to check the control channel position only
             * when in HT/VHT and the channel width is not 20MHz. Return
             * this value as the default one.
             */
            return IWX_PHY_VHT_CTRL_POS_1_BELOW;
    }
}

int ItlIwx::
iwx_phy_ctxt_cmd_v3(struct iwx_softc *sc, struct iwx_phy_ctxt *ctxt,
    uint8_t chains_static, uint8_t chains_dynamic, uint32_t action,
    uint32_t apply_time)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_phy_context_cmd cmd;
    uint8_t active_cnt, idle_cnt;
    struct ieee80211_channel *chan = ctxt->channel;
    memset(&cmd, 0, sizeof(cmd));
    cmd.id_and_color = htole32(IWX_FW_CMD_ID_AND_COLOR(ctxt->id,
                                                       ctxt->color));
    cmd.action = htole32(action);
    cmd.lmac_id = htole32(iwx_lmac_id(sc, chan));
    
    cmd.ci.band = IEEE80211_IS_CHAN_2GHZ(chan) ?
    IWX_PHY_BAND_24 : IWX_PHY_BAND_5;
    cmd.ci.channel = htole32(ieee80211_chan2ieee(ic, chan));
    cmd.ci.width = iwx_get_channel_width(ic, chan);
    cmd.ci.ctrl_pos = iwx_get_ctrl_pos(ic, chan);

    XYLog("%s: 2ghz=%d, channel=%d, channel_width=%d pos=%d chains static=0x%x, dynamic=0x%x, "
          "rx_ant=0x%x, tx_ant=0x%x\n",
          __FUNCTION__,
          cmd.ci.band,
          cmd.ci.channel,
          cmd.ci.width,
          cmd.ci.ctrl_pos,
          chains_static,
          chains_dynamic,
          iwx_fw_valid_rx_ant(sc),
          iwx_fw_valid_tx_ant(sc));
    
    idle_cnt = chains_static;
    active_cnt = chains_dynamic;
    
    /* In scenarios where we only ever use a single-stream rates,
     * i.e. legacy 11b/g/a associations, single-stream APs or even
     * static SMPS, enable both chains to get diversity, improving
     * the case where we're far enough from the AP that attenuation
     * between the two antennas is sufficiently different to impact
     * performance.
     */
    if (active_cnt == 1 && iwx_num_of_ant(iwx_fw_valid_rx_ant(sc)) != 1) {
        idle_cnt = 2;
        active_cnt = 2;
    }
    
    cmd.rxchain_info = htole32(iwx_fw_valid_rx_ant(sc) <<
                               IWX_PHY_RX_CHAIN_VALID_POS);
    cmd.rxchain_info |= htole32(idle_cnt << IWX_PHY_RX_CHAIN_CNT_POS);
    cmd.rxchain_info |= htole32(active_cnt <<
                                IWX_PHY_RX_CHAIN_MIMO_CNT_POS);
    return iwx_send_cmd_pdu(sc, IWX_PHY_CONTEXT_CMD, 0, sizeof(cmd), &cmd);
}

int ItlIwx::
iwx_phy_ctxt_cmd_uhb(struct iwx_softc *sc, struct iwx_phy_ctxt *ctxt,
    uint8_t chains_static, uint8_t chains_dynamic, uint32_t action,
    uint32_t apply_time)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_phy_context_cmd_uhb cmd;
    uint8_t active_cnt, idle_cnt;
    struct ieee80211_channel *chan = ctxt->channel;
    memset(&cmd, 0, sizeof(cmd));
    cmd.id_and_color = htole32(IWX_FW_CMD_ID_AND_COLOR(ctxt->id,
                                                       ctxt->color));
    cmd.action = htole32(action);
    cmd.apply_time = htole32(apply_time);
    
    cmd.ci.band = IEEE80211_IS_CHAN_2GHZ(chan) ?
    IWX_PHY_BAND_24 : IWX_PHY_BAND_5;
    cmd.ci.channel = htole32(ieee80211_chan2ieee(ic, chan));
    cmd.ci.width = iwx_get_channel_width(ic, chan);
    cmd.ci.ctrl_pos = iwx_get_ctrl_pos(ic, chan);

    XYLog("%s: [%s:%s] 2ghz=%d, channel=%d, channel_width=%d pos=%d chains static=0x%x, dynamic=0x%x, "
          "rx_ant=0x%x, tx_ant=0x%x\n",
          __FUNCTION__,
          ic->ic_bss == NULL ? "" : (const char *)ic->ic_bss->ni_essid,
          ic->ic_bss == NULL ? "" : ether_sprintf(ic->ic_bss->ni_bssid),
          cmd.ci.band,
          cmd.ci.channel,
          cmd.ci.width,
          cmd.ci.ctrl_pos,
          chains_static,
          chains_dynamic,
          iwx_fw_valid_rx_ant(sc),
          iwx_fw_valid_tx_ant(sc));
    
    idle_cnt = chains_static;
    active_cnt = chains_dynamic;
    
    cmd.rxchain_info = htole32(iwx_fw_valid_rx_ant(sc) <<
                               IWX_PHY_RX_CHAIN_VALID_POS);
    cmd.rxchain_info |= htole32(idle_cnt << IWX_PHY_RX_CHAIN_CNT_POS);
    cmd.rxchain_info |= htole32(active_cnt <<
                                IWX_PHY_RX_CHAIN_MIMO_CNT_POS);
    cmd.txchain_info = htole32(iwx_fw_valid_tx_ant(sc));
    return iwx_send_cmd_pdu(sc, IWX_PHY_CONTEXT_CMD, 0, sizeof(cmd), &cmd);
}

int ItlIwx::
iwx_phy_ctxt_cmd(struct iwx_softc *sc, struct iwx_phy_ctxt *ctxt,
                 uint8_t chains_static, uint8_t chains_dynamic, uint32_t action,
                 uint32_t apply_time)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_phy_context_cmd_v1 cmd;
    uint8_t active_cnt, idle_cnt;
    struct ieee80211_channel *chan = ctxt->channel;
    
    if (iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_PHY_CONTEXT_CMD) == 3)
        return iwx_phy_ctxt_cmd_v3(sc, ctxt, chains_static,
                                   chains_dynamic, action, apply_time);
    
    /*
     * Intel increased the size of the fw_channel_info struct and neglected
     * to bump the phy_context_cmd struct, which contains an fw_channel_info
     * member in the middle.
     * To keep things simple we use a separate function to handle the larger
     * variant of the phy context command.
     */
    if (isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_ULTRA_HB_CHANNELS))
        return iwx_phy_ctxt_cmd_uhb(sc, ctxt, chains_static,
                                    chains_dynamic, action, apply_time);
    
    memset(&cmd, 0, sizeof(cmd));
    cmd.id_and_color = htole32(IWX_FW_CMD_ID_AND_COLOR(ctxt->id,
                                                       ctxt->color));
    cmd.action = htole32(action);
    cmd.apply_time = htole32(apply_time);
    
    cmd.ci.band = IEEE80211_IS_CHAN_2GHZ(chan) ?
    IWX_PHY_BAND_24 : IWX_PHY_BAND_5;
    cmd.ci.channel = ieee80211_chan2ieee(ic, chan);
    cmd.ci.width = iwx_get_channel_width(ic, chan);
    cmd.ci.ctrl_pos = iwx_get_ctrl_pos(ic, chan);
    
    idle_cnt = chains_static;
    active_cnt = chains_dynamic;
    cmd.rxchain_info = htole32(iwx_fw_valid_rx_ant(sc) <<
                               IWX_PHY_RX_CHAIN_VALID_POS);
    cmd.rxchain_info |= htole32(idle_cnt << IWX_PHY_RX_CHAIN_CNT_POS);
    cmd.rxchain_info |= htole32(active_cnt <<
                                IWX_PHY_RX_CHAIN_MIMO_CNT_POS);
    cmd.txchain_info = htole32(iwx_fw_valid_tx_ant(sc));
    
    return iwx_send_cmd_pdu(sc, IWX_PHY_CONTEXT_CMD, 0, sizeof(cmd), &cmd);
}

int ItlIwx::
iwx_send_cmd(struct iwx_softc *sc, struct iwx_host_cmd *hcmd)
{
    struct iwx_tx_ring *ring = &sc->txq[IWX_DQA_CMD_QUEUE];
    struct iwx_tfh_tfd *desc;
    struct iwx_tx_data *txdata;
    struct iwx_device_cmd *cmd;
    mbuf_t m;
    bus_addr_t paddr;
    uint64_t addr;
    int err = 0, i, paylen, off, s;
    int idx, code, async, group_id;
    size_t hdrlen, datasz;
    uint8_t *data;
    int generation = sc->sc_generation;
    unsigned int max_chunks = 1;
    IOPhysicalSegment seg;
    
    code = hcmd->id;
    async = hcmd->flags & IWX_CMD_ASYNC;
    idx = (ring->cur & (ring->ring_count - 1));
    
    for (i = 0, paylen = 0; i < nitems(hcmd->len); i++) {
        paylen += hcmd->len[i];
    }
    
    /* If this command waits for a response, allocate response buffer. */
    hcmd->resp_pkt = NULL;
    if (hcmd->flags & IWX_CMD_WANT_RESP) {
        uint8_t *resp_buf;
        //        KASSERT(!async);
        //        KASSERT(hcmd->resp_pkt_len >= sizeof(struct iwx_rx_packet));
        //        KASSERT(hcmd->resp_pkt_len <= IWX_CMD_RESP_MAX);
        if (sc->sc_cmd_resp_pkt[idx] != NULL)
            return ENOSPC;
        resp_buf = (uint8_t *)malloc(hcmd->resp_pkt_len, 0,
                                     M_NOWAIT | M_ZERO);
        if (resp_buf == NULL)
            return ENOMEM;
        bzero(resp_buf, hcmd->resp_pkt_len);
        sc->sc_cmd_resp_pkt[idx] = resp_buf;
        sc->sc_cmd_resp_len[idx] = hcmd->resp_pkt_len;
    } else {
        sc->sc_cmd_resp_pkt[idx] = NULL;
    }
    
    s = splnet();
    
    desc = &ring->desc[idx];
    txdata = &ring->data[idx];
    
    /*
     * XXX Intel inside (tm)
     * Firmware API versions >= 50 reject old-style commands in
     * group 0 with a "BAD_COMMAND" firmware error. We must pretend
     * that such commands were in the LONG_GROUP instead in order
     * for firmware to accept them.
     */
    if (iwx_cmd_groupid(code) == 0) {
        code = IWX_WIDE_ID(IWX_LONG_GROUP, code);
        txdata->flags |= IWX_TXDATA_FLAG_CMD_IS_NARROW;
    } else
        txdata->flags &= ~IWX_TXDATA_FLAG_CMD_IS_NARROW;
    
    group_id = iwx_cmd_groupid(code);
    hdrlen = sizeof(cmd->hdr_wide);
    datasz = sizeof(cmd->data_wide);
    
    if (paylen > datasz) {
                /* Command is too large to fit in pre-allocated space. */
        size_t totlen = hdrlen + paylen;
        if (paylen > IWX_MAX_CMD_PAYLOAD_SIZE) {
            XYLog("%s: firmware command too long (%zd bytes)\n",
                  DEVNAME(sc), totlen);
            err = EINVAL;
            goto out;
        }
        mbuf_allocpacket(MBUF_WAITOK, totlen, &max_chunks, &m);
        if (m == NULL) {
            XYLog("%s: could not get fw cmd mbuf (%zd bytes)\n",
                  DEVNAME(sc), totlen);
            err = ENOMEM;
            goto out;
        }
        mbuf_setlen(m, totlen);
        mbuf_pkthdr_setlen(m, totlen);
        cmd = mtod(m, struct iwx_device_cmd *);
        txdata->map->dm_nsegs = txdata->map->cursor->getPhysicalSegmentsWithCoalesce(m, &seg, 1);
        if (txdata->map->dm_nsegs == 0) {
            XYLog("%s: could not load fw cmd mbuf (%zd bytes)\n",
                  DEVNAME(sc), totlen);
            mbuf_freem(m);
            goto out;
        }
//                XYLog("map fw cmd dm_nsegs=%d\n", txdata->map->dm_nsegs);
        txdata->m = m; /* mbuf will be freed in iwm_cmd_done() */
        paddr = seg.location;
    } else {
        cmd = &ring->cmd[idx];
        paddr = txdata->cmd_paddr;
    }
    
    cmd->hdr_wide.cmd = iwx_cmd_opcode(code);
    cmd->hdr_wide.group_id = group_id;
    cmd->hdr_wide.qid = ring->qid;
    cmd->hdr_wide.idx = idx;
    cmd->hdr_wide.length = htole16(paylen);
    cmd->hdr_wide.reserved = htole16(0);
    cmd->hdr_wide.version = iwx_cmd_version(code);
    data = cmd->data_wide;
    
    for (i = 0, off = 0; i < nitems(hcmd->data); i++) {
        if (hcmd->len[i] == 0)
            continue;
        memcpy(data + off, hcmd->data[i], hcmd->len[i]);
        off += hcmd->len[i];
    }
    KASSERT(off == paylen, "off == paylen");
    
    desc->tbs[0].tb_len = htole16(MIN(hdrlen + paylen, IWX_FIRST_TB_SIZE));
    addr = htole64(paddr);
    memcpy(&desc->tbs[0].addr, &addr, sizeof(addr));
    if (hdrlen + paylen > IWX_FIRST_TB_SIZE) {
        desc->tbs[1].tb_len = htole16(hdrlen + paylen -
                                      IWX_FIRST_TB_SIZE);
        addr = htole64(paddr + IWX_FIRST_TB_SIZE);
        memcpy(&desc->tbs[1].addr, &addr, sizeof(addr));
        desc->num_tbs = htole16(2);
    } else
        desc->num_tbs = htole16(1);
    
    
    //    if (paylen > datasz) {
    //        bus_dmamap_sync(sc->sc_dmat, txdata->map, 0,
    //            hdrlen + paylen, BUS_DMASYNC_PREWRITE);
    //    } else {
    //        bus_dmamap_sync(sc->sc_dmat, ring->cmd_dma.map,
    //            (char *)(void *)cmd - (char *)(void *)ring->cmd_dma.vaddr,
    //            hdrlen + paylen, BUS_DMASYNC_PREWRITE);
    //    }
    //    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map,
    //        (char *)(void *)desc - (char *)(void *)ring->desc_dma.vaddr,
    //        sizeof (*desc), BUS_DMASYNC_PREWRITE);
    /* Kick command ring. */
    DPRINTF(("%s: Sending command (%.2x.%.2x), %d bytes at [%d]:%d ver: %d\n", __func__, group_id, cmd->hdr.cmd, cmd->hdr_wide.length, cmd->hdr.idx, cmd->hdr.qid, cmd->hdr_wide.version));
    ring->queued++;
    ring->cur = (ring->cur + 1) % getTxQueueSize();
    IWX_WRITE(sc, IWX_HBUS_TARG_WRPTR, ring->qid << 16 | ring->cur);
    
    if (!async) {
        err = tsleep_nsec(desc, PCATCH, "iwxcmd", SEC_TO_NSEC(1));
        if (err == 0) {
            /* if hardware is no longer up, return error */
            if (generation != sc->sc_generation) {
                err = ENXIO;
                goto out;
            }
            
            /* Response buffer will be freed in iwx_free_resp(). */
            hcmd->resp_pkt = (struct iwx_rx_packet *)sc->sc_cmd_resp_pkt[idx];
            sc->sc_cmd_resp_pkt[idx] = NULL;
        } else if (generation == sc->sc_generation) {
            ::free(sc->sc_cmd_resp_pkt[idx]);
            sc->sc_cmd_resp_pkt[idx] = NULL;
        }
    }
out:
    splx(s);
    
    return err;
}

int ItlIwx::
iwx_send_cmd_pdu(struct iwx_softc *sc, uint32_t id, uint32_t flags,
                 uint16_t len, const void *data)
{
    struct iwx_host_cmd cmd = {
        .id = id,
        .len = { len, },
        .data = { data, },
        .flags = flags,
    };
    
    return iwx_send_cmd(sc, &cmd);
}

int ItlIwx::
iwx_send_cmd_status(struct iwx_softc *sc, struct iwx_host_cmd *cmd,
                    uint32_t *status)
{
    struct iwx_rx_packet *pkt;
    struct iwx_cmd_response *resp;
    int err, resp_len;
    
    KASSERT((cmd->flags & IWX_CMD_WANT_RESP) == 0, "(cmd->flags & IWX_CMD_WANT_RESP) == 0");
    cmd->flags |= IWX_CMD_WANT_RESP;
    cmd->resp_pkt_len = sizeof(*pkt) + sizeof(*resp);
    
    err = iwx_send_cmd(sc, cmd);
    if (err)
        return err;
    
    pkt = cmd->resp_pkt;
    if (pkt == NULL || (pkt->hdr.group_id & IWX_CMD_FAILED_MSK))
        return EIO;
    
    resp_len = iwx_rx_packet_payload_len(pkt);
    if (resp_len != sizeof(*resp)) {
        iwx_free_resp(sc, cmd);
        return EIO;
    }
    
    resp = (struct iwx_cmd_response *)pkt->data;
    *status = le32toh(resp->status);
    iwx_free_resp(sc, cmd);
    return err;
}

int ItlIwx::
iwx_send_cmd_pdu_status(struct iwx_softc *sc, uint32_t id, uint16_t len,
                        const void *data, uint32_t *status)
{
    struct iwx_host_cmd cmd = {
        .id = id,
        .len = { len, },
        .data = { data, },
    };
    
    return iwx_send_cmd_status(sc, &cmd, status);
}

void ItlIwx::
iwx_free_resp(struct iwx_softc *sc, struct iwx_host_cmd *hcmd)
{
    KASSERT((hcmd->flags & (IWX_CMD_WANT_RESP)) == IWX_CMD_WANT_RESP, "(hcmd->flags & (IWX_CMD_WANT_RESP)) == IWX_CMD_WANT_RESP");
    ::free(hcmd->resp_pkt);
    hcmd->resp_pkt = NULL;
}

void ItlIwx::
iwx_cmd_done(struct iwx_softc *sc, int qid, int idx, int code)
{
    struct iwx_tx_ring *ring = &sc->txq[IWX_DQA_CMD_QUEUE];
    struct iwx_tx_data *data;
    
    if (qid != IWX_DQA_CMD_QUEUE) {
        return;    /* Not a command ack. */
    }
    
    data = &ring->data[idx];
    
    if (data->m != NULL) {
        //        bus_dmamap_sync(sc->sc_dmat, data->map, 0,
        //            data->map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
        //        bus_dmamap_unload(sc->sc_dmat, data->map);
        mbuf_freem(data->m);
        data->m = NULL;
    }
    wakeupOn(&ring->desc[idx]);
    
    DPRINTF(("%s: command 0x%x done\n", __func__, code));
    if (ring->queued == 0) {
        DPRINTF(("%s: unexpected firmware response to command 0x%x\n",
                 DEVNAME(sc), code));
    } else if (ring->queued > 0)
        ring->queued--;
}

uint32_t ItlIwx::
iwx_get_tx_ant(struct iwx_softc *sc, struct ieee80211_node *ni,
                               const struct iwx_rate *rinfo, int type, struct ieee80211_frame *wh)
{
    return ((1 << sc->sc_mgmt_last_antenna_idx) << IWX_RATE_MCS_ANT_POS);
}

void ItlIwx::
iwx_toggle_tx_ant(struct iwx_softc *sc, uint8_t *ant)
{
    uint8_t valid = iwx_fw_valid_tx_ant(sc);
    int i;
    uint8_t ind = *ant; 
    
    for (i = 0; i < IWX_RATE_MCS_ANT_NUM; i++) {
        ind = (ind + 1) % IWX_RATE_MCS_ANT_NUM;
        if (valid & (1 << ind)) {
            *ant = ind;
            break;
        }
    }
}

/*
 * Fill in various bit for management frames, and leave them
 * unfilled for data frames (firmware takes care of that).
 * Return the selected TX rate.
 */
const struct iwx_rate *ItlIwx::
iwx_tx_fill_cmd(struct iwx_softc *sc, struct iwx_node *in,
                struct ieee80211_frame *wh, uint32_t *flags, uint32_t *rate_n_flags)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    struct ieee80211_rateset *rs = &ni->ni_rates;
    const struct iwx_rate *rinfo;
    int type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    int min_ridx = iwx_rval2ridx(ieee80211_min_basic_rate(ic));
    int ridx, rate_flags;
    uint8_t cmdver;
    uint8_t hwrate;

    *flags = 0;
    if (IEEE80211_IS_MULTICAST(wh->i_addr1) ||
        type != IEEE80211_FC0_TYPE_DATA) {
        /* for non-data, use the lowest supported rate */
        ridx = min_ridx;
        *flags |= IWX_TX_FLAGS_CMD_RATE;
    } else if (ic->ic_fixed_mcs != -1) {
        ridx = sc->sc_fixed_ridx;
        *flags |= IWX_TX_FLAGS_CMD_RATE;
    } else if (ic->ic_fixed_rate != -1) {
        ridx = sc->sc_fixed_ridx;
        *flags |= IWX_TX_FLAGS_CMD_RATE;
    } else if (ni->ni_flags & IEEE80211_NODE_HT) {
        ridx = iwx_mcs2ridx[ni->ni_txmcs];
        return &iwx_rates[ridx];
    } else {
        uint8_t rval;
        rval = (rs->rs_rates[ni->ni_txrate] & IEEE80211_RATE_VAL);
        ridx = iwx_rval2ridx(rval);
        if (ridx < min_ridx)
            ridx = min_ridx;
        return &iwx_rates[ridx];
    }
    
    rinfo = &iwx_rates[ridx];
    
    rate_flags = iwx_get_tx_ant(sc, ni, rinfo, type, wh);
    
    hwrate = rinfo->plcp;
    cmdver = iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_TX_CMD);
    if (cmdver > 8 && cmdver != IWX_FW_CMD_VER_UNKNOWN) {
        if (IWX_RIDX_IS_CCK(ridx)) {
            rate_flags |= IWX_RATE_MCS_CCK_MSK;
            hwrate = ridx;
        } else {
            rate_flags |= IWX_RATE_MCS_LEGACY_OFDM_MSK;
            hwrate = iwx_rate2idx(iwx_ridx2rate(rs, ridx) & IEEE80211_RATE_VAL);
        }
    } else if (IWX_RIDX_IS_CCK(ridx))
        rate_flags |= IWX_RATE_MCS_CCK_MSK_V1;
    XYLog("%s hwrate: %d ridx: %d rate: %d minrate: %d\n", __FUNCTION__, hwrate, ridx, iwx_ridx2rate(rs, ridx) & IEEE80211_RATE_VAL, ieee80211_min_basic_rate(ic));
    *rate_n_flags = htole32(rate_flags | hwrate);
    
    return rinfo;
}

void ItlIwx::
iwx_tx_update_byte_tbl(struct iwx_softc *sc, struct iwx_tx_ring *txq, int idx, uint16_t byte_cnt,
                       uint16_t num_tbs)
{
    uint8_t filled_tfd_size, num_fetch_chunks;
    uint16_t len = byte_cnt;
    uint16_t bc_ent;
    
    filled_tfd_size = offsetof(struct iwx_tfh_tfd, tbs) +
    num_tbs * sizeof(struct iwx_tfh_tb);
    /*
     * filled_tfd_size contains the number of filled bytes in the TFD.
     * Dividing it by 64 will give the number of chunks to fetch
     * to SRAM- 0 for one chunk, 1 for 2 and so on.
     * If, for example, TFD contains only 3 TBs then 32 bytes
     * of the TFD are used, and only one chunk of 64 bytes should
     * be fetched
     */
    num_fetch_chunks = howmany(filled_tfd_size, 64) - 1;
    
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210) {
        struct iwx_gen3_bc_tbl *scd_bc_tbl_gen3 = (struct iwx_gen3_bc_tbl *)txq->bc_tbl.vaddr;
        
        /* Starting from AX210, the HW expects bytes */
        bc_ent = htole16(len | (num_fetch_chunks << 14));
        scd_bc_tbl_gen3->tfd_offset[idx] = bc_ent;
    } else {
        struct iwx_agn_scd_bc_tbl *scd_bc_tbl = (struct iwx_agn_scd_bc_tbl *)txq->bc_tbl.vaddr;
        
        /* Before AX210, the HW expects DW */
        len = howmany(len, 4);
        bc_ent = htole16(len | (num_fetch_chunks << 12));
        scd_bc_tbl->tfd_offset[idx] = bc_ent;
    }
}

int ItlIwx::
iwx_tx(struct iwx_softc *sc, mbuf_t m, struct ieee80211_node *ni, int ac)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_node *in = (struct iwx_node *)ni;
    struct iwx_tx_ring *ring;
    struct iwx_tx_data *data;
    struct iwx_tfh_tfd *desc;
    struct iwx_device_cmd *cmd;
    struct iwx_tx_cmd_gen2 *tx_gen2;
    struct iwx_tx_cmd_gen3 *tx_gen3;
    struct ieee80211_frame *wh;
    struct ieee80211_key *k = NULL;
    const struct iwx_rate *rinfo;
    uint64_t paddr;
    u_int hdrlen;
    IOPhysicalSegment *seg;
    IOPhysicalSegment segs[IWX_TFH_NUM_TBS - 2];
    int nsegs = 0;
    uint32_t flags = 0, rate_n_flags = 0;
    uint16_t offload_assist = 0;
    uint16_t cmd_size = 0;

    uint16_t num_tbs;
    uint8_t tid, type, subtype;
    int i, totlen;
    int qid = IWX_INVALID_QUEUE;
    int idx;

    wh = mtod(m, struct ieee80211_frame *);
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    if (type == IEEE80211_FC0_TYPE_CTL)
        hdrlen = sizeof(struct ieee80211_frame_min);
    else
        hdrlen = ieee80211_get_hdrlen(wh);
    
    tid = IWX_MGMT_TID;
    qid = sc->first_data_qid;

    /* Put QoS frames on the data queue which maps to their TID. */
    if (ieee80211_has_qos(wh)) {
        struct ieee80211_tx_ba *ba;
        uint16_t qos = ieee80211_get_qos(wh);
        uint8_t tid = qos & IEEE80211_QOS_TID;

        ba = &ni->ni_tx_ba[tid];
        if (!IEEE80211_IS_MULTICAST(wh->i_addr1) &&
            type == IEEE80211_FC0_TYPE_DATA &&
            subtype != IEEE80211_FC0_SUBTYPE_NODATA &&
            sc->sc_tid_data[tid].qid != 0 &&
            sc->sc_tid_data[tid].qid != IWX_INVALID_QUEUE &&
            ba->ba_state == IEEE80211_BA_AGREED) {
            qid = sc->sc_tid_data[tid].qid;
        }
    }

    ring = &sc->txq[qid];
    if (ring->ring_count == 0) {
        mbuf_freem(m);
        return EINVAL;
    }
    idx = (ring->cur & (ring->ring_count - 1));
    desc = &ring->desc[idx];
    memset(desc, 0, sizeof(*desc));
    data = &ring->data[idx];
    
    cmd = &ring->cmd[idx];
    cmd->hdr.cmd = IWX_TX_CMD;
    cmd->hdr.group_id = 0;
    cmd->hdr.qid = ring->qid;
    cmd->hdr.idx = idx;
    
    rinfo = iwx_tx_fill_cmd(sc, in, wh, &flags, &rate_n_flags);
    
#if NBPFILTER > 0
    if (sc->sc_drvbpf != NULL) {
        struct iwx_tx_radiotap_header *tap = &sc->sc_txtap;
        uint16_t chan_flags;
        
        tap->wt_flags = 0;
        tap->wt_chan_freq = htole16(ni->ni_chan->ic_freq);
        chan_flags = ni->ni_chan->ic_flags;
        if (ic->ic_curmode != IEEE80211_MODE_11N)
            chan_flags &= ~IEEE80211_CHAN_HT;
        tap->wt_chan_flags = htole16(chan_flags);
        if ((ni->ni_flags & IEEE80211_NODE_HT) &&
            !IEEE80211_IS_MULTICAST(wh->i_addr1) &&
            type == IEEE80211_FC0_TYPE_DATA &&
            rinfo->ht_plcp != IWX_RATE_HT_SISO_MCS_INV_PLCP) {
            tap->wt_rate = (0x80 | rinfo->ht_plcp);
        } else
            tap->wt_rate = rinfo->rate;
        if ((ic->ic_flags & IEEE80211_F_WEPON) &&
            (wh->i_fc[1] & IEEE80211_FC1_PROTECTED))
            tap->wt_flags |= IEEE80211_RADIOTAP_F_WEP;
        
        bpf_mtap_hdr(sc->sc_drvbpf, tap, sc->sc_txtap_len,
                     m, BPF_DIRECTION_OUT);
    }
#endif
    
    if (wh->i_fc[1] & IEEE80211_FC1_PROTECTED) {
        k = ieee80211_get_txkey(ic, wh, ni);
        if (k->k_cipher != IEEE80211_CIPHER_CCMP) {
            if ((m = ieee80211_encrypt(ic, m, k)) == NULL)
                return ENOBUFS;
            /* 802.11 header may have moved. */
            wh = mtod(m, struct ieee80211_frame *);
            flags |= htole32(IWX_TX_FLAGS_ENCRYPT_DIS);
        } else {
            k->k_tsc++;
            /* Hardware increments PN internally and adds IV. */
        }
    } else
        flags |= htole32(IWX_TX_FLAGS_ENCRYPT_DIS);
    //    totlen = m->m_pkthdr.len;
    totlen = mbuf_pkthdr_len(m);
    
    if (hdrlen % 4)
        offload_assist |= IWX_TX_CMD_OFFLD_PAD;
    
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210) {
        tx_gen3 = (struct iwx_tx_cmd_gen3 *)cmd->data;
        
        cmd_size = sizeof(*tx_gen3);
        memset(tx_gen3, 0, cmd_size);
        
        tx_gen3->len = htole16(totlen);
        tx_gen3->offload_assist = htole32(offload_assist);
        /* Copy 802.11 header in TX command. */
        memcpy(((uint8_t *)tx_gen3) + sizeof(*tx_gen3), wh, hdrlen);
        tx_gen3->flags = htole16(flags);
        tx_gen3->rate_n_flags = htole32(rate_n_flags);
    } else {
        tx_gen2 = (struct iwx_tx_cmd_gen2 *)cmd->data;
        
        cmd_size = sizeof(*tx_gen2);
        memset(tx_gen2, 0, cmd_size);
        tx_gen2->len = htole16(totlen);
        tx_gen2->offload_assist = htole16(offload_assist);
        /* Copy 802.11 header in TX command. */
        memcpy(((uint8_t *)tx_gen2) + sizeof(*tx_gen2), wh, hdrlen);
        tx_gen2->flags = htole32(flags);
        tx_gen2->rate_n_flags = htole32(rate_n_flags);
    }
    
    /* Trim 802.11 header. */
    mbuf_adj(m, hdrlen);
    
    nsegs = data->map->cursor->getPhysicalSegmentsWithCoalesce(m, &segs[0], IWX_TFH_NUM_TBS - 2);
    if (nsegs == 0) {
        XYLog("%s: can't map mbuf (error %d)\n", DEVNAME(sc),
              nsegs);
        mbuf_freem(m);
        return ENOMEM;
    }
    data->m = m;
    data->in = in;
    data->type = type;

    DPRINTFN(3, ("sending data: 嘤嘤嘤 tid=%d qid=%d idx=%d queued=%d len=%d nsegs=%d flags=0x%08x rate_n_flags=0x%08x offload_assist=%u\n",
          tid, ring->qid, ring->cur, ring->queued, totlen, nsegs, le32toh(flags),
          le32toh(rate_n_flags), offload_assist));
    
    /* Fill TX descriptor. */
    num_tbs = 2 + nsegs;
    desc->num_tbs = htole16(num_tbs);
    
    desc->tbs[0].tb_len = htole16(IWX_FIRST_TB_SIZE);
    paddr = htole64(data->cmd_paddr);
    memcpy(&desc->tbs[0].addr, &paddr, sizeof(paddr));
    if (data->cmd_paddr >> 32 != (data->cmd_paddr + le32toh(desc->tbs[0].tb_len)) >> 32)
        DPRINTF(("%s: TB0 crosses 32bit boundary\n", __func__));
    desc->tbs[1].tb_len = htole16(_ALIGN(sizeof(struct iwx_cmd_header) +
                                  cmd_size + hdrlen - IWX_FIRST_TB_SIZE, 4));
    paddr = htole64(data->cmd_paddr + IWX_FIRST_TB_SIZE);
    memcpy(&desc->tbs[1].addr, &paddr, sizeof(paddr));
    
    if (data->cmd_paddr >> 32 != (data->cmd_paddr + le32toh(desc->tbs[1].tb_len)) >> 32)
        DPRINTF(("%s: TB1 crosses 32bit boundary\n", __func__));
    
    /* Other DMA segments are for data payload. */
    for (i = 0; i < nsegs; i++) {
        seg = &segs[i];
        desc->tbs[i + 2].tb_len = htole16(seg->length);
        paddr = htole64(seg->location);
        memcpy(&desc->tbs[i + 2].addr, &paddr, sizeof(paddr));
        if (data->cmd_paddr >> 32 != (data->cmd_paddr + le32toh(desc->tbs[i + 2].tb_len)) >> 32)
            DPRINTF(("%s: TB%d crosses 32bit boundary\n", __func__, i + 2));
//        XYLog("DMA segments index=%d location=0x%llx length=%llu", i, seg->location, seg->length);
    }
    
    //    bus_dmamap_sync(sc->sc_dmat, data->map, 0, data->map->dm_mapsize,
    //        BUS_DMASYNC_PREWRITE);
    //    bus_dmamap_sync(sc->sc_dmat, ring->cmd_dma.map,
    //        (char *)(void *)cmd - (char *)(void *)ring->cmd_dma.vaddr,
    //        sizeof (*cmd), BUS_DMASYNC_PREWRITE);
    //    bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map,
    //        (char *)(void *)desc - (char *)(void *)ring->desc_dma.vaddr,
    //        sizeof (*desc), BUS_DMASYNC_PREWRITE);
    
    iwx_tx_update_byte_tbl(sc, ring, idx, totlen, num_tbs);
    
    /* Kick TX ring. */
    ring->cur = (ring->cur + 1) % getTxQueueSize();
    IWX_WRITE(sc, IWX_HBUS_TARG_WRPTR, ring->qid << 16 | ring->cur);
    
    /* Mark TX ring as full if we reach a certain threshold. */
    if (++ring->queued > ring->hi_mark) {
//        XYLog("%s sc->qfullmsk is FULL qid=%d ring->cur=%d ring->queued=%d\n", __FUNCTION__, ring->qid, ring->cur, ring->queued);
        sc->qfullmsk |= 1 << ring->qid;
    }
    
    return 0;
}

int ItlIwx::
iwx_flush_sta_tids(struct iwx_softc *sc, int sta_id, uint16_t tids)
{
    struct iwx_rx_packet *pkt;
    struct iwx_tx_path_flush_cmd_rsp *resp;
    struct iwx_tx_path_flush_cmd flush_cmd = {
        .sta_id = htole32(sta_id),
        .tid_mask = htole16(tids),
    };
    struct iwx_host_cmd hcmd = {
        .id = IWX_TXPATH_FLUSH,
        .len = { sizeof(flush_cmd), },
        .data = { &flush_cmd, },
        .flags = IWX_CMD_WANT_RESP,
        .resp_pkt_len = sizeof(*pkt) + sizeof(*resp),
    };
    int err, resp_len, i, num_flushed_queues;
    
    err = iwx_send_cmd(sc, &hcmd);
    if (err)
        return err;
    
    pkt = hcmd.resp_pkt;
    if (!pkt || (pkt->hdr.group_id & IWX_CMD_FAILED_MSK)) {
        err = EIO;
        goto out;
    }
    
    resp_len = iwx_rx_packet_payload_len(pkt);
    /* Some firmware versions don't provide a response. */
    if (resp_len == 0)
        goto out;
    else if (resp_len != sizeof(*resp)) {
        err = EIO;
        goto out;
    }
    
    resp = (struct iwx_tx_path_flush_cmd_rsp *)pkt->data;
    
    if (le16toh(resp->sta_id) != sta_id) {
        err = EIO;
        goto out;
    }
    
    num_flushed_queues = le16toh(resp->num_flushed_queues);
    if (num_flushed_queues > IWX_TX_FLUSH_QUEUE_RSP) {
        err = EIO;
        goto out;
    }
    
    for (i = 0; i < num_flushed_queues; i++) {
        struct iwx_flush_queue_info *queue_info = &resp->queues[i];
        uint16_t tid = le16toh(queue_info->tid);
        uint16_t read_after = le16toh(queue_info->read_after_flush);
        uint16_t qid = le16toh(queue_info->queue_num);
        struct iwx_tx_ring *txq;
        
        if (qid >= nitems(sc->txq))
            continue;

        if (sc->sc_tid_data[tid].qid != qid)
            continue;
        txq = &sc->txq[qid];
        
        iwx_ampdu_txq_advance(sc, txq, IWX_AGG_SSN_TO_TXQ_IDX(read_after, txq->ring_count));
    }
out:
    iwx_free_resp(sc, &hcmd);
    return err;
}

int ItlIwx::
iwx_flush_sta(struct iwx_softc *sc, struct iwx_node *in)
{
    int err;
    
    splassert(IPL_NET);
    
    sc->sc_flags |= IWX_FLAG_TXFLUSH;
    
    err = iwx_drain_sta(sc, in, 1);
    
    if (err == ENXIO)
        goto done;
    
    err = iwx_flush_sta_tids(sc, IWX_STATION_ID, 0xffff);
    if (err) {
        XYLog("%s: could not flush Tx path (error %d)\n",
               __FUNCTION__, err);
        goto done;
    }
    
    err = iwx_drain_sta(sc, in, 0);
    if (err == ENXIO)
        goto done;
    else
        err = 0;
done:
    sc->sc_flags &= ~IWX_FLAG_TXFLUSH;
    return err;
}

int ItlIwx::
iwx_drain_sta(struct iwx_softc *sc, struct iwx_node* in, int drain)
{
    struct iwx_add_sta_cmd cmd;
    int err;
    uint32_t status;
    
    memset(&cmd, 0, sizeof(cmd));
    cmd.mac_id_n_color = htole32(IWX_FW_CMD_ID_AND_COLOR(in->in_id,
                                                         in->in_color));
    cmd.sta_id = IWX_STATION_ID;
    cmd.add_modify = IWX_STA_MODE_MODIFY;
    cmd.station_flags = drain ? htole32(IWX_STA_FLG_DRAIN_FLOW) : 0;
    cmd.station_flags_msk = htole32(IWX_STA_FLG_DRAIN_FLOW);
    
    status = IWX_ADD_STA_SUCCESS;
    err = iwx_send_cmd_pdu_status(sc, IWX_ADD_STA,
                                  sizeof(cmd), &cmd, &status);
    if (err) {
        printf("%s: could not update sta (error %d)\n",
               DEVNAME(sc), err);
        return err;
    }
    
    switch (status & IWX_ADD_STA_STATUS_MASK) {
        case IWX_ADD_STA_SUCCESS:
            break;
        default:
            err = EIO;
            printf("%s: Couldn't %s draining for station\n",
                   DEVNAME(sc), drain ? "enable" : "disable");
            break;
    }
    
    return err;
}

#define IWX_POWER_KEEP_ALIVE_PERIOD_SEC    25

int ItlIwx::
iwx_beacon_filter_send_cmd(struct iwx_softc *sc,
                           struct iwx_beacon_filter_cmd *cmd)
{
    size_t len;
    
    if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_BEACON_FILTER_V4))
        len = sizeof(struct iwx_beacon_filter_cmd);
    else
        len = offsetof(struct iwx_beacon_filter_cmd,
                       bf_threshold_absolute_low);
    return iwx_send_cmd_pdu(sc, IWX_REPLY_BEACON_FILTERING_CMD,
                            0, len, cmd);
}

int ItlIwx::
iwx_update_beacon_abort(struct iwx_softc *sc, struct iwx_node *in, int enable)
{
    struct iwx_beacon_filter_cmd cmd = {
        IWX_BF_CMD_CONFIG_DEFAULTS,
        .bf_enable_beacon_filter = htole32(1),
        .ba_enable_beacon_abort = htole32(enable),
    };
    
    if (!sc->sc_bf.bf_enabled)
        return 0;
    
    sc->sc_bf.ba_enabled = enable;
    return iwx_beacon_filter_send_cmd(sc, &cmd);
}

void ItlIwx::
iwx_power_build_cmd(struct iwx_softc *sc, struct iwx_node *in,
                    struct iwx_mac_power_cmd *cmd)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    int dtim_period, dtim_msec, keep_alive;
    
    cmd->id_and_color = htole32(IWX_FW_CMD_ID_AND_COLOR(in->in_id,
                                                        in->in_color));
    if (ni->ni_dtimperiod)
        dtim_period = ni->ni_dtimperiod;
    else
        dtim_period = 1;
    
    /*
     * Regardless of power management state the driver must set
     * keep alive period. FW will use it for sending keep alive NDPs
     * immediately after association. Check that keep alive period
     * is at least 3 * DTIM.
     */
    dtim_msec = dtim_period * ni->ni_intval;
    keep_alive = MAX(3 * dtim_msec, 1000 * IWX_POWER_KEEP_ALIVE_PERIOD_SEC);
    keep_alive = roundup(keep_alive, 1000) / 1000;
    cmd->keep_alive_seconds = htole16(keep_alive);
    
    if (ic->ic_opmode != IEEE80211_M_MONITOR)
        cmd->flags = htole16(IWX_POWER_FLAGS_POWER_SAVE_ENA_MSK);
}

int ItlIwx::
iwx_power_mac_update_mode(struct iwx_softc *sc, struct iwx_node *in)
{
    int err;
    int ba_enable;
    struct iwx_mac_power_cmd cmd;
    
    memset(&cmd, 0, sizeof(cmd));
    
    iwx_power_build_cmd(sc, in, &cmd);
    
    err = iwx_send_cmd_pdu(sc, IWX_MAC_PM_POWER_TABLE, 0,
                           sizeof(cmd), &cmd);
    if (err != 0)
        return err;
    
    ba_enable = !!(cmd.flags &
                   htole16(IWX_POWER_FLAGS_POWER_MANAGEMENT_ENA_MSK));
    return iwx_update_beacon_abort(sc, in, ba_enable);
}

int ItlIwx::
iwx_power_update_device(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_device_power_cmd cmd = { };
    struct ieee80211com *ic = &sc->sc_ic;
    
    if (ic->ic_opmode != IEEE80211_M_MONITOR)
        cmd.flags = htole16(IWX_DEVICE_POWER_FLAGS_POWER_SAVE_ENA_MSK);
    
    return iwx_send_cmd_pdu(sc,
                            IWX_POWER_TABLE_CMD, 0, sizeof(cmd), &cmd);
}

int ItlIwx::
iwx_enable_beacon_filter(struct iwx_softc *sc, struct iwx_node *in)
{
    struct iwx_beacon_filter_cmd cmd = {
        IWX_BF_CMD_CONFIG_DEFAULTS,
        .bf_enable_beacon_filter = htole32(1),
        .ba_enable_beacon_abort = htole32(sc->sc_bf.ba_enabled),
    };
    int err;
    
    err = iwx_beacon_filter_send_cmd(sc, &cmd);
    if (err == 0)
        sc->sc_bf.bf_enabled = 1;
    
    return err;
}

int ItlIwx::
iwx_disable_beacon_filter(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_beacon_filter_cmd cmd;
    int err;
    
    memset(&cmd, 0, sizeof(cmd));
    
    err = iwx_beacon_filter_send_cmd(sc, &cmd);
    if (err == 0)
        sc->sc_bf.bf_enabled = 0;
    
    return err;
}

int ItlIwx::
iwx_add_sta_cmd(struct iwx_softc *sc, struct iwx_node *in, int update)
{
    struct iwx_add_sta_cmd add_sta_cmd;
    int err;
    uint32_t status, agg_size = 0;
    uint32_t max_aggsize = (IWX_STA_FLG_MAX_AGG_SIZE_4M >> IWX_STA_FLG_MAX_AGG_SIZE_SHIFT);
    struct ieee80211com *ic = &sc->sc_ic;
    
    if (!update && (sc->sc_flags & IWX_FLAG_STA_ACTIVE)) {
        XYLog("STA already added\n");
        return 0;
    }
    
    memset(&add_sta_cmd, 0, sizeof(add_sta_cmd));
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        add_sta_cmd.sta_id = IWX_MONITOR_STA_ID;
        add_sta_cmd.station_type = IWX_STA_GENERAL_PURPOSE;
    } else {
        add_sta_cmd.sta_id = IWX_STATION_ID;
        add_sta_cmd.station_type = IWX_STA_LINK;
    }
    add_sta_cmd.mac_id_n_color
    = htole32(IWX_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    if (!update) {
        if (ic->ic_opmode == IEEE80211_M_MONITOR)
            IEEE80211_ADDR_COPY(&add_sta_cmd.addr,
                                etheranyaddr);
        else
            IEEE80211_ADDR_COPY(&add_sta_cmd.addr,
                                in->in_macaddr);
    }
    add_sta_cmd.add_modify = update ? 1 : 0;
    add_sta_cmd.station_flags_msk
    |= htole32(IWX_STA_FLG_FAT_EN_MSK | IWX_STA_FLG_MIMO_EN_MSK);
    add_sta_cmd.tid_disable_tx = htole16(0xffff);
        
    if ((in->in_ni.ni_flags & IEEE80211_NODE_HT) ||
        (in->in_ni.ni_flags & IEEE80211_NODE_VHT) ||
        (in->in_ni.ni_flags & IEEE80211_NODE_HE)) {
        add_sta_cmd.station_flags_msk
        |= htole32(IWX_STA_FLG_MAX_AGG_SIZE_MSK |
                   IWX_STA_FLG_AGG_MPDU_DENS_MSK);
        
        if (ic->ic_state >= IEEE80211_S_ASSOC) {
            switch (in->in_ni.ni_chw) {
                case IEEE80211_CHAN_WIDTH_80P80:
                case IEEE80211_CHAN_WIDTH_160:
                    add_sta_cmd.station_flags |= htole32(IWX_STA_FLG_FAT_EN_160MHZ);
                case IEEE80211_CHAN_WIDTH_80:
                    add_sta_cmd.station_flags |= htole32(IWX_STA_FLG_FAT_EN_80MHZ);
                case IEEE80211_CHAN_WIDTH_40:
                    add_sta_cmd.station_flags |= htole32(IWX_STA_FLG_FAT_EN_40MHZ);
                case IEEE80211_CHAN_WIDTH_20:
                default:
                    add_sta_cmd.station_flags |= htole32(IWX_STA_FLG_FAT_EN_20MHZ);
                    break;
            }
        }
        
        if (iwx_mimo_enabled(sc) && ic->ic_bss->ni_rx_nss > 1)
            add_sta_cmd.station_flags |= htole32(IWX_STA_FLG_MIMO_EN_MIMO2);
        else
            add_sta_cmd.station_flags |= htole32(IWX_STA_FLG_MIMO_EN_SISO);
        
        if (in->in_ni.ni_flags & IEEE80211_NODE_HE) {
            agg_size = in->in_ni.ni_vhtcaps &
            IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK;
            agg_size >>=
            IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT;
            agg_size += u8_get_bits(in->in_ni.ni_he_cap_elem.mac_cap_info[3],
                                    IEEE80211_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_MASK);
            add_sta_cmd.station_flags |=
            htole32(min(max_aggsize, agg_size) << IWX_STA_FLG_MAX_AGG_SIZE_SHIFT);
        } else if (in->in_ni.ni_flags & IEEE80211_NODE_VHT) {
            agg_size = in->in_ni.ni_vhtcaps &
            IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK;
            agg_size >>=
            IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT;
            add_sta_cmd.station_flags |=
            htole32(min(max_aggsize, agg_size) << IWX_STA_FLG_MAX_AGG_SIZE_SHIFT);
        } else if (in->in_ni.ni_flags & IEEE80211_NODE_HT)
            add_sta_cmd.station_flags |= htole32(IWX_STA_FLG_MAX_AGG_SIZE_64K);
        
        switch (ic->ic_ampdu_params & IEEE80211_AMPDU_PARAM_SS) {
            case IEEE80211_AMPDU_PARAM_SS_2:
                add_sta_cmd.station_flags
                |= htole32(IWX_STA_FLG_AGG_MPDU_DENS_2US);
                break;
            case IEEE80211_AMPDU_PARAM_SS_4:
                add_sta_cmd.station_flags
                |= htole32(IWX_STA_FLG_AGG_MPDU_DENS_4US);
                break;
            case IEEE80211_AMPDU_PARAM_SS_8:
                add_sta_cmd.station_flags
                |= htole32(IWX_STA_FLG_AGG_MPDU_DENS_8US);
                break;
            case IEEE80211_AMPDU_PARAM_SS_16:
                add_sta_cmd.station_flags
                |= htole32(IWX_STA_FLG_AGG_MPDU_DENS_16US);
                break;
            default:
                break;
        }
    }
    
    status = IWX_ADD_STA_SUCCESS;
    err = iwx_send_cmd_pdu_status(sc, IWX_ADD_STA, sizeof(add_sta_cmd),
                                  &add_sta_cmd, &status);
    if (!err && (status & IWX_ADD_STA_STATUS_MASK) != IWX_ADD_STA_SUCCESS)
        err = EIO;
    else
        sc->sc_flags |= IWX_FLAG_STA_ACTIVE;

    return err;
}

int ItlIwx::
iwx_add_aux_sta(struct iwx_softc *sc)
{
    
    XYLog("%s\n", __FUNCTION__);
    struct iwx_add_sta_cmd cmd;
    int err, qid = IWX_DQA_AUX_QUEUE;
    uint32_t status;
    uint8_t cmdver;
    
    /*
     * Add auxiliary station for scanning.
     * Newer versions of this command implies that the fw uses
     * internal aux station for all aux activities that don't
     * requires a dedicated data queue.
     * In old version the aux station uses mac id like other
     * station and not lmac id
     */
    cmdver = iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_ADD_STA);
    if (cmdver != IWX_FW_CMD_VER_UNKNOWN && cmdver >= 12)
        return 0;
    
    memset(&cmd, 0, sizeof(cmd));
    cmd.sta_id = IWX_AUX_STA_ID;
    cmd.station_type = IWX_STA_AUX_ACTIVITY;
    cmd.mac_id_n_color =
    htole32(IWX_FW_CMD_ID_AND_COLOR(IWX_MAC_INDEX_AUX, 0));
    cmd.tid_disable_tx = htole16(0xffff);
    
    status = IWX_ADD_STA_SUCCESS;
    err = iwx_send_cmd_pdu_status(sc, IWX_ADD_STA, sizeof(cmd), &cmd,
                                  &status);
    if (!err && (status & IWX_ADD_STA_STATUS_MASK) != IWX_ADD_STA_SUCCESS)
        return EIO;
    
    return iwx_enable_txq(sc, IWX_AUX_STA_ID, qid, IWX_MGMT_TID,
                          sc->txq[qid].ring_count);
    return 0;
}

int ItlIwx::
iwx_rm_sta_cmd(struct iwx_softc *sc, struct iwx_node *in)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_rm_sta_cmd rm_sta_cmd;
    int err;
    
    if ((sc->sc_flags & IWX_FLAG_STA_ACTIVE) == 0) {
        XYLog("sta already removed\n");
        return 0;
    }
    
    memset(&rm_sta_cmd, 0, sizeof(rm_sta_cmd));
    if (ic->ic_opmode == IEEE80211_M_MONITOR)
        rm_sta_cmd.sta_id = IWX_MONITOR_STA_ID;
    else
        rm_sta_cmd.sta_id = IWX_STATION_ID;
    
    err = iwx_send_cmd_pdu(sc, IWX_REMOVE_STA, 0, sizeof(rm_sta_cmd),
                           &rm_sta_cmd);
    
    sc->sc_flags &= ~IWX_FLAG_STA_ACTIVE;

    return err;
}

int ItlIwx::
iwx_rm_sta(struct iwx_softc *sc, struct iwx_node *in)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    int err, i;

    err = iwx_flush_sta(sc, in);
    if (err) {
        XYLog("%s: could not flush Tx path (error %d)\n",
            __FUNCTION__, err);
        return err;
    }
    err = iwx_rm_sta_cmd(sc, in);
    if (err) {
        printf("%s: could not remove STA (error %d)\n",
            DEVNAME(sc), err);
        return err;
    }

    sc->sc_rx_ba_sessions = 0;
    sc->ba_rx.start_tidmask = 0;
    sc->ba_rx.stop_tidmask = 0;
    sc->ba_tx.start_tidmask = 0;
    sc->ba_tx.stop_tidmask = 0;
    for (i = 0; i < IEEE80211_NUM_TID; i++) {
        struct ieee80211_tx_ba *ba = &ni->ni_tx_ba[i];
        if (ba->ba_state != IEEE80211_BA_AGREED)
            continue;
        ieee80211_delba_request(ic, ni, 0, 1, i);
    }

    return 0;
}

uint8_t ItlIwx::
iwx_umac_scan_fill_channels(struct iwx_softc *sc,
                            struct iwx_scan_channel_cfg_umac *chan, int n_ssids, int bgscan)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_channel *c;
    uint8_t nchan;
    
    for (nchan = 0, c = &ic->ic_channels[1];
         c <= &ic->ic_channels[IEEE80211_CHAN_MAX] &&
         nchan < sc->sc_capa_n_scan_channels;
         c++) {
        uint8_t channel_num;
        
        if (c->ic_flags == 0)
            continue;
        
        channel_num = ieee80211_mhz2ieee(c->ic_freq, 0);
        if (isset(sc->sc_ucode_api,
                  IWX_UCODE_TLV_API_SCAN_EXT_CHAN_VER)) {
            chan->v2.channel_num = channel_num;
            if (IEEE80211_IS_CHAN_2GHZ(c))
                chan->v2.band = IWX_PHY_BAND_24;
            else
                chan->v2.band = IWX_PHY_BAND_5;
            chan->v2.iter_count = 1;
            chan->v2.iter_interval = 0;
        } else {
            chan->v1.channel_num = channel_num;
            chan->v1.iter_count = 1;
            chan->v1.iter_interval = htole16(0);
        }
        
        if (n_ssids != 0 && !bgscan)
            chan->flags = htole32(1 << 0); /* select SSID 0 */
        chan++;
        nchan++;
    }
    
    return nchan;
}

int ItlIwx::
iwx_fill_probe_req_v1(struct iwx_softc *sc, struct iwx_scan_probe_req_v1 *preq1)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_scan_probe_req preq2;
    int err, i;
    
    err = iwx_fill_probe_req(sc, &preq2);
    if (err)
        return err;
    
    preq1->mac_header = preq2.mac_header;
    for (i = 0; i < nitems(preq1->band_data); i++)
        preq1->band_data[i] = preq2.band_data[i];
    preq1->common_data = preq2.common_data;
    memcpy(preq1->buf, preq2.buf, sizeof(preq1->buf));
    return 0;
}

int ItlIwx::
iwx_fill_probe_req(struct iwx_softc *sc, struct iwx_scan_probe_req *preq)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = IC2IFP(ic);
    struct ieee80211_frame *wh = (struct ieee80211_frame *)preq->buf;
    struct ieee80211_rateset *rs;
    size_t remain = sizeof(preq->buf);
    uint8_t *frm, *pos;
    
    memset(preq, 0, sizeof(*preq));
    
    if (remain < sizeof(*wh) + 2)
        return ENOBUFS;
    
    /*
     * Build a probe request frame.  Most of the following code is a
     * copy & paste of what is done in net80211.
     */
    wh->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT |
    IEEE80211_FC0_SUBTYPE_PROBE_REQ;
    wh->i_fc[1] = IEEE80211_FC1_DIR_NODS;
//    IEEE80211_ADDR_COPY(ic->ic_myaddr, LLADDR(ifp->if_sadl));
    IEEE80211_ADDR_COPY(wh->i_addr1, etherbroadcastaddr);
    IEEE80211_ADDR_COPY(wh->i_addr2, ic->ic_myaddr);
    IEEE80211_ADDR_COPY(wh->i_addr3, etherbroadcastaddr);
    *(uint16_t *)&wh->i_dur[0] = 0;    /* filled by HW */
    *(uint16_t *)&wh->i_seq[0] = 0;    /* filled by HW */
    
    frm = (uint8_t *)(wh + 1);
    *frm++ = IEEE80211_ELEMID_SSID;
    *frm++ = 0;
    /* hardware inserts SSID */
    
    /* Tell the firmware where the MAC header is. */
    preq->mac_header.offset = 0;
    preq->mac_header.len = htole16(frm - (uint8_t *)wh);
    remain -= frm - (uint8_t *)wh;
    
    /* Fill in 2GHz IEs and tell firmware where they are. */
    rs = &ic->ic_sup_rates[IEEE80211_MODE_11G];
    if (rs->rs_nrates > IEEE80211_RATE_SIZE) {
        if (remain < 4 + rs->rs_nrates)
            return ENOBUFS;
    } else if (remain < 2 + rs->rs_nrates)
        return ENOBUFS;
    preq->band_data[0].offset = htole16(frm - (uint8_t *)wh);
    pos = frm;
    frm = ieee80211_add_rates(frm, rs);
    if (rs->rs_nrates > IEEE80211_RATE_SIZE)
        frm = ieee80211_add_xrates(frm, rs);
    remain -= frm - pos;
    
    if (isset(sc->sc_enabled_capa,
              IWX_UCODE_TLV_CAPA_DS_PARAM_SET_IE_SUPPORT)) {
        if (remain < 3)
            return ENOBUFS;
        *frm++ = IEEE80211_ELEMID_DSPARMS;
        *frm++ = 1;
        *frm++ = 0;
        remain -= 3;
    }
    preq->band_data[0].len = htole16(frm - pos);
    
    if (sc->sc_nvm.sku_cap_band_52GHz_enable) {
        /* Fill in 5GHz IEs. */
        rs = &ic->ic_sup_rates[IEEE80211_MODE_11A];
        if (rs->rs_nrates > IEEE80211_RATE_SIZE) {
            if (remain < 4 + rs->rs_nrates)
                return ENOBUFS;
        } else if (remain < 2 + rs->rs_nrates)
            return ENOBUFS;
        preq->band_data[1].offset = htole16(frm - (uint8_t *)wh);
        pos = frm;
        frm = ieee80211_add_rates(frm, rs);
        if (rs->rs_nrates > IEEE80211_RATE_SIZE)
            frm = ieee80211_add_xrates(frm, rs);
        preq->band_data[1].len = htole16(frm - pos);
        remain -= frm - pos;
        if (ic->ic_flags & IEEE80211_F_VHTON) {
            if (remain < sizeof(struct ieee80211_ie_vhtcap))
                return ENOBUFS;
            frm = ieee80211_add_vhtcaps(frm, ic);
            remain -= frm - pos;
        }
    }
    
    /* Send 11n IEs on both 2GHz and 5GHz bands. */
    preq->common_data.offset = htole16(frm - (uint8_t *)wh);
    pos = frm;
    if (ic->ic_flags & IEEE80211_F_HTON) {
        if (remain < sizeof(struct ieee80211_ie_htcap))
            return ENOBUFS;
        frm = ieee80211_add_htcaps(frm, ic);
        /* XXX add WME info? */
    }

    preq->common_data.len = htole16(frm - pos);
    
    return 0;
}

int ItlIwx::
iwx_config_umac_scan(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_scan_config *scan_config;
    int err;
    size_t cmd_size;
    struct iwx_host_cmd hcmd = {
        .id = iwx_cmd_id(IWX_SCAN_CFG_CMD, IWX_LONG_GROUP, 0),
        .flags = 0,
    };
    uint8_t cmdver;
    
    if (!isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_REDUCED_SCAN_CONFIG))
        return iwx_config_legacy_umac_scan(sc);
    
    cmd_size = sizeof(*scan_config);
    
    scan_config = (struct iwx_scan_config *)malloc(cmd_size, 0, M_ZERO);
    if (scan_config == NULL)
        return ENOMEM;
    
    scan_config->tx_chains = htole32(iwx_fw_valid_tx_ant(sc));
    scan_config->rx_chains = htole32(iwx_fw_valid_rx_ant(sc));
    
    cmdver = iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_ADD_STA);
    if (cmdver == IWX_FW_CMD_VER_UNKNOWN || cmdver < 12)
        scan_config->bcast_sta_id = IWX_AUX_STA_ID;
    else if (cmdver == IWX_FW_CMD_VER_UNKNOWN || cmdver < 5)
        scan_config->bcast_sta_id = 0xFF;
    
    hcmd.data[0] = scan_config;
    hcmd.len[0] = cmd_size;
    
    err = iwx_send_cmd(sc, &hcmd);
    ::free(scan_config);
    return err;
}

int ItlIwx::
iwx_config_legacy_umac_scan(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_scan_config_v2 *scan_config;
    struct ieee80211com *ic = &sc->sc_ic;
    int err, nchan;
    struct ieee80211_channel *c;
    size_t cmd_size;
    struct iwx_host_cmd hcmd = {
        .id = iwx_cmd_id(IWX_SCAN_CFG_CMD, IWX_LONG_GROUP, 0),
        .flags = 0,
    };
    static const uint32_t rates = (IWX_SCAN_CONFIG_RATE_1M |
                                   IWX_SCAN_CONFIG_RATE_2M | IWX_SCAN_CONFIG_RATE_5M |
                                   IWX_SCAN_CONFIG_RATE_11M | IWX_SCAN_CONFIG_RATE_6M |
                                   IWX_SCAN_CONFIG_RATE_9M | IWX_SCAN_CONFIG_RATE_12M |
                                   IWX_SCAN_CONFIG_RATE_18M | IWX_SCAN_CONFIG_RATE_24M |
                                   IWX_SCAN_CONFIG_RATE_36M | IWX_SCAN_CONFIG_RATE_48M |
                                   IWX_SCAN_CONFIG_RATE_54M);
    
    cmd_size = sizeof(*scan_config) + sc->sc_capa_n_scan_channels;
    
    scan_config = (struct iwx_scan_config_v2 *)malloc(cmd_size, 0, M_ZERO);
    if (scan_config == NULL)
        return ENOMEM;
    
    scan_config->tx_chains = htole32(iwx_fw_valid_tx_ant(sc));
    scan_config->rx_chains = htole32(iwx_fw_valid_rx_ant(sc));
    scan_config->legacy_rates = htole32(rates |
                                        IWX_SCAN_CONFIG_SUPPORTED_RATE(rates));
    
    /* These timings correspond to iwlwifi's UNASSOC scan. */
    scan_config->dwell.active = 10;
    scan_config->dwell.passive = 110;
    scan_config->dwell.fragmented = 44;
    scan_config->dwell.extended = 90;
    scan_config->out_of_channel_time[IWX_SCAN_LB_LMAC_IDX] = htole32(0);
    scan_config->out_of_channel_time[IWX_SCAN_HB_LMAC_IDX] = htole32(0);
    scan_config->suspend_time[IWX_SCAN_LB_LMAC_IDX] = htole32(0);
    scan_config->suspend_time[IWX_SCAN_HB_LMAC_IDX] = htole32(0);
    
    IEEE80211_ADDR_COPY(scan_config->mac_addr, sc->sc_ic.ic_myaddr);
    
    scan_config->bcast_sta_id = IWX_AUX_STA_ID;
    scan_config->channel_flags = 0;
    
    for (c = &ic->ic_channels[1], nchan = 0;
         c <= &ic->ic_channels[IEEE80211_CHAN_MAX] &&
         nchan < sc->sc_capa_n_scan_channels; c++) {
        if (c->ic_flags == 0)
            continue;
        scan_config->channel_array[nchan++] =
        ieee80211_mhz2ieee(c->ic_freq, 0);
    }
    
    scan_config->flags = htole32(IWX_SCAN_CONFIG_FLAG_ACTIVATE |
                                 IWX_SCAN_CONFIG_FLAG_ALLOW_CHUB_REQS |
                                 IWX_SCAN_CONFIG_FLAG_SET_TX_CHAINS |
                                 IWX_SCAN_CONFIG_FLAG_SET_RX_CHAINS |
                                 IWX_SCAN_CONFIG_FLAG_SET_AUX_STA_ID |
                                 IWX_SCAN_CONFIG_FLAG_SET_ALL_TIMES |
                                 IWX_SCAN_CONFIG_FLAG_SET_LEGACY_RATES |
                                 IWX_SCAN_CONFIG_FLAG_SET_MAC_ADDR |
                                 IWX_SCAN_CONFIG_FLAG_SET_CHANNEL_FLAGS|
                                 IWX_SCAN_CONFIG_N_CHANNELS(nchan) |
                                 IWX_SCAN_CONFIG_FLAG_CLEAR_FRAGMENTED);
    
    scan_config->channel_flags = IWX_CHANNEL_FLAG_EBS | 
    IWX_CHANNEL_FLAG_ACCURATE_EBS |
    IWX_CHANNEL_FLAG_EBS_ADD |
    IWX_CHANNEL_FLAG_PRE_SCAN_PASSIVE2ACTIVE;
    
    hcmd.data[0] = scan_config;
    hcmd.len[0] = cmd_size;
    
    err = iwx_send_cmd(sc, &hcmd);
    ::free(scan_config);
    return err;
}

int ItlIwx::
iwx_umac_scan_size(struct iwx_softc *sc)
{
    int base_size = IWX_SCAN_REQ_UMAC_SIZE_V1;
    int tail_size;
    uint8_t scan_ver = iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_SCAN_REQ_UMAC);
    
    if (scan_ver == 12)
        return sizeof(iwx_scan_req_umac_v12);
    else if (scan_ver == 14)
        return sizeof(iwx_scan_req_umac_v14);
    
    if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_ADAPTIVE_DWELL_V2))
        base_size = IWX_SCAN_REQ_UMAC_SIZE_V8;
    else if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_ADAPTIVE_DWELL))
        base_size = IWX_SCAN_REQ_UMAC_SIZE_V7;
    else
        base_size = IWX_SCAN_REQ_UMAC_SIZE_V6;
    
    if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_SCAN_EXT_CHAN_VER))
        tail_size = sizeof(struct iwx_scan_req_umac_tail_v2);
    else
        tail_size = sizeof(struct iwx_scan_req_umac_tail_v1);
    
    return base_size + sizeof(struct iwx_scan_channel_cfg_umac) *
    sc->sc_capa_n_scan_channels + tail_size;
}

struct iwx_scan_umac_chan_param *ItlIwx::
iwx_get_scan_req_umac_chan_param(struct iwx_softc *sc,
                                 struct iwx_scan_req_umac *req)
{
    if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_ADAPTIVE_DWELL_V2))
        return &req->v8.channel;
    
    if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_ADAPTIVE_DWELL))
        return &req->v7.channel;

    return &req->v6.channel;
}

void *ItlIwx::
iwx_get_scan_req_umac_data(struct iwx_softc *sc, struct iwx_scan_req_umac *req)
{
    if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_ADAPTIVE_DWELL_V2))
        return (void *)&req->v8.data;
    
    if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_ADAPTIVE_DWELL))
        return (void *)&req->v7.data;
    
    return (void *)&req->v6.data;
}

#define IWL_SCAN_DWELL_ACTIVE        10
#define IWL_SCAN_DWELL_PASSIVE        110
#define IWL_SCAN_DWELL_FRAGMENTED    44
#define IWL_SCAN_DWELL_EXTENDED        90
#define IWL_SCAN_NUM_OF_FRAGS        3
#define IWL_SCAN_LAST_2_4_CHN        14

/* adaptive dwell max budget time [TU] for full scan */
#define IWX_SCAN_ADWELL_MAX_BUDGET_FULL_SCAN 300
/* adaptive dwell max budget time [TU] for directed scan */
#define IWX_SCAN_ADWELL_MAX_BUDGET_DIRECTED_SCAN 100
/* adaptive dwell default high band APs number */
#define IWX_SCAN_ADWELL_DEFAULT_HB_N_APS 8
/* adaptive dwell default low band APs number */
#define IWX_SCAN_ADWELL_DEFAULT_LB_N_APS 2
/* adaptive dwell default APs number in social channels (1, 6, 11) */
#define IWX_SCAN_ADWELL_DEFAULT_N_APS_SOCIAL 10
/* number of scan channels */
#define IWX_SCAN_NUM_CHANNELS 112
/* adaptive dwell number of APs override mask for p2p friendly GO */
#define IWX_SCAN_ADWELL_N_APS_GO_FRIENDLY_BIT (1 << 20)
/* adaptive dwell number of APs override mask for social channels */
#define IWX_SCAN_ADWELL_N_APS_SOCIAL_CHS_BIT (1 << 21)
/* adaptive dwell number of APs override for p2p friendly GO channels */
#define IWX_SCAN_ADWELL_N_APS_GO_FRIENDLY 10
/* adaptive dwell number of APs override for social channels */
#define IWX_SCAN_ADWELL_N_APS_SOCIAL_CHS 2

/* minimal number of 2GHz and 5GHz channels in the regular scan request */
#define IWX_MVM_6GHZ_PASSIVE_SCAN_MIN_CHANS 4

int ItlIwx::
iwx_umac_scan(struct iwx_softc *sc, int bgscan)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_host_cmd hcmd = {
        .id = iwx_cmd_id(IWX_SCAN_REQ_UMAC, IWX_LONG_GROUP, 0),
        .len = { 0, },
        .data = { NULL, },
        .flags = 0,
    };
    struct iwx_scan_req_umac *req;
    void *cmd_data, *tail_data;
    struct iwx_scan_req_umac_tail_v2 *tail;
    struct iwx_scan_req_umac_tail_v1 *tailv1;
    struct iwx_scan_umac_chan_param *chanparam;
    size_t req_len;
    int err, async = bgscan;
    const uint32_t timeout = bgscan ?  htole32(120) : htole32(0);
    uint8_t scan_ver = iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_SCAN_REQ_UMAC);
    
    if (scan_ver == 12)
        return iwx_umac_scan_v12(sc, bgscan);
    else if (scan_ver == 14)
        return iwx_umac_scan_v14(sc, bgscan);
    
    req_len = iwx_umac_scan_size(sc);
    if ((req_len < IWX_SCAN_REQ_UMAC_SIZE_V1 +
         sizeof(struct iwx_scan_req_umac_tail_v1)) ||
        req_len > IWX_MAX_CMD_PAYLOAD_SIZE)
        return ERANGE;
    req = (struct iwx_scan_req_umac *)malloc(req_len, 0,
                                             (async ? M_NOWAIT : M_WAITOK) | M_ZERO);
    if (req == NULL)
        return ENOMEM;
    
    hcmd.len[0] = (uint16_t)req_len;
    hcmd.data[0] = (void *)req;
    hcmd.flags |= async ? IWX_CMD_ASYNC : 0;
    
    if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_ADAPTIVE_DWELL)) {
        req->v7.adwell_default_n_aps_social =
        IWX_SCAN_ADWELL_DEFAULT_N_APS_SOCIAL;
        req->v7.adwell_default_n_aps =
        IWX_SCAN_ADWELL_DEFAULT_LB_N_APS;
        
        if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_ADWELL_HB_DEF_N_AP))
            req->v9.adwell_default_hb_n_aps = IWX_SCAN_ADWELL_DEFAULT_HB_N_APS;
        
        if (ic->ic_des_esslen != 0 && !bgscan)
            req->v7.adwell_max_budget =
            htole16(IWX_SCAN_ADWELL_MAX_BUDGET_DIRECTED_SCAN);
        else
            req->v7.adwell_max_budget =
            htole16(IWX_SCAN_ADWELL_MAX_BUDGET_FULL_SCAN);
        
        req->v7.scan_priority = htole32(IWX_SCAN_PRIORITY_EXT_6);
        req->v7.max_out_time[IWX_SCAN_LB_LMAC_IDX] = timeout;
        req->v7.suspend_time[IWX_SCAN_LB_LMAC_IDX] = timeout;
        
        if (isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_CDB_SUPPORT)) {
            req->v7.max_out_time[IWX_SCAN_HB_LMAC_IDX] =
                timeout;
            req->v7.suspend_time[IWX_SCAN_HB_LMAC_IDX] =
                timeout;
        }
        
        if (isset(sc->sc_ucode_api,
                  IWX_UCODE_TLV_API_ADAPTIVE_DWELL_V2)) {
            req->v8.active_dwell[IWX_SCAN_LB_LMAC_IDX] = IWL_SCAN_DWELL_ACTIVE;
            req->v8.passive_dwell[IWX_SCAN_LB_LMAC_IDX] = IWL_SCAN_DWELL_PASSIVE;
            if (isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_CDB_SUPPORT)) {
                req->v8.active_dwell[IWX_SCAN_HB_LMAC_IDX] =
                    IWL_SCAN_DWELL_ACTIVE;
                req->v8.passive_dwell[IWX_SCAN_HB_LMAC_IDX] =
                    IWL_SCAN_DWELL_PASSIVE;
            }
        } else {
            req->v7.active_dwell = IWL_SCAN_DWELL_ACTIVE;
            req->v7.passive_dwell = IWL_SCAN_DWELL_PASSIVE;
            req->v7.fragmented_dwell = IWL_SCAN_DWELL_FRAGMENTED;
        }
    } else {
        /* These timings correspond to iwlwifi's UNASSOC scan. */
        req->v1.active_dwell = IWL_SCAN_DWELL_ACTIVE;
        req->v1.passive_dwell = IWL_SCAN_DWELL_PASSIVE;
        req->v1.fragmented_dwell = IWL_SCAN_DWELL_FRAGMENTED;
        req->v1.extended_dwell = IWL_SCAN_DWELL_EXTENDED;
        
        if (isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_CDB_SUPPORT)) {
            req->v6.max_out_time[IWX_SCAN_HB_LMAC_IDX] =
                timeout;
            req->v6.suspend_time[IWX_SCAN_HB_LMAC_IDX] =
                timeout;
        }
        
        req->v6.scan_priority =
            htole32(IWX_SCAN_PRIORITY_EXT_6);
        req->v6.max_out_time[IWX_SCAN_LB_LMAC_IDX] =
            timeout;
        req->v6.suspend_time[IWX_SCAN_LB_LMAC_IDX] =
            timeout;
    }
    
    req->ooc_priority = htole32(IWX_SCAN_PRIORITY_EXT_6);
    
    cmd_data = iwx_get_scan_req_umac_data(sc, req);
    chanparam = iwx_get_scan_req_umac_chan_param(sc, req);
    chanparam->count = iwx_umac_scan_fill_channels(sc,
                                                   (struct iwx_scan_channel_cfg_umac *)cmd_data,
                                                   ic->ic_des_esslen != 0, bgscan);
    chanparam->flags = 0;
    
    tail_data = (uint8_t*)cmd_data + sizeof(struct iwx_scan_channel_cfg_umac) *
    sc->sc_capa_n_scan_channels;
    tail = (struct iwx_scan_req_umac_tail_v2 *)tail_data;
    /* tail v1 layout differs in preq and direct_scan member fields. */
    tailv1 = (struct iwx_scan_req_umac_tail_v1 *)tail_data;
    
    req->general_flags = htole32(IWX_UMAC_SCAN_GEN_FLAGS_PASS_ALL |
                                 IWX_UMAC_SCAN_GEN_FLAGS_ITER_COMPLETE);
    if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_ADAPTIVE_DWELL_V2)) {
        req->v8.general_flags2 =
        IWX_UMAC_SCAN_GEN_FLAGS2_ALLOW_CHNL_REORDER;
    }
    
    /* Check if we're doing an active directed scan. */
    if (ic->ic_des_esslen != 0 && !bgscan) {
        if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_SCAN_EXT_CHAN_VER)) {
            tail->direct_scan[0].id = IEEE80211_ELEMID_SSID;
            tail->direct_scan[0].len = ic->ic_des_esslen;
            memcpy(tail->direct_scan[0].ssid, ic->ic_des_essid,
                   ic->ic_des_esslen);
        } else {
            tailv1->direct_scan[0].id = IEEE80211_ELEMID_SSID;
            tailv1->direct_scan[0].len = ic->ic_des_esslen;
            memcpy(tailv1->direct_scan[0].ssid, ic->ic_des_essid,
                   ic->ic_des_esslen);
        }
        req->general_flags |=
        htole32(IWX_UMAC_SCAN_GEN_FLAGS_PRE_CONNECT);
    } else
        req->general_flags |= htole32(IWX_UMAC_SCAN_GEN_FLAGS_PASSIVE);
    
    if (isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_DS_PARAM_SET_IE_SUPPORT) &&
        isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_WFA_TPC_REP_IE_SUPPORT))
        req->general_flags |=
        htole32(IWX_UMAC_SCAN_GEN_FLAGS_RRM_ENABLED);
    
    if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_ADAPTIVE_DWELL)) {
        req->general_flags |=
        htole32(IWX_UMAC_SCAN_GEN_FLAGS_ADAPTIVE_DWELL);
    } else {
        req->general_flags |=
        htole32(IWX_UMAC_SCAN_GEN_FLAGS_EXTENDED_DWELL);
    }
    
    if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_SCAN_EXT_CHAN_VER))
        err = iwx_fill_probe_req(sc, &tail->preq);
    else
        err = iwx_fill_probe_req_v1(sc, &tailv1->preq);
    if (err) {
        ::free(req);
        return err;
    }
    
    /* Specify the scan plan: We'll do one iteration. */
    tail->schedule[0].interval = 0;
    tail->schedule[0].iter_count = 1;
    
    err = iwx_send_cmd(sc, &hcmd);
    ::free(req);
    return err;
}

int ItlIwx::
iwx_umac_scan_v12(struct iwx_softc *sc, int bgscan)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    int err = 0, async = bgscan;
    struct iwx_scan_req_umac_v12 *req;
    size_t req_len;
    uint16_t gen_flags = 0;
    const uint32_t timeout = bgscan ?  htole32(120) : htole32(0);
    struct iwx_scan_general_params_v10 *general_params;
    struct iwx_scan_channel_params_v4 *cp;
    struct iwx_host_cmd hcmd = {
        .id = iwx_cmd_id(IWX_SCAN_REQ_UMAC, IWX_LONG_GROUP, 0),
        .len = { 0, },
        .data = { NULL, },
        .flags = 0,
    };
    
    req_len = iwx_umac_scan_size(sc);
    req = (struct iwx_scan_req_umac_v12 *)malloc(req_len, 0,
                                             (async ? M_NOWAIT : M_WAITOK) | M_ZERO);
    if (req == NULL)
        return ENOMEM;
    
    hcmd.len[0] = (uint16_t)req_len;
    hcmd.data[0] = (void *)req;
    hcmd.flags |= async ? IWX_CMD_ASYNC : 0;
    
    general_params = &req->scan_params.general_params;
    
    req->ooc_priority = htole32(IWX_SCAN_PRIORITY_EXT_6);
    
    if (ic->ic_des_esslen == 0 || bgscan)
        gen_flags |= IWX_UMAC_SCAN_GEN_FLAGS_V2_FORCE_PASSIVE;
    
    gen_flags |= IWX_UMAC_SCAN_GEN_FLAGS_V2_PASS_ALL |
    IWX_UMAC_SCAN_GEN_FLAGS_V2_ADAPTIVE_DWELL;
    
    req->scan_params.general_params.flags = gen_flags;
    
    general_params->adwell_default_social_chn =
        IWX_SCAN_ADWELL_DEFAULT_N_APS_SOCIAL;
    general_params->adwell_default_2g = IWX_SCAN_ADWELL_DEFAULT_LB_N_APS;
    general_params->adwell_default_5g = IWX_SCAN_ADWELL_DEFAULT_HB_N_APS;

    if (ic->ic_des_esslen != 0 && !bgscan)
        general_params->adwell_max_budget =
            cpu_to_le16(IWX_SCAN_ADWELL_MAX_BUDGET_DIRECTED_SCAN);
    else
        general_params->adwell_max_budget =
            cpu_to_le16(IWX_SCAN_ADWELL_MAX_BUDGET_FULL_SCAN);
    
    general_params->scan_priority = htole32(IWX_SCAN_PRIORITY_EXT_6);
    general_params->max_out_of_time[IWX_SCAN_LB_LMAC_IDX] =
        timeout;
    general_params->suspend_time[IWX_SCAN_LB_LMAC_IDX] =
        timeout;
    
    general_params->max_out_of_time[IWX_SCAN_HB_LMAC_IDX] =
        timeout;
    general_params->suspend_time[IWX_SCAN_HB_LMAC_IDX] =
        timeout;

    general_params->active_dwell[IWX_SCAN_LB_LMAC_IDX] = IWL_SCAN_DWELL_ACTIVE;
    general_params->passive_dwell[IWX_SCAN_LB_LMAC_IDX] = IWL_SCAN_DWELL_PASSIVE;
    general_params->active_dwell[IWX_SCAN_HB_LMAC_IDX] = IWL_SCAN_DWELL_ACTIVE;
    general_params->passive_dwell[IWX_SCAN_HB_LMAC_IDX] = IWL_SCAN_DWELL_PASSIVE;
    
    /* Specify the scan plan: We'll do one iteration. */
    req->scan_params.periodic_params.schedule[0].interval = 0;
    req->scan_params.periodic_params.schedule[0].iter_count = 1;
    
    err = iwx_fill_probe_req(sc, &req->scan_params.probe_params.preq);
    if (err)
        return err;

    if (ic->ic_des_esslen != 0 && !bgscan) {
        req->scan_params.probe_params.ssid_num = 1;
        req->scan_params.probe_params.direct_scan[0].id = IEEE80211_ELEMID_SSID;
        req->scan_params.probe_params.direct_scan[0].len = ic->ic_des_esslen;
        memcpy(req->scan_params.probe_params.direct_scan[0].ssid, ic->ic_des_essid,
               ic->ic_des_esslen);
    } else
        req->scan_params.probe_params.ssid_num = 0;
    
    cp = &req->scan_params.channel_params;
    
    cp->flags = IWX_SCAN_CHANNEL_FLAG_ENABLE_CHAN_ORDER;
    cp->count = iwx_umac_scan_fill_channels(sc,
                                            (struct iwx_scan_channel_cfg_umac *)cp->channel_config,
                                            ic->ic_des_esslen != 0, bgscan);
    cp->num_of_aps_override = IWX_SCAN_ADWELL_N_APS_GO_FRIENDLY;
    
    err = iwx_send_cmd(sc, &hcmd);
    ::free(req);
    return err;
}

int ItlIwx::
iwx_umac_scan_v14(struct iwx_softc *sc, int bgscan)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    int err = 0, async = bgscan;
    struct iwx_scan_req_umac_v14 *req;
    size_t req_len;
    uint16_t gen_flags = 0;
    struct iwx_scan_general_params_v10 *general_params;
    struct iwx_scan_channel_params_v6 *cp;
    const uint32_t timeout = bgscan ?  htole32(120) : htole32(0);
    struct iwx_host_cmd hcmd = {
        .id = iwx_cmd_id(IWX_SCAN_REQ_UMAC, IWX_LONG_GROUP, 0),
        .len = { 0, },
        .data = { NULL, },
        .flags = 0,
    };
    
    req_len = iwx_umac_scan_size(sc);
    req = (struct iwx_scan_req_umac_v14 *)malloc(req_len, 0,
                                             (async ? M_NOWAIT : M_WAITOK) | M_ZERO);
    if (req == NULL)
        return ENOMEM;
    
    hcmd.len[0] = (uint16_t)req_len;
    hcmd.data[0] = (void *)req;
    hcmd.flags |= async ? IWX_CMD_ASYNC : 0;
    
    general_params = &req->scan_params.general_params;
    
    req->ooc_priority = htole32(IWX_SCAN_PRIORITY_EXT_6);
    
    if (ic->ic_des_esslen == 0 || bgscan)
        gen_flags |= IWX_UMAC_SCAN_GEN_FLAGS_V2_FORCE_PASSIVE;
    
    gen_flags |= IWX_UMAC_SCAN_GEN_FLAGS_V2_PASS_ALL |
    IWX_UMAC_SCAN_GEN_FLAGS_V2_ADAPTIVE_DWELL;
    
    req->scan_params.general_params.flags = gen_flags;
    
    general_params->adwell_default_social_chn =
        IWX_SCAN_ADWELL_DEFAULT_N_APS_SOCIAL;
    general_params->adwell_default_2g = IWX_SCAN_ADWELL_DEFAULT_LB_N_APS;
    general_params->adwell_default_5g = IWX_SCAN_ADWELL_DEFAULT_HB_N_APS;
    if (ic->ic_des_esslen != 0 && !bgscan)
        general_params->adwell_max_budget =
            cpu_to_le16(IWX_SCAN_ADWELL_MAX_BUDGET_DIRECTED_SCAN);
    else
        general_params->adwell_max_budget =
            cpu_to_le16(IWX_SCAN_ADWELL_MAX_BUDGET_FULL_SCAN);
    
    general_params->scan_priority = htole32(IWX_SCAN_PRIORITY_EXT_6);
    general_params->max_out_of_time[IWX_SCAN_LB_LMAC_IDX] =
        timeout;
    general_params->suspend_time[IWX_SCAN_LB_LMAC_IDX] =
        timeout;
    
    general_params->max_out_of_time[IWX_SCAN_HB_LMAC_IDX] =
        timeout;
    general_params->suspend_time[IWX_SCAN_HB_LMAC_IDX] =
        timeout;

    general_params->active_dwell[IWX_SCAN_LB_LMAC_IDX] = IWL_SCAN_DWELL_ACTIVE;
    general_params->passive_dwell[IWX_SCAN_LB_LMAC_IDX] = IWL_SCAN_DWELL_PASSIVE;
    general_params->active_dwell[IWX_SCAN_HB_LMAC_IDX] = IWL_SCAN_DWELL_ACTIVE;
    general_params->passive_dwell[IWX_SCAN_HB_LMAC_IDX] = IWL_SCAN_DWELL_PASSIVE;
    
    /* Specify the scan plan: We'll do one iteration. */
    req->scan_params.periodic_params.schedule[0].interval = 0;
    req->scan_params.periodic_params.schedule[0].iter_count = 1;
    
    err = iwx_fill_probe_req(sc, &req->scan_params.probe_params.preq);
    if (err)
        return err;
    if (ic->ic_des_esslen != 0 && !bgscan) {
        req->scan_params.probe_params.direct_scan[0].id = IEEE80211_ELEMID_SSID;
        req->scan_params.probe_params.direct_scan[0].len = ic->ic_des_esslen;
        memcpy(req->scan_params.probe_params.direct_scan[0].ssid, ic->ic_des_essid,
               ic->ic_des_esslen);
    }
    
    cp = &req->scan_params.channel_params;
    
    cp->flags = IWX_SCAN_CHANNEL_FLAG_ENABLE_CHAN_ORDER;
    cp->count = iwx_umac_scan_fill_channels(sc,
                                            (struct iwx_scan_channel_cfg_umac *)cp->channel_config,
                                            ic->ic_des_esslen != 0, bgscan);
    cp->n_aps_override[0] = IWX_SCAN_ADWELL_N_APS_GO_FRIENDLY;
    cp->n_aps_override[1] = IWX_SCAN_ADWELL_N_APS_SOCIAL_CHS;
    
    err = iwx_send_cmd(sc, &hcmd);
    ::free(req);
    return err;
}

void ItlIwx::
iwx_mcc_update(struct iwx_softc *sc, struct iwx_mcc_chub_notif *notif)
{
   struct ieee80211com *ic = &sc->sc_ic;
   struct _ifnet *ifp = IC2IFP(ic);

    snprintf(sc->sc_fw_mcc, sizeof(sc->sc_fw_mcc), "%c%c",
             (le16toh(notif->mcc) & 0xff00) >> 8, le16toh(notif->mcc) & 0xff);
    if (sc->sc_fw_mcc_int != notif->mcc && sc->sc_ic.ic_event_handler) {
        (*sc->sc_ic.ic_event_handler)(&sc->sc_ic, IEEE80211_EVT_COUNTRY_CODE_UPDATE, NULL);
    }
    sc->sc_fw_mcc_int = notif->mcc;

    if (ifp->if_flags & IFF_DEBUG) {
        DPRINTFN(3, ("%s: firmware has detected regulatory domain '%s' "
               "(0x%x)\n", DEVNAME(sc), sc->sc_fw_mcc, le16toh(notif->mcc)));
    }

   /* TODO: Schedule a task to send MCC_UPDATE_CMD? */
}

uint8_t ItlIwx::
iwx_ridx2rate(struct ieee80211_rateset *rs, int ridx)
{
    int i;
    uint8_t rval;
    
    for (i = 0; i < rs->rs_nrates; i++) {
        rval = (rs->rs_rates[i] & IEEE80211_RATE_VAL);
        if (rval == iwx_rates[ridx].rate)
            return rs->rs_rates[i];
    }
    
    return 0;
}

int ItlIwx::
iwx_rval2ridx(int rval)
{
    int ridx;
    
    for (ridx = 0; ridx < nitems(iwx_rates); ridx++) {
        if (iwx_rates[ridx].plcp == IWX_RATE_INVM_PLCP)
            continue;
        if (rval == iwx_rates[ridx].rate)
            break;
    }
    
    return ridx;
}

int ItlIwx::
iwx_rate2idx(int rate)
{
    const struct ieee80211_rateset *rs = &ieee80211_std_rateset_11a;
    int idx;
    
    for (idx = 0; idx < rs->rs_nrates; idx++) {
        if (rs->rs_rates[idx] == rate)
            return idx;
    }
    
    return 0;
}

void ItlIwx::
iwx_ack_rates(struct iwx_softc *sc, struct iwx_node *in, int *cck_rates,
              int *ofdm_rates)
{
    struct ieee80211_node *ni = &in->in_ni;
    struct ieee80211_rateset *rs = &ni->ni_rates;
    int lowest_present_ofdm = -1;
    int lowest_present_cck = -1;
    uint8_t cck = 0;
    uint8_t ofdm = 0;
    int i;
    
    if (ni->ni_chan == IEEE80211_CHAN_ANYC ||
        IEEE80211_IS_CHAN_2GHZ(ni->ni_chan)) {
        for (i = IWX_FIRST_CCK_RATE; i < IWX_FIRST_OFDM_RATE; i++) {
            if ((iwx_ridx2rate(rs, i) & IEEE80211_RATE_BASIC) == 0)
                continue;
            cck |= (1 << i);
            if (lowest_present_cck == -1 || lowest_present_cck > i)
                lowest_present_cck = i;
        }
    }
    for (i = IWX_FIRST_OFDM_RATE; i <= IWX_LAST_NON_HT_RATE; i++) {
        if ((iwx_ridx2rate(rs, i) & IEEE80211_RATE_BASIC) == 0)
            continue;
        ofdm |= (1 << (i - IWX_FIRST_OFDM_RATE));
        if (lowest_present_ofdm == -1 || lowest_present_ofdm > i)
            lowest_present_ofdm = i;
    }
    
    /*
     * Now we've got the basic rates as bitmaps in the ofdm and cck
     * variables. This isn't sufficient though, as there might not
     * be all the right rates in the bitmap. E.g. if the only basic
     * rates are 5.5 Mbps and 11 Mbps, we still need to add 1 Mbps
     * and 6 Mbps because the 802.11-2007 standard says in 9.6:
     *
     *    [...] a STA responding to a received frame shall transmit
     *    its Control Response frame [...] at the highest rate in the
     *    BSSBasicRateSet parameter that is less than or equal to the
     *    rate of the immediately previous frame in the frame exchange
     *    sequence ([...]) and that is of the same modulation class
     *    ([...]) as the received frame. If no rate contained in the
     *    BSSBasicRateSet parameter meets these conditions, then the
     *    control frame sent in response to a received frame shall be
     *    transmitted at the highest mandatory rate of the PHY that is
     *    less than or equal to the rate of the received frame, and
     *    that is of the same modulation class as the received frame.
     *
     * As a consequence, we need to add all mandatory rates that are
     * lower than all of the basic rates to these bitmaps.
     */
    
    if (IWX_RATE_24M_INDEX < lowest_present_ofdm)
        ofdm |= IWX_RATE_BIT_MSK(24) >> IWX_FIRST_OFDM_RATE;
    if (IWX_RATE_12M_INDEX < lowest_present_ofdm)
        ofdm |= IWX_RATE_BIT_MSK(12) >> IWX_FIRST_OFDM_RATE;
    /* 6M already there or needed so always add */
    ofdm |= IWX_RATE_BIT_MSK(6) >> IWX_FIRST_OFDM_RATE;
    
    /*
     * CCK is a bit more complex with DSSS vs. HR/DSSS vs. ERP.
     * Note, however:
     *  - if no CCK rates are basic, it must be ERP since there must
     *    be some basic rates at all, so they're OFDM => ERP PHY
     *    (or we're in 5 GHz, and the cck bitmap will never be used)
     *  - if 11M is a basic rate, it must be ERP as well, so add 5.5M
     *  - if 5.5M is basic, 1M and 2M are mandatory
     *  - if 2M is basic, 1M is mandatory
     *  - if 1M is basic, that's the only valid ACK rate.
     * As a consequence, it's not as complicated as it sounds, just add
     * any lower rates to the ACK rate bitmap.
     */
    if (IWX_RATE_11M_INDEX < lowest_present_cck)
        cck |= IWX_RATE_BIT_MSK(11) >> IWX_FIRST_CCK_RATE;
    if (IWX_RATE_5M_INDEX < lowest_present_cck)
        cck |= IWX_RATE_BIT_MSK(5) >> IWX_FIRST_CCK_RATE;
    if (IWX_RATE_2M_INDEX < lowest_present_cck)
        cck |= IWX_RATE_BIT_MSK(2) >> IWX_FIRST_CCK_RATE;
    /* 1M already there or needed so always add */
    cck |= IWX_RATE_BIT_MSK(1) >> IWX_FIRST_CCK_RATE;
    
    *cck_rates = cck;
    *ofdm_rates = ofdm;
}

static uint8_t iwx_mvm_mac80211_ac_to_ucode_ac(enum ieee80211_edca_ac ac)
{
   static const uint8_t mac80211_ac_to_ucode_ac[] = {
       IWX_AC_BE,
       IWX_AC_BK,
       IWX_AC_VI,
       IWX_AC_VO
   };

   return mac80211_ac_to_ucode_ac[ac];
}

void ItlIwx::
iwx_mac_ctxt_cmd_common(struct iwx_softc *sc, struct iwx_node *in,
                        struct iwx_mac_ctx_cmd *cmd, uint32_t action)
{
#define IWX_EXP2(x)    ((1 << (x)) - 1)    /* CWmin = 2^ECWmin - 1 */
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    int cck_ack_rates, ofdm_ack_rates;
    int i;
    
    cmd->id_and_color = htole32(IWX_FW_CMD_ID_AND_COLOR(in->in_id,
                                                        in->in_color));
    cmd->action = htole32(action);

    if (action == IWX_FW_CTXT_ACTION_REMOVE)
        return;

    if (ic->ic_opmode == IEEE80211_M_MONITOR)
        cmd->mac_type = htole32(IWX_FW_MAC_TYPE_LISTENER);
    else if (ic->ic_opmode == IEEE80211_M_STA)
        cmd->mac_type = htole32(IWX_FW_MAC_TYPE_BSS_STA);
    else
        panic("unsupported operating mode %d\n", ic->ic_opmode);
    cmd->tsf_id = htole32(IWX_TSF_ID_A);
    
    IEEE80211_ADDR_COPY(cmd->node_addr, ic->ic_myaddr);
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        IEEE80211_ADDR_COPY(cmd->bssid_addr, etherbroadcastaddr);
        return;
    }
    
    IEEE80211_ADDR_COPY(cmd->bssid_addr, in->in_macaddr);
    iwx_ack_rates(sc, in, &cck_ack_rates, &ofdm_ack_rates);
    cmd->cck_rates = htole32(cck_ack_rates);
    cmd->ofdm_rates = htole32(ofdm_ack_rates);
    
    cmd->cck_short_preamble
    = htole32((ic->ic_flags & IEEE80211_F_SHPREAMBLE)
              ? IWX_MAC_FLG_SHORT_PREAMBLE : 0);
    cmd->short_slot
    = htole32((ic->ic_flags & IEEE80211_F_SHSLOT)
              ? IWX_MAC_FLG_SHORT_SLOT : 0);
    
    for (i = 0; i < EDCA_NUM_AC; i++) {
        struct ieee80211_edca_ac_params *ac = &ic->ic_edca_ac[i];
        int txf = iwx_ac_to_tx_fifo[i];
        uint8_t ucode_ac = iwx_mvm_mac80211_ac_to_ucode_ac((enum ieee80211_edca_ac)i);
        
        cmd->ac[ucode_ac].cw_min = htole16(IWX_EXP2(ac->ac_ecwmin));
        cmd->ac[ucode_ac].cw_max = htole16(IWX_EXP2(ac->ac_ecwmax));
        cmd->ac[ucode_ac].aifsn = ac->ac_aifsn;
        cmd->ac[ucode_ac].fifos_mask = (1 << txf);
        cmd->ac[ucode_ac].edca_txop = htole16(ac->ac_txoplimit * 32);
    }
    if (ni->ni_flags & IEEE80211_NODE_QOS)
        cmd->qos_flags |= htole32(IWX_MAC_QOS_FLG_UPDATE_EDCA);
    
    if (ni->ni_flags & IEEE80211_NODE_HT) {
        enum ieee80211_htprot htprot =
        (enum ieee80211_htprot)(ni->ni_htop1 & IEEE80211_HTOP1_PROT_MASK);
        
        /* The fw does not distinguish between ht and fat */
        uint32_t ht_flag = IWX_MAC_PROT_FLG_HT_PROT | IWX_MAC_PROT_FLG_FAT_PROT;
        
        /*
         * See section 9.23.3.1 of IEEE 80211-2012.
         * Nongreenfield HT STAs Present is not supported.
         */
        switch (htprot) {
            case IEEE80211_HTPROT_NONE:
                break;
            case IEEE80211_HTPROT_NONMEMBER:
            case IEEE80211_HTPROT_NONHT_MIXED:
                cmd->protection_flags = htole32(ht_flag);
                break;
            case IEEE80211_HTPROT_20MHZ:
                /* Protect when channel wider than 20MHz */
                if (ni->ni_chw > IEEE80211_CHAN_WIDTH_20)
                    cmd->protection_flags = htole32(ht_flag);
                break;
            default:
                XYLog("Illegal protection mode %d\n", htprot);
                break;
        }
        
        cmd->qos_flags |= htole32(IWX_MAC_QOS_FLG_TGN);
    }
    if (ic->ic_flags & IEEE80211_F_USEPROT)
        cmd->protection_flags |= htole32(IWX_MAC_PROT_FLG_TGG_PROTECT);
    
    cmd->filter_flags = htole32(IWX_MAC_FILTER_ACCEPT_GRP);
#undef IWX_EXP2
}

void ItlIwx::
iwx_mac_ctxt_cmd_fill_sta(struct iwx_softc *sc, struct iwx_node *in,
                          struct iwx_mac_data_sta *sta, int assoc)
{
    struct ieee80211_node *ni = &in->in_ni;
    uint32_t dtim_off;
    uint64_t tsf;
    
    dtim_off = ni->ni_dtimcount * ni->ni_intval * IEEE80211_DUR_TU;
    memcpy(&tsf, ni->ni_tstamp, sizeof(tsf));
    tsf = letoh64(tsf);
    
    sta->is_assoc = htole32(assoc);
    sta->dtim_time = htole32(ni->ni_rstamp + dtim_off);
    sta->dtim_tsf = htole64(tsf + dtim_off);
    sta->bi = htole32(ni->ni_intval);
    sta->bi_reciprocal = htole32(iwx_reciprocal(ni->ni_intval));
    sta->dtim_interval = htole32(ni->ni_intval * ni->ni_dtimperiod);
    sta->dtim_reciprocal = htole32(iwx_reciprocal(sta->dtim_interval));
    sta->listen_interval = htole32(10);
    sta->assoc_id = htole32(ni->ni_associd);
    sta->assoc_beacon_arrive_time = htole32(ni->ni_rstamp);
}

int ItlIwx::
iwx_mac_ctxt_cmd(struct iwx_softc *sc, struct iwx_node *in, uint32_t action,
                 int assoc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    struct iwx_mac_ctx_cmd cmd;
    int active = (sc->sc_flags & IWX_FLAG_MAC_ACTIVE);
    
    if (action == IWX_FW_CTXT_ACTION_ADD && active) {
        XYLog("MAC already added\n");
        return 0;
    }
    if (action == IWX_FW_CTXT_ACTION_REMOVE && !active) {
        XYLog("MAC already removed\n");
        return 0;
    }
    
    memset(&cmd, 0, sizeof(cmd));
    
    iwx_mac_ctxt_cmd_common(sc, in, &cmd, action);

    if (action == IWX_FW_CTXT_ACTION_REMOVE) {
        return iwx_send_cmd_pdu(sc, IWX_MAC_CONTEXT_CMD, 0,
                                sizeof(cmd), &cmd);
    }

    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        cmd.filter_flags |= htole32(IWX_MAC_FILTER_IN_PROMISC |
                                    IWX_MAC_FILTER_IN_CONTROL_AND_MGMT |
                                    IWX_MAC_FILTER_ACCEPT_GRP |
                                    IWX_MAC_FILTER_IN_BEACON |
                                    IWX_MAC_FILTER_IN_PROBE_REQUEST |
                                    IWX_MAC_FILTER_IN_CRC32);
    } else if (!assoc || !ni->ni_associd || !ni->ni_dtimperiod)
    /*
     * Allow beacons to pass through as long as we are not
     * associated or we do not have dtim period information.
     */
        cmd.filter_flags |= htole32(IWX_MAC_FILTER_IN_BEACON);
    else
        iwx_mac_ctxt_cmd_fill_sta(sc, in, &cmd.sta, assoc);
    
    if (ni->ni_flags & IEEE80211_NODE_HE) {
        cmd.filter_flags |= htole32(IWX_MAC_FILTER_IN_11AX);
    }
    
    return iwx_send_cmd_pdu(sc, IWX_MAC_CONTEXT_CMD, 0, sizeof(cmd), &cmd);
}

int ItlIwx::
iwx_clear_statistics(struct iwx_softc *sc)
{
    struct iwx_statistics_cmd scmd = {
        .flags = htole32(IWX_STATISTICS_FLG_CLEAR)
    };
    struct iwx_host_cmd cmd = {
        .id = IWX_STATISTICS_CMD,
        .len[0] = sizeof(scmd),
        .data[0] = &scmd,
        .flags = IWX_CMD_WANT_RESP,
        .resp_pkt_len = sizeof(struct iwx_notif_statistics),
    };
    int err;
    
    err = iwx_send_cmd(sc, &cmd);
    if (err)
        return err;
    
    iwx_free_resp(sc, &cmd);
    return 0;
}

int ItlIwx::
iwx_update_quotas(struct iwx_softc *sc, struct iwx_node *in, int running)
{
    struct iwx_time_quota_cmd cmd;
    int i, idx, num_active_macs, quota, quota_rem;
    int colors[IWX_MAX_BINDINGS] = { -1, -1, -1, -1, };
    int n_ifs[IWX_MAX_BINDINGS] = {0, };
    uint16_t id;
    
    memset(&cmd, 0, sizeof(cmd));
    
    /* currently, PHY ID == binding ID */
    if (in && in->in_phyctxt) {
        id = in->in_phyctxt->id;
        KASSERT(id < IWX_MAX_BINDINGS, "id < IWX_MAX_BINDINGS");
        colors[id] = in->in_phyctxt->color;
        if (running)
            n_ifs[id] = 1;
    }
    
    /*
     * The FW's scheduling session consists of
     * IWX_MAX_QUOTA fragments. Divide these fragments
     * equally between all the bindings that require quota
     */
    num_active_macs = 0;
    for (i = 0; i < IWX_MAX_BINDINGS; i++) {
        cmd.quotas[i].id_and_color = htole32(IWX_FW_CTXT_INVALID);
        num_active_macs += n_ifs[i];
    }
    
    quota = 0;
    quota_rem = 0;
    if (num_active_macs) {
        quota = IWX_MAX_QUOTA / num_active_macs;
        quota_rem = IWX_MAX_QUOTA % num_active_macs;
    }
    
    for (idx = 0, i = 0; i < IWX_MAX_BINDINGS; i++) {
        if (colors[i] < 0)
            continue;
        
        cmd.quotas[idx].id_and_color =
        htole32(IWX_FW_CMD_ID_AND_COLOR(i, colors[i]));
        
        if (n_ifs[i] <= 0) {
            cmd.quotas[idx].quota = htole32(0);
            cmd.quotas[idx].max_duration = htole32(0);
        } else {
            cmd.quotas[idx].quota = htole32(quota * n_ifs[i]);
            cmd.quotas[idx].max_duration = htole32(0);
        }
        idx++;
    }
    
    /* Give the remainder of the session to the first binding */
    cmd.quotas[0].quota = htole32(le32toh(cmd.quotas[0].quota) + quota_rem);
    
    return iwx_send_cmd_pdu(sc, IWX_TIME_QUOTA_CMD, 0,
                            sizeof(cmd), &cmd);
}

void ItlIwx::
iwx_add_task(struct iwx_softc *sc, struct taskq *taskq, struct task *task)
{
    XYLog("%s %s\n", __FUNCTION__, task->name);
    int s = splnet();
    
    if (sc->sc_flags & IWX_FLAG_SHUTDOWN) {
        XYLog("%s %s sc->sc_flags & IWX_FLAG_SHUTDOWN\n", __FUNCTION__, task->name);
        splx(s);
        return;
    }
    
    //    refcnt_take(&sc->task_refs);
    if (!task_add(taskq, task)) {
        //        refcnt_rele_wake(&sc->task_refs);
    }
    splx(s);
}

void ItlIwx::
iwx_del_task(struct iwx_softc *sc, struct taskq *taskq, struct task *task)
{
    XYLog("%s %s\n", __FUNCTION__, task->name);
    if (task_del(taskq, task)) {
        //        refcnt_rele(&sc->task_refs);
    }
}

int ItlIwx::
iwx_scan(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = IC2IFP(ic);
    int err;
    
    if (sc->sc_flags & IWX_FLAG_BGSCAN) {
        err = iwx_scan_abort(sc);
        if (err) {
            XYLog("%s: could not abort background scan\n",
                  DEVNAME(sc));
            return err;
        }
    }
    
    err = iwx_umac_scan(sc, 0);
    if (err) {
        XYLog("%s: could not initiate scan\n", DEVNAME(sc));
        return err;
    }
    
    /*
     * The current mode might have been fixed during association.
     * Ensure all channels get scanned.
     */
    if (IFM_MODE(ic->ic_media.ifm_cur->ifm_media) == IFM_AUTO)
        ieee80211_setmode(ic, IEEE80211_MODE_AUTO);
    
    sc->sc_flags |= IWX_FLAG_SCANNING;
    if (ifp->if_flags & IFF_DEBUG)
        XYLog("%s: %s -> %s\n", ifp->if_xname,
              ieee80211_state_name[ic->ic_state],
              ieee80211_state_name[IEEE80211_S_SCAN]);
    if ((sc->sc_flags & IWX_FLAG_BGSCAN) == 0) {
        ieee80211_set_link_state(ic, LINK_STATE_DOWN);
        ieee80211_node_cleanup(ic, ic->ic_bss);
    }
    ic->ic_state = IEEE80211_S_SCAN;
    wakeupOn(&ic->ic_state); /* wake iwx_init() */
    
    return 0;
}

int ItlIwx::
iwx_bgscan(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_softc *sc = (struct iwx_softc *)IC2IFP(ic)->if_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    int err;
    
    if (sc->sc_flags & IWX_FLAG_SCANNING)
        return 0;
    
    err = that->iwx_umac_scan(sc, 1);
    if (err) {
        XYLog("%s: could not initiate scan\n", DEVNAME(sc));
        return err;
    }
    
    sc->sc_flags |= IWX_FLAG_BGSCAN;
    return 0;
}

int ItlIwx::
iwx_umac_scan_abort(struct iwx_softc *sc)
{
    struct iwx_umac_scan_abort cmd = { 0 };
    
    return iwx_send_cmd_pdu(sc,
                            IWX_WIDE_ID(IWX_LONG_GROUP, IWX_SCAN_ABORT_UMAC),
                            0, sizeof(cmd), &cmd);
}

int ItlIwx::
iwx_scan_abort(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int err;
    
    err = iwx_umac_scan_abort(sc);
    if (err == 0)
        sc->sc_flags &= ~(IWX_FLAG_SCANNING | IWX_FLAG_BGSCAN);
    return err;
}

int ItlIwx::
iwx_enable_mgmt_queue(struct iwx_softc *sc)
{
    int err;
    int cmdver;

    cmdver = iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP, IWX_ADD_STA);
    if (cmdver != IWX_FW_CMD_VER_UNKNOWN && cmdver >= 12)
        sc->first_data_qid = IWX_QID_MGMT - 1;
    else
        sc->first_data_qid = IWX_QID_MGMT;
    err = iwx_enable_txq(sc, IWX_STATION_ID,
                         sc->first_data_qid, IWX_MGMT_TID,
                         sc->txq[sc->first_data_qid].ring_count);
    if (err) {
        XYLog("%s: could not enable MGMT Tx queue %d (error %d)\n",
              DEVNAME(sc), sc->first_data_qid, err);
        return err;
    }
    
    return 0;
}

int ItlIwx::
iwx_rs_rval2idx(uint8_t rval)
{
   /* Firmware expects indices which match our 11g rate set. */
   const struct ieee80211_rateset *rs = &ieee80211_std_rateset_11g;
   int i;

   for (i = 0; i < rs->rs_nrates; i++) {
       if ((rs->rs_rates[i] & IEEE80211_RATE_VAL) == rval)
           return i;
   }

   return -1;
}

uint16_t ItlIwx::
iwx_rs_ht_rates(struct iwx_softc *sc, struct ieee80211_node *ni, int rsidx)
{
   struct ieee80211com *ic = &sc->sc_ic;
   const struct ieee80211_ht_rateset *rs;
   uint16_t htrates = 0;
   int mcs;

   rs = &ieee80211_std_ratesets_11n[rsidx];
   for (mcs = rs->min_mcs; mcs <= rs->max_mcs; mcs++) {
       if (!isset(ni->ni_rxmcs, mcs) ||
           !isset(ic->ic_sup_mcs, mcs))
           continue;
       htrates |= (1 << (mcs - rs->min_mcs));
   }

   return htrates;
}

static uint8_t iwx_rs_fw_bw_from_sta_bw(uint8_t bw)
{
    uint8_t fw_bw;
    switch (bw) {
        case IEEE80211_CHAN_WIDTH_20:
            fw_bw = IWX_TLC_MNG_CH_WIDTH_20MHZ;
            break;
        case IEEE80211_CHAN_WIDTH_40:
            fw_bw = IWX_TLC_MNG_CH_WIDTH_40MHZ;
            break;
        case IEEE80211_CHAN_WIDTH_80:
            fw_bw = IWX_TLC_MNG_CH_WIDTH_80MHZ;
            break;
        case IEEE80211_CHAN_WIDTH_80P80:
        case IEEE80211_CHAN_WIDTH_160:
            fw_bw = IWX_TLC_MNG_CH_WIDTH_160MHZ;
            break;
        default:
            fw_bw = IWX_TLC_MNG_CH_WIDTH_20MHZ;
            break;
    }
    return fw_bw;
}

uint16_t ItlIwx::
iwx_rs_fw_get_config_flags(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    uint16_t flags = 0;
    
    if (ic->ic_state < IEEE80211_S_ASSOC) {
        return flags;
    }
    
    if (iwx_num_of_ant(iwx_fw_valid_tx_ant(sc)) > 1) {
        if ((ni->ni_flags & IEEE80211_NODE_HE) &&
            ni->ni_he_cap_elem.phy_cap_info[2] &
            IEEE80211_HE_PHY_CAP2_STBC_RX_UNDER_80MHZ) {
            flags |= IWX_TLC_MNG_CFG_FLAGS_STBC_MSK;
        } else if (ni->ni_vhtcaps & IEEE80211_VHTCAP_RXSTBC_MASK)
            flags |= IWX_TLC_MNG_CFG_FLAGS_STBC_MSK;
        else if (ni->ni_htcaps & IEEE80211_HTCAP_RXSTBC_MASK)
            flags |= IWX_TLC_MNG_CFG_FLAGS_STBC_MSK;
    }
    
    if (((ni->ni_htcaps & IEEE80211_HTCAP_LDPC) ||
         ((ic->ic_flags & IEEE80211_F_VHTON) && (ni->ni_vhtcaps & IEEE80211_VHTCAP_RXLDPC))))
        flags |= IWX_TLC_MNG_CFG_FLAGS_LDPC_MSK;
    
    /* consider LDPC support in case of HE */
    if ((ni->ni_flags & IEEE80211_NODE_HE) &&
        (ni->ni_he_cap_elem.phy_cap_info[1] &
        IEEE80211_HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD))
        flags |= IWX_TLC_MNG_CFG_FLAGS_LDPC_MSK;
    
    if ((ni->ni_flags & IEEE80211_NODE_HE) &&
        !(ni->ni_he_cap_elem.phy_cap_info[1] &
         IEEE80211_HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD))
        flags &= ~IWX_TLC_MNG_CFG_FLAGS_LDPC_MSK;

    if ((ni->ni_flags & IEEE80211_NODE_HE) &&
        (ni->ni_he_cap_elem.phy_cap_info[3] &
         IEEE80211_HE_PHY_CAP3_DCM_MAX_CONST_RX_MASK))
        flags |= IWX_TLC_MNG_CFG_FLAGS_HE_DCM_NSS_1_MSK;
    
    return flags;
}

static
int rs_fw_vht_highest_rx_mcs_index(struct iwx_softc *sc,
                   int nss)
{
    uint16_t rx_mcs = le16toh(sc->sc_ic.ic_bss->ni_vht_mcsinfo.rx_mcs_map) &
        (0x3 << (2 * (nss - 1)));
    rx_mcs >>= (2 * (nss - 1));

    switch (rx_mcs) {
    case IEEE80211_VHT_MCS_SUPPORT_0_7:
        return IWX_TLC_MNG_HT_RATE_MCS7;
    case IEEE80211_VHT_MCS_SUPPORT_0_8:
        return IWX_TLC_MNG_HT_RATE_MCS8;
    case IEEE80211_VHT_MCS_SUPPORT_0_9:
        return IWX_TLC_MNG_HT_RATE_MCS9;
    default:
        WARN_ON_ONCE(1);
        break;
    }

    return 0;
}

static void
iwx_rs_fw_vht_set_enabled_rates(struct iwx_softc *sc,
                struct iwx_tlc_config_cmd_v4 *cmd)
{
    uint16_t supp;
    int i, highest_mcs;
    struct ieee80211com *ic = &sc->sc_ic;

    for (i = 0; i < IWX_TLC_NSS_MAX && i < ic->ic_bss->ni_rx_nss; i++) {
        highest_mcs = rs_fw_vht_highest_rx_mcs_index(sc, i + 1);
        if (!highest_mcs)
            continue;

        supp = (1 << (highest_mcs + 1)) - 1;
        if (ic->ic_bss->ni_chw == IEEE80211_CHAN_WIDTH_20)
            supp &= ~(1 << IWX_TLC_MNG_HT_RATE_MCS9);

        cmd->ht_rates[i][IWX_TLC_MCS_PER_BW_80] = htole16(supp);
        if (ic->ic_bss->ni_chw == IEEE80211_CHAN_WIDTH_80P80 || ic->ic_bss->ni_chw == IEEE80211_CHAN_WIDTH_160)
            cmd->ht_rates[i][1] = cmd->ht_rates[i][0];
    }
}

static uint16_t rs_fw_he_ieee80211_mcs_to_rs_mcs(uint16_t mcs)
{
    switch (mcs) {
    case IEEE80211_HE_MCS_SUPPORT_0_7:
        return BIT(IWX_TLC_MNG_HT_RATE_MCS7 + 1) - 1;
    case IEEE80211_HE_MCS_SUPPORT_0_9:
        return BIT(IWX_TLC_MNG_HT_RATE_MCS9 + 1) - 1;
    case IEEE80211_HE_MCS_SUPPORT_0_11:
        return BIT(IWX_TLC_MNG_HT_RATE_MCS11 + 1) - 1;
    case IEEE80211_HE_MCS_NOT_SUPPORTED:
        return 0;
    }

    XYLog("invalid HE MCS %d\n", mcs);
    return 0;
}

static uint8_t iwx_rs_fw_set_active_chains(uint8_t chains)
{
    uint8_t fw_chains = 0;

    if (chains & IWX_ANT_A)
        fw_chains |= IWX_TLC_MNG_CHAIN_A_MSK;
    if (chains & IWX_ANT_B)
        fw_chains |= IWX_TLC_MNG_CHAIN_B_MSK;

    return fw_chains;
}

static void
iwx_rs_fw_he_set_enabled_rates(struct iwx_softc *sc,
                           struct iwx_tlc_config_cmd_v4 *cmd)
{
    struct ieee80211com *ic = &sc->sc_ic;
    uint16_t mcs_160 = le16toh(ic->ic_he_mcs_nss_supp.rx_mcs_160);
    uint16_t mcs_80 = le16toh(ic->ic_he_mcs_nss_supp.rx_mcs_80);
    uint16_t tx_mcs_80 =
    le16toh(ic->ic_he_mcs_nss_supp.tx_mcs_80);
    uint16_t tx_mcs_160 =
    le16toh(ic->ic_he_mcs_nss_supp.tx_mcs_160);
    int i;
    uint8_t nss = ic->ic_bss->ni_rx_nss;

    for (i = 0; i < nss && i < IWX_TLC_NSS_MAX; i++) {
        uint16_t _mcs_160 = (mcs_160 >> (2 * i)) & 0x3;
        uint16_t _mcs_80 = (mcs_80 >> (2 * i)) & 0x3;
        uint16_t _tx_mcs_160 = (tx_mcs_160 >> (2 * i)) & 0x3;
        uint16_t _tx_mcs_80 = (tx_mcs_80 >> (2 * i)) & 0x3;

        /* If one side doesn't support - mark both as not supporting */
        if (_mcs_80 == IEEE80211_HE_MCS_NOT_SUPPORTED ||
            _tx_mcs_80 == IEEE80211_HE_MCS_NOT_SUPPORTED) {
            _mcs_80 = IEEE80211_HE_MCS_NOT_SUPPORTED;
            _tx_mcs_80 = IEEE80211_HE_MCS_NOT_SUPPORTED;
        }
        if (_mcs_80 > _tx_mcs_80)
            _mcs_80 = _tx_mcs_80;
        cmd->ht_rates[i][IWX_TLC_MCS_PER_BW_80] =
            htole16(rs_fw_he_ieee80211_mcs_to_rs_mcs(_mcs_80));

        /* If one side doesn't support - mark both as not supporting */
        if (_mcs_160 == IEEE80211_HE_MCS_NOT_SUPPORTED ||
            _tx_mcs_160 == IEEE80211_HE_MCS_NOT_SUPPORTED) {
            _mcs_160 = IEEE80211_HE_MCS_NOT_SUPPORTED;
            _tx_mcs_160 = IEEE80211_HE_MCS_NOT_SUPPORTED;
        }
        if (_mcs_160 > _tx_mcs_160)
            _mcs_160 = _tx_mcs_160;
        cmd->ht_rates[i][IWX_TLC_MCS_PER_BW_160] =
        htole16(rs_fw_he_ieee80211_mcs_to_rs_mcs(_mcs_160));
    }
}

int ItlIwx::
iwx_rs_init(struct iwx_softc *sc, struct iwx_node *in, bool update)
{
    struct ieee80211_node *ni = &in->in_ni;
    struct ieee80211_rateset *rs = &ni->ni_rates;
    struct iwx_tlc_config_cmd_v4 cfg_cmd;
    uint32_t cmd_id;
    int i;
    uint16_t cmd_size;
    uint8_t cmdver;

    memset(&cfg_cmd, 0, sizeof(cfg_cmd));

    for (i = 0; i < rs->rs_nrates; i++) {
        uint8_t rval = rs->rs_rates[i] & IEEE80211_RATE_VAL;
        int idx = iwx_rs_rval2idx(rval);
        if (idx == -1)
            return EINVAL;
        cfg_cmd.non_ht_rates |= (1 << idx);
    }
    if (ni->ni_flags & IEEE80211_NODE_HE) {
        cfg_cmd.mode = IWX_TLC_MNG_MODE_HE;
        iwx_rs_fw_he_set_enabled_rates(sc, &cfg_cmd);
    } else if (ni->ni_flags & IEEE80211_NODE_VHT) {
        cfg_cmd.mode = IWX_TLC_MNG_MODE_VHT;
        iwx_rs_fw_vht_set_enabled_rates(sc, &cfg_cmd);
    } else if (ni->ni_flags & IEEE80211_NODE_HT) {
        cfg_cmd.mode = IWX_TLC_MNG_MODE_HT;
        cfg_cmd.ht_rates[IWX_TLC_NSS_1][IWX_TLC_MCS_PER_BW_80] = htole16(iwx_rs_ht_rates(sc, ni, ni->ni_chw == IEEE80211_CHAN_WIDTH_40 ? IEEE80211_HT_RATESET_CBW40_SISO : IEEE80211_HT_RATESET_SISO));
        if (ni->ni_rx_nss > 1)
            cfg_cmd.ht_rates[IWX_TLC_NSS_2][IWX_TLC_MCS_PER_BW_80] = htole16(iwx_rs_ht_rates(sc, ni, ni->ni_chw == IEEE80211_CHAN_WIDTH_40 ? IEEE80211_HT_RATESET_CBW40_MIMO2 : IEEE80211_HT_RATESET_MIMO2));
    } else
        cfg_cmd.mode = IWX_TLC_MNG_MODE_NON_HT;

    cfg_cmd.sta_id = IWX_STATION_ID;
    cfg_cmd.max_ch_width = update ? iwx_rs_fw_bw_from_sta_bw(ni->ni_chw) : IWX_RATE_MCS_CHAN_WIDTH_20;
    cfg_cmd.chains = iwx_rs_fw_set_active_chains(iwx_fw_valid_tx_ant(sc));
    cfg_cmd.flags = iwx_rs_fw_get_config_flags(sc);
    if ((ni->ni_flags & IEEE80211_NODE_HE) == 0) {
        if (ieee80211_node_supports_ht_sgi20(ni))
            cfg_cmd.sgi_ch_width_supp = (1 << IWX_TLC_MNG_CH_WIDTH_20MHZ);

        if (ieee80211_node_supports_ht_sgi40(ni))
            cfg_cmd.sgi_ch_width_supp |= (1 << IWX_TLC_MNG_CH_WIDTH_40MHZ);
        
        if (ieee80211_node_supports_vht_sgi80(ni)) {
            cfg_cmd.sgi_ch_width_supp |= (1 << IWX_TLC_MNG_CH_WIDTH_80MHZ);
        }
        
        if (ieee80211_node_supports_vht_sgi160(ni)) {
            cfg_cmd.sgi_ch_width_supp |= (1 << IWX_TLC_MNG_CH_WIDTH_160MHZ);
        }
    }

    cmd_id = iwx_cmd_id(IWX_TLC_MNG_CONFIG_CMD, IWX_DATA_PATH_GROUP, 0);
    cmdver = iwx_lookup_cmd_ver(sc, IWX_DATA_PATH_GROUP, IWX_TLC_MNG_CONFIG_CMD);
    XYLog("%s cmdver %d\n", __FUNCTION__, cmdver);
    if (cmdver == 4) {
        return iwx_send_cmd_pdu(sc, cmd_id, IWX_CMD_ASYNC,
                                sizeof(cfg_cmd), &cfg_cmd);
    } else if (cmdver < 4 || cmdver == IWX_FW_CMD_VER_UNKNOWN) {
        struct iwl_tlc_config_cmd_v3 cfg_cmd_v3 = {
            .sta_id = cfg_cmd.sta_id,
            .max_ch_width = cfg_cmd.max_ch_width,
            .mode = cfg_cmd.mode,
            .chains = cfg_cmd.chains,
            .amsdu = !!cfg_cmd.max_mpdu_len,
            .flags = cfg_cmd.flags,
            .non_ht_rates = cfg_cmd.non_ht_rates,
            .ht_rates[0][0] = cfg_cmd.ht_rates[0][0],
            .ht_rates[0][1] = cfg_cmd.ht_rates[0][1],
            .ht_rates[1][0] = cfg_cmd.ht_rates[1][0],
            .ht_rates[1][1] = cfg_cmd.ht_rates[1][1],
            .sgi_ch_width_supp = cfg_cmd.sgi_ch_width_supp,
            .max_mpdu_len = cfg_cmd.max_mpdu_len,
        };
        
        cmd_size = sizeof(cfg_cmd_v3);
        
        /* In old versions of the API the struct is 4 bytes smaller */
        if (cmdver == IWX_FW_CMD_VER_UNKNOWN || cmdver < 3)
            cmd_size -= 4;
        
        return iwx_send_cmd_pdu(sc, cmd_id, IWX_CMD_ASYNC, cmd_size,
                                &cfg_cmd_v3);
    } else {
        return -EINVAL;
    }
}

static uint32_t iwx_new_rate_from_v1(uint32_t rate_v1)
{
    uint32_t rate_v2 = 0;
    uint32_t dup = 0;
    
    if (rate_v1 == 0)
        return rate_v1;
    /* convert rate */
    if (rate_v1 & IWX_RATE_MCS_HT_MSK_V1) {
        uint32_t nss = 0;
        
        rate_v2 |= IWX_RATE_MCS_HT_MSK;
        rate_v2 |=
        rate_v1 & IWX_RATE_HT_MCS_RATE_CODE_MSK_V1;
        nss = (rate_v1 & IWX_RATE_HT_MCS_MIMO2_MSK) >>
        IWX_RATE_HT_MCS_NSS_POS_V1;
        rate_v2 |= nss << IWX_RATE_MCS_NSS_POS;
    } else if (rate_v1 & IWX_RATE_MCS_VHT_MSK_V1 ||
               rate_v1 & IWX_RATE_MCS_HE_MSK_V1) {
        rate_v2 |= rate_v1 & IWX_RATE_VHT_MCS_RATE_CODE_MSK;
        
        rate_v2 |= rate_v1 & IWX_RATE_VHT_MCS_MIMO2_MSK;
        
        if (rate_v1 & IWX_RATE_MCS_HE_MSK_V1) {
            uint32_t he_type_bits = rate_v1 & IWX_RATE_MCS_HE_TYPE_MSK_V1;
            uint32_t he_type = he_type_bits >> IWX_RATE_MCS_HE_TYPE_POS_V1;
            uint32_t he_106t = (rate_v1 & IWX_RATE_MCS_HE_106T_MSK_V1) >>
            IWX_RATE_MCS_HE_106T_POS_V1;
            uint32_t he_gi_ltf = (rate_v1 & IWX_RATE_MCS_HE_GI_LTF_MSK_V1) >>
            IWX_RATE_MCS_HE_GI_LTF_POS;
            
            if ((he_type_bits == IWX_RATE_MCS_HE_TYPE_SU ||
                 he_type_bits == IWX_RATE_MCS_HE_TYPE_EXT_SU) &&
                he_gi_ltf == IWX_RATE_MCS_HE_SU_4_LTF)
            /* the new rate have an additional bit to
             * represent the value 4 rather then using SGI
             * bit for this purpose - as it was done in the old
             * rate */
                he_gi_ltf += (rate_v1 & IWX_RATE_MCS_SGI_MSK_V1) >>
                IWX_RATE_MCS_SGI_POS_V1;
            
            rate_v2 |= he_gi_ltf << IWX_RATE_MCS_HE_GI_LTF_POS;
            rate_v2 |= he_type << IWX_RATE_MCS_HE_TYPE_POS;
            rate_v2 |= he_106t << IWX_RATE_MCS_HE_106T_POS;
            rate_v2 |= rate_v1 & IWX_RATE_HE_DUAL_CARRIER_MODE_MSK;
            rate_v2 |= IWX_RATE_MCS_HE_MSK;
        } else {
            rate_v2 |= IWX_RATE_MCS_VHT_MSK;
        }
        /* if legacy format */
    } else {
        uint32_t legacy_rate = iwx_hwrate_to_plcp_idx(rate_v1);
        
        WARN_ON(legacy_rate < 0);
        rate_v2 |= legacy_rate;
        if (!(rate_v1 & IWX_RATE_MCS_CCK_MSK_V1))
            rate_v2 |= IWX_RATE_MCS_LEGACY_OFDM_MSK;
    }
    
    /* convert flags */
    if (rate_v1 & IWX_RATE_MCS_LDPC_MSK_V1)
        rate_v2 |= IWX_RATE_MCS_LDPC_MSK;
    rate_v2 |= (rate_v1 & IWX_RATE_MCS_CHAN_WIDTH_MSK_V1) |
    (rate_v1 & IWX_RATE_MCS_ANT_AB_MSK) |
    (rate_v1 & IWX_RATE_MCS_STBC_MSK) |
    (rate_v1 & IWX_RATE_MCS_BF_MSK);
    
    dup = (rate_v1 & IWX_RATE_MCS_DUP_MSK_V1) >> IWX_RATE_MCS_DUP_POS_V1;
    if (dup) {
        rate_v2 |= IWX_RATE_MCS_DUP_MSK;
        rate_v2 |= dup << IWX_RATE_MCS_CHAN_WIDTH_POS;
    }
    
    if ((!(rate_v1 & IWX_RATE_MCS_HE_MSK_V1)) &&
        (rate_v1 & IWX_RATE_MCS_SGI_MSK_V1))
        rate_v2 |= IWX_RATE_MCS_SGI_MSK;
    
    return rate_v2;
}

void ItlIwx::
iwx_rs_update(struct iwx_softc *sc, struct iwx_tlc_update_notif *notif)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    struct ieee80211_rateset *rs = &ni->ni_rates;
    uint32_t rate_n_flags;
    int i;
    char pretty_rate[100];
    uint8_t notifver;
    uint32_t format;

    if (notif->sta_id != IWX_STATION_ID ||
        (le32toh(notif->flags) & IWX_TLC_NOTIF_FLAG_RATE) == 0)
        return;

    rate_n_flags = le32toh(notif->rate);
    notifver = iwx_lookup_notif_ver(sc, IWX_DATA_PATH_GROUP, IWX_TLC_MNG_UPDATE_NOTIF);
    if (notifver < 3 || notifver == IWX_FW_CMD_VER_UNKNOWN) {
        iwx_rs_pretty_print_rate_v1(pretty_rate, sizeof(pretty_rate),
                                    rate_n_flags);
        rate_n_flags = iwx_new_rate_from_v1(rate_n_flags);
    } else {
        iwx_rs_pretty_print_rate(pretty_rate, sizeof(pretty_rate),
                                 rate_n_flags);
    }
    XYLog("%s new rate: %s\n", __FUNCTION__, pretty_rate);
    format = rate_n_flags & IWX_RATE_MCS_MOD_TYPE_MSK;
    if (format == IWX_RATE_MCS_VHT_MSK ||
        format == IWX_RATE_MCS_HE_MSK ||
        format == IWX_RATE_MCS_EHT_MSK) {
        ni->ni_txmcs = rate_n_flags & IWX_RATE_MCS_CODE_MSK;
    } else if (format == IWX_RATE_MCS_HT_MSK) {
        ni->ni_txmcs = IWX_RATE_HT_MCS_INDEX(rate_n_flags);
    } else {
        uint8_t plcp = (rate_n_flags & IWX_RATE_LEGACY_RATE_MSK_V1);
        uint8_t rval = 0;
        for (i = IWX_RATE_1M_INDEX; i < nitems(iwx_rates); i++) {
            if (iwx_rates[i].plcp == plcp) {
                rval = iwx_rates[i].rate;
                break;
            }
        }
        if (rval) {
            uint8_t rv;
            for (i = 0; i < rs->rs_nrates; i++) {
                rv = rs->rs_rates[i] & IEEE80211_RATE_VAL;
                if (rv == rval) {
                    ni->ni_txrate = i;
                    break;
                }
            }
        }
    }
}

int ItlIwx::
iwx_phy_ctxt_update(struct iwx_softc *sc, struct iwx_phy_ctxt *phyctxt,
                    struct ieee80211_channel *chan, uint8_t chains_static,
                    uint8_t chains_dynamic, uint32_t apply_time)
{
    uint16_t band_flags = (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_5GHZ);
    int err;
    
    if (isset(sc->sc_enabled_capa,
              IWX_UCODE_TLV_CAPA_BINDING_CDB_SUPPORT) &&
        (phyctxt->channel->ic_flags & band_flags) !=
        (chan->ic_flags & band_flags)) {
        err = iwx_phy_ctxt_cmd(sc, phyctxt, chains_static,
                               chains_dynamic, IWX_FW_CTXT_ACTION_REMOVE, apply_time);
        if (err) {
            printf("%s: could not remove PHY context "
                   "(error %d)\n", DEVNAME(sc), err);
            return err;
        }
        phyctxt->channel = chan;
        err = iwx_phy_ctxt_cmd(sc, phyctxt, chains_static,
                               chains_dynamic, IWX_FW_CTXT_ACTION_ADD, apply_time);
        if (err) {
            printf("%s: could not add PHY context "
                   "(error %d)\n", DEVNAME(sc), err);
            return err;
        }
    } else {
        phyctxt->channel = chan;
        err = iwx_phy_ctxt_cmd(sc, phyctxt, chains_static,
                               chains_dynamic, IWX_FW_CTXT_ACTION_MODIFY, apply_time);
        if (err) {
            printf("%s: could not update PHY context (error %d)\n",
                   DEVNAME(sc), err);
            return err;
        }
    }
    
    return 0;
}

int ItlIwx::
iwx_auth(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_node *in = (struct iwx_node *)ic->ic_bss;
    uint32_t duration;
    int generation = sc->sc_generation, err = 0;
    
    splassert(IPL_NET);
    
    in->in_ni.ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
    in->in_ni.ni_flags &= ~(IEEE80211_NODE_HT |
                            IEEE80211_NODE_QOS |
                            IEEE80211_NODE_HT_SGI20 |
                            IEEE80211_NODE_HT_SGI40 |
                            IEEE80211_NODE_VHT |
                            IEEE80211_NODE_VHT_SGI80 |
                            IEEE80211_NODE_VHT_SGI160 |
                            IEEE80211_NODE_HE);
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        err = iwx_phy_ctxt_update(sc, &sc->sc_phyctxt[0],
                                  ic->ic_ibss_chan, 1, 1, 0);
        if (err)
            return err;
    } else {
        err = iwx_phy_ctxt_update(sc, &sc->sc_phyctxt[0],
                                  in->in_ni.ni_chan, 1, 1, 0);
        if (err)
            return err;
    }
    in->in_phyctxt = &sc->sc_phyctxt[0];
    IEEE80211_ADDR_COPY(in->in_macaddr, in->in_ni.ni_macaddr);
    
    err = iwx_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_ADD, 0);
    if (err) {
        XYLog("%s: could not add MAC context (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    sc->sc_flags |= IWX_FLAG_MAC_ACTIVE;
    
    err = iwx_binding_cmd(sc, in, IWX_FW_CTXT_ACTION_ADD);
    if (err) {
        XYLog("%s: could not add binding (error %d)\n",
              DEVNAME(sc), err);
        goto rm_mac_ctxt;
    }
    sc->sc_flags |= IWX_FLAG_BINDING_ACTIVE;
    
    err = iwx_add_sta_cmd(sc, in, 0);
    if (err) {
        XYLog("%s: could not add sta (error %d)\n",
              DEVNAME(sc), err);
        goto rm_binding;
    }
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        err = iwx_enable_txq(sc, IWX_MONITOR_STA_ID,
                             IWX_DQA_INJECT_MONITOR_QUEUE, IWX_MGMT_TID,
                             sc->txq[IWX_DQA_INJECT_MONITOR_QUEUE].ring_count);
        if (err)
            goto rm_sta;
        return 0;
    }
    
    err = iwx_enable_mgmt_queue(sc);
    if (err)
        goto rm_sta;
    
    err = iwx_clear_statistics(sc);
    if (err)
        goto rm_sta;
    
    /*
     * Prevent the FW from wandering off channel during association
     * by "protecting" the session with a time event.
     */
    if (in->in_ni.ni_intval)
        duration = in->in_ni.ni_intval * 2;
    else
        duration = IEEE80211_DUR_TU;
    
    /* Try really hard to protect the session and hear a beacon
     * The new session protection command allows us to protect the
     * session for a much longer time since the firmware will internally
     * create two events: a 300TU one with a very high priority that
     * won't be fragmented which should be enough for 99% of the cases,
     * and another one (which we configure here to be 900TU long) which
     * will have a slightly lower priority, but more importantly, can be
     * fragmented so that it'll allow other activities to run.
     */
    if (isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD))
        err = iwx_schedule_protect_session(sc, in, duration);
    else
        iwx_protect_session(sc, in, duration, in->in_ni.ni_intval / 2);
    
    return err;
    
rm_sta:
    if (generation == sc->sc_generation)
        iwx_rm_sta_cmd(sc, in);
rm_binding:
    if (generation == sc->sc_generation) {
        iwx_binding_cmd(sc, in, IWX_FW_CTXT_ACTION_REMOVE);
        sc->sc_flags &= ~IWX_FLAG_BINDING_ACTIVE;
    }
rm_mac_ctxt:
    if (generation == sc->sc_generation) {
        iwx_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_REMOVE, 0);
        sc->sc_flags &= ~IWX_FLAG_MAC_ACTIVE;
    }
    return err;
}

int ItlIwx::
iwx_deauth(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_node *in = (struct iwx_node *)ic->ic_bss;
    int err;
    
    splassert(IPL_NET);
    
    if (!isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD))
        iwx_unprotect_session(sc, in);
    else
        iwx_cancel_session_protection(sc, in);
    
    if (sc->sc_flags & IWX_FLAG_STA_ACTIVE) {
        err = iwx_rm_sta(sc, in);
        if (err)
            return err;
    }
    
    if (sc->sc_flags & IWX_FLAG_BINDING_ACTIVE) {
        err = iwx_binding_cmd(sc, in, IWX_FW_CTXT_ACTION_REMOVE);
        if (err) {
            XYLog("%s: could not remove binding (error %d)\n",
                  DEVNAME(sc), err);
            return err;
        }
        sc->sc_flags &= ~IWX_FLAG_BINDING_ACTIVE;
    }
    
    if (sc->sc_flags & IWX_FLAG_MAC_ACTIVE) {
        err = iwx_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_REMOVE, 0);
        if (err) {
            XYLog("%s: could not remove MAC context (error %d)\n",
                  DEVNAME(sc), err);
            return err;
        }
        sc->sc_flags &= ~IWX_FLAG_MAC_ACTIVE;
    }
    
    in->in_ni.ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
    in->in_ni.ni_flags &= ~(IEEE80211_NODE_HT |
                            IEEE80211_NODE_QOS |
                            IEEE80211_NODE_HT_SGI20 |
                            IEEE80211_NODE_HT_SGI40 |
                            IEEE80211_NODE_VHT |
                            IEEE80211_NODE_VHT_SGI80 |
                            IEEE80211_NODE_VHT_SGI160 |
                            IEEE80211_NODE_HE);
    /* Move unused PHY context to a default channel. */
    err = iwx_phy_ctxt_update(sc, &sc->sc_phyctxt[0],
                              &ic->ic_channels[1], 1, 1, 0);
    if (err)
        return err;
    
    return 0;
}

int ItlIwx::
iwx_run(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_node *in = (struct iwx_node *)ic->ic_bss;
    int err;
    int chains = iwx_mimo_enabled(sc) ? 2 : 1;
    
    splassert(IPL_NET);
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        /* Add a MAC context and a sniffing STA. */
        err = iwx_auth(sc);
        if (err)
            return err;
    }
    
    if (in->in_ni.ni_chw == IEEE80211_CHAN_WIDTH_80P80) {
        /* Fallback to 20mhz VHT */
        in->in_ni.ni_chw = IEEE80211_CHAN_WIDTH_20;
    }
    
    /* Configure Rx chains for MIMO. */
    if ((ic->ic_opmode == IEEE80211_M_MONITOR ||
         (in->in_ni.ni_flags & IEEE80211_NODE_HT) ||
         (in->in_ni.ni_flags & IEEE80211_NODE_VHT) ||
         (in->in_ni.ni_flags & IEEE80211_NODE_HE))) {
        err = iwx_phy_ctxt_update(sc, &sc->sc_phyctxt[0],
                                  in->in_ni.ni_chan, chains, chains, 0);
        if (err) {
            XYLog("%s: failed to update PHY\n",
                  DEVNAME(sc));
            return err;
        }
    }
    
    /* We have now been assigned an associd by the AP. */
    err = iwx_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_MODIFY, 1);
    if (err) {
        XYLog("%s: failed to update MAC\n", DEVNAME(sc));
        return err;
    }
    
    err = iwx_sf_config(sc, IWX_SF_FULL_ON);
    if (err) {
        XYLog("%s: could not set sf full on (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    
    err = iwx_allow_mcast(sc);
    if (err) {
        XYLog("%s: could not allow mcast (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    
    err = iwx_power_update_device(sc);
    if (err) {
        XYLog("%s: could not send power command (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
#ifdef notyet
    /*
     * Disabled for now. Default beacon filter settings
     * prevent net80211 from getting ERP and HT protection
     * updates from beacons.
     */
    err = iwx_enable_beacon_filter(sc, in);
    if (err) {
        XYLog("%s: could not enable beacon filter\n",
              DEVNAME(sc));
        return err;
    }
#endif
    err = iwx_power_mac_update_mode(sc, in);
    if (err) {
        XYLog("%s: could not update MAC power (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    
    if (!isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_DYNAMIC_QUOTA)) {
        err = iwx_update_quotas(sc, in, 1);
        if (err) {
            XYLog("%s: could not update quotas (error %d)\n",
                  DEVNAME(sc), err);
            return err;
        }
    }
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR)
        return 0;
    
    /* Start at lowest available bit-rate. Firmware will raise. */
    in->in_ni.ni_txrate = 0;
    in->in_ni.ni_txmcs = 0;

    err = iwx_add_sta_cmd(sc, in, 1);
    if (err) {
        XYLog("%s: could not update sta (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    
    err = iwx_rs_init(sc, in, true);
    if (err) {
        XYLog("%s: could not update rate scaling (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    return 0;
}

int ItlIwx::
iwx_run_stop(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_node *in = (struct iwx_node *)ic->ic_bss;
    int err, i;
    
    splassert(IPL_NET);
    
    err = iwx_flush_sta(sc, in);
    if (err) {
        XYLog("%s: could not flush Tx path (error %d)\n",
              __FUNCTION__, err);
        return err;
    }
    
    /*
     * Stop Rx BA sessions now. We cannot rely on the BA task
     * for this when moving out of RUN state since it runs in a
     * separate thread.
     * Note that in->in_ni (struct ieee80211_node) already represents
     * our new access point in case we are roaming between APs.
     * This means we cannot rely on struct ieee802111_node to tell
     * us which BA sessions exist.
     */
    for (i = 0; i < nitems(sc->sc_rxba_data); i++) {
        struct iwx_rxba_data *rxba = &sc->sc_rxba_data[i];
        if (rxba->baid == IWX_RX_REORDER_DATA_INVALID_BAID)
            continue;
        iwx_sta_rx_agg(sc, ic->ic_bss, rxba->tid, 0, 0, 0, 0);
    }
    
    err = iwx_sf_config(sc, IWX_SF_INIT_OFF);
    if (err)
        return err;
    
    err = iwx_disable_beacon_filter(sc);
    if (err) {
        XYLog("%s: could not disable beacon filter (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    
    if (!isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_DYNAMIC_QUOTA)) {
        err = iwx_update_quotas(sc, in, 0);
        if (err) {
            XYLog("%s: could not update quotas (error %d)\n",
                  DEVNAME(sc), err);
            return err;
        }
    }
    
    err = iwx_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_MODIFY, 0);
    if (err) {
        XYLog("%s: failed to update MAC\n", DEVNAME(sc));
        return err;
    }
    
    /* Reset Tx chains in case MIMO was enabled. */
    if ((in->in_ni.ni_flags & IEEE80211_NODE_HT) &&
        iwx_mimo_enabled(sc)) {
        err = iwx_phy_ctxt_update(sc, &sc->sc_phyctxt[0],
                                  in->in_ni.ni_chan, 1, 1, 0);
        if (err) {
            XYLog("%s: failed to update PHY\n", DEVNAME(sc));
            return err;
        }
    }
    
    return 0;
}

struct ieee80211_node *ItlIwx::
iwx_node_alloc(struct ieee80211com *ic)
{
    return (struct ieee80211_node *)malloc(sizeof (struct iwx_node), 0, M_NOWAIT | M_ZERO);
}

int ItlIwx::
iwx_set_key(struct ieee80211com *ic, struct ieee80211_node *ni,
            struct ieee80211_key *k)
{
    struct iwx_softc *sc = (struct iwx_softc *)ic->ic_softc;
    struct iwx_add_sta_key_cmd cmd;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    
    if (k->k_cipher != IEEE80211_CIPHER_CCMP) {
        /* Fallback to software crypto for other ciphers. */
        return (ieee80211_set_key(ic, ni, k));
    }
    
    memset(&cmd, 0, sizeof(cmd));
    
    cmd.common.key_flags = htole16(IWX_STA_KEY_FLG_CCM |
                                   IWX_STA_KEY_FLG_WEP_KEY_MAP |
                                   ((k->k_id << IWX_STA_KEY_FLG_KEYID_POS) &
                                    IWX_STA_KEY_FLG_KEYID_MSK));
    if (k->k_flags & IEEE80211_KEY_GROUP) {
        cmd.common.key_offset = 1;
        cmd.common.key_flags |= htole16(IWX_STA_KEY_MULTICAST);
    } else
        cmd.common.key_offset = 0;
    
    memcpy(cmd.common.key, k->k_key, MIN(sizeof(cmd.common.key), k->k_len));
    cmd.common.sta_id = IWX_STATION_ID;
    
    cmd.transmit_seq_cnt = htole64(k->k_tsc);
    
    return that->iwx_send_cmd_pdu(sc, IWX_ADD_STA_KEY, IWX_CMD_ASYNC,
                            sizeof(cmd), &cmd);
}

void ItlIwx::
iwx_delete_key(struct ieee80211com *ic, struct ieee80211_node *ni,
               struct ieee80211_key *k)
{
    struct iwx_softc *sc = (struct iwx_softc *)ic->ic_softc;
    struct iwx_add_sta_key_cmd cmd;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    
    if (k->k_cipher != IEEE80211_CIPHER_CCMP) {
        /* Fallback to software crypto for other ciphers. */
        ieee80211_delete_key(ic, ni, k);
        return;
    }
    
    memset(&cmd, 0, sizeof(cmd));
    
    cmd.common.key_flags = htole16(IWX_STA_KEY_NOT_VALID |
                                   IWX_STA_KEY_FLG_NO_ENC | IWX_STA_KEY_FLG_WEP_KEY_MAP |
                                   ((k->k_id << IWX_STA_KEY_FLG_KEYID_POS) &
                                    IWX_STA_KEY_FLG_KEYID_MSK));
    memcpy(cmd.common.key, k->k_key, MIN(sizeof(cmd.common.key), k->k_len));
    if (k->k_flags & IEEE80211_KEY_GROUP)
        cmd.common.key_offset = 1;
    else
        cmd.common.key_offset = 0;
    cmd.common.sta_id = IWX_STATION_ID;
    
    that->iwx_send_cmd_pdu(sc, IWX_ADD_STA_KEY, IWX_CMD_ASYNC, sizeof(cmd), &cmd);
}

int ItlIwx::
iwx_media_change(struct _ifnet *ifp)
{
    struct iwx_softc *sc = (struct iwx_softc *)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    uint8_t rate, ridx;
    int err;
    
    err = ieee80211_media_change(ifp);
    if (err != ENETRESET)
        return err;
    
    if (ic->ic_fixed_mcs != -1)
        sc->sc_fixed_ridx = iwx_mcs2ridx[ic->ic_fixed_mcs];
    else if (ic->ic_fixed_rate != -1) {
        rate = ic->ic_sup_rates[ic->ic_curmode].
        rs_rates[ic->ic_fixed_rate] & IEEE80211_RATE_VAL;
        /* Map 802.11 rate to HW rate index. */
        for (ridx = 0; ridx <= IWX_RIDX_MAX; ridx++)
            if (iwx_rates[ridx].rate == rate)
                break;
        sc->sc_fixed_ridx = ridx;
    }
    
    if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
        (IFF_UP | IFF_RUNNING)) {
        iwx_stop(ifp);
        err = iwx_init(ifp);
    }
    return err;
}

void ItlIwx::
iwx_newstate_task(void *psc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_softc *sc = (struct iwx_softc *)psc;
    struct ieee80211com *ic = &sc->sc_ic;
    enum ieee80211_state nstate = sc->ns_nstate;
    enum ieee80211_state ostate = ic->ic_state;
    int arg = sc->ns_arg;
    int err = 0, s = splnet();
    ItlIwx *that = container_of(sc, ItlIwx, com);
    
    XYLog("%s sc->sc_flags & IWX_FLAG_SHUTDOWN %s\n", __FUNCTION__, sc->sc_flags & IWX_FLAG_SHUTDOWN ? "true" : "false");
    if (sc->sc_flags & IWX_FLAG_SHUTDOWN) {
        /* iwx_stop() is waiting for us. */
        //        refcnt_rele_wake(&sc->task_refs);
        splx(s);
        return;
    }
    
    if (ostate == IEEE80211_S_SCAN) {
        if (nstate == ostate) {
            if (sc->sc_flags & IWX_FLAG_SCANNING) {
                //                refcnt_rele_wake(&sc->task_refs);
                splx(s);
                return;
            }
            /* Firmware is no longer scanning. Do another scan. */
            goto next_scan;
        }
    }
    
    if (nstate <= ostate) {
        switch (ostate) {
            case IEEE80211_S_RUN:
                err = that->iwx_run_stop(sc);
                if (err)
                    goto out;
                /* FALLTHROUGH */
            case IEEE80211_S_ASSOC:
            case IEEE80211_S_AUTH:
                if (nstate <= IEEE80211_S_AUTH) {
                    err = that->iwx_deauth(sc);
                    if (err)
                        goto out;
                }
                /* FALLTHROUGH */
            case IEEE80211_S_SCAN:
            case IEEE80211_S_INIT:
                break;
        }
        
        /* Die now if iwx_stop() was called while we were sleeping. */
        if (sc->sc_flags & IWX_FLAG_SHUTDOWN) {
            //            refcnt_rele_wake(&sc->task_refs);
            splx(s);
            return;
        }
    }
    
    switch (nstate) {
        case IEEE80211_S_INIT:
            break;
            
        case IEEE80211_S_SCAN:
        next_scan:
            err = that->iwx_scan(sc);
            if (err)
                break;
            //        refcnt_rele_wake(&sc->task_refs);
            splx(s);
            return;
            
        case IEEE80211_S_AUTH:
            err = that->iwx_auth(sc);
            break;
            
        case IEEE80211_S_ASSOC:
            err = that->iwx_rs_init(sc, (iwx_node *)ic->ic_bss, false);
            if (err) {
                XYLog("%s: could not init rate scaling (error %d)\n",
                      DEVNAME(sc), err);
                goto out;
            }
            break;
            
        case IEEE80211_S_RUN:
            err = that->iwx_run(sc);
            break;
    }
    
out:
    if ((sc->sc_flags & IWX_FLAG_SHUTDOWN) == 0) {
        if (err)
            task_add(systq, &sc->init_task);
        else
            sc->sc_newstate(ic, nstate, arg);
    }
    //    refcnt_rele_wake(&sc->task_refs);
    splx(s);
}

int ItlIwx::
iwx_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
    struct _ifnet *ifp = IC2IFP(ic);
    struct iwx_softc *sc = (struct iwx_softc *)ifp->if_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    struct ieee80211_node *ni = ic->ic_bss;
    
    /*
     * Prevent attemps to transition towards the same state, unless
     * we are scanning in which case a SCAN -> SCAN transition
     * triggers another scan iteration. And AUTH -> AUTH is needed
     * to support band-steering.
     */
    if (sc->ns_nstate == nstate && nstate != IEEE80211_S_SCAN &&
        nstate != IEEE80211_S_AUTH)
    
    if (ic->ic_state == IEEE80211_S_RUN) {
        if (nstate == IEEE80211_S_SCAN) {
            /*
             * During RUN->SCAN we don't call sc_newstate() so
             * we must stop A-MPDU Tx ourselves in this case.
             */
            ieee80211_stop_ampdu_tx(ic, ni, -1);
            ieee80211_ba_del(ni);
        }
        that->iwx_del_task(sc, systq, &sc->ba_task);
        that->iwx_del_task(sc, systq, &sc->mac_ctxt_task);
        that->iwx_del_task(sc, systq, &sc->chan_ctxt_task);
    }
    
    sc->ns_nstate = nstate;
    sc->ns_arg = arg;
    
    that->iwx_add_task(sc, sc->sc_nswq, &sc->newstate_task);
    
    return 0;
}

void ItlIwx::
iwx_endscan(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    
    struct ieee80211_node *ni, *nextbs;
    
//    ni = RB_MIN(ieee80211_tree, &ic->ic_tree);
//    for (; ni != NULL; ni = nextbs) {
//        nextbs = RB_NEXT(ieee80211_tree, &ic->ic_tree, ni);
//        XYLog("%s scan_result ssid=%s, bssid=%s, ni_rsnciphers=%d, ni_rsncipher=%d, ni_rsngroupmgmtcipher=%d, ni_rsngroupcipher=%d, ni_rssi=%d,  ni_capinfo=%d, ni_intval=%d, ni_rsnakms=%d, ni_supported_rsnakms=%d, ni_rsnprotos=%d, ni_supported_rsnprotos=%d, ni_rstamp=%d\n", __FUNCTION__, ni->ni_essid, ether_sprintf(ni->ni_bssid), ni->ni_rsnciphers, ni->ni_rsncipher, ni->ni_rsngroupmgmtcipher, ni->ni_rsngroupcipher, ni->ni_rssi, ni->ni_capinfo, ni->ni_intval, ni->ni_rsnakms, ni->ni_supported_rsnakms, ni->ni_rsnprotos, ni->ni_supported_rsnprotos, ni->ni_rstamp);
//    }
    
    if ((sc->sc_flags & (IWX_FLAG_SCANNING | IWX_FLAG_BGSCAN)) == 0)
        return;
    
    sc->sc_flags &= ~(IWX_FLAG_SCANNING | IWX_FLAG_BGSCAN);
    ieee80211_end_scan(&ic->ic_if);
}

/*
 * Aging and idle timeouts for the different possible scenarios
 * in default configuration
 */
static const uint32_t
iwx_sf_full_timeout_def[IWX_SF_NUM_SCENARIO][IWX_SF_NUM_TIMEOUT_TYPES] = {
    {
        htole32(IWX_SF_SINGLE_UNICAST_AGING_TIMER_DEF),
        htole32(IWX_SF_SINGLE_UNICAST_IDLE_TIMER_DEF)
    },
    {
        htole32(IWX_SF_AGG_UNICAST_AGING_TIMER_DEF),
        htole32(IWX_SF_AGG_UNICAST_IDLE_TIMER_DEF)
    },
    {
        htole32(IWX_SF_MCAST_AGING_TIMER_DEF),
        htole32(IWX_SF_MCAST_IDLE_TIMER_DEF)
    },
    {
        htole32(IWX_SF_BA_AGING_TIMER_DEF),
        htole32(IWX_SF_BA_IDLE_TIMER_DEF)
    },
    {
        htole32(IWX_SF_TX_RE_AGING_TIMER_DEF),
        htole32(IWX_SF_TX_RE_IDLE_TIMER_DEF)
    },
};

/*
 * Aging and idle timeouts for the different possible scenarios
 * in single BSS MAC configuration.
 */
static const uint32_t
iwx_sf_full_timeout[IWX_SF_NUM_SCENARIO][IWX_SF_NUM_TIMEOUT_TYPES] = {
    {
        htole32(IWX_SF_SINGLE_UNICAST_AGING_TIMER),
        htole32(IWX_SF_SINGLE_UNICAST_IDLE_TIMER)
    },
    {
        htole32(IWX_SF_AGG_UNICAST_AGING_TIMER),
        htole32(IWX_SF_AGG_UNICAST_IDLE_TIMER)
    },
    {
        htole32(IWX_SF_MCAST_AGING_TIMER),
        htole32(IWX_SF_MCAST_IDLE_TIMER)
    },
    {
        htole32(IWX_SF_BA_AGING_TIMER),
        htole32(IWX_SF_BA_IDLE_TIMER)
    },
    {
        htole32(IWX_SF_TX_RE_AGING_TIMER),
        htole32(IWX_SF_TX_RE_IDLE_TIMER)
    },
};

void ItlIwx::
iwx_fill_sf_command(struct iwx_softc *sc, struct iwx_sf_cfg_cmd *sf_cmd,
                    struct ieee80211_node *ni)
{
    int i, j, watermark;
    
    sf_cmd->watermark[IWX_SF_LONG_DELAY_ON] = htole32(IWX_SF_W_MARK_SCAN);
    
    /*
     * If we are in association flow - check antenna configuration
     * capabilities of the AP station, and choose the watermark accordingly.
     */
    if (ni) {
        if (ni->ni_flags & IEEE80211_NODE_HT || ni->ni_flags & IEEE80211_NODE_VHT || ni->ni_flags & IEEE80211_NODE_HE) {
            if (ni->ni_rxmcs[1] != 0)
                watermark = IWX_SF_W_MARK_MIMO2;
            else
                watermark = IWX_SF_W_MARK_SISO;
        } else {
            watermark = IWX_SF_W_MARK_LEGACY;
        }
        /* default watermark value for unassociated mode. */
    } else {
        watermark = IWX_SF_W_MARK_MIMO2;
    }
    sf_cmd->watermark[IWX_SF_FULL_ON] = htole32(watermark);
    
    for (i = 0; i < IWX_SF_NUM_SCENARIO; i++) {
        for (j = 0; j < IWX_SF_NUM_TIMEOUT_TYPES; j++) {
            sf_cmd->long_delay_timeouts[i][j] =
            htole32(IWX_SF_LONG_DELAY_AGING_TIMER);
        }
    }
    
    if (ni) {
        memcpy(sf_cmd->full_on_timeouts, iwx_sf_full_timeout,
               sizeof(iwx_sf_full_timeout));
    } else {
        memcpy(sf_cmd->full_on_timeouts, iwx_sf_full_timeout_def,
               sizeof(iwx_sf_full_timeout_def));
    }
    
}

int ItlIwx::
iwx_sf_config(struct iwx_softc *sc, int new_state)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_sf_cfg_cmd sf_cmd = {
        .state = htole32(new_state),
    };
    int err = 0;
    
    switch (new_state) {
        case IWX_SF_UNINIT:
        case IWX_SF_INIT_OFF:
            iwx_fill_sf_command(sc, &sf_cmd, NULL);
            break;
        case IWX_SF_FULL_ON:
            iwx_fill_sf_command(sc, &sf_cmd, ic->ic_bss);
            break;
        default:
            return EINVAL;
    }
    
    err = iwx_send_cmd_pdu(sc, IWX_REPLY_SF_CFG_CMD, IWX_CMD_ASYNC,
                           sizeof(sf_cmd), &sf_cmd);
    return err;
}

int ItlIwx::
iwx_send_bt_init_conf(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_bt_coex_cmd bt_cmd;
    
    bt_cmd.mode = htole32(IWX_BT_COEX_WIFI);
    bt_cmd.enabled_modules = 0;
    
    return iwx_send_cmd_pdu(sc, IWX_BT_CONFIG, 0, sizeof(bt_cmd),
                            &bt_cmd);
}

int ItlIwx::
iwx_send_soc_conf(struct iwx_softc *sc)
{
   struct iwx_soc_configuration_cmd cmd;
   int err;
   uint32_t cmd_id, flags = 0;

   memset(&cmd, 0, sizeof(cmd));

   /*
    * In VER_1 of this command, the discrete value is considered
    * an integer; In VER_2, it's a bitmask.  Since we have only 2
    * values in VER_1, this is backwards-compatible with VER_2,
    * as long as we don't set any other flag bits.
    */
   if (!sc->sc_integrated) { /* VER_1 */
       flags = IWX_SOC_CONFIG_CMD_FLAGS_DISCRETE;
   } else { /* VER_2 */
       uint8_t scan_cmd_ver;
       if (sc->sc_ltr_delay != IWX_SOC_FLAGS_LTR_APPLY_DELAY_NONE)
           flags |= (sc->sc_ltr_delay &
               IWX_SOC_FLAGS_LTR_APPLY_DELAY_MASK);
       scan_cmd_ver = iwx_lookup_cmd_ver(sc, IWX_LONG_GROUP,
           IWX_SCAN_REQ_UMAC);
       if (scan_cmd_ver != IWX_FW_CMD_VER_UNKNOWN &&
           scan_cmd_ver >= 2 && sc->sc_low_latency_xtal)
           flags |= IWX_SOC_CONFIG_CMD_FLAGS_LOW_LATENCY;
   }
   cmd.flags = htole32(flags);

   cmd.latency = htole32(sc->sc_xtal_latency);

   cmd_id = iwx_cmd_id(IWX_SOC_CONFIGURATION_CMD, IWX_SYSTEM_GROUP, 0);
   err = iwx_send_cmd_pdu(sc, cmd_id, 0, sizeof(cmd), &cmd);
   if (err)
       XYLog("%s: failed to set soc latency: %d\n", DEVNAME(sc), err);
   return err;
}

int ItlIwx::
iwx_send_update_mcc_cmd(struct iwx_softc *sc, const char *alpha2)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_mcc_update_cmd mcc_cmd;
    struct iwx_host_cmd hcmd = {
        .id = IWX_MCC_UPDATE_CMD,
        .flags = IWX_CMD_WANT_RESP,
        .data = { &mcc_cmd },
    };
    struct iwx_rx_packet *pkt;
    struct iwx_mcc_update_resp *resp;
    size_t resp_len;
    int err;
    
    memset(&mcc_cmd, 0, sizeof(mcc_cmd));
    mcc_cmd.mcc = htole16(alpha2[0] << 8 | alpha2[1]);
    if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_WIFI_MCC_UPDATE) ||
        isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_LAR_MULTI_MCC))
        mcc_cmd.source_id = IWX_MCC_SOURCE_GET_CURRENT;
    else
        mcc_cmd.source_id = IWX_MCC_SOURCE_OLD_FW;
    
    hcmd.len[0] = sizeof(struct iwx_mcc_update_cmd);
    hcmd.resp_pkt_len = IWX_CMD_RESP_MAX;
    
    err = iwx_send_cmd(sc, &hcmd);
    if (err)
        return err;
    
    pkt = hcmd.resp_pkt;
    if (!pkt || (pkt->hdr.group_id & IWX_CMD_FAILED_MSK)) {
        err = EIO;
        goto out;
    }
    
    resp_len = iwx_rx_packet_payload_len(pkt);
    if (resp_len < sizeof(*resp)) {
        err = EIO;
        goto out;
    }
    
    resp = (struct iwx_mcc_update_resp *)pkt->data;
    if (resp_len != sizeof(*resp) +
        resp->n_channels * sizeof(resp->channels[0])) {
        err = EIO;
        goto out;
    }

    DPRINTF(("MCC status=0x%x mcc=0x%x cap=0x%x time=0x%x geo_info=0x%x source_id=0x%d n_channels=%u\n",
             resp->status, resp->mcc, resp->cap, resp->time, resp->geo_info, resp->source_id, resp->n_channels));

    /* Update channel map for net80211 and our scan configuration. */
    iwx_init_channel_map(sc, NULL, resp->channels, resp->n_channels);
    
out:
    iwx_free_resp(sc, &hcmd);
    
    return err;
}

int ItlIwx::
iwx_send_temp_report_ths_cmd(struct iwx_softc *sc)
{
    struct iwx_temp_report_ths_cmd cmd;
    int err;
    
    /*
     * In order to give responsibility for critical-temperature-kill
     * and TX backoff to FW we need to send an empty temperature
     * reporting command at init time.
     */
    memset(&cmd, 0, sizeof(cmd));
    
    err = iwx_send_cmd_pdu(sc,
                           IWX_WIDE_ID(IWX_PHY_OPS_GROUP, IWX_TEMP_REPORTING_THRESHOLDS_CMD),
                           0, sizeof(cmd), &cmd);
    if (err)
        XYLog("%s: TEMP_REPORT_THS_CMD command failed (error %d)\n",
               DEVNAME(sc), err);
    
    return err;
}

#define TX_FIFO_MAX_NUM            15
#define RX_FIFO_MAX_NUM            2
#define TX_FIFO_INTERNAL_MAX_NUM    6

int ItlIwx::
iwx_init_hw(struct iwx_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    int err, i;
    
    err = iwx_preinit(sc);
    if (err)
        return err;
    
    err = iwx_start_hw(sc);
    if (err) {
        XYLog("%s: could not initialize hardware\n", DEVNAME(sc));
        return err;
    }
    
    err = iwx_run_init_mvm_ucode(sc, 0);
    if (err)
        return err;
    
    if (!iwx_nic_lock(sc))
        return EBUSY;
    
    err = iwx_send_tx_ant_cfg(sc, iwx_fw_valid_tx_ant(sc));
    if (err) {
        XYLog("%s: could not init tx ant config (error %d)\n",
               DEVNAME(sc), err);
        goto err;
    }
    
    iwx_toggle_tx_ant(sc, &sc->sc_mgmt_last_antenna_idx);
    
    if (sc->sc_tx_with_siso_diversity) {
        err = iwx_send_phy_cfg_cmd(sc);
        if (err) {
            XYLog("%s: could not send phy config (error %d)\n",
                   DEVNAME(sc), err);
            goto err;
        }
    }
    
    err = iwx_send_bt_init_conf(sc);
    if (err) {
        XYLog("%s: could not init bt coex (error %d)\n",
               DEVNAME(sc), err);
        return err;
    }
    
    err = iwx_send_soc_conf(sc);
    if (err)
        return err;
    
    if (isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_DQA_SUPPORT)){
        err = iwx_send_dqa_cmd(sc);
        if (err)
            return err;
    }
    
    /* Add auxiliary station for scanning */
    err = iwx_add_aux_sta(sc);
    if (err) {
        XYLog("%s: could not add aux station (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
    for (i = 0; i < IWX_NUM_PHY_CTX; i++) {
        /*
         * The channel used here isn't relevant as it's
         * going to be overwritten in the other flows.
         * For now use the first channel we have.
         */
        sc->sc_phyctxt[i].id = i;
        sc->sc_phyctxt[i].channel = &ic->ic_channels[1];
        err = iwx_phy_ctxt_cmd(sc, &sc->sc_phyctxt[i], 1, 1,
                               IWX_FW_CTXT_ACTION_ADD, 0);
        if (err) {
            XYLog("%s: could not add phy context %d (error %d)\n",
                   DEVNAME(sc), i, err);
            goto err;
        }
    }
    
    if (!isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_SET_LTR_GEN2)) {
        err = iwx_config_ltr(sc);
        if (err) {
            XYLog("%s: PCIe LTR configuration failed (error %d)\n",
                  DEVNAME(sc), err);
        }
    }
    
    if (isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_CT_KILL_BY_FW)) {
        err = iwx_send_temp_report_ths_cmd(sc);
        if (err)
            goto err;
    }
    
    err = iwx_power_update_device(sc);
    if (err) {
        XYLog("%s: could not send power command (error %d)\n",
               DEVNAME(sc), err);
        goto err;
    }
    
    if (sc->sc_nvm.lar_enabled) {
        err = iwx_send_update_mcc_cmd(sc, "ZZ");
        if (err) {
            XYLog("%s: could not init LAR (error %d)\n",
                   DEVNAME(sc), err);
            goto err;
        }
    }
    
    err = iwx_config_umac_scan(sc);
    if (err) {
        XYLog("%s: could not configure scan (error %d)\n",
               DEVNAME(sc), err);
        goto err;
    }
    
    err = iwx_disable_beacon_filter(sc);
    if (err) {
        XYLog("%s: could not disable beacon filter (error %d)\n",
               DEVNAME(sc), err);
        goto err;
    }
    
err:
    iwx_nic_unlock(sc);
    return err;
}

/* Allow multicast from our BSSID. */
int ItlIwx::
iwx_allow_mcast(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_node *in = (struct iwx_node *)ic->ic_bss;
    struct iwx_mcast_filter_cmd *cmd;
    size_t size;
    int err;
    
    size = roundup(sizeof(*cmd), 4);
    cmd = (struct iwx_mcast_filter_cmd *)malloc(size, 0, M_NOWAIT | M_ZERO);
    if (cmd == NULL)
        return ENOMEM;
    cmd->filter_own = 1;
    cmd->port_id = 0;
    cmd->count = 0;
    cmd->pass_all = 1;
    IEEE80211_ADDR_COPY(cmd->bssid, in->in_macaddr);
    
    err = iwx_send_cmd_pdu(sc, IWX_MCAST_FILTER_CMD,
                           0, size, cmd);
    ::free(cmd);
    return err;
}

int ItlIwx::
iwx_init(struct _ifnet *ifp)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_softc *sc = (struct iwx_softc *)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    int err, generation;
    int i;

    memset(sc->sc_tid_data, 0, sizeof(sc->sc_tid_data));
    for (i = 0; i < ARRAY_SIZE(sc->sc_tid_data); i++) {
        sc->sc_tid_data[i].qid = IWX_INVALID_QUEUE;
    }
    
    //    rw_assert_wrlock(&sc->ioctl_rwl);
    
    generation = ++sc->sc_generation;
    
    //    KASSERT(sc->task_refs.refs == 0);
    //    refcnt_init(&sc->task_refs);
    
    err = iwx_init_hw(sc);
    if (err) {
        if (generation == sc->sc_generation)
            iwx_stop_device(sc);
        return err;
    }
    
    if (sc->sc_nvm.sku_cap_11n_enable)
        iwx_setup_ht_rates(sc);
    
    if (sc->sc_nvm.sku_cap_11ac_enable)
        iwx_setup_vht_rates(sc);
    
    if (sc->sc_nvm.sku_cap_11ax_enable)
        iwx_setup_he_rates(sc);
    
    ifq_clr_oactive(&ifp->if_snd);
    ifq_flush(&ifp->if_snd);
    ifp->if_flags |= IFF_RUNNING;
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        ic->ic_bss->ni_chan = ic->ic_ibss_chan;
        ieee80211_new_state(ic, IEEE80211_S_RUN, -1);
        return 0;
    }
    
    ieee80211_begin_scan(ifp);
    
    /*
     * ieee80211_begin_scan() ends up scheduling iwx_newstate_task().
     * Wait until the transition to SCAN state has completed.
     */
    do {
        err = tsleep_nsec(&ic->ic_state, PCATCH, "iwxinit",
            SEC_TO_NSEC(1));
        if (generation != sc->sc_generation)
            return ENXIO;
        if (err) {
            iwx_stop(ifp);
            return err;
        }
    } while (ic->ic_state != IEEE80211_S_SCAN);
    
    return 0;
}

IOReturn ItlIwx::
_iwx_start_task(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3)
{
    struct _ifnet *ifp = (struct _ifnet *)arg0;
    struct iwx_softc *sc = (struct iwx_softc *)ifp->if_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni;
    struct ether_header *eh;
    mbuf_t m;
    int ac = EDCA_AC_BE; /* XXX */
    
    if (!(ifp->if_flags & IFF_RUNNING) ||  ifq_is_oactive(&ifp->if_snd)) {
        return kIOReturnError;
    }
    
    for (;;) {
        /* why isn't this done per-queue? */
        if (sc->qfullmsk != 0) {
            ifq_set_oactive(&ifp->if_snd);
            break;
        }

        /* Don't queue additional frames while flushing Tx queues. */
        if (sc->sc_flags & IWX_FLAG_TXFLUSH)
            break;
        
        /* need to send management frames even if we're not RUNning */
        m = mq_dequeue(&ic->ic_mgtq);
        if (m) {
            //            ni = m->m_pkthdr.ph_cookie;
            ni = (struct ieee80211_node *)mbuf_pkthdr_rcvif(m);
            goto sendit;
        }
        
        if (
#ifndef AIRPORT
            ic->ic_state != IEEE80211_S_RUN ||
#endif
            (ic->ic_xflags & IEEE80211_F_TX_MGMT_ONLY))
            break;
        
        m = ifq_dequeue(&ifp->if_snd);
        if (!m)
            break;
        if (mbuf_len(m) < sizeof (*eh) &&
            mbuf_pullup(&m, sizeof (*eh)) != 0) {
            ifp->netStat->outputErrors++;
            continue;
        }
#if NBPFILTER > 0
        if (ifp->if_bpf != NULL)
            bpf_mtap(ifp->if_bpf, m, BPF_DIRECTION_OUT);
#endif
        if ((m = ieee80211_encap(ifp, m, &ni)) == NULL) {
            ifp->netStat->outputErrors++;
            continue;
        }
        
    sendit:
#if NBPFILTER > 0
        if (ic->ic_rawbpf != NULL)
            bpf_mtap(ic->ic_rawbpf, m, BPF_DIRECTION_OUT);
#endif
        if (that->iwx_tx(sc, m, ni, ac) != 0) {
            ieee80211_release_node(ic, ni);
            ifp->netStat->outputErrors++;
            continue;
        }
        ifp->netStat->outputPackets++;
        
        if (ifp->if_flags & IFF_UP) {
            sc->sc_tx_timer = 15;
            ifp->if_timer = 1;
        }
    }
    
    return kIOReturnSuccess;
}

void ItlIwx::
iwx_start(struct _ifnet *ifp)
{
    struct iwx_softc *sc = (struct iwx_softc*)ifp->if_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    that->getMainCommandGate()->attemptAction(_iwx_start_task, &that->com.sc_ic.ic_ac.ac_if);
}

void ItlIwx::
iwx_stop(struct _ifnet *ifp)
{
    struct iwx_softc *sc = (struct iwx_softc *)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_node *in = (struct iwx_node *)ic->ic_bss;
    int i, s = splnet();
    
    //    rw_assert_wrlock(&sc->ioctl_rwl);
    
    sc->sc_flags |= IWX_FLAG_SHUTDOWN; /* Disallow new tasks. */
    
    /* Cancel scheduled tasks and let any stale tasks finish up. */
    task_del(systq, &sc->init_task);
    iwx_del_task(sc, sc->sc_nswq, &sc->newstate_task);
    iwx_del_task(sc, systq, &sc->ba_task);
    iwx_del_task(sc, systq, &sc->mac_ctxt_task);
    iwx_del_task(sc, systq, &sc->chan_ctxt_task);
    KASSERT(sc->task_refs.refs >= 1, "sc->task_refs.refs >= 1");
    //    refcnt_finalize(&sc->task_refs, "iwxstop");
    
    iwx_stop_device(sc);
    
    /* Reset soft state. */
    
    sc->sc_generation++;
    for (i = 0; i < nitems(sc->sc_cmd_resp_pkt); i++) {
        ::free(sc->sc_cmd_resp_pkt[i]);
        sc->sc_cmd_resp_pkt[i] = NULL;
        sc->sc_cmd_resp_len[i] = 0;
    }
    ifp->if_flags &= ~IFF_RUNNING;
    ifq_clr_oactive(&ifp->if_snd);
    ifq_flush(&ifp->if_snd);
    
    if (in != NULL) {
        in->in_phyctxt = NULL;
        in->in_ni.ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
        IEEE80211_ADDR_COPY(in->in_macaddr, etheranyaddr);
    }
    
    sc->sc_flags &= ~(IWX_FLAG_SCANNING | IWX_FLAG_BGSCAN);
    sc->sc_flags &= ~IWX_FLAG_MAC_ACTIVE;
    sc->sc_flags &= ~IWX_FLAG_BINDING_ACTIVE;
    sc->sc_flags &= ~IWX_FLAG_STA_ACTIVE;
    sc->sc_flags &= ~IWX_FLAG_TE_ACTIVE;
    sc->sc_flags &= ~IWX_FLAG_HW_ERR;
    sc->sc_flags &= ~IWX_FLAG_SHUTDOWN;
    sc->sc_flags &= ~IWX_FLAG_TXFLUSH;

    sc->sc_rx_ba_sessions = 0;
    sc->ba_rx.start_tidmask = 0;
    sc->ba_rx.stop_tidmask = 0;
    sc->ba_tx.start_tidmask = 0;
    sc->ba_tx.stop_tidmask = 0;
    
    sc->sc_newstate(ic, IEEE80211_S_INIT, -1);
    sc->ns_nstate = IEEE80211_S_INIT;
    
    for (i = 0; i < nitems(sc->sc_rxba_data); i++) {
        struct iwx_rxba_data *rxba = &sc->sc_rxba_data[i];
        iwx_clear_reorder_buffer(sc, rxba);
    }
    
    ifp->if_timer = sc->sc_tx_timer = 0;
    
    splx(s);
}

void ItlIwx::
iwx_watchdog(struct _ifnet *ifp)
{
    struct iwx_softc *sc = (struct iwx_softc *)ifp->if_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    
    ifp->if_timer = 0;
    if (sc->sc_tx_timer > 0) {
        if (--sc->sc_tx_timer == 0) {
            XYLog("%s: device timeout\n", DEVNAME(sc));
#ifdef IWX_DEBUG
            int i;

            /* Dump driver status (TX and RX rings) while we're here. */
            XYLog("driver status:\n");
            for (i = 0; i < IWX_MAX_QUEUES; i++) {
                struct iwx_tx_ring *ring = &sc->txq[i];
                XYLog("  tx ring %2d: qid=%-2d cur=%-3d "
                      "queued=%-3d\n",
                      i, ring->qid, ring->cur, ring->queued);
            }
            XYLog("  rx ring: cur=%d\n", sc->rxq.cur);
            XYLog("  802.11 state %s\n",
                  ieee80211_state_name[sc->sc_ic.ic_state]);

            that->iwx_nic_error(sc);
#endif
            if ((sc->sc_flags & IWX_FLAG_SHUTDOWN) == 0)
                task_add(systq, &sc->init_task);
            ifp->netStat->outputErrors++;
            return;
        }
        ifp->if_timer = 1;
    }

    ieee80211_watchdog(ifp);
}

int ItlIwx::
iwx_ioctl(struct _ifnet *ifp, u_long cmd, caddr_t data)
{
    struct iwx_softc *sc = (struct iwx_softc *)ifp->if_softc;
    int s, err = 0, generation = sc->sc_generation;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    
    /*
     * Prevent processes from entering this function while another
     * process is tsleep'ing in it.
     */
    //    err = rw_enter(&sc->ioctl_rwl, RW_WRITE | RW_INTR);
    if (err == 0 && generation != sc->sc_generation) {
        //        rw_exit(&sc->ioctl_rwl);
        return ENXIO;
    }
    if (err)
        return err;
    s = splnet();
    
    switch (cmd) {
        case SIOCSIFADDR:
            ifp->if_flags |= IFF_UP;
            /* FALLTHROUGH */
        case SIOCSIFFLAGS:
            if (ifp->if_flags & IFF_UP) {
                if (!(ifp->if_flags & IFF_RUNNING)) {
                    err = that->iwx_init(ifp);
                }
            } else {
                if (ifp->if_flags & IFF_RUNNING)
                    that->iwx_stop(ifp);
            }
            break;
            
        default:
            err = ieee80211_ioctl(ifp, cmd, data);
    }
    
    if (err == ENETRESET) {
        err = 0;
        if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
            (IFF_UP | IFF_RUNNING)) {
            that->iwx_stop(ifp);
            err = that->iwx_init(ifp);
        }
    }
    
    splx(s);
    //    rw_exit(&sc->ioctl_rwl);
    
    return err;
}

#if 1 /* usually #ifdef IWX_DEBUG but always enabled for now */
/*
 * Note: This structure is read from the device with IO accesses,
 * and the reading already does the endian conversion. As it is
 * read with uint32_t-sized accesses, any members with a different size
 * need to be ordered correctly though!
 */
struct iwx_error_event_table {
    uint32_t valid;        /* (nonzero) valid, (0) log is empty */
    uint32_t error_id;        /* type of error */
    uint32_t trm_hw_status0;    /* TRM HW status */
    uint32_t trm_hw_status1;    /* TRM HW status */
    uint32_t blink2;        /* branch link */
    uint32_t ilink1;        /* interrupt link */
    uint32_t ilink2;        /* interrupt link */
    uint32_t data1;        /* error-specific data */
    uint32_t data2;        /* error-specific data */
    uint32_t data3;        /* error-specific data */
    uint32_t bcon_time;        /* beacon timer */
    uint32_t tsf_low;        /* network timestamp function timer */
    uint32_t tsf_hi;        /* network timestamp function timer */
    uint32_t gp1;        /* GP1 timer register */
    uint32_t gp2;        /* GP2 timer register */
    uint32_t fw_rev_type;    /* firmware revision type */
    uint32_t major;        /* uCode version major */
    uint32_t minor;        /* uCode version minor */
    uint32_t hw_ver;        /* HW Silicon version */
    uint32_t brd_ver;        /* HW board version */
    uint32_t log_pc;        /* log program counter */
    uint32_t frame_ptr;        /* frame pointer */
    uint32_t stack_ptr;        /* stack pointer */
    uint32_t hcmd;        /* last host command header */
    uint32_t isr0;        /* isr status register LMPM_NIC_ISR0:
                         * rxtx_flag */
    uint32_t isr1;        /* isr status register LMPM_NIC_ISR1:
                         * host_flag */
    uint32_t isr2;        /* isr status register LMPM_NIC_ISR2:
                         * enc_flag */
    uint32_t isr3;        /* isr status register LMPM_NIC_ISR3:
                         * time_flag */
    uint32_t isr4;        /* isr status register LMPM_NIC_ISR4:
                         * wico interrupt */
    uint32_t last_cmd_id;    /* last HCMD id handled by the firmware */
    uint32_t wait_event;        /* wait event() caller address */
    uint32_t l2p_control;    /* L2pControlField */
    uint32_t l2p_duration;    /* L2pDurationField */
    uint32_t l2p_mhvalid;    /* L2pMhValidBits */
    uint32_t l2p_addr_match;    /* L2pAddrMatchStat */
    uint32_t lmpm_pmg_sel;    /* indicate which clocks are turned on
                             * (LMPM_PMG_SEL) */
    uint32_t u_timestamp;    /* indicate when the date and time of the
                             * compilation */
    uint32_t flow_handler;    /* FH read/write pointers, RX credit */
} __packed /* LOG_ERROR_TABLE_API_S_VER_3 */;

/*
 * UMAC error struct - relevant starting from family 8000 chip.
 * Note: This structure is read from the device with IO accesses,
 * and the reading already does the endian conversion. As it is
 * read with u32-sized accesses, any members with a different size
 * need to be ordered correctly though!
 */
struct iwx_umac_error_event_table {
    uint32_t valid;        /* (nonzero) valid, (0) log is empty */
    uint32_t error_id;    /* type of error */
    uint32_t blink1;    /* branch link */
    uint32_t blink2;    /* branch link */
    uint32_t ilink1;    /* interrupt link */
    uint32_t ilink2;    /* interrupt link */
    uint32_t data1;        /* error-specific data */
    uint32_t data2;        /* error-specific data */
    uint32_t data3;        /* error-specific data */
    uint32_t umac_major;
    uint32_t umac_minor;
    uint32_t frame_pointer;    /* core register 27*/
    uint32_t stack_pointer;    /* core register 28 */
    uint32_t cmd_header;    /* latest host cmd sent to UMAC */
    uint32_t nic_isr_pref;    /* ISR status register */
} __packed;

#define ERROR_START_OFFSET  (1 * sizeof(uint32_t))
#define ERROR_ELEM_SIZE     (7 * sizeof(uint32_t))

void ItlIwx::
iwx_nic_umac_error(struct iwx_softc *sc)
{
    struct iwx_umac_error_event_table table;
    uint32_t base;
    
    base = sc->sc_uc.uc_umac_error_event_table;
    
    if (base < 0x400000) {
        XYLog("%s: Invalid error log pointer 0x%08x\n",
              DEVNAME(sc), base);
        return;
    }
    
    if (iwx_read_mem(sc, base, &table, sizeof(table)/sizeof(uint32_t))) {
        XYLog("%s: reading errlog failed\n", DEVNAME(sc));
        return;
    }
    
    if (ERROR_START_OFFSET <= table.valid * ERROR_ELEM_SIZE) {
        XYLog("%s: Start UMAC Error Log Dump:\n", DEVNAME(sc));
        XYLog("%s: Status: 0x%x, count: %d\n", DEVNAME(sc),
              sc->sc_flags, table.valid);
    }
    
    XYLog("%s: 0x%08X | %s\n", DEVNAME(sc), table.error_id,
          iwx_desc_lookup(table.error_id));
    XYLog("%s: 0x%08X | umac branchlink1\n", DEVNAME(sc), table.blink1);
    XYLog("%s: 0x%08X | umac branchlink2\n", DEVNAME(sc), table.blink2);
    XYLog("%s: 0x%08X | umac interruptlink1\n", DEVNAME(sc), table.ilink1);
    XYLog("%s: 0x%08X | umac interruptlink2\n", DEVNAME(sc), table.ilink2);
    XYLog("%s: 0x%08X | umac data1\n", DEVNAME(sc), table.data1);
    XYLog("%s: 0x%08X | umac data2\n", DEVNAME(sc), table.data2);
    XYLog("%s: 0x%08X | umac data3\n", DEVNAME(sc), table.data3);
    XYLog("%s: 0x%08X | umac major\n", DEVNAME(sc), table.umac_major);
    XYLog("%s: 0x%08X | umac minor\n", DEVNAME(sc), table.umac_minor);
    XYLog("%s: 0x%08X | frame pointer\n", DEVNAME(sc),
          table.frame_pointer);
    XYLog("%s: 0x%08X | stack pointer\n", DEVNAME(sc),
          table.stack_pointer);
    XYLog("%s: 0x%08X | last host cmd\n", DEVNAME(sc), table.cmd_header);
    XYLog("%s: 0x%08X | isr status reg\n", DEVNAME(sc),
          table.nic_isr_pref);
}

#define IWX_FW_SYSASSERT_CPU_MASK 0xf0000000
static struct {
    const char *name;
    uint8_t num;
} advanced_lookup[] = {
    { "NMI_INTERRUPT_WDG", 0x34 },
    { "SYSASSERT", 0x35 },
    { "UCODE_VERSION_MISMATCH", 0x37 },
    { "BAD_COMMAND", 0x38 },
    { "BAD_COMMAND", 0x39 },
    { "NMI_INTERRUPT_DATA_ACTION_PT", 0x3C },
    { "FATAL_ERROR", 0x3D },
    { "NMI_TRM_HW_ERR", 0x46 },
    { "NMI_INTERRUPT_TRM", 0x4C },
    { "NMI_INTERRUPT_BREAK_POINT", 0x54 },
    { "NMI_INTERRUPT_WDG_RXF_FULL", 0x5C },
    { "NMI_INTERRUPT_WDG_NO_RBD_RXF_FULL", 0x64 },
    { "NMI_INTERRUPT_HOST", 0x66 },
    { "NMI_INTERRUPT_LMAC_FATAL", 0x70 },
    { "NMI_INTERRUPT_UMAC_FATAL", 0x71 },
    { "NMI_INTERRUPT_OTHER_LMAC_FATAL", 0x73 },
    { "NMI_INTERRUPT_ACTION_PT", 0x7C },
    { "NMI_INTERRUPT_UNKNOWN", 0x84 },
    { "NMI_INTERRUPT_INST_ACTION_PT", 0x86 },
    { "ADVANCED_SYSASSERT", 0 },
};

const char *ItlIwx::
iwx_desc_lookup(uint32_t num)
{
    int i;
    
    for (i = 0; i < nitems(advanced_lookup) - 1; i++)
        if (advanced_lookup[i].num ==
            (num & ~IWX_FW_SYSASSERT_CPU_MASK))
            return advanced_lookup[i].name;
    
    /* No entry matches 'num', so it is the last: ADVANCED_SYSASSERT */
    return advanced_lookup[i].name;
}

/*
 * Support for dumping the error log seemed like a good idea ...
 * but it's mostly hex junk and the only sensible thing is the
 * hw/ucode revision (which we know anyway).  Since it's here,
 * I'll just leave it in, just in case e.g. the Intel guys want to
 * help us decipher some "ADVANCED_SYSASSERT" later.
 */
void ItlIwx::
iwx_nic_error(struct iwx_softc *sc)
{
    struct iwx_error_event_table table;
    uint32_t base;
    
    XYLog("%s: dumping device error log\n", DEVNAME(sc));
    base = sc->sc_uc.uc_lmac_error_event_table[0];
    if (base < 0x400000) {
        XYLog("%s: Invalid error log pointer 0x%08x\n",
              DEVNAME(sc), base);
        return;
    }
    
    if (iwx_read_mem(sc, base, &table, sizeof(table)/sizeof(uint32_t))) {
        XYLog("%s: reading errlog failed\n", DEVNAME(sc));
        return;
    }
    
    if (!table.valid) {
        XYLog("%s: errlog not found, skipping\n", DEVNAME(sc));
        return;
    }
    
    if (ERROR_START_OFFSET <= table.valid * ERROR_ELEM_SIZE) {
        XYLog("%s: Start Error Log Dump:\n", DEVNAME(sc));
        XYLog("%s: Status: 0x%x, count: %d\n", DEVNAME(sc),
              sc->sc_flags, table.valid);
    }
    
    XYLog("%s: 0x%08X | %-28s\n", DEVNAME(sc), table.error_id,
          iwx_desc_lookup(table.error_id));
    XYLog("%s: %08X | trm_hw_status0\n", DEVNAME(sc),
          table.trm_hw_status0);
    XYLog("%s: %08X | trm_hw_status1\n", DEVNAME(sc),
          table.trm_hw_status1);
    XYLog("%s: %08X | branchlink2\n", DEVNAME(sc), table.blink2);
    XYLog("%s: %08X | interruptlink1\n", DEVNAME(sc), table.ilink1);
    XYLog("%s: %08X | interruptlink2\n", DEVNAME(sc), table.ilink2);
    XYLog("%s: %08X | data1\n", DEVNAME(sc), table.data1);
    XYLog("%s: %08X | data2\n", DEVNAME(sc), table.data2);
    XYLog("%s: %08X | data3\n", DEVNAME(sc), table.data3);
    XYLog("%s: %08X | beacon time\n", DEVNAME(sc), table.bcon_time);
    XYLog("%s: %08X | tsf low\n", DEVNAME(sc), table.tsf_low);
    XYLog("%s: %08X | tsf hi\n", DEVNAME(sc), table.tsf_hi);
    XYLog("%s: %08X | time gp1\n", DEVNAME(sc), table.gp1);
    XYLog("%s: %08X | time gp2\n", DEVNAME(sc), table.gp2);
    XYLog("%s: %08X | uCode revision type\n", DEVNAME(sc),
          table.fw_rev_type);
    XYLog("%s: %08X | uCode version major\n", DEVNAME(sc),
          table.major);
    XYLog("%s: %08X | uCode version minor\n", DEVNAME(sc),
          table.minor);
    XYLog("%s: %08X | hw version\n", DEVNAME(sc), table.hw_ver);
    XYLog("%s: %08X | board version\n", DEVNAME(sc), table.brd_ver);
    XYLog("%s: %08X | hcmd\n", DEVNAME(sc), table.hcmd);
    XYLog("%s: %08X | isr0\n", DEVNAME(sc), table.isr0);
    XYLog("%s: %08X | isr1\n", DEVNAME(sc), table.isr1);
    XYLog("%s: %08X | isr2\n", DEVNAME(sc), table.isr2);
    XYLog("%s: %08X | isr3\n", DEVNAME(sc), table.isr3);
    XYLog("%s: %08X | isr4\n", DEVNAME(sc), table.isr4);
    XYLog("%s: %08X | last cmd Id\n", DEVNAME(sc), table.last_cmd_id);
    XYLog("%s: %08X | wait_event\n", DEVNAME(sc), table.wait_event);
    XYLog("%s: %08X | l2p_control\n", DEVNAME(sc), table.l2p_control);
    XYLog("%s: %08X | l2p_duration\n", DEVNAME(sc), table.l2p_duration);
    XYLog("%s: %08X | l2p_mhvalid\n", DEVNAME(sc), table.l2p_mhvalid);
    XYLog("%s: %08X | l2p_addr_match\n", DEVNAME(sc), table.l2p_addr_match);
    XYLog("%s: %08X | lmpm_pmg_sel\n", DEVNAME(sc), table.lmpm_pmg_sel);
    XYLog("%s: %08X | timestamp\n", DEVNAME(sc), table.u_timestamp);
    XYLog("%s: %08X | flow_handler\n", DEVNAME(sc), table.flow_handler);
    
    if (sc->sc_uc.uc_umac_error_event_table)
        iwx_nic_umac_error(sc);
}
#endif

//#define SYNC_RESP_STRUCT(_var_, _pkt_)                    \
//do {                                    \
//    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*(_pkt_)),    \
//        sizeof(*(_var_)), BUS_DMASYNC_POSTREAD);            \
//    _var_ = (void *)((_pkt_)+1);                    \
//} while (/*CONSTCOND*/0)
//
//#define SYNC_RESP_PTR(_ptr_, _len_, _pkt_)                \
//do {                                    \
//    bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*(_pkt_)),    \
//        sizeof(len), BUS_DMASYNC_POSTREAD);                \
//    _ptr_ = (void *)((_pkt_)+1);                    \
//} while (/*CONSTCOND*/0)

#define SYNC_RESP_STRUCT(_var_, _pkt_, t)                    \
do {                                    \
bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*(_pkt_)),    \
sizeof(*(_var_)), BUS_DMASYNC_POSTREAD);            \
_var_ = (t)((_pkt_)+1);                    \
} while (/*CONSTCOND*/0)

int ItlIwx::
iwx_rx_pkt_valid(struct iwx_rx_packet *pkt)
{
    int qid, idx, code;
    
    qid = pkt->hdr.qid & ~0x80;
    idx = pkt->hdr.idx;
    code = IWX_WIDE_ID(pkt->hdr.group_id, pkt->hdr.cmd);
    
    return (!(qid == 0 && idx == 0 && code == 0) &&
            pkt->len_n_flags != htole32(IWX_FH_RSCSR_FRAME_INVALID));
}

/**
 * struct iwl_pnvm_init_complete_ntfy - PNVM initialization complete
 * @status: PNVM image loading status
 */
struct iwl_pnvm_init_complete_ntfy {
    uint32_t status;
} __packed; /* PNVM_INIT_COMPLETE_NTFY_S_VER_1 */

void ItlIwx::
iwx_rx_pkt(struct iwx_softc *sc, struct iwx_rx_data *data, struct mbuf_list *ml)
{
    struct _ifnet *ifp = IC2IFP(&sc->sc_ic);
    struct iwx_rx_packet *pkt, *nextpkt;
    uint32_t offset = 0, nextoff = 0, nmpdu = 0, len;
    mbuf_t m0, m;
    const size_t minsz = sizeof(pkt->len_n_flags) + sizeof(pkt->hdr);
    int qid, idx, code, handled = 1;
    
    //    bus_dmamap_sync(sc->sc_dmat, data->map, 0, IWX_RBUF_SIZE,
    //        BUS_DMASYNC_POSTREAD);
    
    m0 = data->m;
    while (m0 && offset + minsz < IWX_RBUF_SIZE) {
        pkt = (struct iwx_rx_packet *)((uint8_t*)mbuf_data(m0) + offset);
        qid = pkt->hdr.qid;
        idx = pkt->hdr.idx;
        
        code = IWX_WIDE_ID(pkt->hdr.group_id, pkt->hdr.cmd);
        
        DPRINTFN(3, ("%s gid=%d cmd=%d code=0x%02x qid=%d idx=%d packet_len=%d payload_len=%d\n", __FUNCTION__, pkt->hdr.group_id, pkt->hdr.cmd, code, qid, idx, iwx_rx_packet_len(pkt), iwx_rx_packet_payload_len(pkt)));
        
        if (!iwx_rx_pkt_valid(pkt))
            break;
        
        /*
         * XXX Intel inside (tm)
         * Any commands in the LONG_GROUP could actually be in the
         * LEGACY group. Firmware API versions >= 50 reject commands
         * in group 0, forcing us to use this hack.
         */
        if (iwx_cmd_groupid(code) == IWX_LONG_GROUP) {
            struct iwx_tx_ring *ring = &sc->txq[qid];
            struct iwx_tx_data *txdata = &ring->data[idx];
            if (txdata->flags & IWX_TXDATA_FLAG_CMD_IS_NARROW)
                code = iwx_cmd_opcode(code);
        }
        
        len = sizeof(pkt->len_n_flags) + iwx_rx_packet_len(pkt);
        if (len < minsz || len > (IWX_RBUF_SIZE - offset))
            break;
        
        if (code == IWX_REPLY_RX_MPDU_CMD && ++nmpdu == 1) {
            /* Take mbuf m0 off the RX ring. */
            if (iwx_rx_addbuf(sc, IWX_RBUF_SIZE, sc->rxq.cur)) {
                ifp->netStat->inputErrors++;
                break;
            }
            KASSERT(data->m != m0, "data->m != m0");
        }
        
        switch (code) {
            case IWX_REPLY_RX_PHY_CMD:
                iwx_rx_rx_phy_cmd(sc, pkt, data);
                break;
                
            case IWX_REPLY_RX_MPDU_CMD: {
                size_t maxlen = IWX_RBUF_SIZE - offset - minsz;
                nextoff = offset +
                roundup(len, IWX_FH_RSCSR_FRAME_ALIGN);
                nextpkt = (struct iwx_rx_packet *)
                ((uint8_t*)mbuf_data(m0) + nextoff);
                if (nextoff + minsz >= IWX_RBUF_SIZE ||
                    !iwx_rx_pkt_valid(nextpkt)) {
                    /* No need to copy last frame in buffer. */
                    if (offset > 0)
                        mbuf_adj(m0, offset);
                    iwx_rx_mpdu_mq(sc, m0, pkt->data, maxlen, ml);
                    m0 = NULL; /* stack owns m0 now; abort loop */
                } else {
                    /*
                     * Create an mbuf which points to the current
                     * packet. Always copy from offset zero to
                     * preserve m_pkthdr.
                     */
                    mbuf_copym(m0, 0, MBUF_COPYALL, MBUF_DONTWAIT, &m);
                    if (m == NULL) {
                        ifp->netStat->inputErrors++;
                        mbuf_freem(m0);
                        m0 = NULL;
                        break;
                    }
                    mbuf_adj(m, offset);
                    iwx_rx_mpdu_mq(sc, m, pkt->data, maxlen, ml);
                }
                break;
            }
            case IWX_BA_NOTIF:
                iwx_rx_tx_ba_notif(sc, pkt, data);
                break;
                
            case IWX_TX_CMD:
                iwx_rx_tx_cmd(sc, pkt, data);
                break;
                
            case IWX_MISSED_BEACONS_NOTIFICATION:
                iwx_rx_bmiss(sc, pkt, data);
                break;
                
            case IWX_MFUART_LOAD_NOTIFICATION:
                break;
                
            case IWX_ALIVE: {
                struct iwx_alive_resp_v4 *resp4;
                struct iwx_alive_resp_v5 *resp5;
                
                DPRINTF(("%s: firmware alive, size=%d\n", __FUNCTION__, iwx_rx_packet_payload_len(pkt)));
                if (iwx_rx_packet_payload_len(pkt) == sizeof(*resp4)) {
                    SYNC_RESP_STRUCT(resp4, pkt, struct iwx_alive_resp_v4 *);
                    sc->sc_uc.uc_lmac_error_event_table[0] = le32toh(
                                                                     resp4->lmac_data[0].dbg_ptrs.error_event_table_ptr);
                    sc->sc_uc.uc_lmac_error_event_table[1] = le32toh(
                                                                     resp4->lmac_data[1].dbg_ptrs.error_event_table_ptr);
                    sc->sc_uc.uc_log_event_table = le32toh(
                                                           resp4->lmac_data[0].dbg_ptrs.log_event_table_ptr);
                    sc->sc_uc.uc_umac_error_event_table = le32toh(
                                                                  resp4->umac_data.dbg_ptrs.error_info_addr);
                    if (resp4->status == IWX_ALIVE_STATUS_OK)
                        sc->sc_uc.uc_ok = 1;
                    else
                        sc->sc_uc.uc_ok = 0;
                } else {
                    SYNC_RESP_STRUCT(resp5, pkt, struct iwx_alive_resp_v5 *);
                    sc->sc_uc.uc_lmac_error_event_table[0] = le32toh(
                                                                     resp5->lmac_data[0].dbg_ptrs.error_event_table_ptr);
                    sc->sc_uc.uc_lmac_error_event_table[1] = le32toh(
                                                                     resp5->lmac_data[1].dbg_ptrs.error_event_table_ptr);
                    sc->sc_uc.uc_log_event_table = le32toh(
                                                           resp5->lmac_data[0].dbg_ptrs.log_event_table_ptr);
                    sc->sc_uc.uc_umac_error_event_table = le32toh(
                                                                  resp5->umac_data.dbg_ptrs.error_info_addr);
                    if (resp5->status == IWX_ALIVE_STATUS_OK)
                        sc->sc_uc.uc_ok = 1;
                    else
                        sc->sc_uc.uc_ok = 0;
                    
                    sc->sku_id[0] = le32toh(resp5->sku_id.data[0]);
                    sc->sku_id[1] = le32toh(resp5->sku_id.data[1]);
                    sc->sku_id[2] = le32toh(resp5->sku_id.data[2]);
                    
                    XYLog("Got sku_id: 0x0%x 0x0%x 0x0%x\n",
                                 sc->sku_id[0],
                                 sc->sku_id[1],
                                 sc->sku_id[2]);
                }
                
                sc->sc_uc.uc_intr = 1;
                wakeupOn(&sc->sc_uc);
                break;
            }
                
            case IWX_STATISTICS_NOTIFICATION: {
                struct iwx_notif_statistics *stats;
                struct iwx_notif_statistics_v11 *stats_v11;
                if (isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_NEW_RX_STATS)) {
                    SYNC_RESP_STRUCT(stats, pkt, struct iwx_notif_statistics *);
                    sc->sc_noise = iwx_get_noise((uint8_t *)&stats->rx.general.beacon_silence_rssi_a);
                } else {
                    SYNC_RESP_STRUCT(stats_v11, pkt, struct iwx_notif_statistics_v11 *);
                    sc->sc_noise = iwx_get_noise((uint8_t *)&stats_v11->rx.general.beacon_silence_rssi_a);
                }
                break;
            }
                
            case IWX_DTS_MEASUREMENT_NOTIFICATION:
            case IWX_WIDE_ID(IWX_PHY_OPS_GROUP,
                             IWX_DTS_MEASUREMENT_NOTIF_WIDE):
            case IWX_WIDE_ID(IWX_PHY_OPS_GROUP,
                             IWX_TEMP_REPORTING_THRESHOLDS_CMD):
                break;
                
            case IWX_WIDE_ID(IWX_PHY_OPS_GROUP,
                             IWX_CT_KILL_NOTIFICATION): {
                struct iwx_ct_kill_notif *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwx_ct_kill_notif *);
                XYLog("%s: device at critical temperature (%u degC), "
                       "stopping device\n",
                       DEVNAME(sc), le16toh(notif->temperature));
                sc->sc_flags |= IWX_FLAG_HW_ERR;
                task_add(systq, &sc->init_task);
                break;
            }
                
            case IWX_WIDE_ID(IWX_REGULATORY_AND_NVM_GROUP,
                IWX_NVM_GET_INFO):
            case IWX_ADD_STA_KEY:
            case IWX_PHY_CONFIGURATION_CMD:
            case IWX_TX_ANT_CONFIGURATION_CMD:
            case IWX_ADD_STA:
            case IWX_MAC_CONTEXT_CMD:
            case IWX_REPLY_SF_CFG_CMD:
            case IWX_POWER_TABLE_CMD:
            case IWX_LTR_CONFIG:
            case IWX_PHY_CONTEXT_CMD:
            case IWX_BINDING_CONTEXT_CMD:
            case IWX_WIDE_ID(IWX_LONG_GROUP, IWX_SCAN_CFG_CMD):
            case IWX_WIDE_ID(IWX_LONG_GROUP, IWX_SCAN_REQ_UMAC):
            case IWX_WIDE_ID(IWX_LONG_GROUP, IWX_SCAN_ABORT_UMAC):
            case IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_SESSION_PROTECTION_CMD):
            case IWX_REPLY_BEACON_FILTERING_CMD:
            case IWX_MAC_PM_POWER_TABLE:
            case IWX_TIME_QUOTA_CMD:
            case IWX_REMOVE_STA:
            case IWX_TXPATH_FLUSH:
            case IWX_BT_CONFIG:
            case IWX_MCC_UPDATE_CMD:
            case IWX_TIME_EVENT_CMD:
            case IWX_STATISTICS_CMD:
            case IWX_SCD_QUEUE_CFG: {
                size_t pkt_len;
                
                if (sc->sc_cmd_resp_pkt[idx] == NULL)
                    break;
                
                //            bus_dmamap_sync(sc->sc_dmat, data->map, 0,
                //                sizeof(*pkt), BUS_DMASYNC_POSTREAD);
                
                pkt_len = sizeof(pkt->len_n_flags) +
                iwx_rx_packet_len(pkt);
                
                if ((pkt->hdr.group_id & IWX_CMD_FAILED_MSK) ||
                    pkt_len < sizeof(*pkt) ||
                    pkt_len > sc->sc_cmd_resp_len[idx]) {
                    ::free(sc->sc_cmd_resp_pkt[idx]);
                    sc->sc_cmd_resp_pkt[idx] = NULL;
                    break;
                }
                
                //            bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*pkt),
                //                pkt_len - sizeof(*pkt), BUS_DMASYNC_POSTREAD);
                memcpy(sc->sc_cmd_resp_pkt[idx], pkt, pkt_len);
                break;
            }
                
            case IWX_WIDE_ID(IWX_REGULATORY_AND_NVM_GROUP, IWX_PNVM_INIT_COMPLETE_NTFY):
                wakeupOn(&sc->sc_init_complete);
                struct iwl_pnvm_init_complete_ntfy *pnvm_ntf;
                SYNC_RESP_STRUCT(pnvm_ntf, pkt, struct iwl_pnvm_init_complete_ntfy *);
                XYLog("PNVM complete notification received with status 0x%0x\n", le32toh(pnvm_ntf->status));
                break;
                
            case IWX_INIT_COMPLETE_NOTIF:
                sc->sc_init_complete |= IWX_INIT_COMPLETE;
                wakeupOn(&sc->sc_init_complete);
                break;
                
            case IWX_SCAN_COMPLETE_UMAC: {
                struct iwx_umac_scan_complete *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwx_umac_scan_complete *);
                iwx_endscan(sc);
                break;
            }
                
            case IWX_SCAN_ITERATION_COMPLETE_UMAC: {
                struct iwx_umac_scan_iter_complete_notif *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwx_umac_scan_iter_complete_notif *);
                iwx_endscan(sc);
                break;
            }
                
            case IWX_MCC_CHUB_UPDATE_CMD: {
                struct iwx_mcc_chub_notif *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwx_mcc_chub_notif *);
                iwx_mcc_update(sc, notif);
                break;
            }
                
            case IWX_REPLY_ERROR: {
                struct iwx_error_resp *resp;
                SYNC_RESP_STRUCT(resp, pkt, struct iwx_error_resp *);
                XYLog("%s: firmware error 0x%x, cmd 0x%x\n",
                      DEVNAME(sc), le32toh(resp->error_type),
                      resp->cmd_id);
                break;
            }
                
            case IWX_TIME_EVENT_NOTIFICATION: {
                struct iwx_time_event_notif *notif;
                uint32_t action;
                SYNC_RESP_STRUCT(notif, pkt, struct iwx_time_event_notif *);
                
                if (sc->sc_time_event_uid != le32toh(notif->unique_id))
                    break;
                action = le32toh(notif->action);
                if (action & IWX_TE_V2_NOTIF_HOST_EVENT_END)
                    sc->sc_flags &= ~IWX_FLAG_TE_ACTIVE;
                break;
            }
                
            case IWX_WIDE_ID(IWX_SYSTEM_GROUP,
                             IWX_FSEQ_VER_MISMATCH_NOTIFICATION):
                break;
                
                /*
                 * Firmware versions 21 and 22 generate some DEBUG_LOG_MSG
                 * messages. Just ignore them for now.
                 */
            case IWX_DEBUG_LOG_MSG:
                break;
                
            case IWX_MCAST_FILTER_CMD:
                break;
                
            case IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_DQA_ENABLE_CMD):
                break;
                
            case IWX_WIDE_ID(IWX_SYSTEM_GROUP, IWX_SOC_CONFIGURATION_CMD):
                break;
                
            case IWX_WIDE_ID(IWX_SYSTEM_GROUP, IWX_INIT_EXTENDED_CFG_CMD):
                break;
                
            case IWX_WIDE_ID(IWX_SYSTEM_GROUP, IWX_SHARED_MEM_CFG_CMD):
                break;
                
            case IWX_WIDE_ID(IWX_REGULATORY_AND_NVM_GROUP,
                             IWX_NVM_ACCESS_COMPLETE):
                break;
                
            case IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_RX_NO_DATA_NOTIF):
                break; /* happens in monitor mode; ignore for now */
            case IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_TLC_MNG_CONFIG_CMD):
                break;
                
            case IWX_WIDE_ID(IWX_DATA_PATH_GROUP,
                             IWX_TLC_MNG_UPDATE_NOTIF): {
                struct iwx_tlc_update_notif *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwx_tlc_update_notif *);
                if (iwx_rx_packet_payload_len(pkt) == sizeof(*notif))
                    iwx_rs_update(sc, notif);
                break;
            }
                
            case IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_SESSION_PROTECTION_NOTIF): {
                struct iwx_session_prot_notif *notif;
                SYNC_RESP_STRUCT(notif, pkt, struct iwx_session_prot_notif *);
                if (!notif->status) {
                    XYLog("Session protection failure\n");
                    sc->sc_flags &= ~IWX_FLAG_TE_ACTIVE;
                    break;
                }
                if (!notif->start) {
                    /*
                     * By now, we should have finished association
                     * and know the dtim period.
                     */
                    sc->sc_flags &= ~IWX_FLAG_TE_ACTIVE;
                    XYLog("%s finish association\n", __FUNCTION__);
                }
                break;
            }
            
            case IWX_WIDE_ID(IWX_LEGACY_GROUP, IWX_BAR_FRAME_RELEASE): {
                struct iwx_bar_frame_release *release;
                SYNC_RESP_STRUCT(release, pkt, struct iwx_bar_frame_release *);
                unsigned int baid = le32_get_bits(release->ba_info,
                                  IWX_BAR_FRAME_RELEASE_BAID_MASK);
                unsigned int nssn = le32_get_bits(release->ba_info,
                                  IWX_BAR_FRAME_RELEASE_NSSN_MASK);
                unsigned int sta_id = le32_get_bits(release->sta_tid,
                                    IWX_BAR_FRAME_RELEASE_STA_MASK);
                unsigned int tid = le32_get_bits(release->sta_tid,
                                 IWX_BAR_FRAME_RELEASE_TID_MASK);
                struct iwx_rxba_data *baid_data;
                
                if (iwx_rx_packet_payload_len(pkt) < sizeof(*release))
                    break;
                
                if (baid == IWX_RX_REORDER_DATA_INVALID_BAID || baid >= IWX_MAX_BAID)
                    break;
                
                baid_data = &sc->sc_rxba_data[baid];
                
                if (!baid_data) {
                    DPRINTFN(1, ("Got valid BAID %d but not allocated, invalid BAR release!\n",
                     baid));
                    break;
                }
                
                if (tid != baid_data->tid || sta_id != baid_data->sta_id) {
                    DPRINTFN(1, ("baid 0x%x is mapped to sta:%d tid:%d, but BAR release received for sta:%d tid:%d\n",
                                 baid, baid_data->sta_id, baid_data->tid, sta_id,
                                 tid));
                    break;
                }
                
                iwx_release_frames(sc, sc->sc_ic.ic_bss, baid_data, &baid_data->reorder_buf, nssn, ml);
                
                break;
            }
                
            default:
                handled = 0;
                XYLog("%s: unhandled firmware response 0x%x/0x%x "
                      "rx ring %d[%d]\n",
                      DEVNAME(sc), code, pkt->len_n_flags,
                      (qid & ~0x80), idx);
                break;
        }
        
        /*
         * uCode sets bit 0x80 when it originates the notification,
         * i.e. when the notification is not a direct response to a
         * command sent by the driver.
         * For example, uCode issues IWX_REPLY_RX when it sends a
         * received frame to the driver.
         */
        if (handled && !(qid & (1 << 7))) {
            iwx_cmd_done(sc, qid, idx, code);
        }
        
        offset += roundup(len, IWX_FH_RSCSR_FRAME_ALIGN);
        
        if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
            break;
    }
    
    if (m0 && m0 != data->m && mbuf_type(m0) != MBUF_TYPE_FREE)
        mbuf_freem(m0);
}

void ItlIwx::
iwx_notif_intr(struct iwx_softc *sc)
{
    struct mbuf_list ml = MBUF_LIST_INITIALIZER();
    uint16_t hw;
    
    //    bus_dmamap_sync(sc->sc_dmat, sc->rxq.stat_dma.map,
    //        0, sc->rxq.stat_dma.size, BUS_DMASYNC_POSTREAD);
    
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
        hw = le16toh(*(uint16_t *)(sc->rxq.stat)) & 0xfff;
    else
        hw = le16toh(((struct iwx_rb_status *)sc->rxq.stat)->closed_rb_num) & 0xfff;
    hw &= (IWX_RX_MQ_RING_COUNT - 1);
    DPRINTFN(3, ("%s hw=%d\n", __FUNCTION__, hw));
    while (sc->rxq.cur != hw) {
        struct iwx_rx_data *data = &sc->rxq.data[sc->rxq.cur];
        iwx_rx_pkt(sc, data, &ml);
        sc->rxq.cur = (sc->rxq.cur + 1) % IWX_RX_MQ_RING_COUNT;
    }
    if_input(&sc->sc_ic.ic_if, &ml);
    
    /*
     * Tell the firmware what we have processed.
     * Seems like the hardware gets upset unless we align the write by 8??
     */
    hw = (hw == 0) ? IWX_RX_MQ_RING_COUNT - 1 : hw - 1;
    IWX_WRITE(sc, IWX_RFH_Q0_FRBDCB_WIDX_TRG, hw & ~7);
}

int ItlIwx::
iwx_intr(OSObject *object, IOInterruptEventSource* sender, int count)
{
//    XYLog("Interrupt!!!\n");
    ItlIwx *that = (ItlIwx*)object;
    struct iwx_softc *sc = &that->com;
    int handled = 0;
    int r1, r2, rv = 0;
    
//    IWX_WRITE(&that->com, IWX_CSR_INT_MASK, 0);
    
    if (sc->sc_flags & IWX_FLAG_USE_ICT) {
        uint32_t *ict = (uint32_t *)sc->ict_dma.vaddr;
        int tmp;
        
        tmp = htole32(ict[sc->ict_cur]);
        if (!tmp)
            goto out_ena;
        
        /*
         * ok, there was something.  keep plowing until we have all.
         */
        r1 = r2 = 0;
        while (tmp) {
            r1 |= tmp;
            ict[sc->ict_cur] = 0;
            sc->ict_cur = (sc->ict_cur+1) % IWX_ICT_COUNT;
            tmp = htole32(ict[sc->ict_cur]);
        }
        
        /* this is where the fun begins.  don't ask */
        if (r1 == 0xffffffff)
            r1 = 0;
        
        /* i am not expected to understand this */
        if (r1 & 0xc0000)
            r1 |= 0x8000;
        r1 = (0xff & r1) | ((0xff00 & r1) << 16);
    } else {
        r1 = IWX_READ(sc, IWX_CSR_INT);
        if (r1 == 0xffffffff || (r1 & 0xfffffff0) == 0xa5a5a5a0)
            goto out;
        r2 = IWX_READ(sc, IWX_CSR_FH_INT_STATUS);
    }
    if (r1 == 0 && r2 == 0) {
        goto out_ena;
    }
    
    IWX_WRITE(sc, IWX_CSR_INT, r1 | ~sc->sc_intmask);
    
    if (r1 & IWX_CSR_INT_BIT_ALIVE) {
        int i;
        
        /* Firmware has now configured the RFH. */
        for (i = 0; i < IWX_RX_MQ_RING_COUNT; i++)
            that->iwx_update_rx_desc(sc, &sc->rxq, i);
        IWX_WRITE(sc, IWX_RFH_Q0_FRBDCB_WIDX_TRG, 8);
    }
    
    handled |= (r1 & (IWX_CSR_INT_BIT_ALIVE /*| IWX_CSR_INT_BIT_SCD*/));
    
    if (r1 & IWX_CSR_INT_BIT_RF_KILL) {
        handled |= IWX_CSR_INT_BIT_RF_KILL;
        XYLog("%s RF_KILL has been toggled\n", __FUNCTION__);
        that->iwx_check_rfkill(sc);
        task_add(systq, &sc->init_task);
        rv = 1;
        goto out_ena;
    }
    
    if (r1 & IWX_CSR_INT_BIT_SW_ERR) {
#if 1 /* usually #ifdef IWX_DEBUG but always enabled for now */
        int i;
        
        that->iwx_nic_error(sc);
        
        /* Dump driver status (TX and RX rings) while we're here. */
        XYLog("driver status:\n");
        for (i = 0; i < IWX_MAX_QUEUES; i++) {
            struct iwx_tx_ring *ring = &sc->txq[i];
            XYLog("  tx ring %2d: qid=%-2d cur=%-3d "
                  "queued=%-3d\n",
                  i, ring->qid, ring->cur, ring->queued);
        }
        XYLog("  rx ring: cur=%d\n", sc->rxq.cur);
        XYLog("  802.11 state %s\n",
              ieee80211_state_name[sc->sc_ic.ic_state]);
#endif
        
        XYLog("%s: fatal firmware error\n", DEVNAME(sc));
        if ((sc->sc_flags & IWX_FLAG_SHUTDOWN) == 0)
            task_add(systq, &sc->init_task);
        rv = 1;
        goto out;
        
    }
    
    if (r1 & IWX_CSR_INT_BIT_HW_ERR) {
        handled |= IWX_CSR_INT_BIT_HW_ERR;
        XYLog("%s: hardware error, stopping device \n", DEVNAME(sc));
        if ((sc->sc_flags & IWX_FLAG_SHUTDOWN) == 0) {
            sc->sc_flags |= IWX_FLAG_HW_ERR;
            task_add(systq, &sc->init_task);
        }
        rv = 1;
        goto out;
    }
    
    /* firmware chunk loaded */
    if (r1 & IWX_CSR_INT_BIT_FH_TX) {
        IWX_WRITE(sc, IWX_CSR_FH_INT_STATUS, IWX_CSR_FH_INT_TX_MASK);
        handled |= IWX_CSR_INT_BIT_FH_TX;
        
        sc->sc_fw_chunk_done = 1;
        that->wakeupOn(&sc->sc_fw);
    }
    
    if (r1 & (IWX_CSR_INT_BIT_FH_RX | IWX_CSR_INT_BIT_SW_RX |
              IWX_CSR_INT_BIT_RX_PERIODIC)) {
        if (r1 & (IWX_CSR_INT_BIT_FH_RX | IWX_CSR_INT_BIT_SW_RX)) {
            handled |= (IWX_CSR_INT_BIT_FH_RX | IWX_CSR_INT_BIT_SW_RX);
            IWX_WRITE(sc, IWX_CSR_FH_INT_STATUS, IWX_CSR_FH_INT_RX_MASK);
        }
        if (r1 & IWX_CSR_INT_BIT_RX_PERIODIC) {
            handled |= IWX_CSR_INT_BIT_RX_PERIODIC;
            IWX_WRITE(sc, IWX_CSR_INT, IWX_CSR_INT_BIT_RX_PERIODIC);
        }
        
        /* Disable periodic interrupt; we use it as just a one-shot. */
        IWX_WRITE_1(sc, IWX_CSR_INT_PERIODIC_REG, IWX_CSR_INT_PERIODIC_DIS);
        
        /*
         * Enable periodic interrupt in 8 msec only if we received
         * real RX interrupt (instead of just periodic int), to catch
         * any dangling Rx interrupt.  If it was just the periodic
         * interrupt, there was no dangling Rx activity, and no need
         * to extend the periodic interrupt; one-shot is enough.
         */
        if (r1 & (IWX_CSR_INT_BIT_FH_RX | IWX_CSR_INT_BIT_SW_RX))
            IWX_WRITE_1(sc, IWX_CSR_INT_PERIODIC_REG,
                        IWX_CSR_INT_PERIODIC_ENA);
        
        that->iwx_notif_intr(sc);
    }
    
    rv = 1;
    
out_ena:
    that->iwx_restore_interrupts(sc);
out:
    return rv;
}

int ItlIwx::
iwx_intr_msix(OSObject *object, IOInterruptEventSource* sender, int count)
{
//    XYLog("Interrupt!!!\n");
    ItlIwx *that = (ItlIwx*)object;
    struct iwx_softc *sc = &that->com;
    uint32_t inta_fh, inta_hw;
    int vector = 0;
    
    inta_fh = IWX_READ(sc, IWX_CSR_MSIX_FH_INT_CAUSES_AD);
    inta_hw = IWX_READ(sc, IWX_CSR_MSIX_HW_INT_CAUSES_AD);
    IWX_WRITE(sc, IWX_CSR_MSIX_FH_INT_CAUSES_AD, inta_fh);
    IWX_WRITE(sc, IWX_CSR_MSIX_HW_INT_CAUSES_AD, inta_hw);
    inta_fh &= sc->sc_fh_mask;
    inta_hw &= sc->sc_hw_mask;
    
    if (inta_fh & IWX_MSIX_FH_INT_CAUSES_Q0 ||
        inta_fh & IWX_MSIX_FH_INT_CAUSES_Q1) {
        that->iwx_notif_intr(sc);
    }
    
    /* firmware chunk loaded */
    if (inta_fh & IWX_MSIX_FH_INT_CAUSES_D2S_CH0_NUM) {
        sc->sc_fw_chunk_done = 1;
        that->wakeupOn(&sc->sc_fw);
    }
    
    if ((inta_fh & IWX_MSIX_FH_INT_CAUSES_FH_ERR) ||
        (inta_hw & IWX_MSIX_HW_INT_CAUSES_REG_SW_ERR) ||
        (inta_hw & IWX_MSIX_HW_INT_CAUSES_REG_SW_ERR_V2)) {
#if 1 /* usually #ifdef IWX_DEBUG but always enabled for now */
        int i;
        
        that->iwx_nic_error(sc);
        
        /* Dump driver status (TX and RX rings) while we're here. */
        XYLog("driver status:\n");
        for (i = 0; i < IWX_MAX_QUEUES; i++) {
            struct iwx_tx_ring *ring = &sc->txq[i];
            XYLog("  tx ring %2d: qid=%-2d cur=%-3d "
                  "queued=%-3d\n",
                  i, ring->qid, ring->cur, ring->queued);
        }
        XYLog("  rx ring: cur=%d\n", sc->rxq.cur);
        XYLog("  802.11 state %s\n",
              ieee80211_state_name[sc->sc_ic.ic_state]);
#endif
        
        XYLog("%s: fatal firmware error\n", DEVNAME(sc));
        if ((sc->sc_flags & IWX_FLAG_SHUTDOWN) == 0)
            task_add(systq, &sc->init_task);
        return 1;
    }
    
    if (inta_hw & IWX_MSIX_HW_INT_CAUSES_REG_RF_KILL) {
        that->iwx_check_rfkill(sc);
        task_add(systq, &sc->init_task);
    }
    
    if (inta_hw & IWX_MSIX_HW_INT_CAUSES_REG_HW_ERR) {
        XYLog("%s: hardware error, stopping device \n", DEVNAME(sc));
        if ((sc->sc_flags & IWX_FLAG_SHUTDOWN) == 0) {
            sc->sc_flags |= IWX_FLAG_HW_ERR;
            task_add(systq, &sc->init_task);
        }
        return 1;
    }
    
    if (inta_hw & IWX_MSIX_HW_INT_CAUSES_REG_ALIVE) {
        int i;
        
        /* Firmware has now configured the RFH. */
        for (i = 0; i < IWX_RX_MQ_RING_COUNT; i++)
            that->iwx_update_rx_desc(sc, &sc->rxq, i);
        IWX_WRITE(sc, IWX_RFH_Q0_FRBDCB_WIDX_TRG, 8);
    }
    
    /*
     * Before sending the interrupt the HW disables it to prevent
     * a nested interrupt. This is done by writing 1 to the corresponding
     * bit in the mask register. After handling the interrupt, it should be
     * re-enabled by clearing this bit. This register is defined as
     * write 1 clear (W1C) register, meaning that it's being clear
     * by writing 1 to the bit.
     */
    IWX_WRITE(sc, IWX_CSR_MSIX_AUTOMASK_ST_AD, 1 << vector);
    return 1;
}

#define PCI_VENDOR_INTEL 0x8086

#define IWL_PCI_DEVICE(dev, subdev, cfg) \
.pm_vid = PCI_VENDOR_INTEL,  .pm_pid = (dev), \
.pm_sub_vid = PCI_ANY_ID, .pm_sub_dev = (subdev), \
.drv_data = (void *)&(cfg)

/*
 * If the device doesn't support HE, no need to have that many buffers.
 * 22000 devices can split multiple frames into a single RB, so fewer are
 * needed; AX210 cannot (but use smaller RBs by default) - these sizes
 * were picked according to 8 MSDUs inside 256 A-MSDUs in an A-MPDU, with
 * additional overhead to account for processing time.
 */
#define IWL_NUM_RBDS_NON_HE        512
#define IWL_NUM_RBDS_22000_HE        2048
#define IWL_NUM_RBDS_AX210_HE        4096

/*
 * A-MPDU buffer sizes
 * According to HT size varies from 8 to 64 frames
 * HE adds the ability to have up to 256 frames.
 */
#define IEEE80211_MIN_AMPDU_BUF        0x8
#define IEEE80211_MAX_AMPDU_BUF_HT    0x40
#define IEEE80211_MAX_AMPDU_BUF        0x100

const struct iwl_cfg_trans_params iwl_qu_trans_cfg = {
    .device_family = IWX_DEVICE_FAMILY_22000,
    .integrated = 1,
    .xtal_latency = 5000,
    .ltr_delay = IWX_SOC_FLAGS_LTR_APPLY_DELAY_200,
};

const struct iwl_cfg_trans_params iwl_qu_medium_latency_trans_cfg = {
    .device_family = IWX_DEVICE_FAMILY_22000,
    .integrated = 1,
    .xtal_latency = 1820,
    .ltr_delay = IWX_SOC_FLAGS_LTR_APPLY_DELAY_1820,
};

const struct iwl_cfg_trans_params iwl_qu_long_latency_trans_cfg = {
    .device_family = IWX_DEVICE_FAMILY_22000,
    .integrated = 1,
    .xtal_latency = 12000,
    .low_latency_xtal = true,
    .ltr_delay = IWX_SOC_FLAGS_LTR_APPLY_DELAY_2500,
};

const struct iwl_cfg_trans_params iwl_qnj_trans_cfg = {
    .device_family = IWX_DEVICE_FAMILY_22000,
};

const struct iwl_cfg_trans_params iwl_snj_trans_cfg = {
    .device_family = IWX_DEVICE_FAMILY_AX210,
};

const struct iwl_cfg_trans_params iwl_so_trans_cfg = {
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .integrated = 1,
    .xtal_latency = 500,
    .ltr_delay = IWX_SOC_FLAGS_LTR_APPLY_DELAY_200,
};

const struct iwl_cfg_trans_params iwl_so_long_latency_trans_cfg = {
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .integrated = 1,
    .xtal_latency = 12000,
    .ltr_delay = IWX_SOC_FLAGS_LTR_APPLY_DELAY_2500,
};

const struct iwl_cfg_trans_params iwl_ma_trans_cfg = {
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .integrated = 1,
};

const struct iwl_cfg_trans_params iwl_ax200_trans_cfg = {
    .device_family = IWX_DEVICE_FAMILY_22000,
    .bisr_workaround = 1,
};

const struct iwl_cfg iwlax210_2ax_cfg_so_jf_a0 = {
    .name = "Intel(R) Wireless-AC 9560 160MHz",
    .fwname = "iwlwifi-so-a0-jf-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_NON_HE,
};

const struct iwl_cfg iwlax210_2ax_cfg_so_hr_a0 = {
    .name = "Intel(R) Wi-Fi 6 AX210 160MHz",
    .fwname = "iwlwifi-so-a0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwlax211_2ax_cfg_so_gf_a0 = {
    .name = "Intel(R) Wi-Fi 6 AX211 160MHz",
    .fwname = "iwlwifi-so-a0-gf-a0-68.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwlax211_2ax_cfg_so_gf_a0_long = {
    .name = "Intel(R) Wi-Fi 6 AX211 160MHz",
    .fwname = "iwlwifi-so-a0-gf-a0-68.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .trans.xtal_latency = 12000,
    .trans.low_latency_xtal = 1,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwlax210_2ax_cfg_ty_gf_a0 = {
    .name = "Intel(R) Wi-Fi 6 AX210 160MHz",
    .fwname = "iwlwifi-ty-a0-gf-a0-68.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwlax411_2ax_cfg_so_gf4_a0 = {
    .name = "Intel(R) Wi-Fi 6 AX411 160MHz",
    .fwname = "iwlwifi-so-a0-gf4-a0-68.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwlax411_2ax_cfg_so_gf4_a0_long = {
    .name = "Intel(R) Wi-Fi 6 AX411 160MHz",
    .fwname = "iwlwifi-so-a0-gf4-a0-68.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .trans.xtal_latency = 12000,
    .trans.low_latency_xtal = 1,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwlax411_2ax_cfg_sosnj_gf4_a0 = {
    .name = "Intel(R) Wi-Fi 6 AX411 160MHz",
    .fwname = "iwlwifi-SoSnj-a0-gf4-a0-63.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwlax211_cfg_snj_gf_a0 = {
    .name = "Intel(R) Wi-Fi 6 AX211 160MHz",
    .fwname = "iwlwifi-SoSnj-a0-gf-a0-63.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwl_cfg_snj_hr_b0 = {
    .fwname = "iwlwifi-SoSnj-a0-hr-b0-63.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwl_cfg_snj_a0_jf_b0 = {
    .fwname = "iwlwifi-SoSnj-a0-jf-b0-63.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwl_cfg_ma_a0_hr_b0 = {
    .fwname = "iwlwifi-ma-a0-hr-b0-63.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwl_cfg_ma_a0_gf_a0 = {
    .fwname = "iwlwifi-ma-a0-gf-a0-63.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwl_cfg_ma_a0_gf4_a0 = {
    .fwname = "iwlwifi-ma-a0-gf4-a0-63.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwl_cfg_ma_a0_mr_a0 = {
    .fwname = "iwlwifi-ma-a0-mr-a0-63.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwl_cfg_ma_a0_fm_a0 = {
    .fwname = "iwlwifi-ma-a0-fm-a0-63.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwl_cfg_snj_a0_mr_a0 = {
    .fwname = "iwlwifi-SoSnj-a0-mr-a0-63.ucode",
    .uhb_supported = 1,
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwl_cfg_so_a0_hr_a0 = {
    .fwname = "iwlwifi-so-a0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_AX210_HE,
};

const struct iwl_cfg iwl_cfg_quz_a0_hr_b0 = {
    .fwname = "iwlwifi-QuZ-a0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

static const struct pci_matchid iwx_devices[] = {
    /* Qu devices */
    {IWL_PCI_DEVICE(0x02F0, PCI_ANY_ID, iwl_qu_trans_cfg)},
    {IWL_PCI_DEVICE(0x06F0, PCI_ANY_ID, iwl_qu_trans_cfg)},

    {IWL_PCI_DEVICE(0x34F0, PCI_ANY_ID, iwl_qu_medium_latency_trans_cfg)},
    {IWL_PCI_DEVICE(0x3DF0, PCI_ANY_ID, iwl_qu_medium_latency_trans_cfg)},
    {IWL_PCI_DEVICE(0x4DF0, PCI_ANY_ID, iwl_qu_medium_latency_trans_cfg)},

    {IWL_PCI_DEVICE(0x43F0, PCI_ANY_ID, iwl_qu_long_latency_trans_cfg)},
    {IWL_PCI_DEVICE(0xA0F0, PCI_ANY_ID, iwl_qu_long_latency_trans_cfg)},

    {IWL_PCI_DEVICE(0x2720, PCI_ANY_ID, iwl_qnj_trans_cfg)},

    {IWL_PCI_DEVICE(0x2723, PCI_ANY_ID, iwl_ax200_trans_cfg)},
    
    /* So devices */
    {IWL_PCI_DEVICE(0x2725, PCI_ANY_ID, iwl_so_trans_cfg)},
    {IWL_PCI_DEVICE(0x2726, PCI_ANY_ID, iwl_snj_trans_cfg)},
    {IWL_PCI_DEVICE(0x7A70, PCI_ANY_ID, iwl_so_long_latency_trans_cfg)},
    {IWL_PCI_DEVICE(0x7AF0, PCI_ANY_ID, iwl_so_trans_cfg)},
    {IWL_PCI_DEVICE(0x51F0, PCI_ANY_ID, iwl_so_long_latency_trans_cfg)},
    {IWL_PCI_DEVICE(0x51F1, PCI_ANY_ID, iwl_so_long_latency_trans_cfg)},
    {IWL_PCI_DEVICE(0x54F0, PCI_ANY_ID, iwl_so_long_latency_trans_cfg)},
    {IWL_PCI_DEVICE(0x7F70, PCI_ANY_ID, iwl_so_trans_cfg)},
    
    /* Ma devices */
    {IWL_PCI_DEVICE(0x2729, PCI_ANY_ID, iwl_ma_trans_cfg)},
    {IWL_PCI_DEVICE(0x7E40, PCI_ANY_ID, iwl_ma_trans_cfg)},
};

struct iwl_dev_info {
    uint16_t device;
    uint16_t subdevice;
    uint16_t mac_type;
    uint16_t rf_type;
    uint8_t mac_step;
    uint8_t rf_id;
    uint8_t no_160;
    uint8_t cores;
    uint8_t cdb;
    const struct iwl_cfg *cfg;
    const char *name;
};

#define _IWL_DEV_INFO(_device, _subdevice, _mac_type, _mac_step, _rf_type, \
              _rf_id, _no_160, _cores, _cdb, _cfg, _name)           \
    { .device = (uint16_t)(_device), .subdevice = (uint16_t)(_subdevice), .cfg = &(_cfg),  \
      .name = _name, .mac_type = (uint16_t)_mac_type, .rf_type = (uint16_t)_rf_type,       \
      .no_160 = (uint8_t)_no_160, .cores = (uint8_t)_cores, .rf_id = (uint8_t)_rf_id,           \
      .mac_step = (uint8_t)_mac_step, .cdb = (uint8_t)_cdb }

#define IWL_DEV_INFO(_device, _subdevice, _cfg, _name) \
    _IWL_DEV_INFO(_device, _subdevice, IWL_CFG_ANY, IWL_CFG_ANY,       \
              IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_ANY,  \
              IWL_CFG_NO_CDB, _cfg, _name)

const char iwl9162_name[] = "Intel(R) Wireless-AC 9162";
const char iwl9260_name[] = "Intel(R) Wireless-AC 9260";
const char iwl9260_1_name[] = "Intel(R) Wireless-AC 9260-1";
const char iwl9270_name[] = "Intel(R) Wireless-AC 9270";
const char iwl9461_name[] = "Intel(R) Wireless-AC 9461";
const char iwl9462_name[] = "Intel(R) Wireless-AC 9462";
const char iwl9560_name[] = "Intel(R) Wireless-AC 9560";
const char iwl9162_160_name[] = "Intel(R) Wireless-AC 9162 160MHz";
const char iwl9260_160_name[] = "Intel(R) Wireless-AC 9260 160MHz";
const char iwl9270_160_name[] = "Intel(R) Wireless-AC 9270 160MHz";
const char iwl9461_160_name[] = "Intel(R) Wireless-AC 9461 160MHz";
const char iwl9462_160_name[] = "Intel(R) Wireless-AC 9462 160MHz";
const char iwl9560_160_name[] = "Intel(R) Wireless-AC 9560 160MHz";

const char iwl9260_killer_1550_name[] =
    "Killer (R) Wireless-AC 1550 Wireless Network Adapter (9260NGW) 160MHz";
const char iwl9560_killer_1550i_name[] =
    "Killer (R) Wireless-AC 1550i Wireless Network Adapter (9560NGW)";
const char iwl9560_killer_1550i_160_name[] =
    "Killer(R) Wireless-AC 1550i Wireless Network Adapter (9560NGW) 160MHz";
const char iwl9560_killer_1550s_name[] =
    "Killer (R) Wireless-AC 1550s Wireless Network Adapter (9560NGW)";
const char iwl9560_killer_1550s_160_name[] =
    "Killer(R) Wireless-AC 1550s Wireless Network Adapter (9560D2W) 160MHz";

const char iwl_ax101_name[] = "Intel(R) Wi-Fi 6 AX101";
const char iwl_ax200_name[] = "Intel(R) Wi-Fi 6 AX200 160MHz";
const char iwl_ax201_name[] = "Intel(R) Wi-Fi 6 AX201 160MHz";
const char iwl_ax203_name[] = "Intel(R) Wi-Fi 6 AX203";
const char iwl_ax211_name[] = "Intel(R) Wi-Fi 6E AX211 160MHz";
const char iwl_ax221_name[] = "Intel(R) Wi-Fi 6E AX221 160MHz";
const char iwl_ax231_name[] = "Intel(R) Wi-Fi 6E AX231 160MHz";
const char iwl_ax411_name[] = "Intel(R) Wi-Fi 6E AX411 160MHz";
const char iwl_bz_name[] = "Intel(R) TBD Bz device";

const char iwl_ax200_killer_1650w_name[] =
    "Killer(R) Wi-Fi 6 AX1650w 160MHz Wireless Network Adapter (200D2W)";
const char iwl_ax200_killer_1650x_name[] =
    "Killer(R) Wi-Fi 6 AX1650x 160MHz Wireless Network Adapter (200NGW)";
const char iwl_ax201_killer_1650s_name[] =
    "Killer(R) Wi-Fi 6 AX1650s 160MHz Wireless Network Adapter (201D2W)";
const char iwl_ax201_killer_1650i_name[] =
    "Killer(R) Wi-Fi 6 AX1650i 160MHz Wireless Network Adapter (201NGW)";
const char iwl_ax210_killer_1675w_name[] =
    "Killer(R) Wi-Fi 6E AX1675w 160MHz Wireless Network Adapter (210D2W)";
const char iwl_ax210_killer_1675x_name[] =
    "Killer(R) Wi-Fi 6E AX1675x 160MHz Wireless Network Adapter (210NGW)";
const char iwl_ax211_killer_1675s_name[] =
    "Killer(R) Wi-Fi 6E AX1675s 160MHz Wireless Network Adapter (211NGW)";
const char iwl_ax211_killer_1675i_name[] =
    "Killer(R) Wi-Fi 6E AX1675i 160MHz Wireless Network Adapter (211NGW)";
const char iwl_ax411_killer_1690s_name[] =
    "Killer(R) Wi-Fi 6E AX1690s 160MHz Wireless Network Adapter (411D2W)";
const char iwl_ax411_killer_1690i_name[] =
    "Killer(R) Wi-Fi 6E AX1690i 160MHz Wireless Network Adapter (411NGW)";

const struct iwl_cfg iwl_ax200_cfg_cc = {
    .fwname = "iwlwifi-cc-a0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .tx_with_siso_diversity = 0,
    .uhb_supported = 0,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg iwl_qnj_b0_hr_b0_cfg = {
    .fwname = "iwlwifi-QuQnj-b0-hr-b0-48.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .tx_with_siso_diversity = 0,
    .uhb_supported = 0,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg iwlax210_2ax_cfg_so_jf_b0 = {
    .name = "Intel(R) Wireless-AC 9560 160MHz",
    .fwname = "iwlwifi-so-a0-jf-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_AX210,
    .num_rbds = IWL_NUM_RBDS_NON_HE,
};

const struct iwl_cfg iwl_ax201_cfg_qu_hr = {
    .name = "Intel(R) Wi-Fi 6 AX201 160MHz",
    .fwname = "iwlwifi-Qu-b0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .tx_with_siso_diversity = 0,
    .uhb_supported = 0,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg killer1650s_2ax_cfg_qu_b0_hr_b0 = {
    .name = "Killer(R) Wi-Fi 6 AX1650s 160MHz Wireless Network Adapter (201NGW)",
    .fwname = "iwlwifi-Qu-b0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg killer1650i_2ax_cfg_qu_b0_hr_b0 = {
    .name = "Killer(R) Wi-Fi 6 AX1650i 160MHz Wireless Network Adapter (201D2W)",
    .fwname = "iwlwifi-Qu-b0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg killer1650s_2ax_cfg_qu_c0_hr_b0 = {
    .name = "Killer(R) Wi-Fi 6 AX1650s 160MHz Wireless Network Adapter (201NGW)",
    .fwname = "iwlwifi-Qu-c0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg killer1650i_2ax_cfg_qu_c0_hr_b0 = {
    .name = "Killer(R) Wi-Fi 6 AX1650i 160MHz Wireless Network Adapter (201D2W)",
    .fwname = "iwlwifi-Qu-c0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg iwl_ax201_cfg_quz_hr = {
    .name = "Intel(R) Wi-Fi 6 AX201 160MHz",
    .fwname = "iwlwifi-QuZ-a0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .tx_with_siso_diversity = 0,
    .uhb_supported = 0,
    /*
         * This device doesn't support receiving BlockAck with a large bitmap
         * so we need to restrict the size of transmitted aggregation to the
         * HT size; mac80211 would otherwise pick the HE max (256) by default.
         */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg iwl_ax1650s_cfg_quz_hr = {
    .name = "Killer(R) Wi-Fi 6 AX1650s 160MHz Wireless Network Adapter (201D2W)",
    .fwname = "iwlwifi-QuZ-a0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    /*
         * This device doesn't support receiving BlockAck with a large bitmap
         * so we need to restrict the size of transmitted aggregation to the
         * HT size; mac80211 would otherwise pick the HE max (256) by default.
         */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg iwl_ax1650i_cfg_quz_hr = {
    .name = "Killer(R) Wi-Fi 6 AX1650i 160MHz Wireless Network Adapter (201NGW)",
    .fwname = "iwlwifi-QuZ-a0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    /*
         * This device doesn't support receiving BlockAck with a large bitmap
         * so we need to restrict the size of transmitted aggregation to the
         * HT size; mac80211 would otherwise pick the HE max (256) by default.
         */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

/*
* All JF radio modules are part of the 9000 series, but the MAC part
* looks more like 22000.  That's why this device is here, but called
* 9560 nevertheless.
*/
const struct iwl_cfg iwl9560_qu_b0_jf_b0_cfg = {
    .fwname = "iwlwifi-Qu-b0-jf-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .tx_with_siso_diversity = 0,
    .uhb_supported = 0,
    .num_rbds = IWL_NUM_RBDS_NON_HE,
};

const struct iwl_cfg iwl9560_qu_c0_jf_b0_cfg = {
    .fwname = "iwlwifi-Qu-c0-jf-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .tx_with_siso_diversity = 0,
    .uhb_supported = 0,
    .num_rbds = IWL_NUM_RBDS_NON_HE,
};

const struct iwl_cfg iwl9560_quz_a0_jf_b0_cfg = {
    .fwname = "iwlwifi-QuZ-a0-jf-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .tx_with_siso_diversity = 0,
    .uhb_supported = 0,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_NON_HE,
};

const struct iwl_cfg iwl9560_qnj_b0_jf_b0_cfg = {
    .fwname = "iwlwifi-QuQnj-b0-jf-b0-48.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .tx_with_siso_diversity = 0,
    .uhb_supported = 0,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_NON_HE,
};

const struct iwl_cfg iwl_qu_b0_hr1_b0 = {
    .fwname = "iwlwifi-Qu-b0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .tx_with_siso_diversity = 1,
    .uhb_supported = 0,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg iwl_qu_b0_hr_b0 = {
    .fwname = "iwlwifi-Qu-b0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .uhb_supported = 0,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg iwl_qu_c0_hr_b0 = {
    .fwname = "iwlwifi-Qu-c0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .uhb_supported = 0,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg iwl_qu_c0_hr1_b0 = {
    .fwname = "iwlwifi-Qu-c0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .tx_with_siso_diversity = 1,
    .uhb_supported = 0,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg iwl_quz_a0_hr1_b0 = {
    .fwname = "iwlwifi-QuZ-a0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .tx_with_siso_diversity = 1,
    .uhb_supported = 0,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

const struct iwl_cfg iwl_ax201_cfg_qu_c0_hr_b0 = {
    .name = "Intel(R) Wi-Fi 6 AX201 160MHz",
    .fwname = "iwlwifi-Qu-c0-hr-b0-68.ucode",
    .device_family = IWX_DEVICE_FAMILY_22000,
    .tx_with_siso_diversity = 0,
    .uhb_supported = 0,
    /*
     * This device doesn't support receiving BlockAck with a large bitmap
     * so we need to restrict the size of transmitted aggregation to the
     * HT size; mac80211 would otherwise pick the HE max (256) by default.
     */
    .max_tx_agg_size = IEEE80211_MAX_AMPDU_BUF_HT,
    .num_rbds = IWL_NUM_RBDS_22000_HE,
};

static const struct iwl_dev_info iwl_dev_info_table[] = {
    /* AX200 */
    IWL_DEV_INFO(0x2723, IWL_CFG_ANY, iwl_ax200_cfg_cc, iwl_ax200_name),
    IWL_DEV_INFO(0x2723, 0x1653, iwl_ax200_cfg_cc, iwl_ax200_killer_1650w_name),
    IWL_DEV_INFO(0x2723, 0x1654, iwl_ax200_cfg_cc, iwl_ax200_killer_1650x_name),
    IWL_DEV_INFO(0x51F0, 0x1691, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690s_name),
    IWL_DEV_INFO(0x51F0, 0x1692, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690i_name),
    IWL_DEV_INFO(0x51F1, 0x1692, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690i_name),
    IWL_DEV_INFO(0x54F0, 0x1691, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690s_name),
    IWL_DEV_INFO(0x54F0, 0x1692, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690i_name),
    IWL_DEV_INFO(0x7A70, 0x1691, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690s_name),
    IWL_DEV_INFO(0x7A70, 0x1692, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690i_name),
    IWL_DEV_INFO(0x7AF0, 0x1691, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690s_name),
    IWL_DEV_INFO(0x7AF0, 0x1692, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690i_name),
    
    /* Qu with Hr */
    IWL_DEV_INFO(0x43F0, 0x0070, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x43F0, 0x0074, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x43F0, 0x0078, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x43F0, 0x007C, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x43F0, 0x1651, killer1650s_2ax_cfg_qu_b0_hr_b0, iwl_ax201_killer_1650s_name),
    IWL_DEV_INFO(0x43F0, 0x1652, killer1650i_2ax_cfg_qu_b0_hr_b0, iwl_ax201_killer_1650i_name),
    IWL_DEV_INFO(0x43F0, 0x2074, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x43F0, 0x4070, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0xA0F0, 0x0070, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0xA0F0, 0x0074, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0xA0F0, 0x0078, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0xA0F0, 0x007C, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0xA0F0, 0x0A10, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0xA0F0, 0x1651, killer1650s_2ax_cfg_qu_b0_hr_b0, NULL),
    IWL_DEV_INFO(0xA0F0, 0x1652, killer1650i_2ax_cfg_qu_b0_hr_b0, NULL),
    IWL_DEV_INFO(0xA0F0, 0x2074, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0xA0F0, 0x4070, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0xA0F0, 0x6074, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x02F0, 0x0070, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x02F0, 0x0074, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x02F0, 0x6074, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x02F0, 0x0078, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x02F0, 0x007C, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x02F0, 0x0310, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x02F0, 0x1651, iwl_ax1650s_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x02F0, 0x1652, iwl_ax1650i_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x02F0, 0x2074, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x02F0, 0x4070, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x06F0, 0x0070, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x06F0, 0x0074, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x06F0, 0x0078, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x06F0, 0x007C, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x06F0, 0x0310, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x06F0, 0x1651, iwl_ax1650s_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x06F0, 0x1652, iwl_ax1650i_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x06F0, 0x2074, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x06F0, 0x4070, iwl_ax201_cfg_quz_hr, NULL),
    IWL_DEV_INFO(0x34F0, 0x0070, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x34F0, 0x0074, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x34F0, 0x0078, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x34F0, 0x007C, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x34F0, 0x0310, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x34F0, 0x1651, killer1650s_2ax_cfg_qu_b0_hr_b0, NULL),
    IWL_DEV_INFO(0x34F0, 0x1652, killer1650i_2ax_cfg_qu_b0_hr_b0, NULL),
    IWL_DEV_INFO(0x34F0, 0x2074, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x34F0, 0x4070, iwl_ax201_cfg_qu_hr, NULL),
    
    IWL_DEV_INFO(0x3DF0, 0x0070, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x3DF0, 0x0074, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x3DF0, 0x0078, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x3DF0, 0x007C, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x3DF0, 0x0310, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x3DF0, 0x1651, killer1650s_2ax_cfg_qu_b0_hr_b0, NULL),
    IWL_DEV_INFO(0x3DF0, 0x1652, killer1650i_2ax_cfg_qu_b0_hr_b0, NULL),
    IWL_DEV_INFO(0x3DF0, 0x2074, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x3DF0, 0x4070, iwl_ax201_cfg_qu_hr, NULL),
    
    IWL_DEV_INFO(0x4DF0, 0x0070, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x4DF0, 0x0074, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x4DF0, 0x0078, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x4DF0, 0x007C, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x4DF0, 0x0310, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x4DF0, 0x1651, killer1650s_2ax_cfg_qu_b0_hr_b0, NULL),
    IWL_DEV_INFO(0x4DF0, 0x1652, killer1650i_2ax_cfg_qu_b0_hr_b0, NULL),
    IWL_DEV_INFO(0x4DF0, 0x2074, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x4DF0, 0x4070, iwl_ax201_cfg_qu_hr, NULL),
    IWL_DEV_INFO(0x4DF0, 0x6074, iwl_ax201_cfg_qu_hr, NULL),
    
    /* Qu with JF */
    IWL_DEV_INFO(0x06f0, 0x1551, iwl9560_quz_a0_jf_b0_cfg, iwl9560_killer_1550s_160_name),
    IWL_DEV_INFO(0x06f0, 0x1552, iwl9560_quz_a0_jf_b0_cfg, iwl9560_killer_1550i_160_name),

    /* So with HR */
    IWL_DEV_INFO(0x2725, 0x0090, iwlax211_2ax_cfg_so_gf_a0, NULL),
    IWL_DEV_INFO(0x2725, 0x0020, iwlax210_2ax_cfg_ty_gf_a0, NULL),
    IWL_DEV_INFO(0x2725, 0x2020, iwlax210_2ax_cfg_ty_gf_a0, NULL),
    IWL_DEV_INFO(0x2725, 0x0024, iwlax210_2ax_cfg_ty_gf_a0, NULL),
    IWL_DEV_INFO(0x2725, 0x0310, iwlax210_2ax_cfg_ty_gf_a0, NULL),
    IWL_DEV_INFO(0x2725, 0x0510, iwlax210_2ax_cfg_ty_gf_a0, NULL),
    IWL_DEV_INFO(0x2725, 0x0A10, iwlax210_2ax_cfg_ty_gf_a0, NULL),
    IWL_DEV_INFO(0x2725, 0xE020, iwlax210_2ax_cfg_ty_gf_a0, NULL),
    IWL_DEV_INFO(0x2725, 0xE024, iwlax210_2ax_cfg_ty_gf_a0, NULL),
    IWL_DEV_INFO(0x2725, 0x4020, iwlax210_2ax_cfg_ty_gf_a0, NULL),
    IWL_DEV_INFO(0x2725, 0x6020, iwlax210_2ax_cfg_ty_gf_a0, NULL),
    IWL_DEV_INFO(0x2725, 0x6024, iwlax210_2ax_cfg_ty_gf_a0, NULL),
    IWL_DEV_INFO(0x2725, 0x1673, iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_killer_1675w_name),
    IWL_DEV_INFO(0x2725, 0x1674, iwlax210_2ax_cfg_ty_gf_a0, iwl_ax210_killer_1675x_name),
    IWL_DEV_INFO(0x7A70, 0x0090, iwlax211_2ax_cfg_so_gf_a0_long, NULL),
    IWL_DEV_INFO(0x7A70, 0x0098, iwlax211_2ax_cfg_so_gf_a0_long, NULL),
    IWL_DEV_INFO(0x7A70, 0x00B0, iwlax411_2ax_cfg_so_gf4_a0_long, NULL),
    IWL_DEV_INFO(0x7A70, 0x0310, iwlax211_2ax_cfg_so_gf_a0_long, NULL),
    IWL_DEV_INFO(0x7A70, 0x0510, iwlax211_2ax_cfg_so_gf_a0_long, NULL),
    IWL_DEV_INFO(0x7A70, 0x0A10, iwlax211_2ax_cfg_so_gf_a0_long, NULL),
    IWL_DEV_INFO(0x7AF0, 0x0090, iwlax211_2ax_cfg_so_gf_a0, NULL),
    IWL_DEV_INFO(0x7AF0, 0x0098, iwlax211_2ax_cfg_so_gf_a0, NULL),
    IWL_DEV_INFO(0x7AF0, 0x00B0, iwlax411_2ax_cfg_so_gf4_a0, NULL),
    IWL_DEV_INFO(0x7AF0, 0x0310, iwlax211_2ax_cfg_so_gf_a0, NULL),
    IWL_DEV_INFO(0x7AF0, 0x0510, iwlax211_2ax_cfg_so_gf_a0, NULL),
    IWL_DEV_INFO(0x7AF0, 0x0A10, iwlax211_2ax_cfg_so_gf_a0, NULL),
    
    /* SnJ with HR */
    IWL_DEV_INFO(0x2725, 0x00B0, iwlax411_2ax_cfg_sosnj_gf4_a0, NULL),
    IWL_DEV_INFO(0x2726, 0x0090, iwlax211_cfg_snj_gf_a0, NULL),
    IWL_DEV_INFO(0x2726, 0x0098, iwlax211_cfg_snj_gf_a0, NULL),
    IWL_DEV_INFO(0x2726, 0x00B0, iwlax411_2ax_cfg_sosnj_gf4_a0, NULL),
    IWL_DEV_INFO(0x2726, 0x00B4, iwlax411_2ax_cfg_sosnj_gf4_a0, NULL),
    IWL_DEV_INFO(0x2726, 0x0510, iwlax211_cfg_snj_gf_a0, NULL),
    IWL_DEV_INFO(0x2726, 0x1651, iwl_cfg_snj_hr_b0, iwl_ax201_killer_1650s_name),
    IWL_DEV_INFO(0x2726, 0x1652, iwl_cfg_snj_hr_b0, iwl_ax201_killer_1650i_name),
    IWL_DEV_INFO(0x2726, 0x1691, iwlax411_2ax_cfg_sosnj_gf4_a0, iwl_ax411_killer_1690s_name),
    IWL_DEV_INFO(0x2726, 0x1692, iwlax411_2ax_cfg_sosnj_gf4_a0, iwl_ax411_killer_1690i_name),
    IWL_DEV_INFO(0x7F70, 0x1691, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690s_name),
    IWL_DEV_INFO(0x7F70, 0x1692, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690i_name),
    IWL_DEV_INFO(0x7AF0, 0x1691, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690s_name),
    IWL_DEV_INFO(0x7AF0, 0x1692, iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_killer_1690i_name),
    /* SO with GF2 */
    IWL_DEV_INFO(0x2726, 0x1671, iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name),
    IWL_DEV_INFO(0x2726, 0x1672, iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name),
    IWL_DEV_INFO(0x51F0, 0x1671, iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name),
    IWL_DEV_INFO(0x51F0, 0x1672, iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name),
    IWL_DEV_INFO(0x54F0, 0x1671, iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name),
    IWL_DEV_INFO(0x54F0, 0x1672, iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name),
    IWL_DEV_INFO(0x7A70, 0x1671, iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name),
    IWL_DEV_INFO(0x7A70, 0x1672, iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name),
    IWL_DEV_INFO(0x7AF0, 0x1671, iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name),
    IWL_DEV_INFO(0x7AF0, 0x1672, iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name),
    IWL_DEV_INFO(0x7F70, 0x1671, iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675s_name),
    IWL_DEV_INFO(0x7F70, 0x1672, iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_killer_1675i_name),

    /* MA with GF2 */
    IWL_DEV_INFO(0x7E40, 0x1671, iwl_cfg_ma_a0_gf_a0, iwl_ax211_killer_1675s_name),
    IWL_DEV_INFO(0x7E40, 0x1672, iwl_cfg_ma_a0_gf_a0, iwl_ax211_killer_1675i_name),

    /* Qu with Jf */
    /* Qu B step */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_B_STEP,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_b0_jf_b0_cfg, iwl9461_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_B_STEP,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_b0_jf_b0_cfg, iwl9461_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_B_STEP,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_b0_jf_b0_cfg, iwl9462_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_B_STEP,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_b0_jf_b0_cfg, iwl9462_name),
    
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_B_STEP,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_b0_jf_b0_cfg, iwl9560_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_B_STEP,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_b0_jf_b0_cfg, iwl9560_name),
    
    _IWL_DEV_INFO(IWL_CFG_ANY, 0x1551,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_B_STEP,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_b0_jf_b0_cfg, iwl9560_killer_1550s_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, 0x1552,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_B_STEP,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_b0_jf_b0_cfg, iwl9560_killer_1550i_name),
    
    /* Qu C step */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_C_STEP,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_c0_jf_b0_cfg, iwl9461_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_C_STEP,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_c0_jf_b0_cfg, iwl9461_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_C_STEP,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_c0_jf_b0_cfg, iwl9462_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_C_STEP,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_c0_jf_b0_cfg, iwl9462_name),
    
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_C_STEP,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_c0_jf_b0_cfg, iwl9560_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_C_STEP,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_c0_jf_b0_cfg, iwl9560_name),
    
    _IWL_DEV_INFO(IWL_CFG_ANY, 0x1551,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_C_STEP,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_c0_jf_b0_cfg, iwl9560_killer_1550s_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, 0x1552,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_C_STEP,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qu_c0_jf_b0_cfg, iwl9560_killer_1550i_name),
    
    /* QuZ */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QUZ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_quz_a0_jf_b0_cfg, iwl9461_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QUZ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_quz_a0_jf_b0_cfg, iwl9461_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QUZ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_quz_a0_jf_b0_cfg, iwl9462_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QUZ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_quz_a0_jf_b0_cfg, iwl9462_name),
    
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QUZ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_quz_a0_jf_b0_cfg, iwl9560_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QUZ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_quz_a0_jf_b0_cfg, iwl9560_name),
    
    _IWL_DEV_INFO(IWL_CFG_ANY, 0x1551,
                  IWL_CFG_MAC_TYPE_QUZ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_quz_a0_jf_b0_cfg, iwl9560_killer_1550s_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, 0x1552,
                  IWL_CFG_MAC_TYPE_QUZ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_quz_a0_jf_b0_cfg, iwl9560_killer_1550i_name),
    
    /* QnJ */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qnj_b0_jf_b0_cfg, iwl9461_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qnj_b0_jf_b0_cfg, iwl9461_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qnj_b0_jf_b0_cfg, iwl9462_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qnj_b0_jf_b0_cfg, iwl9462_name),
    
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qnj_b0_jf_b0_cfg, iwl9560_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qnj_b0_jf_b0_cfg, iwl9560_name),
    
    _IWL_DEV_INFO(IWL_CFG_ANY, 0x1551,
                  IWL_CFG_MAC_TYPE_QNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qnj_b0_jf_b0_cfg, iwl9560_killer_1550s_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, 0x1552,
                  IWL_CFG_MAC_TYPE_QNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl9560_qnj_b0_jf_b0_cfg, iwl9560_killer_1550i_name),
    
    /* Qu with Hr */
    /* Qu B step */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_B_STEP,
                  IWL_CFG_RF_TYPE_HR1, IWL_CFG_ANY,
                  IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_qu_b0_hr1_b0, iwl_ax101_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_B_STEP,
                  IWL_CFG_RF_TYPE_HR2, IWL_CFG_ANY,
                  IWL_CFG_NO_160, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_qu_b0_hr_b0, iwl_ax203_name),
    
    /* Qu C step */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_C_STEP,
                  IWL_CFG_RF_TYPE_HR1, IWL_CFG_ANY,
                  IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_qu_c0_hr1_b0, iwl_ax101_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QU, IWX_SILICON_C_STEP,
                  IWL_CFG_RF_TYPE_HR2, IWL_CFG_ANY,
                  IWL_CFG_NO_160, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_qu_c0_hr_b0, iwl_ax203_name),
    
    /* QuZ */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QUZ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_HR1, IWL_CFG_ANY,
                  IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_quz_a0_hr1_b0, iwl_ax101_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QUZ, IWX_SILICON_B_STEP,
                  IWL_CFG_RF_TYPE_HR2, IWL_CFG_ANY,
                  IWL_CFG_NO_160, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_quz_a0_hr_b0, iwl_ax203_name),
    
    /* QnJ with Hr */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_QNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_HR2, IWL_CFG_ANY,
                  IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_qnj_b0_hr_b0_cfg, iwl_ax201_name),
    
    /* SnJ with Jf */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl_cfg_snj_a0_jf_b0, iwl9461_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl_cfg_snj_a0_jf_b0, iwl9461_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl_cfg_snj_a0_jf_b0, iwl9462_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl_cfg_snj_a0_jf_b0, iwl9462_name),
    
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl_cfg_snj_a0_jf_b0, iwl9560_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwl_cfg_snj_a0_jf_b0, iwl9560_name),
    
    /* SnJ with Hr */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_HR1, IWL_CFG_ANY,
                  IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_snj_hr_b0, iwl_ax101_name),
    
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_HR2, IWL_CFG_ANY,
                  IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_snj_hr_b0, iwl_ax201_name),
    
    /* Ma */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_MA, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_HR2, IWL_CFG_ANY,
                  IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_ma_a0_hr_b0, iwl_ax201_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_MA, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_GF, IWL_CFG_ANY,
                  IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_ma_a0_gf_a0, iwl_ax211_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_MA, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_GF, IWL_CFG_ANY,
                  IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_CDB,
                  iwl_cfg_ma_a0_gf4_a0, iwl_ax211_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_MA, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_MR, IWL_CFG_ANY,
                  IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_ma_a0_mr_a0, iwl_ax221_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_MA, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_FM, IWL_CFG_ANY,
                  IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_ma_a0_fm_a0, iwl_ax231_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SNJ, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_MR, IWL_CFG_ANY,
                  IWL_CFG_ANY, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_snj_a0_mr_a0, iwl_ax221_name),
    
    /* So with Hr */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SO, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_HR2, IWL_CFG_ANY,
                  IWL_CFG_NO_160, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_so_a0_hr_a0, iwl_ax203_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SO, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_HR1, IWL_CFG_ANY,
                  IWL_CFG_NO_160, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_so_a0_hr_a0, iwl_ax101_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SO, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_HR2, IWL_CFG_ANY,
                  IWL_CFG_160, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_so_a0_hr_a0, iwl_ax201_name),
    
    /* So-F with Hr */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SOF, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_HR2, IWL_CFG_ANY,
                  IWL_CFG_NO_160, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_so_a0_hr_a0, iwl_ax203_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SOF, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_HR1, IWL_CFG_ANY,
                  IWL_CFG_NO_160, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_so_a0_hr_a0, iwl_ax101_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SOF, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_HR2, IWL_CFG_ANY,
                  IWL_CFG_160, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwl_cfg_so_a0_hr_a0, iwl_ax201_name),
    
    /* So-F with Gf */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SOF, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_GF, IWL_CFG_ANY,
                  IWL_CFG_160, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SOF, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_GF, IWL_CFG_ANY,
                  IWL_CFG_160, IWL_CFG_ANY, IWL_CFG_CDB,
                  iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_name),
    
    /* SoF with JF2 */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SOF, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwlax210_2ax_cfg_so_jf_b0, iwl9560_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SOF, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwlax210_2ax_cfg_so_jf_b0, iwl9560_name),
    
    /* SoF with JF */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SOF, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwlax210_2ax_cfg_so_jf_b0, iwl9461_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SOF, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwlax210_2ax_cfg_so_jf_b0, iwl9462_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SOF, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwlax210_2ax_cfg_so_jf_b0, iwl9461_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SOF, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwlax210_2ax_cfg_so_jf_b0, iwl9462_name),
    
    /* So with GF */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SO, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_GF, IWL_CFG_ANY,
                  IWL_CFG_160, IWL_CFG_ANY, IWL_CFG_NO_CDB,
                  iwlax211_2ax_cfg_so_gf_a0, iwl_ax211_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SO, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_GF, IWL_CFG_ANY,
                  IWL_CFG_160, IWL_CFG_ANY, IWL_CFG_CDB,
                  iwlax411_2ax_cfg_so_gf4_a0, iwl_ax411_name),
    
    /* So with JF2 */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SO, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwlax210_2ax_cfg_so_jf_b0, iwl9560_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SO, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF2, IWL_CFG_RF_ID_JF,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwlax210_2ax_cfg_so_jf_b0, iwl9560_name),
    
    /* So with JF */
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SO, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwlax210_2ax_cfg_so_jf_b0, iwl9461_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SO, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwlax210_2ax_cfg_so_jf_b0, iwl9462_160_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SO, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwlax210_2ax_cfg_so_jf_b0, iwl9461_name),
    _IWL_DEV_INFO(IWL_CFG_ANY, IWL_CFG_ANY,
                  IWL_CFG_MAC_TYPE_SO, IWL_CFG_ANY,
                  IWL_CFG_RF_TYPE_JF1, IWL_CFG_RF_ID_JF1_DIV,
                  IWL_CFG_NO_160, IWL_CFG_CORES_BT, IWL_CFG_NO_CDB,
                  iwlax210_2ax_cfg_so_jf_b0, iwl9462_name)
};

int ItlIwx::
iwx_match(IOPCIDevice *device)
{
    int devId = device->configRead16(kIOPCIConfigDeviceID);
    return pci_matchbyid(PCI_VENDOR_INTEL, devId, iwx_devices,
                         nitems(iwx_devices));
}

int ItlIwx::
iwx_preinit(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = IC2IFP(ic);
    int err;
    static int attached;
    
    err = iwx_prepare_card_hw(sc);
    if (err) {
        XYLog("%s: could not initialize hardware\n", DEVNAME(sc));
        return err;
    }
    
    if (attached) {
        /* Update MAC in case the upper layers changed it. */
        IEEE80211_ADDR_COPY(sc->sc_ic.ic_myaddr,
                            ((struct arpcom *)ifp)->ac_enaddr);
        return 0;
    }
    
    err = iwx_start_hw(sc);
    if (err) {
        XYLog("%s: could not initialize hardware\n", DEVNAME(sc));
        return err;
    }
    
    err = iwx_run_init_mvm_ucode(sc, 1);
    iwx_stop_device(sc);
    if (err)
        return err;
    
    /* Print version info and MAC address on first successful fw load. */
    attached = 1;
    XYLog("%s: hw rev 0x%x, fw ver %s, address %s\n",
          DEVNAME(sc), sc->sc_hw_rev & IWX_CSR_HW_REV_TYPE_MSK,
          sc->sc_fwver, ether_sprintf(sc->sc_nvm.hw_addr));
    
    if (sc->sc_nvm.sku_cap_11n_enable)
        iwx_setup_ht_rates(sc);
    
    if (sc->sc_nvm.sku_cap_11ac_enable)
        iwx_setup_vht_rates(sc);
    
    if (sc->sc_nvm.sku_cap_11ax_enable)
        iwx_setup_he_rates(sc);
    
    /* not all hardware can do 5GHz band */
    if (!sc->sc_nvm.sku_cap_band_52GHz_enable)
        memset(&ic->ic_sup_rates[IEEE80211_MODE_11A], 0,
               sizeof(ic->ic_sup_rates[IEEE80211_MODE_11A]));
    
    /* Configure channel information obtained from firmware. */
    ieee80211_channel_init(ifp);
    
    /* Configure MAC address. */
    err = if_setlladdr(ifp, ic->ic_myaddr);
    if (err)
        XYLog("%s: could not set MAC address (error %d)\n",
                DEVNAME(sc), err);
    
    ieee80211_media_init(ifp);
    
    return 0;
}

void ItlIwx::
iwx_attach_hook(struct device *self)
{
    struct iwx_softc *sc = (struct iwx_softc *)self;
    
    iwx_preinit(sc);
}

bool ItlIwx::
intrFilter(OSObject *object, IOFilterInterruptEventSource *src)
{
    ItlIwx *that = (ItlIwx*)object;
    IWX_WRITE(&that->com, IWX_CSR_INT_MASK, 0);
    return true;
}

bool ItlIwx::
iwx_attach(struct iwx_softc *sc, struct pci_attach_args *pa)
{
    pcireg_t reg, memtype;
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = &ic->ic_if;
    int err;
    int txq_i, i, j;
    
    sc->sc_pct = pa->pa_pc;
    sc->sc_pcitag = pa->pa_tag;
    sc->sc_dmat = pa->pa_dmat;
    
    //    rw_init(&sc->ioctl_rwl, "iwxioctl");
    
    err = pci_get_capability(sc->sc_pct, sc->sc_pcitag,
                             PCI_CAP_PCIEXPRESS, &sc->sc_cap_off, NULL);
    if (err == 0) {
        XYLog("%s: PCIe capability structure not found!\n",
              DEVNAME(sc));
        return false;
    }
    
    /* Clear device-specific "PCI retry timeout" register (41h). */
    reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag, 0x40);
    pci_conf_write(sc->sc_pct, sc->sc_pcitag, 0x40, reg & ~0xff00);

    /* Enable bus-mastering and hardware bug workaround. */
    reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag, PCI_COMMAND_STATUS_REG);
    reg |= PCI_COMMAND_MASTER_ENABLE;
    /* if !MSI */
    if (reg & PCI_COMMAND_INTERRUPT_DISABLE) {
        reg &= ~PCI_COMMAND_INTERRUPT_DISABLE;
    }
    pci_conf_write(sc->sc_pct, sc->sc_pcitag, PCI_COMMAND_STATUS_REG, reg);
    
    memtype = pci_mapreg_type(pa->pa_pc, pa->pa_tag, PCI_MAPREG_START);
    err = pci_mapreg_map(pa, PCI_MAPREG_START, memtype, 0,
                         &sc->sc_st, &sc->sc_sh, NULL, &sc->sc_sz, 0);
    if (err) {
        XYLog("%s: can't map mem space\n", DEVNAME(sc));
        return false;
    }
    if (0) {
        sc->sc_msix = 1;
        XYLog("msix intr mode\n");
    } else if (pci_intr_map_msi(pa, &sc->ih)) {
        XYLog("%s: can't map interrupt\n", DEVNAME(sc));
        return false;
    }
    
    if (!sc->sc_msix) {
        /* Hardware bug workaround. */
        reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag,
            PCI_COMMAND_STATUS_REG);
        if (reg & PCI_COMMAND_INTERRUPT_DISABLE)
            reg &= ~PCI_COMMAND_INTERRUPT_DISABLE;
        pci_conf_write(sc->sc_pct, sc->sc_pcitag,
            PCI_COMMAND_STATUS_REG, reg);
    }
    
    int msiIntrIndex = -1;
    for (int index = 0; ; index++)
    {
        int interruptType;
        int ret = pa->pa_tag->getInterruptType(index, &interruptType);
        if (ret != kIOReturnSuccess)
            break;
        if (interruptType & kIOInterruptTypePCIMessaged)
        {
            msiIntrIndex = index;
            break;
        }
    }
    if (msiIntrIndex == -1) {
        XYLog("%s: can't find MSI interrupt controller\n", DEVNAME(sc));
        return false;
    }

    if (sc->sc_msix)
        sc->sc_ih =
        IOFilterInterruptEventSource::filterInterruptEventSource(this,
                                                                 (IOInterruptEventSource::Action)&ItlIwx::iwx_intr_msix,
                                                                 &ItlIwx::intrFilter
                                                                 ,pa->pa_tag, msiIntrIndex);
    else
        sc->sc_ih = IOFilterInterruptEventSource::filterInterruptEventSource(this,
                                                                             (IOInterruptEventSource::Action)&ItlIwx::iwx_intr, &ItlIwx::intrFilter
                                                                             ,pa->pa_tag, msiIntrIndex);
    if (sc->sc_ih == NULL || pa->workloop->addEventSource(sc->sc_ih) != kIOReturnSuccess) {
        XYLog("%s: can't establish interrupt\n", DEVNAME(sc));
        return false;
    }
    sc->sc_ih->enable();
    
    /* Clear pending interrupts. */
    IWX_WRITE(sc, IWX_CSR_INT_MASK, 0);
    IWX_WRITE(sc, IWX_CSR_INT, ~0);
    IWX_WRITE(sc, IWX_CSR_FH_INT_STATUS, ~0);
    
    sc->sc_hw_rev = IWX_READ(sc, IWX_CSR_HW_REV);
    /*
     * In the 8000 HW family the format of the 4 bytes of CSR_HW_REV have
     * changed, and now the revision step also includes bit 0-1 (no more
     * "dash" value). To keep hw_rev backwards compatible - we'll store it
     * in the old format.
     */
    sc->sc_hw_rev = (sc->sc_hw_rev & 0xfff0) |
    (IWX_CSR_HW_REV_STEP(sc->sc_hw_rev << 2) << 2);
    sc->sc_hw_rf_id = IWX_READ(sc, IWX_CSR_HW_RF_ID);
    uint16_t device = sc->sc_pcitag->configRead16(kIOPCIConfigDeviceID);
    uint16_t subsystem_device = sc->sc_pcitag->configRead16(kIOPCIConfigSubSystemID);
    uint16_t subsystem_vendor = sc->sc_pcitag->configRead16(kIOPCIConfigSubSystemVendorID);
    sc->sc_hw_id = (device << 16) + subsystem_device;
    pci_match(PCI_VENDOR_INTEL, device, subsystem_vendor, subsystem_device, iwx_devices,
              nitems(iwx_devices), (void **)&com.sc_cfg_params);
    if (!com.sc_cfg_params) {
        XYLog("%s: Why??? unknown adapter type\n", DEVNAME(sc));
        return false;
    }
    for (i = 0; i < ARRAY_SIZE(iwl_dev_info_table); i++) {
        const struct iwl_dev_info *dev_info = &iwl_dev_info_table[i];
        if ((dev_info->device == (u16)IWL_CFG_ANY ||
             dev_info->device == device) &&
            (dev_info->subdevice == (u16)IWL_CFG_ANY ||
             dev_info->subdevice == subsystem_device) &&
            (dev_info->mac_type == (u16)IWL_CFG_ANY ||
             dev_info->mac_type ==
             CSR_HW_REV_TYPE(sc->sc_hw_rev)) &&
            (dev_info->mac_step == (u8)IWL_CFG_ANY ||
             dev_info->mac_step ==
             IWX_CSR_HW_REV_STEP(sc->sc_hw_rev)) &&
            (dev_info->rf_type == (u16)IWL_CFG_ANY ||
             dev_info->rf_type ==
             CSR_HW_RFID_TYPE(sc->sc_hw_rf_id)) &&
            (dev_info->cdb == IWL_CFG_NO_CDB ||
             CSR_HW_RFID_IS_CDB(sc->sc_hw_rf_id)) &&
            (dev_info->rf_id == (u8)IWL_CFG_ANY ||
             dev_info->rf_id ==
             IWL_SUBDEVICE_RF_ID(subsystem_device)) &&
            (dev_info->no_160 == (u8)IWL_CFG_ANY ||
             dev_info->no_160 ==
             IWL_SUBDEVICE_NO_160(subsystem_device)) &&
            (dev_info->cores == (u8)IWL_CFG_ANY ||
             dev_info->cores ==
             IWL_SUBDEVICE_CORES(subsystem_device))) {
            sc->sc_cfg = dev_info->cfg;
            if (dev_info->name)
                XYLog("Found device: %s fw: %s index: %d:%zu\n", dev_info->name, dev_info->cfg->fwname, i, ARRAY_SIZE(iwl_dev_info_table));
            else if (dev_info->cfg->name)
                XYLog("Found device cfg: %s fw: %s index: %d:%zu\n", dev_info->cfg->name, dev_info->cfg->fwname, i, ARRAY_SIZE(iwl_dev_info_table));
            else
                XYLog("Found device: No Name fw: %s index: %d:%zu\n", dev_info->cfg->fwname, i, ARRAY_SIZE(iwl_dev_info_table));
        }
    }
    /*
     * Workaround for problematic SnJ device: sometimes when
     * certain RF modules are connected to SnJ, the device ID
     * changes to QnJ's ID.  So we are using QnJ's trans_cfg until
     * here.  But if we detect that the MAC type is actually SnJ,
     * we should switch to it here to avoid problems later.
     */
    if (CSR_HW_REV_TYPE(sc->sc_hw_rev) == IWL_CFG_MAC_TYPE_SNJ)
        sc->sc_cfg_params = &iwl_so_trans_cfg;
    
    /*
     * This is a hack to switch from Qu B0 to Qu C0.  We need to
     * do this for all cfgs that use Qu B0, except for those using
     * Jf, which have already been moved to the new table.  The
     * rest must be removed once we convert Qu with Hr as well.
     */
    if (sc->sc_hw_rev == CSR_HW_REV_TYPE_QU_C0) {
        if (sc->sc_cfg == &iwl_ax201_cfg_qu_hr)
            sc->sc_cfg = &iwl_ax201_cfg_qu_c0_hr_b0;
        else if (sc->sc_cfg == &killer1650s_2ax_cfg_qu_b0_hr_b0)
            sc->sc_cfg = &killer1650s_2ax_cfg_qu_c0_hr_b0;
        else if (sc->sc_cfg == &killer1650i_2ax_cfg_qu_b0_hr_b0)
            sc->sc_cfg = &killer1650i_2ax_cfg_qu_c0_hr_b0;
    }

    /* same thing for QuZ... */
    if (sc->sc_hw_rev == CSR_HW_REV_TYPE_QUZ) {
        if (sc->sc_cfg == &iwl_ax201_cfg_qu_hr)
            sc->sc_cfg = &iwl_ax201_cfg_quz_hr;
        else if (sc->sc_cfg == &killer1650s_2ax_cfg_qu_b0_hr_b0)
            sc->sc_cfg = &iwl_ax1650s_cfg_quz_hr;
        else if (sc->sc_cfg == &killer1650i_2ax_cfg_qu_b0_hr_b0)
            sc->sc_cfg = &iwl_ax1650i_cfg_quz_hr;
    }
    if (sc->sc_cfg == NULL) {
        XYLog("No config found for PCI dev %04x/%04x, rev=0x%x, rfid=0x%x\n",
              device, subsystem_device,
              sc->sc_hw_rev, sc->sc_hw_rf_id);
        return false;
    }
    XYLog("Found PCI dev %04x/%04x, rev=0x%x, rfid=0x%x fw: %s\n",
          device, subsystem_device,
          sc->sc_hw_rev, sc->sc_hw_rf_id, sc->sc_cfg->fwname);
    sc->sc_fwname = sc->sc_cfg->fwname;
    sc->sc_device_family = sc->sc_cfg->device_family;
    sc->sc_integrated = sc->sc_cfg_params->integrated;
    sc->sc_ltr_delay = sc->sc_cfg_params->ltr_delay;
    sc->sc_low_latency_xtal = sc->sc_cfg_params->low_latency_xtal;
    sc->sc_xtal_latency = sc->sc_cfg_params->xtal_latency;
    sc->sc_tx_with_siso_diversity = sc->sc_cfg->tx_with_siso_diversity;
    sc->sc_uhb_supported = sc->sc_cfg->uhb_supported;
    
    /* Allocate DMA memory for loading firmware. */
    if (sc->sc_device_family >= IWX_DEVICE_FAMILY_AX210)
        err = iwx_dma_contig_alloc(sc->sc_dmat, &sc->ctxt_info_dma,
                                   sizeof(struct iwx_context_info_gen3), 0);
    else
        err = iwx_dma_contig_alloc(sc->sc_dmat, &sc->ctxt_info_dma,
                                   sizeof(struct iwx_context_info), 0);
    if (err) {
        XYLog("%s: could not allocate memory for loading firmware\n",
              DEVNAME(sc));
        return false;
    }
    
    /* Allocate interrupt cause table (ICT).*/
    err = iwx_dma_contig_alloc(sc->sc_dmat, &sc->ict_dma,
                               IWX_ICT_SIZE, 1<<IWX_ICT_PADDR_SHIFT);
    if (err) {
        XYLog("%s: could not allocate ICT table\n", DEVNAME(sc));
        goto fail0;
    }
    
    for (txq_i = 0; txq_i < nitems(sc->txq); txq_i++) {
        err = iwx_alloc_tx_ring(sc, &sc->txq[txq_i], txq_i);
        if (err) {
            XYLog("%s: could not allocate TX ring %d\n",
                  DEVNAME(sc), txq_i);
            goto fail4;
        }
    }
    
    err = iwx_alloc_rx_ring(sc, &sc->rxq);
    if (err) {
        XYLog("%s: could not allocate RX ring\n", DEVNAME(sc));
        goto fail4;
    }
    
    taskq_init();
    sc->sc_nswq = taskq_create("iwxns", 1, IPL_NET, 0);
    if (sc->sc_nswq == NULL)
        goto fail4;
    
    ic->ic_phytype = IEEE80211_T_OFDM;    /* not only, but not used */
    ic->ic_opmode = IEEE80211_M_STA;    /* default to BSS mode */
    ic->ic_state = IEEE80211_S_INIT;
    
    /* Set device capabilities. */
    ic->ic_caps =
    IEEE80211_C_WEP |        /* WEP */
    IEEE80211_C_RSN |        /* WPA/RSN */
    IEEE80211_C_SCANALL |    /* device scans all channels at once */
    IEEE80211_C_SCANALLBAND |    /* device scans all bands at once */
    IEEE80211_C_MONITOR |    /* monitor mode supported */
    IEEE80211_C_SHSLOT |    /* short slot time supported */
    IEEE80211_C_SHPREAMBLE;    /* short preamble supported */
    
    ic->ic_htcaps = IEEE80211_HTCAP_SGI20;
    ic->ic_htcaps |=
    (IEEE80211_HTCAP_SMPS_DIS << IEEE80211_HTCAP_SMPS_SHIFT);
    ic->ic_htcaps |= (IEEE80211_HTCAP_CBW20_40 | IEEE80211_HTCAP_SGI40);
    ic->ic_htcaps |= IEEE80211_HTCAP_LDPC;  /* all of the gen2/gen3 cards support LDPC */
    ic->ic_htxcaps = 0;
    ic->ic_txbfcaps = 0;
    ic->ic_aselcaps = 0;
    ic->ic_ampdu_params = (IEEE80211_AMPDU_PARAM_SS_4 | 0x3 /* 64k */);
    ic->ic_caps |= (IEEE80211_C_QOS | IEEE80211_C_TX_AMPDU_SETUP_IN_HW | IEEE80211_C_TX_AMPDU | IEEE80211_C_AMSDU_IN_AMPDU);
    ic->ic_caps |= IEEE80211_C_SUPPORTS_VHT_EXT_NSS_BW;
    
    ic->ic_sup_rates[IEEE80211_MODE_11A] = ieee80211_std_rateset_11a;
    ic->ic_sup_rates[IEEE80211_MODE_11B] = ieee80211_std_rateset_11b;
    ic->ic_sup_rates[IEEE80211_MODE_11G] = ieee80211_std_rateset_11g;
    
    for (i = 0; i < nitems(sc->sc_phyctxt); i++) {
        sc->sc_phyctxt[i].id = i;
    }
    
    /* IBSS channel undefined for now. */
    ic->ic_ibss_chan = &ic->ic_channels[1];
    
    ic->ic_max_rssi = IWX_MAX_DBM - IWX_MIN_DBM;
    
    ifp->if_softc = sc;
    ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST | IFF_DEBUG;
    ifp->if_ioctl = iwx_ioctl;
    ifp->if_start = iwx_start;
    ifp->if_watchdog = iwx_watchdog;
    memcpy(ifp->if_xname, DEVNAME(sc), IFNAMSIZ);
    
    if_attach(ifp);
    ieee80211_ifattach(ifp, getController());
    ieee80211_media_init(ifp);
    
#if NBPFILTER > 0
    iwx_radiotap_attach(sc);
#endif
    for (i = 0; i < nitems(sc->sc_rxba_data); i++) {
        struct iwx_rxba_data *rxba = &sc->sc_rxba_data[i];
        rxba->baid = IWX_RX_REORDER_DATA_INVALID_BAID;
        rxba->sc = sc;
        timeout_set(&rxba->session_timer, iwx_rx_ba_session_expired,
                    rxba);
        timeout_set(&rxba->reorder_buf.reorder_timer,
                    iwx_reorder_timer_expired, &rxba->reorder_buf);
        for (j = 0; j < nitems(rxba->entries); j++)
        ml_init(&rxba->entries[j].frames);
    }
    task_set(&sc->init_task, iwx_init_task, sc, "iwx_init_task");
    task_set(&sc->newstate_task, iwx_newstate_task, sc, "iwx_newstate_task");
    task_set(&sc->ba_task, iwx_ba_task, sc, "iwx_ba_task");
    task_set(&sc->mac_ctxt_task, iwx_mac_ctxt_task, sc, "iwx_mac_ctxt_task");
    task_set(&sc->chan_ctxt_task, iwx_chan_ctxt_task, sc, "iwx_chan_ctxt_task");
    
    ic->ic_node_alloc = iwx_node_alloc;
    ic->ic_bgscan_start = iwx_bgscan;
    ic->ic_set_key = iwx_set_key;
    ic->ic_delete_key = iwx_delete_key;
    
    /* Override 802.11 state transition machine. */
    sc->sc_newstate = ic->ic_newstate;
    ic->ic_newstate = iwx_newstate;
    ic->ic_updateprot = iwx_updateprot;
    ic->ic_updateslot = iwx_updateslot;
    ic->ic_updateedca = iwx_updateedca;
    ic->ic_updatedtim = iwx_updatedtim;
    ic->ic_ampdu_rx_start = iwx_ampdu_rx_start;
    ic->ic_ampdu_rx_stop = iwx_ampdu_rx_stop;
    ic->ic_ampdu_tx_start = iwx_ampdu_tx_start;
    ic->ic_ampdu_tx_stop = iwx_ampdu_tx_stop;
    ic->ic_update_chw = iwx_update_chw;
    /*
     * We cannot read the MAC address without loading the
     * firmware from disk. Postpone until mountroot is done.
     */
    //    config_mountroot(self, iwx_attach_hook);
    if (iwx_preinit(sc)) {
        goto fail5;
    }
    
    return true;
    
fail5:
    for (i = 0; i < nitems(sc->sc_rxba_data); i++) {
        struct iwx_rxba_data *rxba = &sc->sc_rxba_data[i];
        iwx_clear_reorder_buffer(sc, rxba);
    }
fail4:    while (--txq_i >= 0)
    iwx_free_tx_ring(sc, &sc->txq[txq_i]);
    iwx_free_rx_ring(sc, &sc->rxq);
fail3:    if (sc->ict_dma.vaddr != NULL)
    iwx_dma_contig_free(&sc->ict_dma);

fail0:    iwx_dma_contig_free(&sc->ctxt_info_dma);
    return false;
}

#if NBPFILTER > 0
void ItlIwx::
iwx_radiotap_attach(struct iwx_softc *sc)
{
    bpfattach(&sc->sc_drvbpf, &sc->sc_ic.ic_if, DLT_IEEE802_11_RADIO,
              sizeof (struct ieee80211_frame) + IEEE80211_RADIOTAP_HDRLEN);
    
    sc->sc_rxtap_len = sizeof sc->sc_rxtapu;
    sc->sc_rxtap.wr_ihdr.it_len = htole16(sc->sc_rxtap_len);
    sc->sc_rxtap.wr_ihdr.it_present = htole32(IWX_RX_RADIOTAP_PRESENT);
    
    sc->sc_txtap_len = sizeof sc->sc_txtapu;
    sc->sc_txtap.wt_ihdr.it_len = htole16(sc->sc_txtap_len);
    sc->sc_txtap.wt_ihdr.it_present = htole32(IWX_TX_RADIOTAP_PRESENT);
}
#endif

void ItlIwx::
iwx_init_task(void *arg1)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwx_softc *sc = (struct iwx_softc *)arg1;
    struct _ifnet *ifp = &sc->sc_ic.ic_if;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    int s = splnet();
    int generation = sc->sc_generation;
    int fatal = (sc->sc_flags & (IWX_FLAG_HW_ERR | IWX_FLAG_RFKILL));
    
    //    rw_enter_write(&sc->ioctl_rwl);
    if (generation != sc->sc_generation) {
        //        rw_exit(&sc->ioctl_rwl);
        splx(s);
        return;
    }
    
    if (ifp->if_flags & IFF_RUNNING)
        that->iwx_stop(ifp);
    else
        sc->sc_flags &= ~IWX_FLAG_HW_ERR;
    
    if (!fatal && (ifp->if_flags & (IFF_UP | IFF_RUNNING)) == IFF_UP)
        that->iwx_init(ifp);
    
    //    rw_exit(&sc->ioctl_rwl);
    splx(s);
}

int ItlIwx::
iwx_resume(struct iwx_softc *sc)
{
    pcireg_t reg;
    
    /* Clear device-specific "PCI retry timeout" register (41h). */
    reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag, 0x40);
    pci_conf_write(sc->sc_pct, sc->sc_pcitag, 0x40, reg & ~0xff00);
    
    if (!sc->sc_msix) {
        /* Hardware bug workaround. */
        reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag,
                            PCI_COMMAND_STATUS_REG);
        if (reg & PCI_COMMAND_INTERRUPT_DISABLE)
            reg &= ~PCI_COMMAND_INTERRUPT_DISABLE;
        pci_conf_write(sc->sc_pct, sc->sc_pcitag,
                       PCI_COMMAND_STATUS_REG, reg);
    }

    iwx_enable_rfkill_int(sc);
    iwx_check_rfkill(sc);

    return iwx_prepare_card_hw(sc);
}

int ItlIwx::
iwx_activate(struct iwx_softc *sc, int act)
{
    struct _ifnet *ifp = &sc->sc_ic.ic_if;
    int err = 0;
    
    switch (act) {
        case DVACT_QUIESCE:
            if (ifp->if_flags & IFF_RUNNING) {
                //            rw_enter_write(&sc->ioctl_rwl);
                iwx_stop(ifp);
                //            rw_exit(&sc->ioctl_rwl);
            }
            break;
        case DVACT_RESUME:
            err = iwx_resume(sc);
            if (err)
                XYLog("%s: could not initialize hardware\n",
                      DEVNAME(sc));
            break;
        case DVACT_WAKEUP:
            /* Hardware should be up at this point. */
            if (iwx_set_hw_ready(sc))
                task_add(systq, &sc->init_task);
            break;
    }
    
    return 0;
}
