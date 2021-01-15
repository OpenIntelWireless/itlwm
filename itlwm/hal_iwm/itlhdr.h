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
/*    $OpenBSD: if_iwm.c,v 1.316 2020/12/07 20:09:24 tobhe Exp $    */

/*
 * Copyright (c) 2014, 2016 genua gmbh <info@genua.de>
 *   Author: Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2014 Fixup Software Ltd.
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
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
 ***********************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2007 - 2013 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 *  Intel Linux Wireless <ilw@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 *
 * BSD LICENSE
 *
 * Copyright(c) 2005 - 2013 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
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

#ifndef itlhdr_h
#define itlhdr_h

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/kpi_mbuf.h>

#include "if_iwmreg.h"
#include "if_iwmvar.h"
#include <sys/pcireg.h>

#define DEVNAME(_s)    ("itlwm")
#define IWM_DEBUG

#ifdef IWM_DEBUG
#define DPRINTF(x)    do { if (iwm_debug > 0) XYLog x; } while (0)
#define DPRINTFN(n, x)    do { if (iwm_debug >= (n)) XYLog x; } while (0)
extern int iwm_debug;
#else
#define DPRINTF(x)    do { ; } while (0)
#define DPRINTFN(n, x)    do { ; } while (0)
#endif

#define M_DEVBUF 2
#define M_WAIT 3
#define DELAY IODelay

//pci
#define PCI_PCIE_LCSR_ASPM_L1    0x00000002

#define    INFSLP    UINT64_MAX

#define IC2IFP(_ic_) (&(_ic_)->ic_if)
#define LLADDR(s) ((caddr_t)((s)->sdl_data + (s)->sdl_nlen))

const uint8_t iwm_nvm_channels[] = {
    /* 2.4 GHz */
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    /* 5 GHz */
    36, 40, 44 , 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165
};

const uint8_t iwm_nvm_channels_8000[] = {
    /* 2.4 GHz */
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    /* 5 GHz */
    36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92,
    96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177, 181
};

#define IWM_NUM_2GHZ_CHANNELS    14

const struct iwm_rate {
    uint16_t rate;
    uint8_t plcp;
    uint8_t ht_plcp;
} iwm_rates[] = {
        /* Legacy */        /* HT */
    {   2,    IWM_RATE_1M_PLCP,    IWM_RATE_HT_SISO_MCS_INV_PLCP  },
    {   4,    IWM_RATE_2M_PLCP,    IWM_RATE_HT_SISO_MCS_INV_PLCP },
    {  11,    IWM_RATE_5M_PLCP,    IWM_RATE_HT_SISO_MCS_INV_PLCP  },
    {  22,    IWM_RATE_11M_PLCP,    IWM_RATE_HT_SISO_MCS_INV_PLCP },
    {  12,    IWM_RATE_6M_PLCP,    IWM_RATE_HT_SISO_MCS_0_PLCP },
    {  18,    IWM_RATE_9M_PLCP,    IWM_RATE_HT_SISO_MCS_INV_PLCP  },
    {  24,    IWM_RATE_12M_PLCP,    IWM_RATE_HT_SISO_MCS_1_PLCP },
    {  26,    IWM_RATE_INVM_PLCP,    IWM_RATE_HT_MIMO2_MCS_8_PLCP },
    {  36,    IWM_RATE_18M_PLCP,    IWM_RATE_HT_SISO_MCS_2_PLCP },
    {  48,    IWM_RATE_24M_PLCP,    IWM_RATE_HT_SISO_MCS_3_PLCP },
    {  52,    IWM_RATE_INVM_PLCP,    IWM_RATE_HT_MIMO2_MCS_9_PLCP },
    {  72,    IWM_RATE_36M_PLCP,    IWM_RATE_HT_SISO_MCS_4_PLCP },
    {  78,    IWM_RATE_INVM_PLCP,    IWM_RATE_HT_MIMO2_MCS_10_PLCP },
    {  96,    IWM_RATE_48M_PLCP,    IWM_RATE_HT_SISO_MCS_5_PLCP },
    { 104,    IWM_RATE_INVM_PLCP,    IWM_RATE_HT_MIMO2_MCS_11_PLCP },
    { 108,    IWM_RATE_54M_PLCP,    IWM_RATE_HT_SISO_MCS_6_PLCP },
    { 128,    IWM_RATE_INVM_PLCP,    IWM_RATE_HT_SISO_MCS_7_PLCP },
    { 156,    IWM_RATE_INVM_PLCP,    IWM_RATE_HT_MIMO2_MCS_12_PLCP },
    { 208,    IWM_RATE_INVM_PLCP,    IWM_RATE_HT_MIMO2_MCS_13_PLCP },
    { 234,    IWM_RATE_INVM_PLCP,    IWM_RATE_HT_MIMO2_MCS_14_PLCP },
    { 260,    IWM_RATE_INVM_PLCP,    IWM_RATE_HT_MIMO2_MCS_15_PLCP },
};
#define IWM_RIDX_CCK    0
#define IWM_RIDX_OFDM    4
#define IWM_RIDX_MAX    (nitems(iwm_rates)-1)
#define IWM_RIDX_IS_CCK(_i_) ((_i_) < IWM_RIDX_OFDM)
#define IWM_RIDX_IS_OFDM(_i_) ((_i_) >= IWM_RIDX_OFDM)
#define IWM_RVAL_IS_OFDM(_i_) ((_i_) >= 12 && (_i_) != 22)

/* Convert an MCS index into an iwm_rates[] index. */
const int iwm_mcs2ridx[] = {
    IWM_RATE_MCS_0_INDEX,
    IWM_RATE_MCS_1_INDEX,
    IWM_RATE_MCS_2_INDEX,
    IWM_RATE_MCS_3_INDEX,
    IWM_RATE_MCS_4_INDEX,
    IWM_RATE_MCS_5_INDEX,
    IWM_RATE_MCS_6_INDEX,
    IWM_RATE_MCS_7_INDEX,
    IWM_RATE_MCS_8_INDEX,
    IWM_RATE_MCS_9_INDEX,
    IWM_RATE_MCS_10_INDEX,
    IWM_RATE_MCS_11_INDEX,
    IWM_RATE_MCS_12_INDEX,
    IWM_RATE_MCS_13_INDEX,
    IWM_RATE_MCS_14_INDEX,
    IWM_RATE_MCS_15_INDEX,
};

struct iwm_nvm_section {
    uint16_t length;
    uint8_t *data;
};

/* Map ieee80211_edca_ac categories to firmware Tx FIFO. */
const uint8_t iwm_ac_to_tx_fifo[] = {
    IWM_TX_FIFO_BE,
    IWM_TX_FIFO_BK,
    IWM_TX_FIFO_VI,
    IWM_TX_FIFO_VO,
};

#endif /* itlhdr_h */
