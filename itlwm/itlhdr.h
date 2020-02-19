//
//  itlhdr.h
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//

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

#define DEVNAME(_s)    ("itliwm")
#define IWM_DEBUG

#define M_DEVBUF 2
#define M_WAIT 3
#define DELAY IODelay

//pci
#define PCI_PCIE_LCSR_ASPM_L1    0x00000002

#define    INFSLP    UINT64_MAX

#define le16_to_cpup(_a_) (le16toh(*(const uint16_t *)(_a_)))
#define le32_to_cpup(_a_) (le32toh(*(const uint32_t *)(_a_)))

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

const uint8_t iwm_ac_to_tx_fifo[] = {
    IWM_TX_FIFO_VO,
    IWM_TX_FIFO_VI,
    IWM_TX_FIFO_BE,
    IWM_TX_FIFO_BK,
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

#endif /* itlhdr_h */
