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

#include "ItlIwm.hpp"
#include <net/ethernet.h>
#include <IOKit/IOCommandGate.h>
#include <net80211/ieee80211_priv.h>
#include "rs.h"

#ifdef IWM_DEBUG
int iwm_debug = 1;
#endif

int ItlIwm::
iwm_is_valid_channel(uint16_t ch_id)
{
    if (ch_id <= 14 ||
        (36 <= ch_id && ch_id <= 64 && ch_id % 4 == 0) ||
        (100 <= ch_id && ch_id <= 140 && ch_id % 4 == 0) ||
        (145 <= ch_id && ch_id <= 165 && ch_id % 4 == 1))
        return 1;
    return 0;
}

uint8_t ItlIwm::
iwm_ch_id_to_ch_index(uint16_t ch_id)
{
    if (!iwm_is_valid_channel(ch_id))
        return 0xff;
    
    if (ch_id <= 14)
        return ch_id - 1;
    if (ch_id <= 64)
        return (ch_id + 20) / 4;
    if (ch_id <= 140)
        return (ch_id - 12) / 4;
    return (ch_id - 13) / 4;
}


uint16_t ItlIwm::
iwm_channel_id_to_papd(uint16_t ch_id)
{
    if (!iwm_is_valid_channel(ch_id))
        return 0xff;
    
    if (1 <= ch_id && ch_id <= 14)
        return 0;
    if (36 <= ch_id && ch_id <= 64)
        return 1;
    if (100 <= ch_id && ch_id <= 140)
        return 2;
    return 3;
}

uint16_t ItlIwm::
iwm_channel_id_to_txp(struct iwm_softc *sc, uint16_t ch_id)
{
    struct iwm_phy_db *phy_db = &sc->sc_phy_db;
    struct iwm_phy_db_chg_txp *txp_chg;
    int i;
    uint8_t ch_index = iwm_ch_id_to_ch_index(ch_id);
    
    if (ch_index == 0xff)
        return 0xff;
    
    for (i = 0; i < IWM_NUM_TXP_CH_GROUPS; i++) {
        txp_chg = (struct iwm_phy_db_chg_txp *)phy_db->calib_ch_group_txp[i].data;
        if (!txp_chg)
            return 0xff;
        /*
         * Looking for the first channel group the max channel
         * of which is higher than the requested channel.
         */
        if (le16toh(txp_chg->max_channel_idx) >= ch_index)
            return i;
    }
    return 0xff;
}

int ItlIwm::
iwm_mimo_enabled(struct iwm_softc *sc)
{
   struct ieee80211com *ic = &sc->sc_ic;

   return !sc->sc_nvm.sku_cap_mimo_disable &&
       (ic->ic_userflags & IEEE80211_F_NOMIMO) == 0;
}

void ItlIwm::
iwm_init_channel_map(struct iwm_softc *sc, const uint16_t * const nvm_ch_flags,
                     const uint8_t *nvm_channels, size_t nchan)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_nvm_data *data = &sc->sc_nvm;
    int ch_idx;
    struct ieee80211_channel *channel;
    uint16_t ch_flags;
    int is_5ghz;
    int flags, hw_value;
    
    for (ch_idx = 0; ch_idx < nchan; ch_idx++) {
        ch_flags = le16_to_cpup(nvm_ch_flags + ch_idx);
        
        if (ch_idx >= IWM_NUM_2GHZ_CHANNELS &&
            !data->sku_cap_band_52GHz_enable)
            ch_flags &= ~IWM_NVM_CHANNEL_VALID;
        
        if (!(ch_flags & IWM_NVM_CHANNEL_VALID))
            continue;
        
        if (ch_flags & IWM_NVM_CHANNEL_160MHZ)
            data->vht160_supported = true;
        
        hw_value = nvm_channels[ch_idx];
        channel = &ic->ic_channels[hw_value];
        
        is_5ghz = ch_idx >= IWM_NUM_2GHZ_CHANNELS;
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
        
        if (!(ch_flags & IWM_NVM_CHANNEL_ACTIVE))
            channel->ic_flags |= IEEE80211_CHAN_PASSIVE;
        
        if (data->sku_cap_11n_enable)
            channel->ic_flags |= IEEE80211_CHAN_HT20;

        if (!is_5ghz && (ch_flags & IWM_NVM_CHANNEL_40MHZ)) {
            if (hw_value <= IWM_LAST_2GHZ_HT_PLUS) {
                channel->ic_flags |= IEEE80211_CHAN_HT40U;
            }
            if (hw_value >= IWM_FIRST_2GHZ_HT_MINUS) {
                channel->ic_flags |= IEEE80211_CHAN_HT40D;
            }
        } else if (ch_flags & IWM_NVM_CHANNEL_40MHZ) {
            if ((ch_idx - IWM_NUM_2GHZ_CHANNELS) % 2 == 0) {
                channel->ic_flags |= IEEE80211_CHAN_HT40U;
            } else {
                channel->ic_flags |= IEEE80211_CHAN_HT40D;
            }
        }

        if (data->sku_cap_11ac_enable) {
            if (ch_flags & IWM_NVM_CHANNEL_80MHZ) {
                channel->ic_flags |= IEEE80211_CHAN_VHT80;
            }
            if (ch_flags & IWM_NVM_CHANNEL_160MHZ) {
                channel->ic_flags |= IEEE80211_CHAN_VHT160;
            }
        }

        if (ch_flags & IWM_NVM_CHANNEL_DFS) {
            channel->ic_flags |= IEEE80211_CHAN_DFS;
        }

        channel->ic_freq = ieee80211_ieee2mhz(hw_value, flags);
    }
}

void ItlIwm::
iwm_setup_ht_rates(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    uint8_t rx_ant;
    
    /* TX is supported with the same MCS as RX. */
    ic->ic_tx_mcs_set = IEEE80211_TX_MCS_SET_DEFINED;
    
    memset(ic->ic_sup_mcs, 0, sizeof(ic->ic_sup_mcs));
    ic->ic_sup_mcs[0] = 0xff;        /* MCS 0-7 */
    
    if (sc->support_ldpc)
        ic->ic_htcaps |= IEEE80211_HTCAP_LDPC;
    
    if (!iwm_mimo_enabled(sc))
        return;
    
    rx_ant = iwm_fw_valid_rx_ant(sc);
    if ((rx_ant & IWM_ANT_AB) == IWM_ANT_AB ||
        (rx_ant & IWM_ANT_BC) == IWM_ANT_BC)
        ic->ic_sup_mcs[1] = 0xff;    /* MCS 8-15 */
}

void ItlIwm::
iwm_init_reorder_buffer(struct iwm_reorder_buffer *reorder_buf,
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

void ItlIwm::
iwm_clear_reorder_buffer(struct iwm_softc *sc, struct iwm_rxba_data *rxba)
{
    int i;
    struct iwm_reorder_buffer *reorder_buf = &rxba->reorder_buf;
    struct iwm_reorder_buf_entry *entry;
    
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
    rxba->baid = IWM_RX_REORDER_DATA_INVALID_BAID;
}

void ItlIwm::
iwm_rx_ba_session_expired(void *arg)
{
    struct iwm_rxba_data *rxba = (struct iwm_rxba_data *)arg;
    struct iwm_softc *sc = rxba->sc;
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    struct timeval now, timeout, expiry;
    int s;
    
    s = splnet();
    if ((sc->sc_flags & IWM_FLAG_SHUTDOWN) == 0 &&
        ic->ic_state == IEEE80211_S_RUN &&
        rxba->baid != IWM_RX_REORDER_DATA_INVALID_BAID) {
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

void ItlIwm::
iwm_reorder_timer_expired(void *arg)
{
    struct mbuf_list ml = MBUF_LIST_INITIALIZER();
    struct iwm_reorder_buffer *buf = (struct iwm_reorder_buffer *)arg;
    struct iwm_rxba_data *rxba = iwm_rxba_data_from_reorder_buf(buf);
    struct iwm_reorder_buf_entry *entries = &rxba->entries[0];
    struct iwm_softc *sc = rxba->sc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
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
        that->iwm_release_frames(sc, ni, rxba, buf, sn, &ml);
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

uint8_t ItlIwm::
iwm_num_of_ant(uint8_t mask)
{
    return  !!((mask) & IWM_ANT_A) +
        !!((mask) & IWM_ANT_B) +
        !!((mask) & IWM_ANT_C);
}

void ItlIwm::
iwm_setup_vht_rates(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    uint8_t rx_ant, tx_ant;
    unsigned int max_ampdu_exponent = IEEE80211_VHTCAP_MAX_AMPDU_1024K;
    
    if (ic->ic_userflags & IEEE80211_F_NOVHT)
        return;
    
    /* enable 11ac support */
    ic->ic_flags |= IEEE80211_F_VHTON;
    
    rx_ant = iwm_num_of_ant(iwm_fw_valid_rx_ant(sc));
    tx_ant = iwm_num_of_ant(iwm_fw_valid_tx_ant(sc));
    
    ic->ic_vhtcaps = IEEE80211_VHTCAP_SHORT_GI_80 |
    IEEE80211_VHTCAP_RXSTBC_1 |
    IEEE80211_VHTCAP_SU_BEAMFORMEE_CAPABLE |
    3 << IEEE80211_VHTCAP_BEAMFORMEE_STS_SHIFT |
    max_ampdu_exponent <<
    IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT |
    IEEE80211_VHTCAP_MU_BEAMFORMEE_CAPABLE;
    
    if (sc->sc_nvm.vht160_supported)
    ic->ic_vhtcaps |= IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_160MHZ |
            IEEE80211_VHTCAP_SHORT_GI_160;
    
    if (sc->support_ldpc)
        ic->ic_vhtcaps |= IEEE80211_VHTCAP_RXLDPC;
    if (!iwm_mimo_enabled(sc)) {
        rx_ant = 1;
        tx_ant = 1;
    }
    
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
    ic->ic_vht_tx_highest = ic->ic_vht_rx_highest = 0;

    memset(ic->ic_vht_sup_mcs, 0, sizeof(ic->ic_vht_sup_mcs));
    ic->ic_vht_sup_mcs[0] = 0x03FF;        /* MCS 0-9 */
    
    if (!iwm_mimo_enabled(sc))
        return;
    
    ic->ic_vht_sup_mcs[1] = 0x03FF;         /* MCS 0-9 */
}

#define IWM_MAX_RX_BA_SESSIONS 16

int ItlIwm::
iwm_sta_rx_agg(struct iwm_softc *sc, struct ieee80211_node *ni, uint8_t tid,
               uint16_t ssn, uint16_t winsize, int timeout_val, int start)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_add_sta_cmd cmd;
    struct iwm_node *in = (struct iwm_node *)ni;
    int err, s;
    uint32_t status;
    size_t cmdsize;
    struct iwm_rxba_data *rxba = NULL;
    uint8_t baid = 0;
    
    s = splnet();
    
    if (start && sc->sc_rx_ba_sessions >= IWM_MAX_RX_BA_SESSIONS) {
        ieee80211_addba_req_refuse(ic, ni, tid);
        splx(s);
        return 0;
    }
    
    memset(&cmd, 0, sizeof(cmd));
    
    cmd.sta_id = IWM_STATION_ID;
    cmd.mac_id_n_color
    = htole32(IWM_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    cmd.add_modify = IWM_STA_MODE_MODIFY;
    
    if (start) {
        cmd.add_immediate_ba_tid = (uint8_t)tid;
        cmd.add_immediate_ba_ssn = ssn;
        cmd.rx_ba_window = winsize;
    } else {
        cmd.remove_immediate_ba_tid = (uint8_t)tid;
    }
    cmd.modify_mask = start ? IWM_STA_MODIFY_ADD_BA_TID :
    IWM_STA_MODIFY_REMOVE_BA_TID;
    
    status = IWM_ADD_STA_SUCCESS;
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE))
        cmdsize = sizeof(cmd);
    else
        cmdsize = sizeof(struct iwm_add_sta_cmd_v7);
    err = iwm_send_cmd_pdu_status(sc, IWM_ADD_STA, cmdsize, &cmd,
                                  &status);
    if (!err && (status & IWM_ADD_STA_STATUS_MASK) != IWM_ADD_STA_SUCCESS)
        err = EIO;
    if (err) {
        if (start)
            ieee80211_addba_req_refuse(ic, ni, tid);
        splx(s);
        return err;
    }
    
    if (sc->sc_mqrx_supported) {
        /* Deaggregation is done in hardware. */
        if (start) {
            if (!(status & IWM_ADD_STA_BAID_VALID_MASK)) {
                ieee80211_addba_req_refuse(ic, ni, tid);
                splx(s);
                return EIO;
            }
            baid = (status & IWM_ADD_STA_BAID_MASK) >>
            IWM_ADD_STA_BAID_SHIFT;
            if (baid == IWM_RX_REORDER_DATA_INVALID_BAID ||
                baid >= nitems(sc->sc_rxba_data)) {
                ieee80211_addba_req_refuse(ic, ni, tid);
                splx(s);
                return EIO;
            }
            rxba = &sc->sc_rxba_data[baid];
            if (rxba->baid != IWM_RX_REORDER_DATA_INVALID_BAID) {
                ieee80211_addba_req_refuse(ic, ni, tid);
                splx(s);
                return 0;
            }
            rxba->sta_id = IWM_STATION_ID;
            rxba->tid = tid;
            rxba->baid = baid;
            rxba->timeout = timeout_val;
            getmicrouptime(&rxba->last_rx);
            iwm_init_reorder_buffer(&rxba->reorder_buf, ssn,
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
                    IWM_RX_REORDER_DATA_INVALID_BAID)
                    continue;
                if (rxba->tid != tid)
                    continue;
                iwm_clear_reorder_buffer(sc, rxba);
                break;
            }
        }
    }
    
    if (start) {
        sc->sc_rx_ba_sessions++;
        ieee80211_addba_req_accept(ic, ni, tid);
    } else if (sc->sc_rx_ba_sessions > 0)
        sc->sc_rx_ba_sessions--;
    
    splx(s);
    return 0;
}

int ItlIwm::
iwm_sta_tx_agg(struct iwm_softc *sc, struct ieee80211_node *ni, uint8_t tid, uint8_t qid, uint16_t ssn, int start)
{
    struct iwm_add_sta_cmd cmd;
    struct iwm_node *in = (struct iwm_node *)ni;
    int err = 0;
    uint32_t status;
    size_t cmdsize;

    memset(&cmd, 0, sizeof(cmd));

    cmd.mac_id_n_color = htole32(IWM_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    cmd.sta_id = IWM_STATION_ID;
    cmd.add_modify = IWM_STA_MODE_MODIFY;
    cmd.modify_mask = (IWM_STA_MODIFY_QUEUES | IWM_STA_MODIFY_TID_DISABLE_TX);
    cmd.tfd_queue_msk = htole32(sc->agg_queue_mask);
    cmd.tid_disable_tx = htole16(sc->agg_tid_disable);

    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE))
        cmdsize = sizeof(cmd);
    else
        cmdsize = sizeof(struct iwm_add_sta_cmd_v7);

    status = IWM_ADD_STA_SUCCESS;
    err = iwm_send_cmd_pdu_status(sc, IWM_ADD_STA, cmdsize, &cmd,
                                  &status);

    XYLog("%s tx agg %s. err=%d status=%d, mask_status=%d\n", __FUNCTION__, err ? "failed" : "done", err, status, (status & IWM_ADD_STA_STATUS_MASK));
    
    return err || ((status & IWM_ADD_STA_STATUS_MASK) != IWM_ADD_STA_SUCCESS);
}

void ItlIwm::
iwm_set_hw_address_8000(struct iwm_softc *sc, struct iwm_nvm_data *data,
                        const uint16_t *mac_override, const uint16_t *nvm_hw)
{
    const uint8_t *hw_addr;
    
    if (mac_override) {
        static const uint8_t reserved_mac[] = {
            0x02, 0xcc, 0xaa, 0xff, 0xee, 0x00
        };
        
        hw_addr = (const uint8_t *)(mac_override +
                                    IWM_MAC_ADDRESS_OVERRIDE_8000);
        
        /*
         * Store the MAC address from MAO section.
         * No byte swapping is required in MAO section
         */
        memcpy(data->hw_addr, hw_addr, ETHER_ADDR_LEN);
        
        /*
         * Force the use of the OTP MAC address in case of reserved MAC
         * address in the NVM, or if address is given but invalid.
         */
        if (memcmp(reserved_mac, hw_addr, ETHER_ADDR_LEN) != 0 &&
            (memcmp(etherbroadcastaddr, data->hw_addr,
                    sizeof(etherbroadcastaddr)) != 0) &&
            (memcmp(etheranyaddr, data->hw_addr,
                    sizeof(etheranyaddr)) != 0) &&
            !ETHER_IS_MULTICAST(data->hw_addr))
            return;
    }
    
    if (nvm_hw) {
        /* Read the mac address from WFMP registers. */
        uint32_t mac_addr0, mac_addr1;
        
        if (!iwm_nic_lock(sc))
            goto out;
        mac_addr0 = htole32(iwm_read_prph(sc, IWM_WFMP_MAC_ADDR_0));
        mac_addr1 = htole32(iwm_read_prph(sc, IWM_WFMP_MAC_ADDR_1));
        iwm_nic_unlock(sc);
        
        hw_addr = (const uint8_t *)&mac_addr0;
        data->hw_addr[0] = hw_addr[3];
        data->hw_addr[1] = hw_addr[2];
        data->hw_addr[2] = hw_addr[1];
        data->hw_addr[3] = hw_addr[0];
        
        hw_addr = (const uint8_t *)&mac_addr1;
        data->hw_addr[4] = hw_addr[1];
        data->hw_addr[5] = hw_addr[0];
        
        return;
    }
out:
    XYLog("%s: mac address not found\n", DEVNAME(sc));
    memset(data->hw_addr, 0, sizeof(data->hw_addr));
}

/*
 * RSSI values are reported by the FW as positive values - need to negate
 * to obtain their dBM.  Account for missing antennas by replacing 0
 * values by -256dBm: practically 0 power and a non-feasible 8 bit value.
 */
int ItlIwm::
iwm_get_signal_strength(struct iwm_softc *sc, struct ieee80211_rx_status *rx_status, struct iwm_rx_phy_info *phy_info)
{
    int energy_a, energy_b, energy_c, max_energy;
    uint32_t val;
    
    val = le32toh(phy_info->non_cfg_phy[IWM_RX_INFO_ENERGY_ANT_ABC_IDX]);
    energy_a = (val & IWM_RX_INFO_ENERGY_ANT_A_MSK) >>
    IWM_RX_INFO_ENERGY_ANT_A_POS;
    energy_a = energy_a ? -energy_a : -256;
    energy_b = (val & IWM_RX_INFO_ENERGY_ANT_B_MSK) >>
    IWM_RX_INFO_ENERGY_ANT_B_POS;
    energy_b = energy_b ? -energy_b : -256;
    energy_c = (val & IWM_RX_INFO_ENERGY_ANT_C_MSK) >>
    IWM_RX_INFO_ENERGY_ANT_C_POS;
    energy_c = energy_c ? -energy_c : -256;
    max_energy = MAX(energy_a, energy_b);
    max_energy = MAX(max_energy, energy_c);
    
    rx_status->signal = max_energy;
    rx_status->chains = (le16toh(phy_info->phy_flags) &
                IWM_RX_RES_PHY_FLAGS_ANTENNA)
                    >> IWM_RX_RES_PHY_FLAGS_ANTENNA_POS;
    rx_status->chain_signal[0] = energy_a;
    rx_status->chain_signal[1] = energy_b;
    rx_status->chain_signal[2] = energy_c;
    
    return max_energy;
}

int ItlIwm::
iwm_rxmq_get_signal_strength(struct iwm_softc *sc, struct ieee80211_rx_status *rx_status, uint32_t rate_n_flags,
                             struct iwm_rx_mpdu_desc *desc)
{
    int energy_a, energy_b;
    
    energy_a = desc->v1.energy_a;
    energy_b = desc->v1.energy_b;
    energy_a = energy_a ? -energy_a : -256;
    energy_b = energy_b ? -energy_b : -256;
    rx_status->signal = MAX(energy_a, energy_b);
    rx_status->chains = (rate_n_flags & RATE_MCS_ANT_AB_MSK) >> RATE_MCS_ANT_POS;
    rx_status->chain_signal[0] = energy_a;
    rx_status->chain_signal[1] = energy_b;
    rx_status->chain_signal[2] = S8_MIN;
    
    return rx_status->signal;
}

/*
 * Retrieve the average noise (in dBm) among receivers.
 */
int ItlIwm::
iwm_get_noise(const struct iwm_statistics_rx_non_phy *stats)
{
    int i, total, nbant, noise;
    
    total = nbant = noise = 0;
    for (i = 0; i < 3; i++) {
        noise = letoh32(stats->beacon_silence_rssi[i]) & 0xff;
        if (noise) {
            total += noise;
            nbant++;
        }
    }
    
    /* There should be at least one antenna but check anyway. */
    return (nbant == 0) ? -127 : (total / nbant) - 107;
}

int ItlIwm::
iwm_ccmp_decap(struct iwm_softc *sc, mbuf_t m, struct ieee80211_node *ni,
               struct ieee80211_rxinfo *rxi)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_key *k = &ni->ni_pairwise_key;
    struct ieee80211_frame *wh;
    uint64_t pn, *prsc;
    uint8_t *ivp;
    uint8_t tid;
    int hdrlen, hasqos;
    
    wh = mtod(m, struct ieee80211_frame *);
    hdrlen = ieee80211_get_hdrlen(wh);
    ivp = (uint8_t *)wh + hdrlen;
    
    /* Check that ExtIV bit is set. */
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

int ItlIwm::
iwm_rx_hwdecrypt(struct iwm_softc *sc, mbuf_t m, uint32_t rx_pkt_status,
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
    
    if (IEEE80211_IS_MULTICAST(wh->i_addr1) ||
        !(wh->i_fc[1] & IEEE80211_FC1_PROTECTED))
        return 0;
    
    ni = ieee80211_find_rxnode(ic, wh);
    /* Handle hardware decryption. */
    if ((ni->ni_flags & IEEE80211_NODE_RXPROT) &&
        ni->ni_pairwise_key.k_cipher == IEEE80211_CIPHER_CCMP) {
        if ((rx_pkt_status & IWM_RX_MPDU_RES_STATUS_SEC_ENC_MSK) !=
            IWM_RX_MPDU_RES_STATUS_SEC_CCM_ENC) {
            ic->ic_stats.is_ccmp_dec_errs++;
            ret = 1;
            goto out;
        }
        /* Check whether decryption was successful or not. */
        if ((rx_pkt_status &
             (IWM_RX_MPDU_RES_STATUS_DEC_DONE |
              IWM_RX_MPDU_RES_STATUS_MIC_OK)) !=
            (IWM_RX_MPDU_RES_STATUS_DEC_DONE |
             IWM_RX_MPDU_RES_STATUS_MIC_OK)) {
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

void ItlIwm::
iwm_rx_frame(struct iwm_softc *sc, mbuf_t m, int chanidx,
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
        iwm_ccmp_decap(sc, m, ni, rxi) != 0) {
        if (ifp->netStat)
            ifp->netStat->inputErrors++;
        mbuf_freem(m);
        ieee80211_release_node(ic, ni);
        return;
    }
    
#if NBPFILTER > 0
    if (sc->sc_drvbpf != NULL) {
        struct iwm_rx_radiotap_header *tap = &sc->sc_rxtap;
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
        if (rate_n_flags & IWM_RATE_MCS_HT_MSK) {
            uint8_t mcs = (rate_n_flags &
                           (IWM_RATE_HT_MCS_RATE_CODE_MSK |
                            IWM_RATE_HT_MCS_NSS_MSK));
            tap->wr_rate = (0x80 | mcs);
        } else {
            uint8_t rate = (rate_n_flags &
                            IWM_RATE_LEGACY_RATE_MSK);
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

#define IWM_AGG_TX_STATE_(x) case IWM_AGG_TX_STATE_ ## x: return #x
static const char *iwm_get_agg_tx_status(u16 status)
{
    switch (status & IWM_AGG_TX_STATE_STATUS_MSK) {
    IWM_AGG_TX_STATE_(TRANSMITTED);
    IWM_AGG_TX_STATE_(UNDERRUN);
    IWM_AGG_TX_STATE_(BT_PRIO);
    IWM_AGG_TX_STATE_(FEW_BYTES);
    IWM_AGG_TX_STATE_(ABORT);
    IWM_AGG_TX_STATE_(TX_ON_AIR_DROP);
    IWM_AGG_TX_STATE_(LAST_SENT_TRY_CNT);
    IWM_AGG_TX_STATE_(LAST_SENT_BT_KILL);
    IWM_AGG_TX_STATE_(SCD_QUERY);
    IWM_AGG_TX_STATE_(TEST_BAD_CRC32);
    IWM_AGG_TX_STATE_(RESPONSE);
    IWM_AGG_TX_STATE_(DUMP_TX);
    IWM_AGG_TX_STATE_(DELAY_TX);
    }

    return "UNKNOWN";
}

#define IEEE80211_TX_MAX_RATES    4

static int ieee80211_tx_get_rates(struct iwm_softc *sc,
                  struct ieee80211_tx_info *info,
                  int *retry_count)
{
    int count = -1;
    int i;
    int max_report_rates = 1;

    for (i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
        if ((info->flags & IEEE80211_TX_CTL_AMPDU) &&
            !(info->flags & IEEE80211_TX_STAT_AMPDU)) {
            /* just the first aggr frame carry status info */
            info->status.rates[i].idx = -1;
            info->status.rates[i].count = 0;
            break;
        } else if (info->status.rates[i].idx < 0) {
            break;
        } else if (i >= max_report_rates) {
            /* the HW cannot have attempted that rate */
            info->status.rates[i].idx = -1;
            info->status.rates[i].count = 0;
            break;
        }

        count += info->status.rates[i].count;
    }

    if (count < 0)
        count = 0;

    *retry_count = count;
    return i - 1;
}

void ieee80211_tx_status(struct iwm_softc *sc, struct ieee80211_tx_info *info, int tid, uint16_t fc, int ssn)
{
    struct _ifnet *ifp = &sc->sc_ic.ic_ac.ac_if;
    int rates_idx, retry_count;
    
    if (!info)
        return;
    
    rates_idx = ieee80211_tx_get_rates(sc, info, &retry_count);
    
    rs_drv_mac80211_tx_status(sc, sc->sc_ic.ic_bss, info, tid, fc, ssn);
    if (!(info->flags & IEEE80211_TX_CTL_HW_80211_ENCAP) &&
        (info->flags & IEEE80211_TX_STAT_AMPDU_NO_BACK) &&
        (ieee80211_is_data_qos(fc)))
        ifp->netStat->outputErrors++;
}

void ItlIwm::
iwm_ampdu_txq_advance(struct iwm_softc *sc, struct iwm_tx_ring *ring, int idx)
{
    struct iwm_tx_data *txd;

    while (ring->tail != idx) {
        txd = &ring->data[ring->tail];
        if (txd->m != NULL) {
            if (ring->qid < IWM_FIRST_AGG_TX_QUEUE)
                DPRINTF(("%s: missed Tx completion: tail=%d "
                         "idx=%d\n", __func__, ring->tail, idx));
            iwm_reset_sched(sc, ring->qid, ring->tail, IWM_STATION_ID);
            iwm_txd_done(sc, txd);
            ring->queued--;
        }
        ring->tail = (ring->tail + 1) % IWM_TX_RING_COUNT;
    }
}

void ItlIwm::
iwm_ampdu_rate_control(struct iwm_softc *sc, struct ieee80211_node *ni,
    struct iwm_tx_ring *ring, uint16_t seq, uint16_t ssn, struct ieee80211_tx_info *tx_info, int tid, uint32_t rate_n_flags)
{
    int idx, end_idx;
    struct iwm_tx_ba *tid_data = &sc->sc_tx_ba[tid];
    int freed = 0;
    bool rs_update = false;

    /* pack lq color from tid_data along the reduced txp */
    tx_info->status.status_driver_data[0] =
        RS_DRV_DATA_PACK(tid_data->lq_color,
                 tx_info->status.status_driver_data[0]);
    tx_info->status.status_driver_data[1] = (void *)(uintptr_t)rate_n_flags;
    /*
    * Update Tx rate statistics for A-MPDUs before firmware's BA window.
    */
    idx = IWM_AGG_SSN_TO_TXQ_IDX(seq);
    end_idx = IWM_AGG_SSN_TO_TXQ_IDX(ssn);
    while (idx != end_idx) {
        struct iwm_tx_data *txdata = &ring->data[idx];
        struct ieee80211_tx_info *info = &txdata->info;

        if (txdata->m != NULL) {
            rs_update = true;
            
            memset(&info->status, 0, sizeof(info->status));
            /* Packet was transmitted successfully, failures come as single
             * frames because before failing a frame the firmware transmits
             * it without aggregation at least once.
             */
            info->flags |= IEEE80211_TX_STAT_ACK;
            
            if (ieee80211_is_data_qos(txdata->fc))
                freed++;
            else
                WARN_ON_ONCE(tid != IWL_MAX_TID_COUNT);
            
            /* this is the first skb we deliver in this batch */
            /* put the rate scaling data there */
            if (freed == 1) {
                info->flags |= IEEE80211_TX_STAT_AMPDU;
                memcpy(&info->status, &tx_info->status,
                       sizeof(tx_info->status));
                iwl_mvm_hwrate_to_tx_status(rate_n_flags, info);
            }
            
            ieee80211_tx_status(sc, info, tid, txdata->fc, ssn);
        }

        idx = (idx + 1) % IWM_TX_RING_COUNT;
    }
    
    /* We got a BA notif with 0 acked or scd_ssn didn't progress which is
     * possible (i.e. first MPDU in the aggregation wasn't acked)
     * Still it's important to update RS about sent vs. acked.
     */
    if (!rs_update) {
        tx_info->band = IEEE80211_IS_CHAN_2GHZ(sc->sc_ic.ic_bss->ni_chan) ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ;
        iwl_mvm_hwrate_to_tx_status(rate_n_flags, tx_info);
        DPRINTFN(3, ("No reclaim. Update rs directly\n"));
        iwl_mvm_rs_tx_status(sc, sc->sc_ic.ic_bss, tid, tx_info, false);
    }
}

void ItlIwm::
iwm_rx_tx_ba_notif(struct iwm_softc *sc, struct iwm_rx_packet *pkt, struct iwm_rx_data *data)
{
    struct ieee80211_tx_ba *ba;
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_ba_notif *ba_notif = (struct iwm_ba_notif *)pkt->data;
    struct iwm_tx_ring *ring;
    uint16_t ssn;
    int qid;
    struct ieee80211_node *ni = ic->ic_bss;
    struct iwm_node *in = (struct iwm_node *)ni;
    struct iwm_tx_ba *tid_data;
    struct ieee80211_tx_info ba_info = {};
    
    DPRINTFN(3, ("TID = %d, SeqCtl = %d, bitmap = 0x%llx, scd_flow = %d, scd_ssn = %d sent:%d, acked:%d\n",
                 ba_notif->tid, le16_to_cpu(ba_notif->seq_ctl),
                 le64_to_cpu(ba_notif->bitmap), le16_to_cpu(ba_notif->scd_flow), le16_to_cpu(ba_notif->scd_ssn),
                 ba_notif->txed, ba_notif->txed_2_done));
    
    if (ic->ic_state != IEEE80211_S_RUN)
        return;
    
    if (iwm_rx_packet_payload_len(pkt) < sizeof(*ba_notif))
        return;
    
    if (ba_notif->sta_id != IWM_STATION_ID ||
        !IEEE80211_ADDR_EQ(in->in_macaddr, ba_notif->sta_addr))
        return;
    
    qid = le16toh(ba_notif->scd_flow);
    if (qid < IWM_FIRST_AGG_TX_QUEUE || qid > IWM_LAST_AGG_TX_QUEUE)
        return;
    
    /* Protect against a firmware bug where the queue/TID are off. */
    if (qid != IWM_FIRST_AGG_TX_QUEUE + ba_notif->tid)
        return;
    
    sc->sc_tx_timer[qid] = 0;
    
    ba = &ni->ni_tx_ba[ba_notif->tid];
    if (ba->ba_state != IEEE80211_BA_AGREED)
        return;
    
    ring = &sc->txq[qid];
    
    /*
     * The firmware's new BA window starting sequence number
     * corresponds to the first hole in ban->scd_ssn, implying
     * that all frames between 'seq' and 'ssn' (non-inclusive)
     * have been acked.
     */
    ssn = le16toh(ba_notif->scd_ssn);
    
    /* pack lq color from tid_data along the reduced txp */
    tid_data = &sc->sc_tx_ba[ba_notif->tid];
    
    ba_info.flags = IEEE80211_TX_STAT_AMPDU;
    ba_info.status.ampdu_ack_len = ba_notif->txed_2_done;
    ba_info.status.ampdu_len = ba_notif->txed;
    ba_info.status.tx_time = tid_data->tx_time;
    ba_info.status.status_driver_data[0] =
        (void *)(uintptr_t)ba_notif->reduced_txp;
    
    if (SEQ_LT(ssn, ba->ba_winstart))
        return;

    /* Skip rate control if our Tx rate is fixed. */
    if (ic->ic_fixed_mcs == -1)
        iwm_ampdu_rate_control(sc, ni, ring,
                               ba->ba_winstart, ssn, &ba_info, ba_notif->tid, tid_data->rate_n_flags);
    
    /*
     * SSN corresponds to the first (perhaps not yet transmitted) frame
     * in firmware's BA window. Firmware is not going to retransmit any
     * frames before its BA window so mark them all as done.
     */
    ieee80211_output_ba_move_window(ic, ni, ba_notif->tid, ssn);
    iwm_ampdu_txq_advance(sc, ring, IWM_AGG_SSN_TO_TXQ_IDX(ssn));
    iwm_clear_oactive(sc, ring);
}

void ItlIwm::
iwm_ampdu_tx_done(struct iwm_softc *sc, struct iwm_cmd_header *cmd_hdr,
    struct iwm_node *in, struct iwm_tx_ring *txq, uint32_t initial_rate,
    uint8_t nframes, uint8_t failure_frame, uint16_t ssn, int status,
    struct iwm_agg_tx_status *agg_status)
{
    struct ieee80211com *ic = &sc->sc_ic;
    int tid = cmd_hdr->qid - IWM_FIRST_AGG_TX_QUEUE;
    struct iwm_tx_data *txdata = &txq->data[cmd_hdr->idx];
    struct ieee80211_node *ni = &in->in_ni;
    int txfail = (status != IWM_TX_STATUS_SUCCESS &&
                  status != IWM_TX_STATUS_DIRECT_DONE);
    struct ieee80211_tx_ba *ba;
    
    if (ic->ic_state != IEEE80211_S_RUN)
        return;
    
    if (nframes > 1) {
        return;
    }
    
    if (ni == NULL)
        return;
    
    ba = &ni->ni_tx_ba[tid];
    if (ba->ba_state != IEEE80211_BA_AGREED)
        return;
    if (SEQ_LT(ssn, ba->ba_winstart))
        return;
    
    /* This is a final single-frame Tx attempt. */
    DPRINTFN(3, ("%s: final tx status=0x%x qid=%d queued=%d idx=%d ssn=%u "
                 "bitmap=0x%llx\n", __func__, status, cmd_hdr->qid, txq->queued,
                 cmd_hdr->idx, ssn, ba->ba_bitmap));
    
    if (txfail) {
        ieee80211_tx_compressed_bar(ic, ni, tid, ssn);
        XYLog("%s sending bar ssn=%d tid=%d\n", __FUNCTION__, ssn, tid);
    }
    
    /*
     * SSN corresponds to the first (perhaps not yet transmitted) frame
     * in firmware's BA window. Firmware is not going to retransmit any
     * frames before its BA window so mark them all as done.
     */
    ieee80211_output_ba_move_window(ic, ni, tid, ssn);
}

#define IWL_MVM_TX_RES_GET_TID(_ra_tid) ((_ra_tid) & 0x0f)
#define TX_RES_INIT_RATE_INDEX_MSK 0x0f
#define TX_RES_RATE_TABLE_COLOR_POS 4
#define TX_RES_RATE_TABLE_COLOR_MSK 0x70
#define TX_RES_INV_RATE_INDEX_MSK 0x80
#define TX_RES_RATE_TABLE_COL_GET(_f) (((_f) & TX_RES_RATE_TABLE_COLOR_MSK) >>\
                       TX_RES_RATE_TABLE_COLOR_POS)

static inline struct iwm_agg_tx_status *
iwl_mvm_get_agg_status(struct iwm_softc *sc, void *tx_resp)
{
    return (struct iwm_agg_tx_status *)(((struct iwm_tx_resp *)tx_resp)->status);
}

static inline u32 iwl_mvm_get_scd_ssn(struct iwm_softc *sc,
                      struct iwm_tx_resp *tx_resp)
{
    return le32_to_cpup((__le32 *)iwl_mvm_get_agg_status(sc, tx_resp) +
                tx_resp->frame_count) & 0xfff;
}

void ItlIwm::
iwm_rx_tx_cmd_single(struct iwm_softc *sc, struct iwm_tx_resp *tx_resp,
                     int qid, int idx)
{
    u32 status = le16toh(iwl_mvm_get_agg_status(sc, tx_resp)->status);
    u16 ssn = iwl_mvm_get_scd_ssn(sc, tx_resp);
    int tid = IWL_MVM_TX_RES_GET_TID(tx_resp->ra_tid);
    struct iwm_tx_data *txd;
    struct iwm_tx_ring *ring = &sc->txq[qid];
    u8 skb_freed = 0;
    u8 lq_color;
    
    while (ring->tail != idx) {
        txd = &ring->data[ring->tail];
        struct ieee80211_tx_info *info = &txd->info;
        bool flushed = false;
        if (txd->m != NULL) {
            skb_freed++;

            memset(&info->status, 0, sizeof(info->status));
            info->flags &= ~(IEEE80211_TX_STAT_ACK | IEEE80211_TX_STAT_TX_FILTERED);

            /* inform mac80211 about what happened with the frame */
            switch (status & IWM_TX_STATUS_MSK) {
            case IWM_TX_STATUS_SUCCESS:
            case IWM_TX_STATUS_DIRECT_DONE:
                info->flags |= IEEE80211_TX_STAT_ACK;
                break;
            case IWM_TX_STATUS_FAIL_FIFO_FLUSHED:
            case IWM_TX_STATUS_FAIL_DRAIN_FLOW:
                flushed = true;
                break;
            case IWM_TX_STATUS_FAIL_DEST_PS:
                /* the FW should have stopped the queue and not
                 * return this status
                 */
                WARN_ON(1);
                info->flags |= IEEE80211_TX_STAT_TX_FILTERED;
                break;
            default:
                break;
            }

            if ((status & IWM_TX_STATUS_MSK) != IWM_TX_STATUS_SUCCESS &&
                ieee80211_is_mgmt(txd->fc))
                iwm_toggle_tx_ant(sc, &sc->sc_mgmt_last_antenna_idx);
            
            if ((status & IWM_TX_STATUS_MSK) != IWM_TX_STATUS_SUCCESS &&
                sc->sc_ic.ic_state <= IEEE80211_S_RUN)
                iwm_toggle_tx_ant(sc, &sc->sc_tx_ant);
                

            /*
             * If we are freeing multiple frames, mark all the frames
             * but the first one as acked, since they were acknowledged
             * before
             * */
            if (skb_freed > 1)
                info->flags |= IEEE80211_TX_STAT_ACK;

            info->status.rates[0].count = tx_resp->failure_frame + 1;
            iwl_mvm_hwrate_to_tx_status(le32_to_cpu(tx_resp->initial_rate),
                            info);
            info->status.status_driver_data[1] =
            (void *)(uintptr_t)le32_to_cpu(tx_resp->initial_rate);

            /* Single frame failure in an AMPDU queue => send BAR */
            if (info->flags & IEEE80211_TX_CTL_AMPDU &&
                !(info->flags & IEEE80211_TX_STAT_ACK) &&
                !(info->flags & IEEE80211_TX_STAT_TX_FILTERED) && !flushed)
                info->flags |= IEEE80211_TX_STAT_AMPDU_NO_BACK;
            info->flags &= ~IEEE80211_TX_CTL_AMPDU;

            /*
             * TODO: this is not accurate if we are freeing more than one
             * packet.
             */
            info->status.tx_time =
                le16_to_cpu(tx_resp->wireless_media_time);
            BUILD_BUG_ON(ARRAY_SIZE(info->status.status_driver_data) < 1);
            lq_color = TX_RES_RATE_TABLE_COL_GET(tx_resp->tlc_info);
            info->status.status_driver_data[0] =
                RS_DRV_DATA_PACK(lq_color, tx_resp->reduced_tpc);

            ieee80211_tx_status(sc, info, tid, txd->fc, ssn);

            iwm_reset_sched(sc, ring->qid, ring->tail, IWM_STATION_ID);
            iwm_txd_done(sc, txd);
            ring->queued--;
        }
        ring->tail = (ring->tail + 1) % IWM_TX_RING_COUNT;
    }
}

void ItlIwm::
iwm_txd_done(struct iwm_softc *sc, struct iwm_tx_data *txd)
{
    struct ieee80211com *ic = &sc->sc_ic;
    
    //    bus_dmamap_sync(sc->sc_dmat, txd->map, 0, txd->map->dm_mapsize,
    //        BUS_DMASYNC_POSTWRITE);
    //    bus_dmamap_unload(sc->sc_dmat, txd->map);
    if (txd->m) {
        mbuf_freem(txd->m);
        txd->m = NULL;
    }
    
    KASSERT(txd->in, "txd->in");
    ieee80211_release_node(ic, &txd->in->in_ni);
    txd->in = NULL;
    txd->totlen = 0;
    txd->txmcs = 0;
    txd->txrate = 0;
    txd->fc = 0;
    memset(&txd->info, 0, sizeof(struct ieee80211_tx_info));
}

void ItlIwm::
iwm_clear_oactive(struct iwm_softc *sc, struct iwm_tx_ring *ring)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = &ic->ic_if;

    if (ring->queued < IWM_TX_RING_LOMARK) {
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

#define TX_RES_INIT_RATE_INDEX_MSK 0x0f
#define TX_RES_RATE_TABLE_COLOR_POS 4
#define TX_RES_RATE_TABLE_COLOR_MSK 0x70
#define TX_RES_INV_RATE_INDEX_MSK 0x80
#define TX_RES_RATE_TABLE_COL_GET(_f) (((_f) & TX_RES_RATE_TABLE_COLOR_MSK) >>\
                       TX_RES_RATE_TABLE_COLOR_POS)

void ItlIwm::
iwm_rx_tx_cmd(struct iwm_softc *sc, struct iwm_rx_packet *pkt,
              struct iwm_rx_data *data)
{
    struct iwm_cmd_header *cmd_hdr = &pkt->hdr;
    int idx = cmd_hdr->idx;
    int qid = cmd_hdr->qid;
    struct iwm_tx_ring *ring;
    struct iwm_tx_data *txd;
    struct iwm_tx_resp *tx_resp = (struct iwm_tx_resp *)pkt->data;
    uint32_t ssn;
    uint32_t len = iwm_rx_packet_len(pkt);
    struct iwm_tx_ba *tid_data;
    
    bus_dmamap_sync(sc->sc_dmat, data->map, 0, IWM_RBUF_SIZE,
                    BUS_DMASYNC_POSTREAD);
    
    /* Sanity checks. */
    if (sizeof(*tx_resp) > len)
        return;
    if (qid < IWM_FIRST_AGG_TX_QUEUE && tx_resp->frame_count > 1)
        return;
    if (qid > IWM_LAST_AGG_TX_QUEUE)
        return;
    if (sizeof(*tx_resp) + sizeof(ssn) +
        tx_resp->frame_count * sizeof(struct iwm_agg_tx_status) > len)
        return;
    
    sc->sc_tx_timer[qid] = 0;
    
    ring = &sc->txq[qid];
    txd = &ring->data[idx];
    
    if (tx_resp->frame_count > 1) {
        for (int i = 0; i < tx_resp->frame_count; i++) {
            struct iwm_agg_tx_status *frame_status = iwl_mvm_get_agg_status(sc, tx_resp);
            u16 fstatus = le16_to_cpu(frame_status[i].status);

            DPRINTFN(3, ("status %s (0x%04x), try-count (%d) qid (%d) seq (0x%x)\n",
                         iwm_get_agg_tx_status(fstatus),
                         fstatus & IWM_AGG_TX_STATE_STATUS_MSK,
                         (fstatus & IWM_AGG_TX_STATE_TRY_CNT_MSK) >>
                         IWM_AGG_TX_STATE_TRY_CNT_POS,
                         qid,
                         le16_to_cpu(frame_status[i].idx)));
        }
        int tid = cmd_hdr->qid - IWM_FIRST_AGG_TX_QUEUE;
        if (tid < 0)
            return;
        tid_data = &sc->sc_tx_ba[tid];
        tid_data->lq_color = TX_RES_RATE_TABLE_COL_GET(tx_resp->tlc_info);
        tid_data->tx_time = le16toh(tx_resp->wireless_media_time);
        tid_data->rate_n_flags = le32toh(tx_resp->initial_rate);
        return;
    }
    
    DPRINTFN(2, ("%s idx=%d qid=%d txd->txmcs=%d txd->txrate=%d, frame_count=%d len=%d\n", __FUNCTION__, idx, qid, txd->txmcs, txd->txrate, ((struct           iwm_tx_resp *)pkt->data)->frame_count, ((struct iwm_tx_resp *)pkt->data)->byte_cnt));

    ssn = iwm_get_scd_ssn(tx_resp);
    iwm_rx_tx_cmd_single(sc, tx_resp, qid, IWM_AGG_SSN_TO_TXQ_IDX(ssn));
    if (qid >= IWM_FIRST_AGG_TX_QUEUE) {
        int status;
        
        status = le16toh(iwl_mvm_get_agg_status(sc, tx_resp)->status) & IWM_TX_STATUS_MSK;
        iwm_ampdu_tx_done(sc, cmd_hdr, txd->in, ring,
                          le32toh(tx_resp->initial_rate), tx_resp->frame_count,
                          tx_resp->failure_frame, ssn, status, iwl_mvm_get_agg_status(sc, tx_resp));
    }

    iwm_clear_oactive(sc, ring);
}

void ItlIwm::
iwm_rx_bmiss(struct iwm_softc *sc, struct iwm_rx_packet *pkt,
             struct iwm_rx_data *data)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_missed_beacons_notif *mbn = (struct iwm_missed_beacons_notif *)pkt->data;
    uint32_t missed;
    
    if ((ic->ic_opmode != IEEE80211_M_STA) ||
        (ic->ic_state != IEEE80211_S_RUN))
        return;
    
    //        bus_dmamap_sync(sc->sc_dmat, data->map, sizeof(*pkt),
    //            sizeof(*mbn), BUS_DMASYNC_POSTREAD);
    
    missed = le32toh(mbn->consec_missed_beacons_since_last_rx);
    if (missed > ic->ic_bmissthres && ic->ic_mgt_timer == 0) {
        if (ic->ic_if.if_flags & IFF_DEBUG)
            XYLog("%s: receiving no beacons from %s; checking if "
                  "this AP is still responding to probe requests\n",
                  DEVNAME(sc), ether_sprintf(ic->ic_bss->ni_macaddr));
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

static int
iwm_rate2ridx(struct iwm_softc *sc, int rate)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    int ridx = -1, i;
    
    int min_ridx = (IEEE80211_IS_CHAN_5GHZ(ni->ni_chan)) ?
        IWL_FIRST_OFDM_RATE : IWL_FIRST_CCK_RATE;
    
    for (i = 0; i < ieee80211_std_rateset_11g.rs_nrates; i++) {
        if (ieee80211_std_rateset_11g.rs_rates[i] == rate) {
            ridx = i;
            break;
        }
    }
    return ridx == -1 ? min_ridx : ridx;
}

/*
 * Fill in various bit for management frames, and leave them
 * unfilled for data frames (firmware takes care of that).
 * Return the selected TX rate.
 */
const struct iwl_rs_rate_info *ItlIwm::
iwm_tx_fill_cmd(struct iwm_softc *sc, struct iwm_node *in,
                struct ieee80211_frame *wh, struct iwm_tx_cmd *tx)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    int type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    int subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    int ridx = -1, rate_flags;
    int min_ridx = iwm_rate2ridx(sc, ieee80211_min_basic_rate(ic));
    
    tx->rts_retry_limit = IWM_RTS_DFAULT_RETRY_LIMIT;
    
    if (type == IEEE80211_FC0_TYPE_CTL &&
        subtype == IEEE80211_FC0_SUBTYPE_BAR)
        tx->data_retry_limit = IWM_BAR_DFAULT_RETRY_LIMIT;
    else
        tx->data_retry_limit = IWM_DEFAULT_TX_RETRY;
    
    if (IEEE80211_IS_MULTICAST(wh->i_addr1) ||
        type != IEEE80211_FC0_TYPE_DATA) {
        /* for non-data, use the lowest supported rate */
        ridx = min_ridx;
        tx->data_retry_limit = IWM_MGMT_DFAULT_RETRY_LIMIT;
    } else if (ic->ic_fixed_mcs != -1) {
        if (ni->ni_flags & IEEE80211_NODE_VHT)
            ridx = IWL_FIRST_OFDM_RATE;
        else
            ridx = sc->sc_fixed_ridx;
    } else if (ic->ic_fixed_rate != -1) {
        ridx = sc->sc_fixed_ridx;
     } else {
        /* Use firmware rateset retry table. */
        tx->initial_rate_index = 0;
        tx->tx_flags |= htole32(IWM_TX_CMD_FLG_STA_RATE);
        if (ni->ni_flags & IEEE80211_NODE_HT) /* VHT implies HT */
            return 0;
        return &iwl_rates[iwm_rate2ridx(sc, ni->ni_txrate)];
    }
    
    if (ridx == -1 || ridx >= IWL_RATE_COUNT_LEGACY)
        ridx = min_ridx;
    
    rate_flags = iwm_get_tx_ant(sc, ni, type, wh);
    XYLog("%s ridx=%d ant=%d\n", __FUNCTION__, ridx, (rate_flags >> RATE_MCS_ANT_POS));
    /* Set CCK flag as needed */
    if ((ridx >= IWL_FIRST_CCK_RATE) && (ridx <= IWL_LAST_CCK_RATE))
        rate_flags |= RATE_MCS_CCK_MSK;
    tx->rate_n_flags = htole32(rate_flags | iwl_mvm_mac80211_idx_to_hwrate(ridx));

    return &iwl_rates[ridx];
}

#define TB0_SIZE 20
int ItlIwm::
iwm_tx(struct iwm_softc *sc, mbuf_t m, struct ieee80211_node *ni, int ac)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ni;
    struct iwm_tx_ring *ring;
    struct iwm_tx_data *data;
    struct iwm_tfd *desc;
    struct iwm_device_cmd *cmd;
    struct iwm_tx_cmd *tx;
    struct ieee80211_frame *wh;
    struct ieee80211_key *k = NULL;
    const struct iwl_rs_rate_info *rinfo;
    uint8_t *ivp;
    uint32_t flags;
    u_int hdrlen;
    IOPhysicalSegment *seg;
    IOPhysicalSegment segs[IWM_NUM_OF_TBS - 2];
    int nsegs = 0;
    uint8_t tid, type, subtype;
    int i, totlen, hasqos;
    int rtsthres = ic->ic_rtsthreshold;
    int qid;
    uint16_t len, tb1_len;
    
    wh = mtod(m, struct ieee80211_frame *);
    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    
    if (type == IEEE80211_FC0_TYPE_CTL)
        hdrlen = sizeof(struct ieee80211_frame_min);
    else
        hdrlen = ieee80211_get_hdrlen(wh);
    
    hasqos = ieee80211_has_qos(wh);
    if (type == IEEE80211_FC0_TYPE_DATA)
        tid = IWM_TID_NON_QOS;
    else
        tid = IWM_MAX_TID_COUNT;
    
    /*
     * Map EDCA categories to Tx data queues.
     *
     * We use static data queue assignments even in DQA mode. We do not
     * need to share Tx queues between stations because we only implement
     * client mode; the firmware's station table contains only one entry
     * which represents our access point.
     */
    if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DQA_SUPPORT))
        qid = IWM_DQA_MIN_MGMT_QUEUE + ac;
    else
        qid = ac;
    
    if (hasqos) {
        struct ieee80211_tx_ba *ba;
        uint16_t qos = ieee80211_get_qos(wh);
        int qostid = qos & IEEE80211_QOS_TID;
        int agg_qid = IWM_FIRST_AGG_TX_QUEUE + qostid;
        
        ba = &ni->ni_tx_ba[qostid];
        if (!IEEE80211_IS_MULTICAST(wh->i_addr1) &&
            type == IEEE80211_FC0_TYPE_DATA &&
            subtype != IEEE80211_FC0_SUBTYPE_NODATA &&
            sc->sc_tx_ba[tid].wn == in &&
            ba->ba_state == IEEE80211_BA_AGREED) {
            qid = agg_qid;
            tid = qostid;
            ac = ieee80211_up_to_ac(ic, qostid);
        }
    }
    
    ring = &sc->txq[qid];
    desc = &ring->desc[ring->cur];
    memset(desc, 0, sizeof(*desc));
    data = &ring->data[ring->cur];
    
    cmd = &ring->cmd[ring->cur];
    cmd->hdr.code = IWM_TX_CMD;
    cmd->hdr.flags = 0;
    cmd->hdr.qid = ring->qid;
    cmd->hdr.idx = ring->cur;
    
    tx = (struct iwm_tx_cmd *)cmd->data;
    memset(tx, 0, sizeof(*tx));
    
    rinfo = iwm_tx_fill_cmd(sc, in, wh, tx);
    
#if NBPFILTER > 0
    if (sc->sc_drvbpf != NULL) {
        struct iwm_tx_radiotap_header *tap = &sc->sc_txtap;
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
            rinfo->ht_plcp != IWM_RATE_HT_SISO_MCS_INV_PLCP) {
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
    totlen = mbuf_pkthdr_len(m);
    
    if (wh->i_fc[1] & IEEE80211_FC1_PROTECTED) {
        k = ieee80211_get_txkey(ic, wh, ni);
        if ((k->k_flags & IEEE80211_KEY_GROUP) ||
            (k->k_cipher != IEEE80211_CIPHER_CCMP)) {
            if ((m = ieee80211_encrypt(ic, m, k)) == NULL)
                return ENOBUFS;
            /* 802.11 header may have moved. */
            wh = mtod(m, struct ieee80211_frame *);
            totlen = mbuf_pkthdr_len(m);
            k = NULL; /* skip hardware crypto below */
        } else {
            /* HW appends CCMP MIC */
            totlen += IEEE80211_CCMP_HDRLEN;
        }
    }
    
    flags = 0;
    if (!IEEE80211_IS_MULTICAST(wh->i_addr1))
        flags |= IWM_TX_CMD_FLG_ACK;
    
    if (type == IEEE80211_FC0_TYPE_DATA &&
        !IEEE80211_IS_MULTICAST(wh->i_addr1) &&
        (totlen + IEEE80211_CRC_LEN > rtsthres ||
         (ic->ic_flags & IEEE80211_F_USEPROT)))
        flags |= IWM_TX_CMD_FLG_PROT_REQUIRE;

    if (type == IEEE80211_FC0_TYPE_CTL &&
        subtype == IEEE80211_FC0_SUBTYPE_BAR) {
        struct ieee80211_frame_min *mwh;
        uint8_t *barfrm;
        uint16_t ctl;
        mwh = mtod(m, struct ieee80211_frame_min *);
        barfrm = (uint8_t *)&mwh[1];
        ctl = LE_READ_2(barfrm);
        tid = (ctl & IEEE80211_BA_TID_INFO_MASK) >>
            IEEE80211_BA_TID_INFO_SHIFT;
        flags |= (IWM_TX_CMD_FLG_ACK | IWM_TX_CMD_FLG_BAR);
    }
    
    tx->sta_id = IWM_STATION_ID;
    
    if (type == IEEE80211_FC0_TYPE_MGT) {
        if (subtype == IEEE80211_FC0_SUBTYPE_ASSOC_REQ ||
            subtype == IEEE80211_FC0_SUBTYPE_REASSOC_REQ)
            tx->pm_frame_timeout = htole16(3);
        else if (subtype == IEEE80211_FC0_SUBTYPE_ACTION)
            tx->pm_frame_timeout = htole16(0);
        else
            tx->pm_frame_timeout = htole16(2);
    } else {
        tx->pm_frame_timeout = htole16(0);
    }
    
    len = sizeof(struct iwm_tx_cmd) + sizeof(struct iwm_cmd_header) + hdrlen - TB0_SIZE;
    
    tb1_len = _ALIGN(len, 4);
    /* Tell NIC about any 2-byte padding after MAC header */
    if (tb1_len != len) {
        flags |= IWM_TX_CMD_FLG_MH_PAD;
        tx->offload_assist |= htole16(IWM_TX_CMD_OFFLD_PAD);
    }
    
    tx->driver_txop = 0;
    
    tx->len = htole16(totlen);
    tx->tid_tspec = tid;
    tx->life_time = htole32(IWM_TX_CMD_LIFE_TIME_INFINITE);
    
    /* Set physical address of "scratch area". */
    tx->dram_lsb_ptr = htole32(data->scratch_paddr);
    tx->dram_msb_ptr = iwm_get_dma_hi_addr(data->scratch_paddr);
    
    /* Copy 802.11 header in TX command. */
    memcpy(((uint8_t *)tx) + sizeof(*tx), wh, hdrlen);
    
    if  (k != NULL && k->k_cipher == IEEE80211_CIPHER_CCMP) {
        /* Trim 802.11 header and prepend CCMP IV. */
        mbuf_adj(m, hdrlen - IEEE80211_CCMP_HDRLEN);
        ivp = mtod(m, u_int8_t *);
        k->k_tsc++;    /* increment the 48-bit PN */
        ivp[0] = k->k_tsc; /* PN0 */
        ivp[1] = k->k_tsc >> 8; /* PN1 */
        ivp[2] = 0;        /* Rsvd */
        ivp[3] = k->k_id << 6 | IEEE80211_WEP_EXTIV;
        ivp[4] = k->k_tsc >> 16; /* PN2 */
        ivp[5] = k->k_tsc >> 24; /* PN3 */
        ivp[6] = k->k_tsc >> 32; /* PN4 */
        ivp[7] = k->k_tsc >> 40; /* PN5 */
        
        tx->sec_ctl = IWM_TX_CMD_SEC_CCM;
        memcpy(tx->key, k->k_key, MIN(sizeof(tx->key), k->k_len));
    } else {
        /* Trim 802.11 header. */
        mbuf_adj(m, hdrlen);
        tx->sec_ctl = 0;
    }
    
    flags |= (iwm_coex_tx_prio(sc, wh, ac) << IWM_TX_CMD_FLG_BT_PRIO_POS);
    if (!hasqos)
        flags |= IWM_TX_CMD_FLG_SEQ_CTL;
    
    tx->tx_flags |= htole32(flags);
    
    nsegs = data->map->cursor->getPhysicalSegmentsWithCoalesce(m, &segs[0], IWM_NUM_OF_TBS - 2);
    //    XYLog("map frame dm_nsegs=%d\n", data->map->dm_nsegs);
    if (nsegs == 0) {
        XYLog("%s: can't map mbuf (error %d)\n", DEVNAME(sc), data->map->dm_nsegs);
        mbuf_freem(m);
        return ENOMEM;
    }
    data->m = m;
    data->in = in;
    data->txmcs = ni->ni_txmcs;
    data->txrate = ni->ni_txrate;
    data->totlen = totlen;
    memcpy(&data->fc, &wh->i_fc[0], sizeof(uint16_t));
    data->info.band = IEEE80211_IS_CHAN_2GHZ(ni->ni_chan) ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ;
    
    DPRINTFN(3, ("sending data: 嘤嘤嘤 qid=%d idx=%d len=%d nsegs=%d txflags=0x%08x rate_n_flags=0x%08x rateidx=%u txmcs=%d ni_txrate=%d\n",
                 ring->qid, ring->cur, totlen, nsegs, le32toh(tx->tx_flags),
                 le32toh(tx->rate_n_flags), tx->initial_rate_index,
                 data->txmcs,
                 data->txrate));
    
    /* Fill TX descriptor. */
    desc->num_tbs = 2 + nsegs;
    
    desc->tbs[0].lo = htole32(data->cmd_paddr);
    desc->tbs[0].hi_n_len = htole16(iwm_get_dma_hi_addr(data->cmd_paddr) |
                                    (TB0_SIZE << 4));
    desc->tbs[1].lo = htole32(data->cmd_paddr + TB0_SIZE);
    desc->tbs[1].hi_n_len = htole16(iwm_get_dma_hi_addr(data->cmd_paddr) |
                                    (tb1_len << 4));
    
    /* Other DMA segments are for data payload. */
    for (i = 0; i < nsegs; i++) {
        seg = &segs[i];
        desc->tbs[i+2].lo = htole32(seg->location);
        desc->tbs[i+2].hi_n_len =
        htole16(iwm_get_dma_hi_addr(seg->location)
                | ((seg->length) << 4));
//        XYLog("DMA segments index=%d location=0x%llx length=%llu", i, seg->location, seg->length);
    }
//    XYLog("----------end sending data------\n");
    
    //        bus_dmamap_sync(sc->sc_dmat, data->map, 0, data->map->dm_mapsize,
    //            BUS_DMASYNC_PREWRITE);
    //        bus_dmamap_sync(sc->sc_dmat, ring->cmd_dma.map,
    //            (char *)(void *)cmd - (char *)(void *)ring->cmd_dma.vaddr,
    //            sizeof (*cmd), BUS_DMASYNC_PREWRITE);
    //        bus_dmamap_sync(sc->sc_dmat, ring->desc_dma.map,
    //            (char *)(void *)desc - (char *)(void *)ring->desc_dma.vaddr,
    //            sizeof (*desc), BUS_DMASYNC_PREWRITE);
    
    iwm_update_sched(sc, ring->qid, ring->cur, tx->sta_id, le16toh(tx->len));
    
    /* Kick TX ring. */
    ring->cur = (ring->cur + 1) % IWM_TX_RING_COUNT;
    IWM_WRITE(sc, IWM_HBUS_TARG_WRPTR, ring->qid << 8 | ring->cur);
    
    /* Mark TX ring as full if we reach a certain threshold. */
    if (++ring->queued > IWM_TX_RING_HIMARK) {
//        XYLog("%s qid=%d sc->qfullmsk is FULL ring->cur=%d ring->queued=%d\n", __FUNCTION__, ring->qid, ring->cur, ring->queued);
        sc->qfullmsk |= 1 << ring->qid;
    }
    
    if (ic->ic_if.if_flags & IFF_UP)
        sc->sc_tx_timer[ring->qid] = 15;
    
    return 0;
}

#define IWM_TX_CRC_SIZE 4
#define IWM_TX_DELIMITER_SIZE 4

void ItlIwm::
iwm_update_sched(struct iwm_softc *sc, int qid, int cur, uint8_t sta_id, uint16_t len)
{
    DPRINTFN(3, ("%s qid=%d cur=%d sta=%d len=%d\n", __FUNCTION__, qid, cur, sta_id, len));

    struct iwm_agn_scd_bc_tbl *scd_bc_tbl;
    uint8_t sec_ctl = 0;
    uint16_t bc_ent;
    struct iwm_tx_ring *txq = &sc->txq[qid];
    iwm_tx_cmd *tx = (struct iwm_tx_cmd *)txq->cmd;
    sec_ctl = tx->sec_ctl;

    scd_bc_tbl = (struct iwm_agn_scd_bc_tbl *)sc->sched_dma.vaddr;
    len += (IWM_TX_CRC_SIZE + IWM_TX_DELIMITER_SIZE);

    switch (sec_ctl & IWM_TX_CMD_SEC_MSK) {
    case IWM_TX_CMD_SEC_CCM:
        len += IEEE80211_CCMP_MICLEN;
        break;
    case IWM_TX_CMD_SEC_TKIP:
        len += IEEE80211_TKIP_ICVLEN;
        break;
    case IWM_TX_CMD_SEC_WEP:
        len += IEEE80211_WEP_IVLEN + IEEE80211_WEP_ICVLEN;
        break;
    }

    len = howmany(len, 4);
    bc_ent = htole16(len | (IWM_STATION_ID << 12));
    scd_bc_tbl[qid].tfd_offset[cur] = bc_ent;
    if (cur < IWM_TFD_QUEUE_SIZE_BC_DUP) {
        scd_bc_tbl[qid].tfd_offset[IWM_TFD_QUEUE_SIZE_MAX + cur] = bc_ent;
    }
}

void ItlIwm::
iwm_reset_sched(struct iwm_softc *sc, int qid, int idx, uint8_t sta_id)
{
    DPRINTFN(3, ("%s qid=%d idx=%d\n", __FUNCTION__, qid, idx));
    
    struct iwm_agn_scd_bc_tbl *scd_bc_tbl;
    uint16_t val;
    
    scd_bc_tbl = (struct iwm_agn_scd_bc_tbl *)sc->sched_dma.vaddr;
    
    val = htole16(1 | (sta_id << 12));
    
    /* Update TX scheduler. */
    scd_bc_tbl[qid].tfd_offset[idx] = val;
    if (idx < IWM_TFD_QUEUE_SIZE_BC_DUP)
        scd_bc_tbl[qid].tfd_offset[IWM_TFD_QUEUE_SIZE_MAX + idx] = val;
}

int ItlIwm::
iwm_flush_tx_path(struct iwm_softc *sc, int tfd_queue_msk)
{
    struct iwm_tx_path_flush_cmd_v1 flush_cmd = {
        .queues_ctl = htole32(tfd_queue_msk),
        .flush_ctl = htole16(IWM_DUMP_TX_FIFO_FLUSH),
    };
    int err;
    
    err = iwm_send_cmd_pdu(sc, IWM_TXPATH_FLUSH, 0,
                           sizeof(flush_cmd), &flush_cmd);
    if (err)
        XYLog("%s: Flushing tx queue failed: %d\n", DEVNAME(sc), err);
    return err;
}

static uint8_t iwm_mvm_mac80211_ac_to_ucode_ac(enum ieee80211_edca_ac ac)
{
   static const uint8_t mac80211_ac_to_ucode_ac[] = {
       IWM_AC_BE,
       IWM_AC_BK,
       IWM_AC_VI,
       IWM_AC_VO,
   };

   return mac80211_ac_to_ucode_ac[ac];
}

void ItlIwm::
iwm_mac_ctxt_cmd_common(struct iwm_softc *sc, struct iwm_node *in,
                        struct iwm_mac_ctx_cmd *cmd, uint32_t action)
{
#define IWM_EXP2(x)    ((1 << (x)) - 1)    /* CWmin = 2^ECWmin - 1 */
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    int cck_ack_rates, ofdm_ack_rates;
    int i;
    
    cmd->id_and_color = htole32(IWM_FW_CMD_ID_AND_COLOR(in->in_id,
                                                        in->in_color));
    cmd->action = htole32(action);
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR)
        cmd->mac_type = htole32(IWM_FW_MAC_TYPE_LISTENER);
    else if (ic->ic_opmode == IEEE80211_M_STA)
        cmd->mac_type = htole32(IWM_FW_MAC_TYPE_BSS_STA);
    else
        panic("unsupported operating mode %d\n", ic->ic_opmode);
    cmd->tsf_id = htole32(IWM_TSF_ID_A);
    
    IEEE80211_ADDR_COPY(cmd->node_addr, ic->ic_myaddr);
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        IEEE80211_ADDR_COPY(cmd->bssid_addr, etherbroadcastaddr);
        return;
    }
    
    IEEE80211_ADDR_COPY(cmd->bssid_addr, in->in_macaddr);
    iwm_ack_rates(sc, in, &cck_ack_rates, &ofdm_ack_rates);
    cmd->cck_rates = htole32(cck_ack_rates);
    cmd->ofdm_rates = htole32(ofdm_ack_rates);
    
    cmd->cck_short_preamble
    = htole32((ic->ic_flags & IEEE80211_F_SHPREAMBLE)
              ? IWM_MAC_FLG_SHORT_PREAMBLE : 0);
    cmd->short_slot
    = htole32((ic->ic_flags & IEEE80211_F_SHSLOT)
              ? IWM_MAC_FLG_SHORT_SLOT : 0);
    
    for (i = 0; i < EDCA_NUM_AC; i++) {
        struct ieee80211_edca_ac_params *ac = &ic->ic_edca_ac[i];
        int txf = iwm_ac_to_tx_fifo[i];
        uint8_t ucode_ac = iwm_mvm_mac80211_ac_to_ucode_ac((enum ieee80211_edca_ac)i);
        
        cmd->ac[ucode_ac].cw_min = htole16(IWM_EXP2(ac->ac_ecwmin));
        cmd->ac[ucode_ac].cw_max = htole16(IWM_EXP2(ac->ac_ecwmax));
        cmd->ac[ucode_ac].aifsn = ac->ac_aifsn;
        cmd->ac[ucode_ac].fifos_mask = (1 << txf);
        cmd->ac[ucode_ac].edca_txop = htole16(ac->ac_txoplimit * 32);
    }
    if (ni->ni_flags & IEEE80211_NODE_QOS)
        cmd->qos_flags |= htole32(IWM_MAC_QOS_FLG_UPDATE_EDCA);
    
    if (ni->ni_flags & IEEE80211_NODE_HT) {
        enum ieee80211_htprot htprot =
        (enum ieee80211_htprot)(ni->ni_htop1 & IEEE80211_HTOP1_PROT_MASK);
        
        /* The fw does not distinguish between ht and fat */
        uint32_t ht_flag = IWM_MAC_PROT_FLG_HT_PROT | IWM_MAC_PROT_FLG_FAT_PROT;
        
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
        
        cmd->qos_flags |= htole32(IWM_MAC_QOS_FLG_TGN);
    }
    if (ic->ic_flags & IEEE80211_F_USEPROT)
        cmd->protection_flags |= htole32(IWM_MAC_PROT_FLG_TGG_PROTECT);
    
    cmd->filter_flags = htole32(IWM_MAC_FILTER_ACCEPT_GRP);
#undef IWM_EXP2
}

void ItlIwm::
iwm_mac_ctxt_cmd_fill_sta(struct iwm_softc *sc, struct iwm_node *in,
                          struct iwm_mac_data_sta *sta, int assoc)
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
    sta->bi_reciprocal = htole32(iwm_reciprocal(ni->ni_intval));
    sta->dtim_interval = htole32(ni->ni_intval * ni->ni_dtimperiod);
    sta->dtim_reciprocal = htole32(iwm_reciprocal(sta->dtim_interval));
    sta->listen_interval = htole32(10);
    sta->assoc_id = htole32(ni->ni_associd);
    sta->assoc_beacon_arrive_time = htole32(ni->ni_rstamp);
}

int ItlIwm::
iwm_mac_ctxt_cmd(struct iwm_softc *sc, struct iwm_node *in, uint32_t action,
                 int assoc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    struct iwm_mac_ctx_cmd cmd;
    int active = (sc->sc_flags & IWM_FLAG_MAC_ACTIVE);
    
    if (action == IWM_FW_CTXT_ACTION_ADD && active) {
        XYLog("MAC already added");
        return 0;
    }
    if (action == IWM_FW_CTXT_ACTION_REMOVE && !active) {
        XYLog("MAC already removed");
        return 0;
    }
    
    memset(&cmd, 0, sizeof(cmd));
    
    iwm_mac_ctxt_cmd_common(sc, in, &cmd, action);
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        cmd.filter_flags |= htole32(IWM_MAC_FILTER_IN_PROMISC |
                                    IWM_MAC_FILTER_IN_CONTROL_AND_MGMT |
                                    IWM_MAC_FILTER_ACCEPT_GRP |
                                    IWM_MAC_FILTER_IN_BEACON |
                                    IWM_MAC_FILTER_IN_PROBE_REQUEST |
                                    IWM_MAC_FILTER_IN_CRC32);
    } else if (!assoc || !ni->ni_associd || !ni->ni_dtimperiod)
    /*
     * Allow beacons to pass through as long as we are not
     * associated or we do not have dtim period information.
     */
        cmd.filter_flags |= htole32(IWM_MAC_FILTER_IN_BEACON);
    else
        iwm_mac_ctxt_cmd_fill_sta(sc, in, &cmd.sta, assoc);
    
    return iwm_send_cmd_pdu(sc, IWM_MAC_CONTEXT_CMD, 0, sizeof(cmd), &cmd);
}

int ItlIwm::
iwm_update_quotas(struct iwm_softc *sc, struct iwm_node *in, int running)
{
    struct iwm_time_quota_cmd_v1 cmd;
    int i, idx, num_active_macs, quota, quota_rem;
    int colors[IWM_MAX_BINDINGS] = { -1, -1, -1, -1, };
    int n_ifs[IWM_MAX_BINDINGS] = {0, };
    uint16_t id;
    
    memset(&cmd, 0, sizeof(cmd));
    
    /* currently, PHY ID == binding ID */
    if (in && in->in_phyctxt) {
        id = in->in_phyctxt->id;
        KASSERT(id < IWM_MAX_BINDINGS, "id < IWM_MAX_BINDINGS");
        colors[id] = in->in_phyctxt->color;
        if (running)
            n_ifs[id] = 1;
    }
    
    /*
     * The FW's scheduling session consists of
     * IWM_MAX_QUOTA fragments. Divide these fragments
     * equally between all the bindings that require quota
     */
    num_active_macs = 0;
    for (i = 0; i < IWM_MAX_BINDINGS; i++) {
        cmd.quotas[i].id_and_color = htole32(IWM_FW_CTXT_INVALID);
        num_active_macs += n_ifs[i];
    }
    
    quota = 0;
    quota_rem = 0;
    if (num_active_macs) {
        quota = IWM_MAX_QUOTA / num_active_macs;
        quota_rem = IWM_MAX_QUOTA % num_active_macs;
    }
    
    for (idx = 0, i = 0; i < IWM_MAX_BINDINGS; i++) {
        if (colors[i] < 0)
            continue;
        
        cmd.quotas[idx].id_and_color =
        htole32(IWM_FW_CMD_ID_AND_COLOR(i, colors[i]));
        
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
    
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_QUOTA_LOW_LATENCY)) {
        struct iwm_time_quota_cmd cmd_v2;
        
        memset(&cmd_v2, 0, sizeof(cmd_v2));
        for (i = 0; i < IWM_MAX_BINDINGS; i++) {
            cmd_v2.quotas[i].id_and_color =
            cmd.quotas[i].id_and_color;
            cmd_v2.quotas[i].quota = cmd.quotas[i].quota;
            cmd_v2.quotas[i].max_duration =
            cmd.quotas[i].max_duration;
        }
        return iwm_send_cmd_pdu(sc, IWM_TIME_QUOTA_CMD, 0,
                                sizeof(cmd_v2), &cmd_v2);
    }
    
    return iwm_send_cmd_pdu(sc, IWM_TIME_QUOTA_CMD, 0, sizeof(cmd), &cmd);
}

int ItlIwm::
iwm_auth(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    uint32_t duration;
    int generation = sc->sc_generation, err;
    
    splassert(IPL_NET);
    
    in->in_ni.ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
    in->in_ni.ni_flags &= ~(IEEE80211_NODE_HT |
                            IEEE80211_NODE_QOS |
                            IEEE80211_NODE_HT_SGI20 |
                            IEEE80211_NODE_HT_SGI40 |
                            IEEE80211_NODE_VHT |
                            IEEE80211_NODE_VHT_SGI80 |
                            IEEE80211_NODE_VHT_SGI160);
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        err = iwm_phy_ctxt_update(sc, &sc->sc_phyctxt[0],
                                  ic->ic_ibss_chan, 1, 1, 0);
        if (err)
            return err;
    } else {
        err = iwm_phy_ctxt_update(sc, &sc->sc_phyctxt[0],
                                  in->in_ni.ni_chan, 1, 1, 0);
        if (err)
            return err;
    }
    in->in_phyctxt = &sc->sc_phyctxt[0];
    IEEE80211_ADDR_COPY(in->in_macaddr, in->in_ni.ni_macaddr);
    
    err = iwm_mac_ctxt_cmd(sc, in, IWM_FW_CTXT_ACTION_ADD, 0);
    if (err) {
        XYLog("%s: could not add MAC context (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    sc->sc_flags |= IWM_FLAG_MAC_ACTIVE;
    
    err = iwm_binding_cmd(sc, in, IWM_FW_CTXT_ACTION_ADD);
    if (err) {
        XYLog("%s: could not add binding (error %d)\n",
              DEVNAME(sc), err);
        goto rm_mac_ctxt;
    }
    sc->sc_flags |= IWM_FLAG_BINDING_ACTIVE;
    
    err = iwm_add_sta_cmd(sc, in, 0, 0);
    if (err) {
        XYLog("%s: could not add sta (error %d)\n",
              DEVNAME(sc), err);
        goto rm_binding;
    }
    
    iwm_toggle_tx_ant(sc, &sc->sc_tx_ant);
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR)
        return 0;
    
    /*
     * Prevent the FW from wandering off channel during association
     * by "protecting" the session with a time event.
     */
    if (in->in_ni.ni_intval)
        duration = in->in_ni.ni_intval * 2;
    else
        duration = IEEE80211_DUR_TU;
    iwm_protect_session(sc, in, duration, in->in_ni.ni_intval / 2);
    
    rs_drv_alloc_sta(sc, &in->in_ni);
    
    iwl_mvm_rs_rate_init(sc, ic->ic_bss,
                         IEEE80211_IS_CHAN_2GHZ(ic->ic_bss->ni_chan) ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ,
                         false);
    
    return 0;
    
rm_binding:
    if (generation == sc->sc_generation) {
        iwm_binding_cmd(sc, in, IWM_FW_CTXT_ACTION_REMOVE);
        sc->sc_flags &= ~IWM_FLAG_BINDING_ACTIVE;
    }
rm_mac_ctxt:
    if (generation == sc->sc_generation) {
        iwm_mac_ctxt_cmd(sc, in, IWM_FW_CTXT_ACTION_REMOVE, 0);
        sc->sc_flags &= ~IWM_FLAG_MAC_ACTIVE;
    }
    return err;
}

int ItlIwm::
iwm_deauth(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    int ac, tfd_queue_msk, err, i;
    
    splassert(IPL_NET);
    
    iwm_unprotect_session(sc, in);
    
    if (sc->sc_flags & IWM_FLAG_STA_ACTIVE) {
        err = iwm_rm_sta_cmd(sc, in);
        if (err) {
            XYLog("%s: could not remove STA (error %d)\n",
                  DEVNAME(sc), err);
            return err;
        }
        sc->sc_rx_ba_sessions = 0;
        for (i = 0; i < nitems(sc->sc_tx_ba); i++)
            sc->sc_tx_ba[i].wn = NULL;
        sc->ba_rx.start_tidmask = 0;
        sc->ba_rx.stop_tidmask = 0;
        sc->ba_tx.start_tidmask = 0;
        sc->ba_tx.stop_tidmask = 0;
    }
    
    tfd_queue_msk = 0;
    for (ac = 0; ac < EDCA_NUM_AC; ac++) {
        int qid = ac;
        if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DQA_SUPPORT))
            qid += IWM_DQA_MIN_MGMT_QUEUE;
        tfd_queue_msk |= htole32(1 << qid);
    }
    
    err = iwm_flush_tx_path(sc, tfd_queue_msk);
    if (err) {
        XYLog("%s: could not flush Tx path (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    
    if (sc->sc_flags & IWM_FLAG_BINDING_ACTIVE) {
        err = iwm_binding_cmd(sc, in, IWM_FW_CTXT_ACTION_REMOVE);
        if (err) {
            XYLog("%s: could not remove binding (error %d)\n",
                  DEVNAME(sc), err);
            return err;
        }
        sc->sc_flags &= ~IWM_FLAG_BINDING_ACTIVE;
    }
    
    if (sc->sc_flags & IWM_FLAG_MAC_ACTIVE) {
        err = iwm_mac_ctxt_cmd(sc, in, IWM_FW_CTXT_ACTION_REMOVE, 0);
        if (err) {
            XYLog("%s: could not remove MAC context (error %d)\n",
                  DEVNAME(sc), err);
            return err;
        }
        sc->sc_flags &= ~IWM_FLAG_MAC_ACTIVE;
    }
    
    in->in_ni.ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
    in->in_ni.ni_flags &= ~(IEEE80211_NODE_HT |
                            IEEE80211_NODE_QOS |
                            IEEE80211_NODE_HT_SGI20 |
                            IEEE80211_NODE_HT_SGI40 |
                            IEEE80211_NODE_VHT |
                            IEEE80211_NODE_VHT_SGI80 |
                            IEEE80211_NODE_VHT_SGI160);
    /* Move unused PHY context to a default channel. */
    err = iwm_phy_ctxt_update(sc, &sc->sc_phyctxt[0],
                              &ic->ic_channels[1], 1, 1, 0);
    if (err)
        return err;
    rs_drv_free_sta(sc, &in->in_ni);
    
    return 0;
}

int ItlIwm::
iwm_run(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    int err;
    int chains = iwm_mimo_enabled(sc) ? 2 : 1;
    
    splassert(IPL_NET);
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        /* Add a MAC context and a sniffing STA. */
        err = iwm_auth(sc);
        if (err)
            return err;
    }
    
    if (in->in_ni.ni_chw == IEEE80211_CHAN_WIDTH_80P80) {
        /* Fallback to 20mhz VHT */
        in->in_ni.ni_chw = IEEE80211_CHAN_WIDTH_20;
    }
    
    if (in->in_ni.ni_flags & IEEE80211_NODE_VHT) {
        if (in->in_ni.ni_chw == IEEE80211_CHAN_WIDTH_20) {
            ic->ic_vht_sup_mcs[0] = 0x01FF;        /* MCS 0-8 */
            if (iwm_mimo_enabled(sc))
                ic->ic_vht_sup_mcs[1] = 0x01FF;         /* MCS 0-8 */
        } else {
            ic->ic_vht_sup_mcs[0] = 0x03FF;        /* MCS 0-9 */
            if (iwm_mimo_enabled(sc))
                ic->ic_vht_sup_mcs[1] = 0x03FF;         /* MCS 0-9 */
        }
    }
    
    /* Configure Rx chains for MIMO. */
    if ((ic->ic_opmode == IEEE80211_M_MONITOR ||
         (in->in_ni.ni_flags & IEEE80211_NODE_HT) ||
         (in->in_ni.ni_flags & IEEE80211_NODE_VHT))) {
        err = iwm_phy_ctxt_update(sc, &sc->sc_phyctxt[0], in->in_ni.ni_chan,
                               chains, chains, 0);
        if (err) {
            XYLog("%s: failed to update PHY\n",
                  DEVNAME(sc));
            return err;
        }
    }
    
    /* Update STA again, for HT-related settings such as MIMO. */
     err = iwm_add_sta_cmd(sc, in, 1, 0);
     if (err) {
         XYLog("%s: could not update STA (error %d)\n",
             DEVNAME(sc), err);
         return err;
     }
    
    /* We have now been assigned an associd by the AP. */
    err = iwm_mac_ctxt_cmd(sc, in, IWM_FW_CTXT_ACTION_MODIFY, 1);
    if (err) {
        XYLog("%s: failed to update MAC\n", DEVNAME(sc));
        return err;
    }
    
    err = iwm_sf_config(sc, IWM_SF_FULL_ON);
    if (err) {
        XYLog("%s: could not set sf full on (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    
    err = iwm_allow_mcast(sc);
    if (err) {
        XYLog("%s: could not allow mcast (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    
    err = iwm_power_update_device(sc);
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
    err = iwm_enable_beacon_filter(sc, in);
    if (err) {
        XYLog("%s: could not enable beacon filter\n",
              DEVNAME(sc));
        return err;
    }
#endif
    err = iwm_power_mac_update_mode(sc, in);
    if (err) {
        XYLog("%s: could not update MAC power (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    
    if (!isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DYNAMIC_QUOTA)) {
        err = iwm_update_quotas(sc, in, 1);
        if (err) {
            XYLog("%s: could not update quotas (error %d)\n",
                  DEVNAME(sc), err);
            return err;
        }
    }
    
    ieee80211_amrr_node_init(&sc->sc_amrr, &in->in_amn);
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        iwm_led_blink_start(sc);
        return 0;
    }
    
    /* Start at lowest available bit-rate, AMRR will raise. */
    in->in_ni.ni_txrate = 0;
    in->in_ni.ni_txmcs = 0;
    
    iwl_mvm_rs_rate_init(sc, ic->ic_bss,
                         IEEE80211_IS_CHAN_2GHZ(ic->ic_bss->ni_chan) ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ,
                         true);
    
    timeout_add_msec(&sc->sc_calib_to, 500);
    iwm_led_enable(sc);
    
    iwm_toggle_tx_ant(sc, &sc->sc_mgmt_last_antenna_idx);
    
    return 0;
}

int ItlIwm::
iwm_run_stop(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    int err, i, tid;
    
    splassert(IPL_NET);
    
    /*
     * Stop Tx/Rx BA sessions now. We cannot rely on the BA task
     * for this when moving out of RUN state since it runs in a
     * separate thread.
     * Note that in->in_ni (struct ieee80211_node) already represents
     * our new access point in case we are roaming between APs.
     * This means we cannot rely on struct ieee802111_node to tell
     * us which BA sessions exist.
     */
    for (i = 0; i < nitems(sc->sc_rxba_data); i++) {
        struct iwm_rxba_data *rxba = &sc->sc_rxba_data[i];
        if (rxba->baid == IWM_RX_REORDER_DATA_INVALID_BAID)
            continue;
        iwm_sta_rx_agg(sc, &in->in_ni, rxba->tid, 0, 0, 0, 0);
        iwm_clear_reorder_buffer(sc, rxba);
        if (sc->sc_rx_ba_sessions > 0)
            sc->sc_rx_ba_sessions--;
    }
    for (tid = 0; tid < IWM_MAX_TID_COUNT; tid++) {
        int qid = IWM_FIRST_AGG_TX_QUEUE + tid;
        struct iwm_tx_ring *ring = &sc->txq[qid];
        if ((sc->agg_queue_mask & (1 << qid)) == 0)
            continue;
        err = iwm_sta_tx_agg(sc, &in->in_ni, tid, 0, 0, 0);
        if (err)
            return err;
        iwm_ampdu_txq_advance(sc, ring, ring->cur);
        iwm_clear_oactive(sc, ring);
    }
    ieee80211_ba_del(&in->in_ni);
    sc->ba_tx.start_tidmask = 0;
    sc->ba_tx.stop_tidmask = 0;
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR)
        iwm_led_blink_stop(sc);
    
    err = iwm_sf_config(sc, IWM_SF_INIT_OFF);
    if (err)
        return err;
    
    iwm_disable_beacon_filter(sc);
    
    if (!isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DYNAMIC_QUOTA)) {
        err = iwm_update_quotas(sc, in, 0);
        if (err) {
            XYLog("%s: could not update quotas (error %d)\n",
                  DEVNAME(sc), err);
            return err;
        }
    }
    
    /* Mark station as disassociated. */
    err = iwm_mac_ctxt_cmd(sc, in, IWM_FW_CTXT_ACTION_MODIFY, 0);
    if (err) {
        XYLog("%s: failed to update MAC\n", DEVNAME(sc));
        return err;
    }
    
    /* Reset Tx chains in case MIMO was enabled. */
    if ((in->in_ni.ni_flags & IEEE80211_NODE_HT) &&
        iwm_mimo_enabled(sc)) {
        err = iwm_phy_ctxt_update(sc, &sc->sc_phyctxt[0], in->in_ni.ni_chan, 1, 1, 0);
        if (err) {
            XYLog("%s: failed to update PHY\n", DEVNAME(sc));
            return err;
        }
    }
    
    return 0;
}

struct ieee80211_node *ItlIwm::
iwm_node_alloc(struct ieee80211com *ic)
{
    return (struct ieee80211_node *)malloc(sizeof (struct iwm_node), M_DEVBUF, M_NOWAIT | M_ZERO);
}

int ItlIwm::
iwm_set_key_v1(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
   struct iwm_softc *sc = (struct iwm_softc *)ic->ic_softc;
   struct iwm_add_sta_key_cmd_v1 cmd;

   memset(&cmd, 0, sizeof(cmd));

   cmd.common.key_flags = htole16(IWM_STA_KEY_FLG_CCM |
       IWM_STA_KEY_FLG_WEP_KEY_MAP |
       ((k->k_id << IWM_STA_KEY_FLG_KEYID_POS) &
       IWM_STA_KEY_FLG_KEYID_MSK));
   if (k->k_flags & IEEE80211_KEY_GROUP)
       cmd.common.key_flags |= htole16(IWM_STA_KEY_MULTICAST);

   memcpy(cmd.common.key, k->k_key, MIN(sizeof(cmd.common.key), k->k_len));
   cmd.common.key_offset = 0;
   cmd.common.sta_id = IWM_STATION_ID;

   return iwm_send_cmd_pdu(sc, IWM_ADD_STA_KEY, IWM_CMD_ASYNC,
       sizeof(cmd), &cmd);
}

int ItlIwm::
iwm_set_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
    struct iwm_softc *sc = (struct iwm_softc *)ic->ic_softc;
    struct iwm_add_sta_key_cmd cmd;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    
    if ((k->k_flags & IEEE80211_KEY_GROUP) ||
        k->k_cipher != IEEE80211_CIPHER_CCMP)  {
        /* Fallback to software crypto for other ciphers. */
        return (ieee80211_set_key(ic, ni, k));
    }
    
    if (!isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_TKIP_MIC_KEYS))
        return that->iwm_set_key_v1(ic, ni, k);
    
    memset(&cmd, 0, sizeof(cmd));
    
    cmd.common.key_flags = htole16(IWM_STA_KEY_FLG_CCM |
                                   IWM_STA_KEY_FLG_WEP_KEY_MAP |
                                   ((k->k_id << IWM_STA_KEY_FLG_KEYID_POS) &
                                    IWM_STA_KEY_FLG_KEYID_MSK));
    if (k->k_flags & IEEE80211_KEY_GROUP)
        cmd.common.key_flags |= htole16(IWM_STA_KEY_MULTICAST);
    
    memcpy(cmd.common.key, k->k_key, MIN(sizeof(cmd.common.key), k->k_len));
    cmd.common.key_offset = 0;
    cmd.common.sta_id = IWM_STATION_ID;
    
    cmd.transmit_seq_cnt = htole64(k->k_tsc);
    
    return that->iwm_send_cmd_pdu(sc, IWM_ADD_STA_KEY, IWM_CMD_ASYNC,
                                  sizeof(cmd), &cmd);
}

void ItlIwm::
iwm_delete_key_v1(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
   struct iwm_softc *sc = (struct iwm_softc *)ic->ic_softc;
   struct iwm_add_sta_key_cmd_v1 cmd;

   memset(&cmd, 0, sizeof(cmd));

   cmd.common.key_flags = htole16(IWM_STA_KEY_NOT_VALID |
       IWM_STA_KEY_FLG_NO_ENC | IWM_STA_KEY_FLG_WEP_KEY_MAP |
       ((k->k_id << IWM_STA_KEY_FLG_KEYID_POS) &
       IWM_STA_KEY_FLG_KEYID_MSK));
   memcpy(cmd.common.key, k->k_key, MIN(sizeof(cmd.common.key), k->k_len));
   cmd.common.key_offset = 0;
   cmd.common.sta_id = IWM_STATION_ID;

   iwm_send_cmd_pdu(sc, IWM_ADD_STA_KEY, IWM_CMD_ASYNC, sizeof(cmd), &cmd);
}

void ItlIwm::
iwm_delete_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
    struct iwm_softc *sc = (struct iwm_softc *)ic->ic_softc;
    struct iwm_add_sta_key_cmd cmd;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    
    if ((k->k_flags & IEEE80211_KEY_GROUP) ||
        (k->k_cipher != IEEE80211_CIPHER_CCMP)) {
        /* Fallback to software crypto for other ciphers. */
        ieee80211_delete_key(ic, ni, k);
        return;
    }
    
    if ((sc->sc_flags & IWM_FLAG_STA_ACTIVE) == 0)
        return;
    
    if (!isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_TKIP_MIC_KEYS))
        return that->iwm_delete_key_v1(ic, ni, k);
    
    memset(&cmd, 0, sizeof(cmd));
    
    cmd.common.key_flags = htole16(IWM_STA_KEY_NOT_VALID |
                                   IWM_STA_KEY_FLG_NO_ENC | IWM_STA_KEY_FLG_WEP_KEY_MAP |
                                   ((k->k_id << IWM_STA_KEY_FLG_KEYID_POS) &
                                    IWM_STA_KEY_FLG_KEYID_MSK));
    memcpy(cmd.common.key, k->k_key, MIN(sizeof(cmd.common.key), k->k_len));
    cmd.common.key_offset = 0;
    cmd.common.sta_id = IWM_STATION_ID;
    
    that->iwm_send_cmd_pdu(sc, IWM_ADD_STA_KEY, IWM_CMD_ASYNC, sizeof(cmd), &cmd);
}

void ItlIwm::
iwm_calib_timeout(void *arg)
{
    struct iwm_softc *sc = (struct iwm_softc *)arg;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    struct ieee80211_node *ni = &in->in_ni;
    int s;
    
    s = splnet();
    if ((ic->ic_fixed_rate == -1 || ic->ic_fixed_mcs == -1) &&
        (ni->ni_flags & IEEE80211_NODE_HT) == 0 &&
        ic->ic_opmode == IEEE80211_M_STA && ic->ic_bss) {
        int old_txrate = ni->ni_txrate;
        ieee80211_amrr_choose(&sc->sc_amrr, &in->in_ni, &in->in_amn);
        /*
         * If AMRR has chosen a new TX rate we must update
         * the firwmare's LQ rate table.
         * ni_txrate may change again before the task runs so
         * cache the chosen rate in the iwm_node structure.
         */
        if (ni->ni_txrate != old_txrate) {
            XYLog("iwm_calib_timeout in->ni_txrate=%d\n", in->in_ni.ni_txrate);
            iwl_mvm_send_lq_cmd(sc, &sc->lq_sta.rs_drv.lq);
        }
    }
    
    splx(s);
    
    timeout_add_msec(&sc->sc_calib_to, 500);
}

/* Allow multicast from our BSSID. */
int ItlIwm::
iwm_allow_mcast(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    struct iwm_mcast_filter_cmd *cmd;
    size_t size;
    int err;
    
    size = roundup(sizeof(*cmd), 4);
    cmd = (struct iwm_mcast_filter_cmd*)malloc(size, M_DEVBUF, M_NOWAIT | M_ZERO);
    if (cmd == NULL)
        return ENOMEM;
    cmd->filter_own = 1;
    cmd->port_id = 0;
    cmd->count = 0;
    cmd->pass_all = 1;
    IEEE80211_ADDR_COPY(cmd->bssid, in->in_macaddr);
    
    err = iwm_send_cmd_pdu(sc, IWM_MCAST_FILTER_CMD,
                           0, size, cmd);
    ::free(cmd);
    return err;
}

/*
 * This function is called by upper layer when an ADDBA request is received
 * from another STA and before the ADDBA response is sent.
 */
int ItlIwm::
iwm_ampdu_rx_start(struct ieee80211com *ic, struct ieee80211_node *ni,
                   uint8_t tid)
{
    struct iwm_softc *sc = (struct iwm_softc *)IC2IFP(ic)->if_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    
    if (sc->sc_rx_ba_sessions >= IWM_MAX_RX_BA_SESSIONS ||
        tid > IWM_MAX_TID_COUNT)
        return ENOSPC;
    
    if (ic->ic_state != IEEE80211_S_RUN)
        return ENOSPC;

    if (sc->ba_rx.start_tidmask & (1 << tid))
        return EBUSY;
    
    sc->ba_rx.start_tidmask |= (1 << tid);
    that->iwm_add_task(sc, systq, &sc->ba_task);
    
    return EBUSY;
}

/*
 * This function is called by upper layer on teardown of an HT-immediate
 * Block Ack agreement (eg. upon receipt of a DELBA frame).
 */
void ItlIwm::
iwm_ampdu_rx_stop(struct ieee80211com *ic, struct ieee80211_node *ni,
                  uint8_t tid)
{
    struct iwm_softc *sc = (struct iwm_softc *)IC2IFP(ic)->if_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    
    if (tid > IWM_MAX_TID_COUNT || sc->ba_rx.stop_tidmask & (1 << tid))
        return;
    
    if (ic->ic_state != IEEE80211_S_RUN)
        return;

    sc->ba_rx.stop_tidmask |= (1 << tid);
    that->iwm_add_task(sc, systq, &sc->ba_task);
}

int ItlIwm::
iwm_ampdu_tx_start(struct ieee80211com *ic, struct ieee80211_node *ni, uint8_t tid)
{
    struct ieee80211_tx_ba *ba = &ni->ni_tx_ba[tid];
    struct iwm_softc *sc = (struct iwm_softc *)ic->ic_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    
    /* We only implement Tx aggregation with DQA-capable firmware. */
    if (!isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DQA_SUPPORT))
        return ENOTSUP;
    
    /* Ensure we can map this TID to an aggregation queue. */
    if (tid >= IWM_MAX_TID_COUNT)
        return EINVAL;
    
    /* We only support a fixed Tx aggregation window size, for now. */
    if (ba->ba_winsize != IWM_FRAME_LIMIT)
        return ENOTSUP;
    
    /* Is firmware already using Tx aggregation on this queue? */
    if (sc->sc_tx_ba[tid].wn != NULL)
        return ENOSPC;
    
    /* Are we already processing an ADDBA request? */
    if (sc->ba_tx.start_tidmask & (1 << tid))
        return EBUSY;
    
    sc->ba_tx.start_tidmask |= (1 << tid);
    that->iwm_add_task(sc, systq, &sc->ba_task);
    return EBUSY;
}

void ItlIwm::
iwm_ampdu_tx_stop(struct ieee80211com *ic, struct ieee80211_node *ni, uint8_t tid)
{
    struct iwm_softc *sc = (struct iwm_softc *)ic->ic_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);

    XYLog("%s\n", __FUNCTION__);

    if (tid > IWM_MAX_TID_COUNT || sc->ba_tx.stop_tidmask & (1 << tid))
        return;
    
    /* Is firmware currently using Tx aggregation on this queue? */
    if (sc->sc_tx_ba[tid].wn == NULL)
        return;
    
    sc->ba_tx.stop_tidmask |= (1 << tid);
    that->iwm_add_task(sc, systq, &sc->ba_task);
}

void ItlIwm::
iwm_update_chw(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_softc *sc = (struct iwm_softc *)ic->ic_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    
    if (ic->ic_state == IEEE80211_S_RUN && (sc->sc_flags & IWM_FLAG_STA_ACTIVE))
        that->iwm_add_task(sc, systq, &sc->chan_ctxt_task);
}

/*
 * This function is called by upper layer when HT protection settings in
 * beacons have changed.
 */
void ItlIwm::
iwm_updateprot(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_softc *sc = (struct iwm_softc *)ic->ic_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    
    if (ic->ic_state == IEEE80211_S_RUN && (sc->sc_flags & IWM_FLAG_STA_ACTIVE))
        that->iwm_add_task(sc, systq, &sc->mac_ctxt_task);
}

void ItlIwm::
iwm_updateslot(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_softc *sc = (struct iwm_softc *)ic->ic_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    
    if (ic->ic_state == IEEE80211_S_RUN && (sc->sc_flags & IWM_FLAG_STA_ACTIVE))
        that->iwm_add_task(sc, systq, &sc->mac_ctxt_task);
}

void ItlIwm::
iwm_updateedca(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_softc *sc = (struct iwm_softc *)ic->ic_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    
    if (ic->ic_state == IEEE80211_S_RUN && (sc->sc_flags & IWM_FLAG_STA_ACTIVE))
        that->iwm_add_task(sc, systq, &sc->mac_ctxt_task);
}

void ItlIwm::
iwm_updatedtim(struct ieee80211com *ic)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_softc *sc = (struct iwm_softc *)ic->ic_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    
    if (ic->ic_state == IEEE80211_S_RUN && (sc->sc_flags & IWM_FLAG_STA_ACTIVE))
        that->iwm_add_task(sc, systq, &sc->mac_ctxt_task);
}

int ItlIwm::iwm_media_change(struct _ifnet *ifp)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_softc *sc = (struct iwm_softc*)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    uint8_t rate, ridx;
    int err;
    
    err = ieee80211_media_change(ifp);
    if (err != ENETRESET)
        return err;
    
    if (ic->ic_fixed_mcs != -1) {
        if (ni->ni_flags & IEEE80211_NODE_VHT)
            sc->sc_fixed_ridx = iwm_mcs2ridx[ic->ic_fixed_mcs];
        else if (ni->ni_flags & IEEE80211_NODE_HT)
            sc->sc_fixed_ridx = iwm_mcs2ridx[ic->ic_fixed_mcs % 8];
    } else if (ic->ic_fixed_rate != -1) {
        rate = ic->ic_sup_rates[ic->ic_curmode].
        rs_rates[ic->ic_fixed_rate] & IEEE80211_RATE_VAL;
        /* Map 802.11 rate to HW rate index. */
        for (ridx = 0; ridx <= ieee80211_std_rateset_11g.rs_nrates; ridx++)
            if (ieee80211_std_rateset_11g.rs_rates[ridx] == rate)
                break;
        sc->sc_fixed_ridx = ridx;
    }
    
    if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
        (IFF_UP | IFF_RUNNING)) {
        iwm_stop(ifp);
        err = iwm_init(ifp);
    }
    return err;
}

void ItlIwm::
iwm_newstate_task(void *psc)
{
    struct iwm_softc *sc = (struct iwm_softc *)psc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    struct ieee80211com *ic = &sc->sc_ic;
    enum ieee80211_state nstate = sc->ns_nstate;
    enum ieee80211_state ostate = ic->ic_state;
    int arg = sc->ns_arg;
    int err = 0, s = splnet();
    
    if (sc->sc_flags & IWM_FLAG_SHUTDOWN) {
        /* iwm_stop() is waiting for us. */
        //            refcnt_rele_wake(&sc->task_refs);
        splx(s);
        return;
    }
    
    if (ostate == IEEE80211_S_SCAN) {
        if (nstate == ostate) {
            if (sc->sc_flags & IWM_FLAG_SCANNING) {
                //                    refcnt_rele_wake(&sc->task_refs);
                splx(s);
                return;
            }
            /* Firmware is no longer scanning. Do another scan. */
            goto next_scan;
        } else
            that->iwm_led_blink_stop(sc);
    }
    
    if (nstate <= ostate) {
        switch (ostate) {
            case IEEE80211_S_RUN:
                err = that->iwm_run_stop(sc);
                if (err)
                    goto out;
                /* FALLTHROUGH */
            case IEEE80211_S_ASSOC:
            case IEEE80211_S_AUTH:
                if (nstate <= IEEE80211_S_AUTH) {
                    err = that->iwm_deauth(sc);
                    if (err)
                        goto out;
                }
                /* FALLTHROUGH */
            case IEEE80211_S_SCAN:
            case IEEE80211_S_INIT:
                break;
        }
        
        /* Die now if iwm_stop() was called while we were sleeping. */
        if (sc->sc_flags & IWM_FLAG_SHUTDOWN) {
            //                refcnt_rele_wake(&sc->task_refs);
            splx(s);
            return;
        }
    }
    
    switch (nstate) {
        case IEEE80211_S_INIT:
            break;
            
        case IEEE80211_S_SCAN:
        next_scan:
            err = that->iwm_scan(sc);
            if (err)
                break;
            //            refcnt_rele_wake(&sc->task_refs);
            splx(s);
            return;
            
        case IEEE80211_S_AUTH:
            err = that->iwm_auth(sc);
            break;
            
        case IEEE80211_S_ASSOC:
            break;
            
        case IEEE80211_S_RUN:
            err = that->iwm_run(sc);
            break;
    }
    
out:
    if ((sc->sc_flags & IWM_FLAG_SHUTDOWN) == 0) {
        if (err)
            task_add(systq, &sc->init_task);
        else
            sc->sc_newstate(ic, nstate, arg);
    }
    //        refcnt_rele_wake(&sc->task_refs);
    splx(s);
}

int ItlIwm::
iwm_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
    XYLog("%s\n", __FUNCTION__);
    struct _ifnet *ifp = IC2IFP(ic);
    struct iwm_softc *sc = (struct iwm_softc*)ifp->if_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
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
        timeout_del(&sc->sc_calib_to);
        that->iwm_del_task(sc, systq, &sc->ba_task);
        that->iwm_del_task(sc, systq, &sc->mac_ctxt_task);
        that->iwm_del_task(sc, systq, &sc->chan_ctxt_task);
    }
    
    sc->ns_nstate = nstate;
    sc->ns_arg = arg;
    
    that->iwm_add_task(sc, sc->sc_nswq, &sc->newstate_task);
    
    return 0;
}

void ItlIwm::
iwm_endscan(struct iwm_softc *sc)
{
    struct ieee80211_node *ni, *nextbs;
    struct ieee80211com *ic = &sc->sc_ic;
    
//    ni = RB_MIN(ieee80211_tree, &ic->ic_tree);
//    for (; ni != NULL; ni = nextbs) {
//        nextbs = RB_NEXT(ieee80211_tree, &ic->ic_tree, ni);
//        XYLog("%s scan_result ssid=%s, bssid=%s, ni_rsnciphers=%d, ni_rsncipher=%d, ni_rsngroupmgmtcipher=%d, ni_rsngroupcipher=%d, ni_rssi=%d,  ni_capinfo=%d, ni_intval=%d, ni_rsnakms=%d, ni_supported_rsnakms=%d, ni_rsnprotos=%d, ni_supported_rsnprotos=%d, ni_rstamp=%d\n", __FUNCTION__, ni->ni_essid, ether_sprintf(ni->ni_bssid), ni->ni_rsnciphers, ni->ni_rsncipher, ni->ni_rsngroupmgmtcipher, ni->ni_rsngroupcipher, ni->ni_rssi, ni->ni_capinfo, ni->ni_intval, ni->ni_rsnakms, ni->ni_supported_rsnakms, ni->ni_rsnprotos, ni->ni_supported_rsnprotos, ni->ni_rstamp);
//    }
    
    if ((sc->sc_flags & (IWM_FLAG_SCANNING | IWM_FLAG_BGSCAN)) == 0)
        return;
    
    sc->sc_flags &= ~(IWM_FLAG_SCANNING | IWM_FLAG_BGSCAN);
    ieee80211_end_scan(&ic->ic_if);
}

/*
 * Aging and idle timeouts for the different possible scenarios
 * in default configuration
 */
static const uint32_t
iwm_sf_full_timeout_def[IWM_SF_NUM_SCENARIO][IWM_SF_NUM_TIMEOUT_TYPES] = {
    {
        htole32(IWM_SF_SINGLE_UNICAST_AGING_TIMER_DEF),
        htole32(IWM_SF_SINGLE_UNICAST_IDLE_TIMER_DEF)
    },
    {
        htole32(IWM_SF_AGG_UNICAST_AGING_TIMER_DEF),
        htole32(IWM_SF_AGG_UNICAST_IDLE_TIMER_DEF)
    },
    {
        htole32(IWM_SF_MCAST_AGING_TIMER_DEF),
        htole32(IWM_SF_MCAST_IDLE_TIMER_DEF)
    },
    {
        htole32(IWM_SF_BA_AGING_TIMER_DEF),
        htole32(IWM_SF_BA_IDLE_TIMER_DEF)
    },
    {
        htole32(IWM_SF_TX_RE_AGING_TIMER_DEF),
        htole32(IWM_SF_TX_RE_IDLE_TIMER_DEF)
    },
};

/*
 * Aging and idle timeouts for the different possible scenarios
 * in single BSS MAC configuration.
 */
static const uint32_t
iwm_sf_full_timeout[IWM_SF_NUM_SCENARIO][IWM_SF_NUM_TIMEOUT_TYPES] = {
    {
        htole32(IWM_SF_SINGLE_UNICAST_AGING_TIMER),
        htole32(IWM_SF_SINGLE_UNICAST_IDLE_TIMER)
    },
    {
        htole32(IWM_SF_AGG_UNICAST_AGING_TIMER),
        htole32(IWM_SF_AGG_UNICAST_IDLE_TIMER)
    },
    {
        htole32(IWM_SF_MCAST_AGING_TIMER),
        htole32(IWM_SF_MCAST_IDLE_TIMER)
    },
    {
        htole32(IWM_SF_BA_AGING_TIMER),
        htole32(IWM_SF_BA_IDLE_TIMER)
    },
    {
        htole32(IWM_SF_TX_RE_AGING_TIMER),
        htole32(IWM_SF_TX_RE_IDLE_TIMER)
    },
};

void ItlIwm::
iwm_fill_sf_command(struct iwm_softc *sc, struct iwm_sf_cfg_cmd *sf_cmd,
                    struct ieee80211_node *ni)
{
    int i, j, watermark;
    
    sf_cmd->watermark[IWM_SF_LONG_DELAY_ON] = htole32(IWM_SF_W_MARK_SCAN);
    
    /*
     * If we are in association flow - check antenna configuration
     * capabilities of the AP station, and choose the watermark accordingly.
     */
    if (ni) {
        if (ni->ni_flags & IEEE80211_NODE_HT) {
            if (ni->ni_rxmcs[1] != 0)
                watermark = IWM_SF_W_MARK_MIMO2;
            else
                watermark = IWM_SF_W_MARK_SISO;
        } else {
            watermark = IWM_SF_W_MARK_LEGACY;
        }
        /* default watermark value for unassociated mode. */
    } else {
        watermark = IWM_SF_W_MARK_MIMO2;
    }
    sf_cmd->watermark[IWM_SF_FULL_ON] = htole32(watermark);
    
    for (i = 0; i < IWM_SF_NUM_SCENARIO; i++) {
        for (j = 0; j < IWM_SF_NUM_TIMEOUT_TYPES; j++) {
            sf_cmd->long_delay_timeouts[i][j] =
            htole32(IWM_SF_LONG_DELAY_AGING_TIMER);
        }
    }
    
    if (ni) {
        memcpy(sf_cmd->full_on_timeouts, iwm_sf_full_timeout,
               sizeof(iwm_sf_full_timeout));
    } else {
        memcpy(sf_cmd->full_on_timeouts, iwm_sf_full_timeout_def,
               sizeof(iwm_sf_full_timeout_def));
    }
    
}

int ItlIwm::
iwm_sf_config(struct iwm_softc *sc, int new_state)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_sf_cfg_cmd sf_cmd = {
        .state = htole32(new_state),
    };
    int err = 0;
    
#if 0    /* only used for models with sdio interface, in iwlwifi */
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_8000)
        sf_cmd.state |= htole32(IWM_SF_CFG_DUMMY_NOTIF_OFF);
#endif
    
    switch (new_state) {
        case IWM_SF_UNINIT:
        case IWM_SF_INIT_OFF:
            iwm_fill_sf_command(sc, &sf_cmd, NULL);
            break;
        case IWM_SF_FULL_ON:
            iwm_fill_sf_command(sc, &sf_cmd, ic->ic_bss);
            break;
        default:
            return EINVAL;
    }
    
    err = iwm_send_cmd_pdu(sc, IWM_REPLY_SF_CFG_CMD, IWM_CMD_ASYNC,
                           sizeof(sf_cmd), &sf_cmd);
    return err;
}

int ItlIwm::
iwm_init_hw(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    int err, i, ac, qid;
    
    err = iwm_preinit(sc);
    if (err)
        return err;
    
    err = iwm_start_hw(sc);
    if (err) {
        XYLog("%s: could not initialize hardware\n", DEVNAME(sc));
        return err;
    }
    
    err = iwm_run_init_mvm_ucode(sc, 0);
    if (err)
        return err;
    
    /* Should stop and start HW since INIT image just loaded. */
    iwm_stop_device(sc);
    err = iwm_start_hw(sc);
    if (err) {
        XYLog("%s: could not initialize hardware\n", DEVNAME(sc));
        return err;
    }
    
    /* Restart, this time with the regular firmware */
    err = iwm_load_ucode_wait_alive(sc, IWM_UCODE_TYPE_REGULAR);
    if (err) {
        XYLog("%s: could not load firmware\n", DEVNAME(sc));
        goto err;
    }
    
    if (!iwm_nic_lock(sc))
        return EBUSY;
    
    err = iwm_send_tx_ant_cfg(sc, iwm_fw_valid_tx_ant(sc));
    if (err) {
        XYLog("%s: could not init tx ant config (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
    err = iwm_send_phy_db_data(sc);
    if (err) {
        XYLog("%s: could not init phy db (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
    err = iwm_send_phy_cfg_cmd(sc);
    if (err) {
        XYLog("%s: could not send phy config (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
    err = iwm_send_bt_init_conf(sc);
    if (err) {
        XYLog("%s: could not init bt coex (error %d)\n",
              DEVNAME(sc), err);
        return err;
    }
    
    if (isset(sc->sc_enabled_capa,
              IWM_UCODE_TLV_CAPA_SOC_LATENCY_SUPPORT)) {
        err = iwm_send_soc_conf(sc);
        if (err)
            return err;
    }
    
    if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DQA_SUPPORT)) {
        err = iwm_send_dqa_cmd(sc);
        if (err)
            return err;
    }
    
    /* Add auxiliary station for scanning */
    err = iwm_add_aux_sta(sc);
    if (err) {
        XYLog("%s: could not add aux station (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
    for (i = 0; i < IWM_NUM_PHY_CTX; i++) {
        /*
         * The channel used here isn't relevant as it's
         * going to be overwritten in the other flows.
         * For now use the first channel we have.
         */
        sc->sc_phyctxt[i].id = i;
        sc->sc_phyctxt[i].channel = &ic->ic_channels[1];
        err = iwm_phy_ctxt_cmd(sc, &sc->sc_phyctxt[i], 1, 1,
                               IWM_FW_CTXT_ACTION_ADD, 0);
        if (err) {
            XYLog("%s: could not add phy context %d (error %d)\n",
                  DEVNAME(sc), i, err);
            goto err;
        }
    }
    
    /* Initialize tx backoffs to the minimum. */
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000)
        iwm_tt_tx_backoff(sc, 0);
    
    
    err = iwm_config_ltr(sc);
    if (err) {
        XYLog("%s: PCIe LTR configuration failed (error %d)\n",
              DEVNAME(sc), err);
    }
    
    if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_CT_KILL_BY_FW)) {
        err = iwm_send_temp_report_ths_cmd(sc);
        if (err)
            goto err;
    }
    
    err = iwm_power_update_device(sc);
    if (err) {
        XYLog("%s: could not send power command (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
    if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_LAR_SUPPORT)) {
        err = iwm_send_update_mcc_cmd(sc, "ZZ");
        if (err) {
            XYLog("%s: could not init LAR (error %d)\n",
                  DEVNAME(sc), err);
            goto err;
        }
    }
    
    if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_UMAC_SCAN)) {
        err = iwm_config_umac_scan(sc);
        if (err) {
            XYLog("%s: could not configure scan (error %d)\n",
                  DEVNAME(sc), err);
            goto err;
        }
    }
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DQA_SUPPORT))
            qid = IWM_DQA_INJECT_MONITOR_QUEUE;
        else
            qid = IWM_AUX_QUEUE;
        err = iwm_enable_txq(sc, IWM_MONITOR_STA_ID, qid,
                             iwm_ac_to_tx_fifo[EDCA_AC_BE], 0, IWM_MAX_TID_COUNT, 0);
        if (err) {
            XYLog("%s: could not enable monitor inject Tx queue "
                  "(error %d)\n", DEVNAME(sc), err);
            goto err;
        }
    } else {
        for (ac = 0; ac < EDCA_NUM_AC; ac++) {
            if (isset(sc->sc_enabled_capa,
                      IWM_UCODE_TLV_CAPA_DQA_SUPPORT))
                qid = ac + IWM_DQA_MIN_MGMT_QUEUE;
            else
                qid = ac;
            err = iwm_enable_txq(sc, IWM_STATION_ID, qid,
                                 iwm_ac_to_tx_fifo[ac], 0, IWM_TID_NON_QOS, 0);
            if (err) {
                XYLog("%s: could not enable Tx queue %d "
                      "(error %d)\n", DEVNAME(sc), ac, err);
                goto err;
            }
        }
    }
    
    err = iwm_disable_beacon_filter(sc);
    if (err) {
        XYLog("%s: could not disable beacon filter (error %d)\n",
              DEVNAME(sc), err);
        goto err;
    }
    
err:
    iwm_nic_unlock(sc);
    return err;
}

int ItlIwm::
iwm_init(struct _ifnet *ifp)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_softc *sc = (struct iwm_softc*)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    int err, generation;
    
    //    rw_assert_wrlock(&sc->ioctl_rwl);
    sc->agg_tid_disable = 0xffff;
    sc->agg_queue_mask = 0;
    memset(sc->sc_tx_ba, 0, sizeof(sc->sc_tx_ba));
    
    generation = ++sc->sc_generation;
    
    KASSERT(sc->task_refs.refs == 0, "sc->task_refs.refs == 0");
    //        refcnt_init(&sc->task_refs);
    
    err = iwm_init_hw(sc);
    if (err) {
        if (generation == sc->sc_generation)
            iwm_stop_device(sc);
        return err;
    }
    
    if (sc->sc_nvm.sku_cap_11n_enable)
        iwm_setup_ht_rates(sc);
    
    if (sc->sc_nvm.sku_cap_11ac_enable)
        iwm_setup_vht_rates(sc);
    
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
     * ieee80211_begin_scan() ends up scheduling iwm_newstate_task().
     * Wait until the transition to SCAN state has completed.
     */
    do {
        err = tsleep_nsec(&ic->ic_state, PCATCH, "iwminit",
                          SEC_TO_NSEC(1));
        if (generation != sc->sc_generation)
            return ENXIO;
        if (err) {
            iwm_stop(ifp);
            return err;
        }
    } while (ic->ic_state != IEEE80211_S_SCAN);
    
    return 0;
}

IOReturn ItlIwm::
_iwm_start_task(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3)
{
    struct _ifnet *ifp = (struct _ifnet *)arg0;
    struct iwm_softc *sc = (struct iwm_softc*)ifp->if_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni;
    struct ether_header *eh;
    mbuf_t m;
    int ac = EDCA_AC_BE; /* XXX */
    
    if (!(ifp->if_flags & IFF_RUNNING) || ifq_is_oactive(&ifp->if_snd)) {
        return kIOReturnOutputDropped;
    }
    
    for (;;) {
        /* why isn't this done per-queue? */
        if (sc->qfullmsk != 0) {
            ifq_set_oactive(&ifp->if_snd);
            break;
        }
        
        /* need to send management frames even if we're not RUNning */
        m = mq_dequeue(&ic->ic_mgtq);
        if (m) {
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
        if (!m) {
            break;
        }
        if (mbuf_len(m) < sizeof (*eh) &&
            mbuf_pullup(&m, sizeof (*eh)) != 0) {
            XYLog("%s %d OUTPUT_ERROR\n", __FUNCTION__, __LINE__);
            ifp->netStat->outputErrors++;
            continue;
        }
#if NBPFILTER > 0
        if (ifp->if_bpf != NULL)
            bpf_mtap(ifp->if_bpf, m, BPF_DIRECTION_OUT);
#endif
        if ((m = ieee80211_encap(ifp, m, &ni)) == NULL) {
            XYLog("%s %d ieee80211_encap OUTPUT_ERROR\n", __FUNCTION__, __LINE__);
            ifp->netStat->outputErrors++;
            continue;
        }
//        XYLog("%s if_snd->send\n", __FUNCTION__);
        
    sendit:
#if NBPFILTER > 0
        if (ic->ic_rawbpf != NULL)
            bpf_mtap(ic->ic_rawbpf, m, BPF_DIRECTION_OUT);
#endif
        if (that->iwm_tx(sc, m, ni, ac) != 0) {
            XYLog("%s %d iwm_tx OUTPUT_ERROR\n", __FUNCTION__, __LINE__);
            ieee80211_release_node(ic, ni);
            ifp->netStat->outputErrors++;
            continue;
        }
        ifp->netStat->outputPackets++;
        
        if (ifp->if_flags & IFF_UP)
            ifp->if_timer = 1;
    }
    
    return kIOReturnSuccess;
}

void ItlIwm::
iwm_start(struct _ifnet *ifp)
{
    struct iwm_softc *sc = (struct iwm_softc*)ifp->if_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
//        if (that->outputThreadSignal) {
//            semaphore_signal(that->outputThreadSignal);
//        }
    that->getMainCommandGate()->attemptAction(_iwm_start_task, &that->com.sc_ic.ic_ac.ac_if);
//    _iwm_start_task(that, &that->com.sc_ic.ic_ac.ac_if, NULL, NULL, NULL);
}

void ItlIwm::
iwm_stop(struct _ifnet *ifp)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_softc *sc = (struct iwm_softc*)ifp->if_softc;
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    int i, s = splnet();
    
    //    rw_assert_wrlock(&sc->ioctl_rwl);
    
    sc->sc_flags |= IWM_FLAG_SHUTDOWN; /* Disallow new tasks. */
    
    /* Cancel scheduled tasks and let any stale tasks finish up. */
    task_del(systq, &sc->init_task);
    iwm_del_task(sc, sc->sc_nswq, &sc->newstate_task);
    iwm_del_task(sc, systq, &sc->ba_task);
    iwm_del_task(sc, systq, &sc->mac_ctxt_task);
    iwm_del_task(sc, systq, &sc->chan_ctxt_task);
    //    KASSERT(sc->task_refs.refs >= 1, "sc->task_refs.refs >= 1");
    //    refcnt_finalize(&sc->task_refs, "iwmstop");
    
    iwm_stop_device(sc);
    
    /* Reset soft state. */
    
    sc->sc_generation++;
    for (i = 0; i < nitems(sc->sc_cmd_resp_pkt); i++) {
        ::free(sc->sc_cmd_resp_pkt[i]);
        sc->sc_cmd_resp_pkt[i] = NULL;
        sc->sc_cmd_resp_len[i] = 0;
    }
    ifp->if_flags &= ~IFF_RUNNING;
    ifq_flush(&ifp->if_snd);
    ifq_clr_oactive(&ifp->if_snd);
    
    in->in_phyctxt = NULL;
    in->in_ni.ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
    IEEE80211_ADDR_COPY(in->in_macaddr, etheranyaddr);
    
    sc->sc_flags &= ~(IWM_FLAG_SCANNING | IWM_FLAG_BGSCAN);
    sc->sc_flags &= ~IWM_FLAG_MAC_ACTIVE;
    sc->sc_flags &= ~IWM_FLAG_BINDING_ACTIVE;
    sc->sc_flags &= ~IWM_FLAG_STA_ACTIVE;
    sc->sc_flags &= ~IWM_FLAG_TE_ACTIVE;
    sc->sc_flags &= ~IWM_FLAG_HW_ERR;
    sc->sc_flags &= ~IWM_FLAG_SHUTDOWN;

    sc->sc_rx_ba_sessions = 0;
    sc->ba_rx.start_tidmask = 0;
    sc->ba_rx.stop_tidmask = 0;
    for (i = 0; i < nitems(sc->sc_tx_ba); i++)
        sc->sc_tx_ba[i].wn = NULL;
    sc->ba_tx.start_tidmask = 0;
    sc->ba_tx.stop_tidmask = 0;
    
    sc->sc_newstate(ic, IEEE80211_S_INIT, -1);
    sc->ns_nstate = IEEE80211_S_INIT;
    
    timeout_del(&sc->sc_calib_to); /* XXX refcount? */
    for (i = 0; i < nitems(sc->sc_rxba_data); i++) {
        struct iwm_rxba_data *rxba = &sc->sc_rxba_data[i];
        iwm_clear_reorder_buffer(sc, rxba);
    }
    iwm_led_blink_stop(sc);
    memset(sc->sc_tx_timer, 0, sizeof(sc->sc_tx_timer));
    ifp->if_timer = 0;
    
    splx(s);
}

void ItlIwm::
iwm_watchdog(struct _ifnet *ifp)
{
    struct iwm_softc *sc = (struct iwm_softc *)ifp->if_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    int i;
    
    ifp->if_timer = 0;

    /*
     * We maintain a separate timer for each Tx queue because
     * Tx aggregation queues can get "stuck" while other queues
     * keep working. The Linux driver uses a similar workaround.
     */
    for (i = 0; i < nitems(sc->sc_tx_timer); i++) {
        if (sc->sc_tx_timer[i] > 0) {
            if (--sc->sc_tx_timer[i] == 0) {
                XYLog("%s: device timeout\n", DEVNAME(sc));
#ifdef IWM_DEBUG
                that->iwm_nic_error(sc);
#endif
                if ((sc->sc_flags & IWM_FLAG_SHUTDOWN) == 0) {
                    task_add(systq, &sc->init_task);
                }
                XYLog("%s %d OUTPUT_ERROR\n", __FUNCTION__, __LINE__);
                ifp->netStat->outputErrors++;
                return;
            }
            ifp->if_timer = 1;
        }
    }
    
    ieee80211_watchdog(ifp);
}

int ItlIwm::
iwm_ioctl(struct _ifnet *ifp, u_long cmd, caddr_t data)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_softc *sc = (struct iwm_softc *)ifp->if_softc;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    int s, err = 0, generation = sc->sc_generation;
    
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
                    err = that->iwm_init(ifp);
                }
            } else {
                if (ifp->if_flags & IFF_RUNNING)
                    that->iwm_stop(ifp);
            }
            break;
            
        default:
            err = ieee80211_ioctl(ifp, cmd, data);
    }
    
    if (err == ENETRESET) {
        err = 0;
        if ((ifp->if_flags & (IFF_UP | IFF_RUNNING)) ==
            (IFF_UP | IFF_RUNNING)) {
            that->iwm_stop(ifp);
            err = that->iwm_init(ifp);
        }
    }
    
    splx(s);
    //    rw_exit(&sc->ioctl_rwl);
    
    return err;
}

#ifdef IWM_DEBUG
/*
 * Note: This structure is read from the device with IO accesses,
 * and the reading already does the endian conversion. As it is
 * read with uint32_t-sized accesses, any members with a different size
 * need to be ordered correctly though!
 */
struct iwm_error_event_table {
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
struct iwm_umac_error_event_table {
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

void ItlIwm::
iwm_nic_umac_error(struct iwm_softc *sc)
{
    struct iwm_umac_error_event_table table;
    uint32_t base;
    
    base = sc->sc_uc.uc_umac_error_event_table;
    
    if (base < 0x800000) {
        XYLog("%s: Invalid error log pointer 0x%08x\n",
              DEVNAME(sc), base);
        return;
    }
    
    if (iwm_read_mem(sc, base, &table, sizeof(table)/sizeof(uint32_t))) {
        XYLog("%s: reading errlog failed\n", DEVNAME(sc));
        return;
    }
    
    if (ERROR_START_OFFSET <= table.valid * ERROR_ELEM_SIZE) {
        XYLog("%s: Start UMAC Error Log Dump:\n", DEVNAME(sc));
        XYLog("%s: Status: 0x%x, count: %d\n", DEVNAME(sc),
              sc->sc_flags, table.valid);
    }
    
    XYLog("%s: 0x%08X | %s\n", DEVNAME(sc), table.error_id,
          iwm_desc_lookup(table.error_id));
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

#define IWM_FW_SYSASSERT_CPU_MASK 0xf0000000
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

const char *ItlIwm::
iwm_desc_lookup(uint32_t num)
{
    int i;
    
    for (i = 0; i < nitems(advanced_lookup) - 1; i++)
        if (advanced_lookup[i].num ==
            (num & ~IWM_FW_SYSASSERT_CPU_MASK))
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
void ItlIwm::
iwm_nic_error(struct iwm_softc *sc)
{
    struct iwm_error_event_table table;
    uint32_t base;
    
    XYLog("%s: dumping device error log\n", DEVNAME(sc));
    base = sc->sc_uc.uc_error_event_table;
    if (base < 0x800000) {
        XYLog("%s: Invalid error log pointer 0x%08x\n",
              DEVNAME(sc), base);
        return;
    }
    
    if (iwm_read_mem(sc, base, &table, sizeof(table)/sizeof(uint32_t))) {
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
          iwm_desc_lookup(table.error_id));
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
        iwm_nic_umac_error(sc);
}
#endif

#define ADVANCE_RXQ(sc) (sc->rxq.cur = (sc->rxq.cur + 1) % count);

void ItlIwm::
iwm_notif_intr(struct iwm_softc *sc)
{
    struct mbuf_list ml = MBUF_LIST_INITIALIZER();
    uint32_t wreg;
    uint16_t hw;
    int count;
    
    //        bus_dmamap_sync(sc->sc_dmat, sc->rxq.stat_dma.map,
    //            0, sc->rxq.stat_dma.size, BUS_DMASYNC_POSTREAD);
    
    if (sc->sc_mqrx_supported) {
        count = IWM_RX_MQ_RING_COUNT;
        wreg = IWM_RFH_Q0_FRBDCB_WIDX_TRG;
    } else {
        count = IWM_RX_RING_COUNT;
        wreg = IWM_FH_RSCSR_CHNL0_WPTR;
    }
    
    hw = le16toh(sc->rxq.stat->closed_rb_num) & 0xfff;
    hw &= (count - 1);
    while (sc->rxq.cur != hw) {
        struct iwm_rx_data *data = &sc->rxq.data[sc->rxq.cur];
        iwm_rx_pkt(sc, data, &ml);
        ADVANCE_RXQ(sc);
    }
    if_input(&sc->sc_ic.ic_if, &ml);
    /*
     * Tell the firmware what we have processed.
     * Seems like the hardware gets upset unless we align the write by 8??
     */
    hw = (hw == 0) ? count - 1 : hw - 1;
    IWM_WRITE(sc, wreg, hw & ~7);
}

int ItlIwm::
iwm_intr(OSObject *arg, IOInterruptEventSource* sender, int count)
{
    ItlIwm *that = (ItlIwm*)arg;
    struct iwm_softc *sc = &that->com;
    int handled = 0;
    int rv = 0;
    uint32_t r1, r2;
    
    if (sc->sc_flags & IWM_FLAG_USE_ICT) {
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
            sc->ict_cur = (sc->ict_cur+1) % IWM_ICT_COUNT;
            tmp = htole32(ict[sc->ict_cur]);
        }
        
        /* this is where the fun begins.  don't ask */
        if (r1 == 0xffffffff)
            r1 = 0;
        
        /*
         * Workaround for hardware bug where bits are falsely cleared
         * when using interrupt coalescing.  Bit 15 should be set if
         * bits 18 and 19 are set.
         */
        if (r1 & 0xc0000)
            r1 |= 0x8000;
        
        r1 = (0xff & r1) | ((0xff00 & r1) << 16);
    } else {
        r1 = IWM_READ(sc, IWM_CSR_INT);
        r2 = IWM_READ(sc, IWM_CSR_FH_INT_STATUS);
    }
    if (r1 == 0 && r2 == 0) {
        goto out_ena;
    }
    if (r1 == 0xffffffff || (r1 & 0xfffffff0) == 0xa5a5a5a0)
        goto out;
    
    IWM_WRITE(sc, IWM_CSR_INT, r1 | ~sc->sc_intmask);
    
    /* ignored */
    handled |= (r1 & (IWM_CSR_INT_BIT_ALIVE /*| IWM_CSR_INT_BIT_SCD*/));
    
    if (r1 & IWM_CSR_INT_BIT_RF_KILL) {
        handled |= IWM_CSR_INT_BIT_RF_KILL;
        XYLog("%s RF_KILL has been toggled\n", __FUNCTION__);
        that->iwm_check_rfkill(sc);
        task_add(systq, &sc->init_task);
        rv = 1;
        goto out_ena;
    }
    
    if (r1 & IWM_CSR_INT_BIT_SW_ERR) {
#ifdef IWM_DEBUG
        int i;
        
        that->iwm_nic_error(sc);
        
        /* Dump driver status (TX and RX rings) while we're here. */
        XYLog("driver status:\n");
        for (i = 0; i < IWM_MAX_QUEUES; i++) {
            struct iwm_tx_ring *ring = &sc->txq[i];
            XYLog("  tx ring %2d: qid=%-2d cur=%-3d "
                  "queued=%-3d\n",
                  i, ring->qid, ring->cur, ring->queued);
        }
        XYLog("  rx ring: cur=%d\n", sc->rxq.cur);
        XYLog("  802.11 state %s\n",
              ieee80211_state_name[sc->sc_ic.ic_state]);
#endif
        
        XYLog("%s: fatal firmware error\n", DEVNAME(sc));
        if ((sc->sc_flags & IWM_FLAG_SHUTDOWN) == 0)
            task_add(systq, &sc->init_task);
        rv = 1;
        goto out;
        
    }
    
    if (r1 & IWM_CSR_INT_BIT_HW_ERR) {
        handled |= IWM_CSR_INT_BIT_HW_ERR;
        XYLog("%s: hardware error, stopping device \n", DEVNAME(sc));
        if ((sc->sc_flags & IWM_FLAG_SHUTDOWN) == 0) {
            sc->sc_flags |= IWM_FLAG_HW_ERR;
            task_add(systq, &sc->init_task);
        }
        rv = 1;
        goto out;
    }
    
    /* firmware chunk loaded */
    if (r1 & IWM_CSR_INT_BIT_FH_TX) {
        IWM_WRITE(sc, IWM_CSR_FH_INT_STATUS, IWM_CSR_FH_INT_TX_MASK);
        handled |= IWM_CSR_INT_BIT_FH_TX;
        
        sc->sc_fw_chunk_done = 1;
        that->wakeupOn(&sc->sc_fw);
    }
    
    if (r1 & (IWM_CSR_INT_BIT_FH_RX | IWM_CSR_INT_BIT_SW_RX |
              IWM_CSR_INT_BIT_RX_PERIODIC)) {
        if (r1 & (IWM_CSR_INT_BIT_FH_RX | IWM_CSR_INT_BIT_SW_RX)) {
            handled |= (IWM_CSR_INT_BIT_FH_RX | IWM_CSR_INT_BIT_SW_RX);
            IWM_WRITE(sc, IWM_CSR_FH_INT_STATUS, IWM_CSR_FH_INT_RX_MASK);
        }
        if (r1 & IWM_CSR_INT_BIT_RX_PERIODIC) {
            handled |= IWM_CSR_INT_BIT_RX_PERIODIC;
            IWM_WRITE(sc, IWM_CSR_INT, IWM_CSR_INT_BIT_RX_PERIODIC);
        }
        
        /* Disable periodic interrupt; we use it as just a one-shot. */
        IWM_WRITE_1(sc, IWM_CSR_INT_PERIODIC_REG, IWM_CSR_INT_PERIODIC_DIS);
        
        /*
         * Enable periodic interrupt in 8 msec only if we received
         * real RX interrupt (instead of just periodic int), to catch
         * any dangling Rx interrupt.  If it was just the periodic
         * interrupt, there was no dangling Rx activity, and no need
         * to extend the periodic interrupt; one-shot is enough.
         */
        if (r1 & (IWM_CSR_INT_BIT_FH_RX | IWM_CSR_INT_BIT_SW_RX))
            IWM_WRITE_1(sc, IWM_CSR_INT_PERIODIC_REG,
                        IWM_CSR_INT_PERIODIC_ENA);
        
        that->iwm_notif_intr(sc);
    }
    
    rv = 1;
    
out_ena:
    that->iwm_restore_interrupts(sc);
out:
    return rv;
}

int ItlIwm::
iwm_intr_msix(OSObject *object, IOInterruptEventSource* sender, int count)
{
    ItlIwm *that = (ItlIwm*)object;
    struct iwm_softc *sc = &that->com;
    uint32_t inta_fh, inta_hw;
    int vector = 0;
    
    inta_fh = IWM_READ(sc, IWM_CSR_MSIX_FH_INT_CAUSES_AD);
    inta_hw = IWM_READ(sc, IWM_CSR_MSIX_HW_INT_CAUSES_AD);
    IWM_WRITE(sc, IWM_CSR_MSIX_FH_INT_CAUSES_AD, inta_fh);
    IWM_WRITE(sc, IWM_CSR_MSIX_HW_INT_CAUSES_AD, inta_hw);
    inta_fh &= sc->sc_fh_mask;
    inta_hw &= sc->sc_hw_mask;
    
    if (inta_fh & IWM_MSIX_FH_INT_CAUSES_Q0 ||
        inta_fh & IWM_MSIX_FH_INT_CAUSES_Q1) {
        that->iwm_notif_intr(sc);
    }
    
    /* firmware chunk loaded */
    if (inta_fh & IWM_MSIX_FH_INT_CAUSES_D2S_CH0_NUM) {
        sc->sc_fw_chunk_done = 1;
        that->wakeupOn(&sc->sc_fw);
    }
    
    if ((inta_fh & IWM_MSIX_FH_INT_CAUSES_FH_ERR) ||
        (inta_hw & IWM_MSIX_HW_INT_CAUSES_REG_SW_ERR) ||
        (inta_hw & IWM_MSIX_HW_INT_CAUSES_REG_SW_ERR_V2)) {
#ifdef IWM_DEBUG
        int i;
        
        that->iwm_nic_error(sc);
        
        /* Dump driver status (TX and RX rings) while we're here. */
        XYLog("driver status:\n");
        for (i = 0; i < IWM_MAX_QUEUES; i++) {
            struct iwm_tx_ring *ring = &sc->txq[i];
            XYLog("  tx ring %2d: qid=%-2d cur=%-3d "
                  "queued=%-3d\n",
                  i, ring->qid, ring->cur, ring->queued);
        }
        XYLog("  rx ring: cur=%d\n", sc->rxq.cur);
        XYLog("  802.11 state %s\n",
              ieee80211_state_name[sc->sc_ic.ic_state]);
#endif
        
        XYLog("%s: fatal firmware error\n", DEVNAME(sc));
        if ((sc->sc_flags & IWM_FLAG_SHUTDOWN) == 0)
            task_add(systq, &sc->init_task);
        return 1;
    }
    
    if (inta_hw & IWM_MSIX_HW_INT_CAUSES_REG_RF_KILL) {
        that->iwm_check_rfkill(sc);
        task_add(systq, &sc->init_task);
    }
    
    if (inta_hw & IWM_MSIX_HW_INT_CAUSES_REG_HW_ERR) {
        XYLog("%s: hardware error, stopping device \n", DEVNAME(sc));
        if ((sc->sc_flags & IWM_FLAG_SHUTDOWN) == 0) {
            sc->sc_flags |= IWM_FLAG_HW_ERR;
            task_add(systq, &sc->init_task);
        }
        return 1;
    }
    
    /*
     * Before sending the interrupt the HW disables it to prevent
     * a nested interrupt. This is done by writing 1 to the corresponding
     * bit in the mask register. After handling the interrupt, it should be
     * re-enabled by clearing this bit. This register is defined as
     * write 1 clear (W1C) register, meaning that it's being clear
     * by writing 1 to the bit.
     */
    IWM_WRITE(sc, IWM_CSR_MSIX_AUTOMASK_ST_AD, 1 << vector);
    return 1;
}

typedef void *iwm_match_t;

#define PCI_VENDOR_INTEL 0x8086
#define    PCI_PRODUCT_INTEL_WL_7260_1    0x08b1        /* Dual Band Wireless AC 7260 */
#define    PCI_PRODUCT_INTEL_WL_7260_2    0x08b2        /* Dual Band Wireless AC 7260 */
#define    PCI_PRODUCT_INTEL_WL_3160_1    0x08b3        /* Dual Band Wireless AC 3160 */
#define    PCI_PRODUCT_INTEL_WL_3160_2    0x08b4        /* Dual Band Wireless AC 3160 */
#define    PCI_PRODUCT_INTEL_WL_7265_1    0x095a        /* Dual Band Wireless AC 7265 */
#define    PCI_PRODUCT_INTEL_WL_7265_2    0x095b        /* Dual Band Wireless AC 7265 */
#define    PCI_PRODUCT_INTEL_WL_3165_1    0x3165        /* Dual Band Wireless AC 3165 */
#define    PCI_PRODUCT_INTEL_WL_3165_2    0x3166        /* Dual Band Wireless AC 3165 */
#define    PCI_PRODUCT_INTEL_WL_8260_1    0x24f3        /* Dual Band Wireless AC 8260 */
#define    PCI_PRODUCT_INTEL_WL_8260_2    0x24f4        /* Dual Band Wireless AC 8260 */
#define    PCI_PRODUCT_INTEL_WL_4165_1    0x24f5        /* Dual Band Wireless AC 4165 */
#define    PCI_PRODUCT_INTEL_WL_4165_2    0x24f6        /* Dual Band Wireless AC 4165 */
#define    PCI_PRODUCT_INTEL_WL_3168_1    0x24fb        /* Dual Band Wireless-AC 3168 */
#define    PCI_PRODUCT_INTEL_WL_8265_1    0x24fd        /* Dual Band Wireless-AC 8265 */
#define    PCI_PRODUCT_INTEL_WL_9260_1    0x2526
#define    PCI_PRODUCT_INTEL_WL_9560_1    0x9df0        /* Dual Band Wireless AC 9560 */
#define    PCI_PRODUCT_INTEL_WL_9560_2    0xa370        /* Dual Band Wireless AC 9560 */
#define    PCI_PRODUCT_INTEL_WL_9560_3    0x31DC        /* Dual Band Wireless AC 9560 */
#define    PCI_PRODUCT_INTEL_WL_9560_4    0x30DC        /* Dual Band Wireless AC 9560 */
#define    PCI_PRODUCT_INTEL_WL_9560_5    0x271C        /* Dual Band Wireless AC 9560 */
#define    PCI_PRODUCT_INTEL_WL_9560_6    0x271B        /* Dual Band Wireless AC 9560 */
#define    PCI_PRODUCT_INTEL_WL_9462_1    0x42a4        /* Dual Band Wireless AC 9462 */
#define    PCI_PRODUCT_INTEL_WL_9462_2    0x00a0        /* Dual Band Wireless AC 9462 */
#define    PCI_PRODUCT_INTEL_WL_9462_3    0x00a4        /* Dual Band Wireless AC 9462 */
#define    PCI_PRODUCT_INTEL_WL_9462_4    0x02a0        /* Dual Band Wireless AC 9462 */
//#define    PCI_PRODUCT_INTEL_WL_9462_5    0x02a4        /* Dual Band Wireless AC 9462 */
#define    PCI_PRODUCT_INTEL_WL_9462_6    0x40a4        /* Dual Band Wireless AC 9462 */
#define    PCI_PRODUCT_INTEL_WL_9461_1    0x0060        /* Dual Band Wireless AC 9461 */
#define    PCI_PRODUCT_INTEL_WL_9461_2    0x0064        /* Dual Band Wireless AC 9461 */
#define    PCI_PRODUCT_INTEL_WL_9461_3    0x0260        /* Dual Band Wireless AC 9461 */
#define    PCI_PRODUCT_INTEL_WL_9461_4    0x0264        /* Dual Band Wireless AC 9461 */

static const struct pci_matchid iwm_devices[] = {
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_3160_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_3160_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_3165_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_3165_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_3168_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_7260_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_7260_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_7265_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_7265_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_8260_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_8260_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_8265_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9260_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9560_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9560_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9560_3 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9560_4 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9560_5 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9560_6 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9462_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9462_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9462_3 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9462_4 },
    //{ PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9462_5 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9462_6 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9461_1 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9461_2 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9461_3 },
    { PCI_VENDOR_INTEL, PCI_PRODUCT_INTEL_WL_9461_4 }
};

int ItlIwm::
iwm_match(struct IOPCIDevice *device)
{
    int devId = device->configRead16(kIOPCIConfigDeviceID);
    XYLog("%s devId=0x%04X\n", __FUNCTION__, devId);
    return pci_matchbyid(PCI_VENDOR_INTEL, devId, iwm_devices,
                         nitems(iwm_devices));
}

int ItlIwm::
iwm_preinit(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = IC2IFP(ic);
    int err;
    static int attached;
    
    err = iwm_prepare_card_hw(sc);
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
    
    err = iwm_start_hw(sc);
    if (err) {
        XYLog("%s: could not initialize hardware\n", DEVNAME(sc));
        return err;
    }
    
    err = iwm_run_init_mvm_ucode(sc, 1);
    iwm_stop_device(sc);
    if (err)
        return err;
    
    /* Print version info and MAC address on first successful fw load. */
    attached = 1;
    XYLog("%s: hw rev 0x%x, fw ver %s, address %s\n",
          DEVNAME(sc), sc->sc_hw_rev & IWM_CSR_HW_REV_TYPE_MSK,
          sc->sc_fwver, ether_sprintf(sc->sc_nvm.hw_addr));
    
    if (sc->sc_nvm.sku_cap_11n_enable)
        iwm_setup_ht_rates(sc);
    
    if (sc->sc_nvm.sku_cap_11ac_enable) {
        iwm_setup_vht_rates(sc);
    }
    
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
    
    iwm_rs_free(sc);
    iwm_rs_alloc(sc);
    
    return 0;
}

void ItlIwm::
iwm_attach_hook(struct device *self)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_softc *sc = (struct iwm_softc *)self;
    
    KASSERT(!cold, "!cold");
    
    iwm_preinit(sc);
}

bool ItlIwm::
intrFilter(OSObject *object, IOFilterInterruptEventSource *src)
{
    ItlIwm *that = (ItlIwm*)object;
    IWM_WRITE(&that->com, IWM_CSR_INT_MASK, 0);
    return true;
}

bool ItlIwm::
iwm_attach(struct iwm_softc *sc, struct pci_attach_args *pa)
{
    XYLog("%s\n", __FUNCTION__);
    pcireg_t reg, memtype;
    struct ieee80211com *ic = &sc->sc_ic;
    struct _ifnet *ifp = &ic->ic_if;
    int err;
    int txq_i, i, j;
    
    sc->sc_pct = pa->pa_pc;
    sc->sc_pcitag = pa->pa_tag;
    sc->sc_dmat = pa->pa_dmat;
    
    //    rw_init(&sc->ioctl_rwl, "iwmioctl");
    
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
        //    if (pci_intr_map_msix(pa, 0, &sc->ih) == 0) {
        sc->sc_msix = 1;
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
                                                                 (IOInterruptEventSource::Action)&ItlIwm::iwm_intr_msix,
                                                                 &ItlIwm::intrFilter
                                                                 ,pa->pa_tag, msiIntrIndex);
    else
        sc->sc_ih = IOFilterInterruptEventSource::filterInterruptEventSource(this,
                                                                             (IOInterruptEventSource::Action)&ItlIwm::iwm_intr, &ItlIwm::intrFilter
                                                                             , pa->pa_tag, msiIntrIndex);
    if (sc->sc_ih == NULL || pa->workloop->addEventSource(sc->sc_ih) != kIOReturnSuccess) {
        XYLog("%s: can't establish interrupt\n", DEVNAME(sc));
        return false;
    }
    sc->sc_ih->enable();
    
    sc->sc_hw_rev = IWM_READ(sc, IWM_CSR_HW_REV);
    int pa_id = pa->pa_tag->configRead16(kIOPCIConfigDeviceID);
    switch (pa_id) {
        case PCI_PRODUCT_INTEL_WL_3160_1:
        case PCI_PRODUCT_INTEL_WL_3160_2:
            sc->sc_fwname = "iwm-3160-17";
            sc->host_interrupt_operation_mode = 1;
            sc->sc_device_family = IWM_DEVICE_FAMILY_7000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ;
            sc->sc_nvm_max_section_size = 16384;
            sc->nvm_type = IWM_NVM;
            sc->support_ldpc = 0;
            sc->non_shared_ant = IWM_ANT_A;
            break;
        case PCI_PRODUCT_INTEL_WL_3165_1:
        case PCI_PRODUCT_INTEL_WL_3165_2:
            sc->sc_fwname = "iwm-7265-17";
            sc->host_interrupt_operation_mode = 0;
            sc->sc_device_family = IWM_DEVICE_FAMILY_7000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ;
            sc->sc_nvm_max_section_size = 16384;
            sc->nvm_type = IWM_NVM;
            sc->support_ldpc = 0;
            sc->non_shared_ant = IWM_ANT_A;
            break;
        case PCI_PRODUCT_INTEL_WL_3168_1:
            sc->sc_fwname = "iwm-3168-29";
            sc->host_interrupt_operation_mode = 0;
            sc->sc_device_family = IWM_DEVICE_FAMILY_7000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ;
            sc->sc_nvm_max_section_size = 16384;
            sc->nvm_type = IWM_NVM_SDP;
            sc->support_ldpc = 0;
            sc->non_shared_ant = IWM_ANT_A;
            break;
        case PCI_PRODUCT_INTEL_WL_7260_1:
        case PCI_PRODUCT_INTEL_WL_7260_2:
            sc->sc_fwname = "iwm-7260-17";
            sc->host_interrupt_operation_mode = 1;
            sc->sc_device_family = IWM_DEVICE_FAMILY_7000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ;
            sc->sc_nvm_max_section_size = 16384;
            sc->nvm_type = IWM_NVM;
            sc->support_ldpc = 0;
            sc->non_shared_ant = IWM_ANT_A;
            break;
        case PCI_PRODUCT_INTEL_WL_7265_1:
        case PCI_PRODUCT_INTEL_WL_7265_2:
            sc->sc_fwname = "iwm-7265-17";
            sc->host_interrupt_operation_mode = 0;
            sc->sc_device_family = IWM_DEVICE_FAMILY_7000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ;
            sc->sc_nvm_max_section_size = 16384;
            sc->nvm_type = IWM_NVM;
            sc->support_ldpc = 1;
            sc->non_shared_ant = IWM_ANT_A;
            break;
        case PCI_PRODUCT_INTEL_WL_8260_1:
        case PCI_PRODUCT_INTEL_WL_8260_2:
            sc->sc_fwname = "iwm-8000C-36";
            sc->host_interrupt_operation_mode = 0;
            sc->sc_device_family = IWM_DEVICE_FAMILY_8000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ_8000;
            sc->sc_nvm_max_section_size = 32768;
            sc->nvm_type = IWM_NVM_EXT;
            sc->support_ldpc = 1;
            sc->non_shared_ant = IWM_ANT_A;
            break;
        case PCI_PRODUCT_INTEL_WL_8265_1:
            sc->sc_fwname = "iwm-8265-36";
            sc->host_interrupt_operation_mode = 0;
            sc->sc_device_family = IWM_DEVICE_FAMILY_8000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ_8000;
            sc->sc_nvm_max_section_size = 32768;
            sc->nvm_type = IWM_NVM_EXT;
            sc->support_ldpc = 1;
            sc->non_shared_ant = IWM_ANT_A;
            break;
        case PCI_PRODUCT_INTEL_WL_9260_1:
            sc->sc_fwname = "iwm-9260-46";
            sc->host_interrupt_operation_mode = 0;
            sc->sc_device_family = IWM_DEVICE_FAMILY_9000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ_8000;
            sc->sc_nvm_max_section_size = 32768;
            sc->sc_mqrx_supported = 1;
            sc->support_ldpc = 1;
            sc->non_shared_ant = IWM_ANT_B;
            break;
        case PCI_PRODUCT_INTEL_WL_9560_1:
        case PCI_PRODUCT_INTEL_WL_9560_2:
        case PCI_PRODUCT_INTEL_WL_9560_3:
        case PCI_PRODUCT_INTEL_WL_9560_4:
        case PCI_PRODUCT_INTEL_WL_9560_5:
        case PCI_PRODUCT_INTEL_WL_9560_6:
        case PCI_PRODUCT_INTEL_WL_9462_1:
        case PCI_PRODUCT_INTEL_WL_9462_2:
        case PCI_PRODUCT_INTEL_WL_9462_3:
        case PCI_PRODUCT_INTEL_WL_9462_4:
        //case PCI_PRODUCT_INTEL_WL_9462_5:
        case PCI_PRODUCT_INTEL_WL_9462_6:
        case PCI_PRODUCT_INTEL_WL_9461_1:
        case PCI_PRODUCT_INTEL_WL_9461_2:
        case PCI_PRODUCT_INTEL_WL_9461_3:
        case PCI_PRODUCT_INTEL_WL_9461_4:
            sc->sc_fwname = "iwm-9000-46";
            sc->host_interrupt_operation_mode = 0;
            sc->sc_device_family = IWM_DEVICE_FAMILY_9000;
            sc->sc_fwdmasegsz = IWM_FWDMASEGSZ_8000;
            sc->sc_nvm_max_section_size = 32768;
            sc->sc_mqrx_supported = 1;
            sc->sc_integrated = 1;
            sc->support_ldpc = 1;
            sc->sc_xtal_latency = 650;
            sc->non_shared_ant = IWM_ANT_B;
            break;
        default:
            XYLog("%s: unknown adapter type\n", DEVNAME(sc));
            return false;
    }
    
    /*
     * In the 8000 HW family the format of the 4 bytes of CSR_HW_REV have
     * changed, and now the revision step also includes bit 0-1 (no more
     * "dash" value). To keep hw_rev backwards compatible - we'll store it
     * in the old format.
     */
    if (sc->sc_device_family >= IWM_DEVICE_FAMILY_8000) {
        uint32_t hw_step;
        
        sc->sc_hw_rev = (sc->sc_hw_rev & 0xfff0) |
        (IWM_CSR_HW_REV_STEP(sc->sc_hw_rev << 2) << 2);
        
        if (iwm_prepare_card_hw(sc) != 0) {
            XYLog("%s: could not initialize hardware\n",
                  DEVNAME(sc));
            return false;
        }
        
        /*
         * In order to recognize C step the driver should read the
         * chip version id located at the AUX bus MISC address.
         */
        IWM_SETBITS(sc, IWM_CSR_GP_CNTRL,
                    IWM_CSR_GP_CNTRL_REG_FLAG_INIT_DONE);
        DELAY(2);
        
        err = iwm_poll_bit(sc, IWM_CSR_GP_CNTRL,
                           IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
                           IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
                           25000);
        if (!err) {
            XYLog("%s: Failed to wake up the nic\n", DEVNAME(sc));
            return false;
        }
        
        if (iwm_nic_lock(sc)) {
            hw_step = iwm_read_prph(sc, IWM_WFPM_CTRL_REG);
            hw_step |= IWM_ENABLE_WFPM;
            iwm_write_prph(sc, IWM_WFPM_CTRL_REG, hw_step);
            hw_step = iwm_read_prph(sc, IWM_AUX_MISC_REG);
            hw_step = (hw_step >> IWM_HW_STEP_LOCATION_BITS) & 0xF;
            if (hw_step == 0x3)
                sc->sc_hw_rev = (sc->sc_hw_rev & 0xFFFFFFF3) |
                (IWM_SILICON_C_STEP << 2);
            iwm_nic_unlock(sc);
        } else {
            XYLog("%s: Failed to lock the nic\n", DEVNAME(sc));
            return false;
        }
    }
    
    XYLog("alloc contig\n");
    
    /*
     * Allocate DMA memory for firmware transfers.
     * Must be aligned on a 16-byte boundary.
     */
    err = iwm_dma_contig_alloc(sc->sc_dmat, &sc->fw_dma,
        sc->sc_fwdmasegsz, 16);
    if (err) {
        XYLog("%s: could not allocate memory for firmware\n",
            DEVNAME(sc));
        return false;
    }

    /* Allocate "Keep Warm" page, used internally by the card. */
    err = iwm_dma_contig_alloc(sc->sc_dmat, &sc->kw_dma, 4096, 4096);
    if (err) {
        XYLog("%s: could not allocate keep warm page\n", DEVNAME(sc));
        goto fail1;
    }

    /* Allocate interrupt cause table (ICT).*/
    err = iwm_dma_contig_alloc(sc->sc_dmat, &sc->ict_dma,
        IWM_ICT_SIZE, 1<<IWM_ICT_PADDR_SHIFT);
    if (err) {
        XYLog("%s: could not allocate ICT table\n", DEVNAME(sc));
        goto fail2;
    }

    /* TX scheduler rings must be aligned on a 1KB boundary. */
    err = iwm_dma_contig_alloc(sc->sc_dmat, &sc->sched_dma,
        nitems(sc->txq) * sizeof(struct iwm_agn_scd_bc_tbl), 1024);
    if (err) {
        XYLog("%s: could not allocate TX scheduler rings\n",
            DEVNAME(sc));
        goto fail3;
    }

    for (txq_i = 0; txq_i < nitems(sc->txq); txq_i++) {
        err = iwm_alloc_tx_ring(sc, &sc->txq[txq_i], txq_i);
        if (err) {
            XYLog("%s: could not allocate TX ring %d\n",
                DEVNAME(sc), txq_i);
            goto fail4;
        }
    }

    err = iwm_alloc_rx_ring(sc, &sc->rxq);
    if (err) {
        XYLog("%s: could not allocate RX ring\n", DEVNAME(sc));
        goto fail4;
    }
    
    taskq_init();
    sc->sc_nswq = taskq_create("iwmns", 1, IPL_NET, 0);
    if (sc->sc_nswq == NULL)
        goto fail4;
    
    XYLog("config ieee80211\n");
    
    /* Clear pending interrupts. */
    IWM_WRITE(sc, IWM_CSR_INT, 0xffffffff);
    
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
    ic->ic_htxcaps = 0;
    ic->ic_txbfcaps = 0;
    ic->ic_aselcaps = 0;
    ic->ic_ampdu_params = (IEEE80211_AMPDU_PARAM_SS_4 | 0x3 /* 64k */);
    ic->ic_caps |= (IEEE80211_C_QOS | IEEE80211_C_TX_AMPDU | IEEE80211_C_AMSDU_IN_AMPDU);
    ic->ic_caps |= IEEE80211_C_SUPPORTS_VHT_EXT_NSS_BW;
#if 0
    ic->ic_caps |= IEEE80211_C_TX_AMPDU_SETUP_IN_RS;
#endif
    
    ic->ic_sup_rates[IEEE80211_MODE_11A] = ieee80211_std_rateset_11a;
    ic->ic_sup_rates[IEEE80211_MODE_11B] = ieee80211_std_rateset_11b;
    ic->ic_sup_rates[IEEE80211_MODE_11G] = ieee80211_std_rateset_11g;
    
    for (i = 0; i < nitems(sc->sc_phyctxt); i++) {
        sc->sc_phyctxt[i].id = i;
    }
    
    sc->sc_amrr.amrr_min_success_threshold =  1;
    sc->sc_amrr.amrr_max_success_threshold = 15;
    
    /* IBSS channel undefined for now. */
    ic->ic_ibss_chan = &ic->ic_channels[1];
    
    ic->ic_max_rssi = IWM_MAX_DBM - IWM_MIN_DBM;
    
    ifp->if_softc = sc;
    ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST | IFF_DEBUG;
    ifp->if_ioctl = iwm_ioctl;
    ifp->if_start = iwm_start;
    ifp->if_watchdog = iwm_watchdog;
    memcpy(ifp->if_xname, DEVNAME(sc), IFNAMSIZ);
    
    if_attach(ifp);
    ieee80211_ifattach(ifp, getController());
    ieee80211_media_init(ifp);
    
#if NBPFILTER > 0
    iwm_radiotap_attach(sc);
#endif
    timeout_set(&sc->sc_calib_to, iwm_calib_timeout, sc);
    timeout_set(&sc->sc_led_blink_to, iwm_led_blink_timeout, sc);
    for (i = 0; i < nitems(sc->sc_rxba_data); i++) {
        struct iwm_rxba_data *rxba = &sc->sc_rxba_data[i];
        rxba->baid = IWM_RX_REORDER_DATA_INVALID_BAID;
        rxba->sc = sc;
        timeout_set(&rxba->session_timer, iwm_rx_ba_session_expired,
                    rxba);
        timeout_set(&rxba->reorder_buf.reorder_timer,
                    iwm_reorder_timer_expired, &rxba->reorder_buf);
        for (j = 0; j < nitems(rxba->entries); j++)
            ml_init(&rxba->entries[j].frames);
    }
    task_set(&sc->init_task, iwm_init_task, sc, "init_task");
    task_set(&sc->newstate_task, iwm_newstate_task, sc, "newstate_task");
    task_set(&sc->ba_task, iwm_ba_task, sc, "ba_task");
    task_set(&sc->mac_ctxt_task, iwm_mac_ctxt_task, sc, "mac_ctxt_task");
    task_set(&sc->chan_ctxt_task, iwm_chan_ctxt_task, sc, "chan_ctxt_task");
    
    ic->ic_node_alloc = iwm_node_alloc;
    ic->ic_bgscan_start = iwm_bgscan;
    ic->ic_set_key = iwm_set_key;
    ic->ic_delete_key = iwm_delete_key;
    
    /* Override 802.11 state transition machine. */
    sc->sc_newstate = ic->ic_newstate;
    ic->ic_newstate = iwm_newstate;
    ic->ic_updateprot = iwm_updateprot;
    ic->ic_updateslot = iwm_updateslot;
    ic->ic_updateedca = iwm_updateedca;
    ic->ic_updatedtim = iwm_updatedtim;
    ic->ic_ampdu_rx_start = iwm_ampdu_rx_start;
    ic->ic_ampdu_rx_stop = iwm_ampdu_rx_stop;
    ic->ic_ampdu_tx_start = iwm_ampdu_tx_start;
    ic->ic_ampdu_tx_stop = iwm_ampdu_tx_stop;
    ic->ic_update_chw = iwm_update_chw;
    /*
     * We cannot read the MAC address without loading the
     * firmware from disk. Postpone until mountroot is done.
     */
    //    config_mountroot(self, iwm_attach_hook);
    if (iwm_preinit(sc)) {
        goto fail5;
    }
    
    XYLog("attach succeed.\n");
    
    return true;
    
fail5:
    for (i = 0; i < nitems(sc->sc_rxba_data); i++) {
        struct iwm_rxba_data *rxba = &sc->sc_rxba_data[i];
        iwm_clear_reorder_buffer(sc, rxba);
    }
fail4:    while (--txq_i >= 0)
    iwm_free_tx_ring(sc, &sc->txq[txq_i]);
    iwm_free_rx_ring(sc, &sc->rxq);
    iwm_dma_contig_free(&sc->sched_dma);
fail3:    if (sc->ict_dma.vaddr != NULL)
    iwm_dma_contig_free(&sc->ict_dma);
    
fail2:    iwm_dma_contig_free(&sc->kw_dma);
fail1:    iwm_dma_contig_free(&sc->fw_dma);
    XYLog("attach failed.\n");
    return false;
}

#if NBPFILTER > 0
void ItlIwm::
iwm_radiotap_attach(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    bpfattach(&sc->sc_drvbpf, &sc->sc_ic.ic_if, DLT_IEEE802_11_RADIO,
              sizeof (struct ieee80211_frame) + IEEE80211_RADIOTAP_HDRLEN);
    
    sc->sc_rxtap_len = sizeof sc->sc_rxtapu;
    sc->sc_rxtap.wr_ihdr.it_len = htole16(sc->sc_rxtap_len);
    sc->sc_rxtap.wr_ihdr.it_present = htole32(IWM_RX_RADIOTAP_PRESENT);
    
    sc->sc_txtap_len = sizeof sc->sc_txtapu;
    sc->sc_txtap.wt_ihdr.it_len = htole16(sc->sc_txtap_len);
    sc->sc_txtap.wt_ihdr.it_present = htole32(IWM_TX_RADIOTAP_PRESENT);
}
#endif

void ItlIwm::
iwm_init_task(void *arg1)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_softc *sc = (struct iwm_softc *)arg1;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    struct _ifnet *ifp = &sc->sc_ic.ic_if;
    int s = splnet();
    int generation = sc->sc_generation;
    int fatal = (sc->sc_flags & (IWM_FLAG_HW_ERR | IWM_FLAG_RFKILL));
    
    //    rw_enter_write(&sc->ioctl_rwl);
    if (generation != sc->sc_generation) {
        //        rw_exit(&sc->ioctl_rwl);
        splx(s);
        return;
    }
    
    if (ifp->if_flags & IFF_RUNNING)
        that->iwm_stop(ifp);
    else
        sc->sc_flags &= ~IWM_FLAG_HW_ERR;
    
    if (!fatal && (ifp->if_flags & (IFF_UP | IFF_RUNNING)) == IFF_UP)
        that->iwm_init(ifp);
    
    //    rw_exit(&sc->ioctl_rwl);
    splx(s);
}

void ItlIwm::
iwm_mac_ctxt_task(void *arg)
{
    struct iwm_softc *sc = (struct iwm_softc *)arg;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    int err, s = splnet();
    
    if (sc->sc_flags & IWM_FLAG_SHUTDOWN ||
        ic->ic_state != IEEE80211_S_RUN ||
        in->in_phyctxt == NULL) {
        //        refcnt_rele_wake(&sc->task_refs);
        splx(s);
        return;
    }
    
    err = that->iwm_mac_ctxt_cmd(sc, in, IWM_FW_CTXT_ACTION_MODIFY, 1);
    if (err)
        printf("%s: failed to update MAC\n", DEVNAME(sc));
    
    that->iwm_unprotect_session(sc, in);
    
    //    refcnt_rele_wake(&sc->task_refs);
    splx(s);
}

void ItlIwm::
iwm_chan_ctxt_task(void *arg)
{
    struct iwm_softc *sc = (struct iwm_softc *)arg;
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *in = (struct iwm_node *)ic->ic_bss;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    int err, s = splnet();
    
    if (sc->sc_flags & IWM_FLAG_SHUTDOWN ||
        ic->ic_state != IEEE80211_S_RUN ||
        in->in_phyctxt == NULL) {
        //        refcnt_rele_wake(&sc->task_refs);
        splx(s);
        return;
    }
    
    int chains = that->iwm_mimo_enabled(sc) ? 2 : 1;
    err = that->iwm_phy_ctxt_update(sc, in->in_phyctxt, in->in_ni.ni_chan,
                                 chains, chains, 0);
    if (err) {
        XYLog("%s: failed to update PHY\n",
              __FUNCTION__);
        //        refcnt_rele_wake(&sc->task_refs);
        splx(s);
        return;
    }

    rs_drv_rate_update(sc, &in->in_ni, IEEE80211_IS_CHAN_2GHZ(in->in_ni.ni_chan) ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ, true);
    iwl_mvm_send_lq_cmd(sc, &sc->lq_sta.rs_drv.lq);
    
    //    refcnt_rele_wake(&sc->task_refs);
    splx(s);
}

void ItlIwm::
iwm_ba_task(void *arg)
{
    struct iwm_softc *sc = (struct iwm_softc *)arg;
    ItlIwm *that = container_of(sc, ItlIwm, com);
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    int s = splnet();
    int tid, err = 0;
    
    if ((sc->sc_flags & IWM_FLAG_SHUTDOWN) ||
        ic->ic_state != IEEE80211_S_RUN) {
//        refcnt_rele_wake(&sc->task_refs);
        splx(s);
        return;
    }
    
    for (tid = 0; tid < IWM_MAX_TID_COUNT; tid++) {
        if (sc->sc_flags & IWM_FLAG_SHUTDOWN)
            break;
        if (sc->ba_rx.start_tidmask & (1 << tid)) {
            struct ieee80211_rx_ba *ba = &ni->ni_rx_ba[tid];
            err = that->iwm_sta_rx_agg(sc, ni, tid,  ba->ba_winstart,
                           ba->ba_winsize, ba->ba_timeout_val, 1);
            sc->ba_rx.start_tidmask &= ~(1 << tid);
        } else if (sc->ba_rx.stop_tidmask & (1 << tid)) {
            err = that->iwm_sta_rx_agg(sc, ni, tid, 0, 0, 0, 0);
            sc->ba_rx.stop_tidmask &= ~(1 << tid);
        }
    }
    
    for (tid = 0; tid < IWM_MAX_TID_COUNT && !err; tid++) {
        if (sc->sc_flags & IWM_FLAG_SHUTDOWN)
            break;
        struct ieee80211_tx_ba *ba = &ni->ni_tx_ba[tid];
        int qid = IWM_FIRST_AGG_TX_QUEUE + tid;
        struct iwm_tx_ring *ring = &sc->txq[qid];
        struct iwm_tx_ba *tx_ba;
        uint16_t ssn = ba->ba_winstart;
        if (sc->ba_tx.start_tidmask & (1 << tid)) {
            uint8_t fifo = iwm_ac_to_tx_fifo[tid_to_mac80211_ac[tid]];

            XYLog("%s tx_start ssn=%d, tid=%d scd_queue=%d\n", __FUNCTION__, ssn, tid, qid);

            if (!that->iwm_nic_lock(sc))
                goto out;
            if (that->iwm_enable_txq(sc, IWM_STATION_ID, qid, fifo, ssn, tid, 1))
                goto out;
            /*
             * If iwm_enable_txq() employed the SCD hardware bug
             * workaround we must skip the frame with seqnum SSN.
             */
            if (IWM_AGG_SSN_TO_TXQ_IDX(ring->cur) !=
                IWM_AGG_SSN_TO_TXQ_IDX(ssn)) {
                ssn = (ssn + 1) & 0xfff;
                ieee80211_output_ba_move_window(ic, ni, tid, ssn);
                ni->ni_qos_txseqs[tid] = ssn;
            }
            if (that->iwm_add_sta_cmd(sc, (struct iwm_node *)ni, 1, IWM_STA_MODIFY_QUEUES))
                goto out;

            sc->agg_tid_disable &= ~(1 << tid);
            sc->agg_queue_mask |= (1 << qid);
            sc->sc_tx_ba[tid].wn = (iwm_node *)ni;
            ba->ba_bitmap = 0;
            if (!that->iwm_sta_tx_agg(sc, ni, tid, 0, ssn, 1)) {
                ieee80211_addba_resp_accept(ic, ni, tid);
                sc->lq_sta.rs_drv.lq.agg_frame_cnt_limit = LINK_QUAL_AGG_FRAME_LIMIT_DEF;

                XYLog("Tx aggregation enabled on ra = %s tid = %d\n",
                         ether_sprintf(ni->ni_macaddr), tid);

                iwl_mvm_send_lq_cmd(sc, &sc->lq_sta.rs_drv.lq);
            } else {
            out:
                ieee80211_addba_resp_refuse(ic, ni, tid,
                                            IEEE80211_STATUS_UNSPECIFIED);
            }
            that->iwm_nic_unlock(sc);
            sc->ba_tx.start_tidmask &= ~(1 << tid);
        } else if (sc->ba_tx.stop_tidmask & (1 << tid)) {
            sc->agg_tid_disable |= (1 << tid);
            that->iwm_sta_tx_agg(sc, ni, tid, 0, 0, 0);
            that->iwm_ampdu_txq_advance(sc, ring, ring->cur);
            that->iwm_clear_oactive(sc, ring);
            /* In DQA-mode the queue isn't removed on agg termination */
            tx_ba = &sc->sc_tx_ba[tid];
            tx_ba->wn = NULL;
            tx_ba->lq_color = 0;
            tx_ba->rate_n_flags = 0;
            tx_ba->tpt_meas_start = 0;
            tx_ba->tx_count = 0;
            tx_ba->tx_count_last = 0;
            tx_ba->tx_time = 0;
            ba->ba_bitmap = 0;
            sc->ba_tx.stop_tidmask &= ~(1 << tid);
        }
    }
    
    //    refcnt_rele_wake(&sc->task_refs);
    splx(s);
}

int ItlIwm::
iwm_resume(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
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

    iwm_enable_rfkill_int(sc);
    iwm_check_rfkill(sc);

    return iwm_prepare_card_hw(sc);
}

void ItlIwm::
iwm_add_task(struct iwm_softc *sc, struct taskq *taskq, struct task *task)
{
    int s = splnet();
    
    if (sc->sc_flags & IWM_FLAG_SHUTDOWN) {
        splx(s);
        return;
    }
    
    //    refcnt_take(&sc->task_refs);
    if (!task_add(taskq, task)) {
        //        refcnt_rele_wake(&sc->task_refs);
    }
    splx(s);
}

void ItlIwm::
iwm_del_task(struct iwm_softc *sc, struct taskq *taskq, struct task *task)
{
    if (task_del(taskq, task)) {
        //        refcnt_rele(&sc->task_refs);
    }
}

int ItlIwm::
iwm_activate(struct iwm_softc *sc, int act)
{
    struct _ifnet *ifp = &sc->sc_ic.ic_if;
    int err = 0;
    
    switch (act) {
        case DVACT_QUIESCE:
            if (ifp->if_flags & IFF_RUNNING) {
                //                rw_enter_write(&sc->ioctl_rwl);
                iwm_stop(ifp);
                //                rw_exit(&sc->ioctl_rwl);
            }
            break;
        case DVACT_RESUME:
            err = iwm_resume(sc);
            if (err)
                XYLog("%s: could not initialize hardware\n",
                      DEVNAME(sc));
            break;
        case DVACT_WAKEUP:
            /* Hardware should be up at this point. */
            if (iwm_set_hw_ready(sc))
                task_add(systq, &sc->init_task);
            break;
    }
    
    return 0;
}
