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
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2013-2014, 2018-2020 Intel Corporation
 * Copyright (C) 2013-2015 Intel Mobile Communications GmbH
 */

#include "ItlIwm.hpp"

#define LINK_QUAL_AGG_TIME_LIMIT_DEF    (4000)
#define LINK_QUAL_AGG_TIME_LIMIT_BT_ACT    (1200)

uint16_t ItlIwm::
iwm_coex_agg_time_limit(struct iwm_softc *sc, struct ieee80211_node *ni)
{
    return LINK_QUAL_AGG_TIME_LIMIT_DEF;
}

uint8_t ItlIwm::
iwm_coex_tx_prio(struct iwm_softc *sc, struct ieee80211_frame *wh, uint8_t ac)
{
    uint8_t type, subtype;
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = ic->ic_bss;
    bool mplut_enabled = isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_BT_MPLUT_SUPPORT);
    
    if (!ni || !ni->ni_chan)
        return 0;
    
    if (!IEEE80211_IS_CHAN_2GHZ(ni->ni_chan))
        return 0;

    type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
    subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
    
    if (type == IEEE80211_FC0_TYPE_DATA) {
        if (ieee80211_has_qos(wh)) {
            switch (ac) {
                case EDCA_AC_BE:
                    return mplut_enabled ? 1 : 0;
                case EDCA_AC_VI:
                    return mplut_enabled ? 2 : 3;
                case EDCA_AC_VO:
                    return 3;
                default:
                    return 0;
            }
        } else if (IEEE80211_IS_MULTICAST(wh->i_addr1))
            return 3;
        else
            return 0;
    } else if (type == IEEE80211_FC0_TYPE_MGT)
        return subtype == IEEE80211_FC0_SUBTYPE_DISASSOC ? 0 : 3;
    else if (type == IEEE80211_FC0_TYPE_CTL)
        /* ignore cfend and cfendack frames as we never send those */
        return 3;
    
    return 0;
}

bool ItlIwm::
iwm_coex_is_ant_avail(struct iwm_softc *sc, u8 ant)
{
#if 0
    /* there is no other antenna, shared antenna is always available */
    if (mvm->cfg->bt_shared_single_ant)
        return true;
#endif
    
    if (ant & sc->non_shared_ant)
        return true;
    
#ifdef notyet_coex
    return le32_to_cpu(mvm->last_bt_notif.bt_activity_grading) <
                BT_HIGH_TRAFFIC;
#else
    return true;
#endif
}

bool ItlIwm::
iwm_coex_is_mimo_allowed(struct iwm_softc *sc, struct ieee80211_node *ni)
{
#ifdef notyet_coex
    struct iwm_node *in = (struct iwm_node *)ni;
    struct iwm_phy_ctxt *phy_ctxt = in->in_phyctxt;
    enum iwl_bt_coex_lut_type lut_type;

    if (sc->last_bt_notif.ttc_status & BIT(phy_ctxt->id))
        return true;

    if (le32_to_cpu(sc->last_bt_notif.bt_activity_grading) <
        BT_HIGH_TRAFFIC)
        return true;

    /*
     * In Tight / TxTxDis, BT can't Rx while we Tx, so use both antennas
     * since BT is already killed.
     * In Loose, BT can Rx while we Tx, so forbid MIMO to let BT Rx while
     * we Tx.
     * When we are in 5GHz, we'll get BT_COEX_INVALID_LUT allowing MIMO.
     */
    lut_type = iwl_get_coex_type(mvm, mvmsta->vif);
    return lut_type != BT_COEX_LOOSE_LUT;
#else
    return true;
#endif
}

bool ItlIwm::
iwm_coex_is_tpc_allowed(struct iwm_softc *mvm, bool is5G)
{
    if (is5G)
        return false;
    
#ifdef notyet_coex
    return le32_to_cpu(mvm->last_bt_notif.bt_activity_grading) >= BT_LOW_TRAFFIC;
#else
    return false;
#endif
}

bool ItlIwm::
iwm_coex_is_shared_ant_avail(struct iwm_softc *mvm)
{
#ifdef notyet_coex
    return le32_to_cpu(mvm->last_bt_notif.bt_activity_grading) < BT_HIGH_TRAFFIC;
#else
    return mvm->sc_device_family == IWM_DEVICE_FAMILY_9000 &&
            (iwm_fw_valid_tx_ant(mvm) & IWM_ANT_B);
#endif
}
