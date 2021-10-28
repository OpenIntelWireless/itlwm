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
iwm_coex_agg_time_limit(struct iwm_softc *sc)
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
