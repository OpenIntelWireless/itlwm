/*
 * Copyright (C) 2020  pigworlds
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
/*    $OpenBSD: if_iwn.c,v 1.243 2020/11/12 15:16:18 krw Exp $    */

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

/*
 * Driver for Intel WiFi Link 4965 and 1000/5000/6000 Series 802.11 network
 * adapters.
 */

#ifndef ItlIwn_hpp
#define ItlIwn_hpp
#include <compat.h>
#include <linux/kernel.h>

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

#include "if_iwnreg.h"
#include "if_iwnvar.h"
#include <sys/pcireg.h>

#include <IOKit/network/IOEthernetController.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <libkern/c++/OSString.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <IOKit/IOFilterInterruptEventSource.h>

#include <HAL/ItlHalService.hpp>
#include <HAL/ItlDriverInfo.hpp>
#include <HAL/ItlDriverController.hpp>

class ItlIwn : public ItlHalService, ItlDriverInfo, ItlDriverController {
    OSDeclareDefaultStructors(ItlIwn)
    
public:
    
    //kext
    void free() override;
    virtual bool attach(IOPCIDevice *device) override;
    virtual void detach(IOPCIDevice *device) override;
    IOReturn enable(IONetworkInterface *netif) override;
    IOReturn disable(IONetworkInterface *netif) override;
    virtual struct ieee80211com *get80211Controller() override;
    
    static bool intrFilter(OSObject *object, IOFilterInterruptEventSource *src);
    static IOReturn _iwn_start_task(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);
    
    virtual ItlDriverInfo *getDriverInfo() override;
    
    virtual ItlDriverController *getDriverController() override;
    
    //driver info
    virtual const char *getFirmwareVersion() override;
    
    virtual int16_t getBSSNoise() override;
    
    virtual bool is5GBandSupport() override;
    
    virtual int getTxNSS() override;
    
    virtual const char *getFirmwareName() override;
    
    virtual UInt32 supportedFeatures() override;

    virtual const char *getFirmwareCountryCode() override;
    
    virtual uint32_t getTxQueueSize() override;
    
    //driver controller
    virtual void clearScanningFlags() override;
    
    virtual IOReturn setMulticastList(IOEthernetAddress *addr, int count) override;
    
    void releaseAll();
    void joinSSID(const char *ssid, const char *pwd);
    
    //utils
    static void *mallocarray(size_t, size_t, int, int);
    
    static int        iwn_match(struct IOPCIDevice *device);
    bool       iwn_attach(struct iwn_softc *sc, struct pci_attach_args *pa);
    int        iwn4965_attach(struct iwn_softc *, pci_product_id_t);
    int        iwn5000_attach(struct iwn_softc *, pci_product_id_t);
    #if NBPFILTER > 0
    void        iwn_radiotap_attach(struct iwn_softc *);
    #endif
    int        iwn_activate(struct iwn_softc *sc, int);
    void       iwn_wakeup(struct iwn_softc *);
    static void        iwn_init_task(void *);
    int        iwn_eeprom_lock(struct iwn_softc *);
    int        iwn_init_otprom(struct iwn_softc *);
    int        iwn_read_prom_data(struct iwn_softc *, uint32_t, void *, int);
    int        iwn_dma_contig_alloc(bus_dma_tag_t, struct iwn_dma_info *,
                void **, bus_size_t, bus_size_t);
    void        iwn_dma_contig_free(struct iwn_dma_info *);
    int        iwn_alloc_sched(struct iwn_softc *);
    void        iwn_free_sched(struct iwn_softc *);
    int        iwn_alloc_kw(struct iwn_softc *);
    void        iwn_free_kw(struct iwn_softc *);
    int        iwn_alloc_ict(struct iwn_softc *);
    void        iwn_free_ict(struct iwn_softc *);
    int        iwn_alloc_fwmem(struct iwn_softc *);
    void        iwn_free_fwmem(struct iwn_softc *);
    int        iwn_alloc_rx_ring(struct iwn_softc *, struct iwn_rx_ring *);
    void        iwn_reset_rx_ring(struct iwn_softc *, struct iwn_rx_ring *);
    void        iwn_free_rx_ring(struct iwn_softc *, struct iwn_rx_ring *);
    int        iwn_alloc_tx_ring(struct iwn_softc *, struct iwn_tx_ring *,
                int);
    void        iwn_reset_tx_ring(struct iwn_softc *, struct iwn_tx_ring *);
    void        iwn_free_tx_ring(struct iwn_softc *, struct iwn_tx_ring *);
    void        iwn5000_ict_reset(struct iwn_softc *);
    int        iwn_read_eeprom(struct iwn_softc *);
    static void        iwn4965_read_eeprom(struct iwn_softc *);
    void        iwn4965_print_power_group(struct iwn_softc *, int);
    static void        iwn5000_read_eeprom(struct iwn_softc *);
    void        iwn_read_eeprom_channels(struct iwn_softc *, int, uint32_t);
    void        iwn_read_eeprom_enhinfo(struct iwn_softc *);
    static struct        ieee80211_node *iwn_node_alloc(struct ieee80211com *);
    static void        iwn_newassoc(struct ieee80211com *, struct ieee80211_node *,
                int);
    int        iwn_media_change(struct _ifnet *);
    static int        iwn_newstate(struct ieee80211com *, enum ieee80211_state, int);
    static void        iwn_iter_func(void *, struct ieee80211_node *);
    static void        iwn_calib_timeout(void *);
    int        iwn_ccmp_decap(struct iwn_softc *, mbuf_t,
                struct ieee80211_node *);
    void        iwn_rx_phy(struct iwn_softc *, struct iwn_rx_desc *,
                struct iwn_rx_data *);
    void        iwn_rx_done(struct iwn_softc *, struct iwn_rx_desc *,
                struct iwn_rx_data *, struct mbuf_list *);
    void        iwn_ra_choose(struct iwn_softc *, struct ieee80211_node *);
    void        iwn_ampdu_rate_control(struct iwn_softc *, struct ieee80211_node *,
                struct iwn_tx_ring *, uint16_t, uint16_t);
    void        iwn_ht_single_rate_control(struct iwn_softc *,
                struct ieee80211_node *, uint8_t, uint8_t, uint8_t, int);
    void        iwn_rx_compressed_ba(struct iwn_softc *, struct iwn_rx_desc *,
                struct iwn_rx_data *);
    void        iwn5000_rx_calib_results(struct iwn_softc *,
                struct iwn_rx_desc *, struct iwn_rx_data *);
    void        iwn_rx_statistics(struct iwn_softc *, struct iwn_rx_desc *,
                struct iwn_rx_data *);
    void        iwn_ampdu_txq_advance(struct iwn_softc *, struct iwn_tx_ring *,
                int, int);
    void        iwn_ampdu_tx_done(struct iwn_softc *, struct iwn_tx_ring *,
                struct iwn_rx_desc *, uint16_t, uint8_t, uint8_t, uint8_t,
                int, uint32_t, struct iwn_txagg_status *);
    static void        iwn4965_tx_done(struct iwn_softc *, struct iwn_rx_desc *,
                struct iwn_rx_data *);
    static void        iwn5000_tx_done(struct iwn_softc *, struct iwn_rx_desc *,
                struct iwn_rx_data *);
    void        iwn_tx_done_free_txdata(struct iwn_softc *,
                struct iwn_tx_data *);
    void        iwn_clear_oactive(struct iwn_softc *, struct iwn_tx_ring *);
    void        iwn_tx_done(struct iwn_softc *, struct iwn_rx_desc *,
                uint8_t, uint8_t, uint8_t, int, int, uint16_t);
    void        iwn_cmd_done(struct iwn_softc *, struct iwn_rx_desc *);
    void        iwn_notif_intr(struct iwn_softc *);
    void        iwn_wakeup_intr(struct iwn_softc *);
    void        iwn_fatal_intr(struct iwn_softc *);
    static int        iwn_intr(OSObject *object, IOInterruptEventSource* sender, int count);
    static void        iwn4965_update_sched(struct iwn_softc *, int, int, uint8_t,
                uint16_t);
    static void        iwn4965_reset_sched(struct iwn_softc *, int, int);
    static void        iwn5000_update_sched(struct iwn_softc *, int, int, uint8_t,
                uint16_t);
    static void        iwn5000_reset_sched(struct iwn_softc *, int, int);
    int        iwn_tx(struct iwn_softc *, mbuf_t,
                struct ieee80211_node *);
    int        iwn_rval2ridx(int);
    static void        iwn_start(struct _ifnet *);
    static void        iwn_watchdog(struct _ifnet *);
    static int        iwn_ioctl(struct _ifnet *, u_long, caddr_t);
    int        iwn_cmd(struct iwn_softc *, int, const void *, int, int);
    static int        iwn4965_add_node(struct iwn_softc *, struct iwn_node_info *,
                int);
    static int        iwn5000_add_node(struct iwn_softc *, struct iwn_node_info *,
                int);
    int        iwn_set_link_quality(struct iwn_softc *,
                struct ieee80211_node *);
    int        iwn_add_broadcast_node(struct iwn_softc *, int, int);
    static void        iwn_updateedca(struct ieee80211com *);
    void        iwn_set_led(struct iwn_softc *, uint8_t, uint8_t, uint8_t);
    int        iwn_set_critical_temp(struct iwn_softc *);
    int        iwn_set_timing(struct iwn_softc *, struct ieee80211_node *);
    static void        iwn4965_power_calibration(struct iwn_softc *, int);
    static int        iwn4965_set_txpower(struct iwn_softc *, int);
    static int        iwn5000_set_txpower(struct iwn_softc *, int);
    static int        iwn4965_get_rssi(const struct iwn_rx_stat *);
    static int        iwn5000_get_rssi(const struct iwn_rx_stat *);
    int        iwn_get_noise(const struct iwn_rx_general_stats *);
    static int        iwn4965_get_temperature(struct iwn_softc *);
    static int        iwn5000_get_temperature(struct iwn_softc *);
    int        iwn_init_sensitivity(struct iwn_softc *);
    void        iwn_collect_noise(struct iwn_softc *,
                const struct iwn_rx_general_stats *);
    static int        iwn4965_init_gains(struct iwn_softc *);
    static int        iwn5000_init_gains(struct iwn_softc *);
    static int        iwn4965_set_gains(struct iwn_softc *);
    static int        iwn5000_set_gains(struct iwn_softc *);
    void        iwn_tune_sensitivity(struct iwn_softc *,
                const struct iwn_rx_stats *);
    int        iwn_send_sensitivity(struct iwn_softc *);
    int        iwn_set_pslevel(struct iwn_softc *, int, int, int);
    int        iwn_send_temperature_offset(struct iwn_softc *);
    int        iwn_send_btcoex(struct iwn_softc *);
    int        iwn_send_advanced_btcoex(struct iwn_softc *);
    int        iwn5000_runtime_calib(struct iwn_softc *);
    int        iwn_config(struct iwn_softc *);
    uint16_t    iwn_get_active_dwell_time(struct iwn_softc *, uint16_t, uint8_t);
    uint16_t    iwn_limit_dwell(struct iwn_softc *, uint16_t);
    uint16_t    iwn_get_passive_dwell_time(struct iwn_softc *, uint16_t);
    int        iwn_scan(struct iwn_softc *, uint16_t, int);
    void        iwn_scan_abort(struct iwn_softc *);
    static int        iwn_bgscan(struct ieee80211com *);
    void       iwn_rxon_configure_ht40(struct ieee80211com *,
                                        struct ieee80211_node *);
    int        iwn_rxon_ht40_enabled(struct iwn_softc *);
    int        iwn_auth(struct iwn_softc *, int);
    int        iwn_run(struct iwn_softc *);
    static int        iwn_set_key(struct ieee80211com *, struct ieee80211_node *,
                struct ieee80211_key *);
    static void        iwn_delete_key(struct ieee80211com *, struct ieee80211_node *,
                struct ieee80211_key *);
    static void        iwn_updateprot(struct ieee80211com *);
    static void        iwn_updateslot(struct ieee80211com *);
    void        iwn_update_rxon_restore_power(struct iwn_softc *);
    static void        iwn5000_update_rxon(struct iwn_softc *);
    static void        iwn4965_update_rxon(struct iwn_softc *);
    static int        iwn_ampdu_rx_start(struct ieee80211com *,
                struct ieee80211_node *, uint8_t);
    static void        iwn_ampdu_rx_stop(struct ieee80211com *,
                struct ieee80211_node *, uint8_t);
    static int        iwn_ampdu_tx_start(struct ieee80211com *,
                struct ieee80211_node *, uint8_t);
    static void        iwn_ampdu_tx_stop(struct ieee80211com *,
                struct ieee80211_node *, uint8_t);
    static void        iwn4965_ampdu_tx_start(struct iwn_softc *,
                struct ieee80211_node *, uint8_t, uint16_t);
    static void        iwn4965_ampdu_tx_stop(struct iwn_softc *,
                uint8_t, uint16_t);
    static void        iwn5000_ampdu_tx_start(struct iwn_softc *,
                struct ieee80211_node *, uint8_t, uint16_t);
    static void        iwn5000_ampdu_tx_stop(struct iwn_softc *,
                uint8_t, uint16_t);
    static void        iwn_update_chw(struct ieee80211com *);
    static int        iwn5000_query_calibration(struct iwn_softc *);
    static int        iwn5000_send_calibration(struct iwn_softc *);
    static int        iwn5000_send_wimax_coex(struct iwn_softc *);
    static int        iwn5000_crystal_calib(struct iwn_softc *);
    static int        iwn6000_temp_offset_calib(struct iwn_softc *);
    static int        iwn2000_temp_offset_calib(struct iwn_softc *);
    static int        iwn4965_post_alive(struct iwn_softc *);
    static int        iwn5000_post_alive(struct iwn_softc *);
    static int        iwn4965_load_bootcode(struct iwn_softc *, const uint8_t *,
                int);
    static int        iwn4965_load_firmware(struct iwn_softc *);
    static int        iwn5000_load_firmware_section(struct iwn_softc *, uint32_t,
                const uint8_t *, int);
    static int        iwn5000_load_firmware(struct iwn_softc *);
    int        iwn_read_firmware_leg(struct iwn_softc *,
                struct iwn_fw_info *);
    int        iwn_read_firmware_tlv(struct iwn_softc *,
                struct iwn_fw_info *, uint16_t);
    int        iwn_read_firmware(struct iwn_softc *);
    int        iwn_clock_wait(struct iwn_softc *);
    int        iwn_apm_init(struct iwn_softc *);
    void        iwn_apm_stop_master(struct iwn_softc *);
    void        iwn_apm_stop(struct iwn_softc *);
    static int        iwn4965_nic_config(struct iwn_softc *);
    static int        iwn5000_nic_config(struct iwn_softc *);
    int        iwn_hw_prepare(struct iwn_softc *);
    int        iwn_hw_init(struct iwn_softc *);
    void        iwn_hw_stop(struct iwn_softc *);
    int        iwn_init(struct _ifnet *);
    void        iwn_stop(struct _ifnet *);
    
public:
    IOInterruptEventSource* fInterrupt;
    struct pci_attach_args pci;
    struct iwn_softc com;
};

#endif
