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
#ifndef _ITLWMX_H
#define _ITLWMX_H
#include "compat.h"
#include "kernel.h"

#include "itlwmx_interface.hpp"
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

#include "if_iwxreg.h"
#include "if_iwxvar.h"
#include <sys/pcireg.h>

#include <IOKit/network/IOEthernetController.h>
#include <IOKit/IOWorkLoop.h>
#include "IOKit/network/IOGatedOutputQueue.h"
#include <libkern/c++/OSString.h>
#include <IOKit/IOService.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOLib.h>
#include <libkern/OSKextLib.h>
#include <libkern/c++/OSMetaClass.h>
#include <IOKit/IOFilterInterruptEventSource.h>

enum
{
    kPowerStateOff = 0,
    kPowerStateOn,
    kPowerStateCount
};

class itlwmx : public IOEthernetController {
    OSDeclareDefaultStructors(itlwmx)
    
public:
    
    //kext
    bool init(OSDictionary *properties) override;
    void free() override;
    IOService* probe(IOService* provider, SInt32* score) override;
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    IOReturn getHardwareAddress(IOEthernetAddress* addrP) override;
    IOReturn enable(IONetworkInterface *netif) override;
    IOReturn disable(IONetworkInterface *netif) override;
    UInt32 outputPacket(mbuf_t, void * param) override;
    IOReturn setPromiscuousMode(IOEnetPromiscuousMode mode) override;
    IOReturn setMulticastMode(IOEnetMulticastMode mode) override;
    IOReturn setMulticastList(IOEthernetAddress* addr, UInt32 len) override;
    virtual const OSString * newVendorString() const override;
    virtual const OSString * newModelString() const override;
    virtual IOReturn getMaxPacketSize(UInt32* maxSize) const override;
    virtual IONetworkInterface * createInterface() override;
    virtual UInt32 getFeatures() const override;
    
    bool configureInterface(IONetworkInterface *netif) override;
    static IOReturn tsleepHandler(OSObject* owner, void* arg0 = 0, void* arg1 = 0, void* arg2 = 0, void* arg3 = 0);
    int tsleep_nsec(void *ident, int priority, const char *wmesg, int timo);
    void wakeupOn(void* ident);
    static bool intrFilter(OSObject *object, IOFilterInterruptEventSource *src);
    static IOReturn _iwm_start_task(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);
    virtual bool createWorkLoop() override;
    virtual IOWorkLoop* getWorkLoop() const override;
    void watchdogAction(IOTimerEventSource *timer);
    static IOReturn _iwx_start_task(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3);
    
    virtual IOReturn getPacketFilters(const OSSymbol *group, UInt32 *filters) const override;
    bool createMediumTables(const IONetworkMedium **primary);
    virtual IOReturn selectMedium(const IONetworkMedium *medium) override;
    
    bool initPCIPowerManagment(IOPCIDevice *provider);
    
    struct ifnet *getIfp();
    struct iwx_softc *getSoft();
    IOEthernetInterface *getNetworkInterface();
    
    //-----------------------------------------------------------------------
    // Power management support.
    //-----------------------------------------------------------------------
    virtual IOReturn registerWithPolicyMaker( IOService * policyMaker ) override;
    virtual IOReturn setPowerState( unsigned long powerStateOrdinal,
                                    IOService *   policyMaker) override;
    virtual IOReturn setWakeOnMagicPacket( bool active ) override;
    void setPowerStateOff(void);
    void setPowerStateOn(void);
    void unregistPM();
    
    void releaseAll();
    void joinSSID(const char *ssid, const char *pwd);
    void associateSSID(const char *ssid, const char *pwd);
    
    //utils
    static void *mallocarray(size_t, size_t, int, int);
    
    static void onLoadFW(OSKextRequestTag requestTag, OSReturn result, const void *resourceData, uint32_t resourceDataLength, void *context);
    
    uint8_t    iwx_lookup_cmd_ver(struct iwx_softc *, uint8_t, uint8_t);
    int    iwx_is_mimo_ht_plcp(uint8_t);
    int    iwx_is_mimo_mcs(int);
    int    iwx_store_cscheme(struct iwx_softc *, uint8_t *, size_t);
    int    iwx_alloc_fw_monitor_block(struct iwx_softc *, uint8_t, uint8_t);
    int    iwx_alloc_fw_monitor(struct iwx_softc *, uint8_t);
    int    iwx_apply_debug_destination(struct iwx_softc *);
    int    iwx_ctxt_info_init(struct iwx_softc *, const struct iwx_fw_sects *);
    void iwx_ctxt_info_free_fw_img(struct iwx_softc *sc);
    int iwx_ctxt_info_alloc_dma(struct iwx_softc *sc,
                                const struct iwx_fw_onesect *sec, struct iwx_dma_info *dram);
    void    iwx_ctxt_info_free_paging(struct iwx_softc *);
    int iwx_get_num_sections(const struct iwx_fw_sects *fws, int start);
    int    iwx_init_fw_sec(struct iwx_softc *, const struct iwx_fw_sects *,
            struct iwx_context_info_dram *);
    int    iwx_firmware_store_section(struct iwx_softc *, enum iwx_ucode_type,
            uint8_t *, size_t);
    int    iwx_set_default_calib(struct iwx_softc *, const void *);
    void    iwx_fw_info_free(struct iwx_fw_info *);
    int    iwx_read_firmware(struct iwx_softc *);
    uint32_t iwx_read_prph(struct iwx_softc *, uint32_t);
    void    iwx_write_prph(struct iwx_softc *, uint32_t, uint32_t);
    void iwx_write_prph64(struct iwx_softc *sc, uint64_t addr, uint64_t val);
    int    iwx_read_mem(struct iwx_softc *, uint32_t, void *, int);
    int    iwx_write_mem(struct iwx_softc *, uint32_t, const void *, int);
    int    iwx_write_mem32(struct iwx_softc *, uint32_t, uint32_t);
    int    iwx_poll_bit(struct iwx_softc *, int, uint32_t, uint32_t, int);
    int    iwx_nic_lock(struct iwx_softc *);
    void    iwx_nic_assert_locked(struct iwx_softc *);
    void    iwx_nic_unlock(struct iwx_softc *);
    void    iwx_set_bits_mask_prph(struct iwx_softc *, uint32_t, uint32_t,
            uint32_t);
    void    iwx_set_bits_prph(struct iwx_softc *, uint32_t, uint32_t);
    void    iwx_clear_bits_prph(struct iwx_softc *, uint32_t, uint32_t);
    int    iwx_dma_contig_alloc(bus_dma_tag_t, struct iwx_dma_info *, bus_size_t,
            bus_size_t);
    void    iwx_dma_contig_free(struct iwx_dma_info *);
    int    iwx_alloc_rx_ring(struct iwx_softc *, struct iwx_rx_ring *);
    void    iwx_disable_rx_dma(struct iwx_softc *);
    void    iwx_reset_rx_ring(struct iwx_softc *, struct iwx_rx_ring *);
    void    iwx_free_rx_ring(struct iwx_softc *, struct iwx_rx_ring *);
    int    iwx_alloc_tx_ring(struct iwx_softc *, struct iwx_tx_ring *, int);
    void    iwx_reset_tx_ring(struct iwx_softc *, struct iwx_tx_ring *);
    void    iwx_free_tx_ring(struct iwx_softc *, struct iwx_tx_ring *);
    void    iwx_enable_rfkill_int(struct iwx_softc *);
    int    iwx_check_rfkill(struct iwx_softc *);
    void    iwx_enable_interrupts(struct iwx_softc *);
    void    iwx_enable_fwload_interrupt(struct iwx_softc *);
    void    iwx_restore_interrupts(struct iwx_softc *);
    void    iwx_disable_interrupts(struct iwx_softc *);
    void    iwx_ict_reset(struct iwx_softc *);
    int    iwx_set_hw_ready(struct iwx_softc *);
    int    iwx_prepare_card_hw(struct iwx_softc *);
    void    iwx_force_power_gating(struct iwx_softc *);
    void    iwx_apm_config(struct iwx_softc *);
    int    iwx_apm_init(struct iwx_softc *);
    void    iwx_apm_stop(struct iwx_softc *);
    int    iwx_allow_mcast(struct iwx_softc *);
    void    iwx_init_msix_hw(struct iwx_softc *);
    void    iwx_conf_msix_hw(struct iwx_softc *, int);
    int    iwx_start_hw(struct iwx_softc *);
    void    iwx_stop_device(struct iwx_softc *);
    void    iwx_nic_config(struct iwx_softc *);
    int    iwx_nic_rx_init(struct iwx_softc *);
    int    iwx_nic_init(struct iwx_softc *);
    int    iwx_enable_txq(struct iwx_softc *, int, int, int, int);
    void    iwx_post_alive(struct iwx_softc *);
    int iwx_send_time_event_cmd(struct iwx_softc *sc,
                            const struct iwx_time_event_cmd *cmd);
    void    iwx_protect_session(struct iwx_softc *, struct iwx_node *, uint32_t,
            uint32_t);
    void    iwx_unprotect_session(struct iwx_softc *, struct iwx_node *);
    uint8_t iwx_fw_valid_tx_ant(struct iwx_softc *sc);
    uint8_t iwx_fw_valid_rx_ant(struct iwx_softc *sc);
    void    iwx_init_channel_map(struct iwx_softc *, uint16_t *, uint32_t *, int);
    void    iwx_setup_ht_rates(struct iwx_softc *);
    int    iwx_mimo_enabled(struct iwx_softc *);
    static void    iwx_htprot_task(void *);
    static void    iwx_update_htprot(struct ieee80211com *, struct ieee80211_node *);
    static int    iwx_ampdu_rx_start(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    static void    iwx_ampdu_rx_stop(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    void    iwx_sta_rx_agg(struct iwx_softc *, struct ieee80211_node *, uint8_t,
            uint16_t, uint16_t, int);
    #ifdef notyet
    int    iwx_ampdu_tx_start(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    void    iwx_ampdu_tx_stop(struct ieee80211com *, struct ieee80211_node *,
            uint8_t);
    #endif
    static void    iwx_ba_task(void *);

    int    iwx_set_mac_addr_from_csr(struct iwx_softc *, struct iwx_nvm_data *);
    int    iwx_is_valid_mac_addr(const uint8_t *);
    int    iwx_nvm_get(struct iwx_softc *);
    int    iwx_load_firmware(struct iwx_softc *);
    int    iwx_start_fw(struct iwx_softc *);
    int    iwx_send_tx_ant_cfg(struct iwx_softc *, uint8_t);
    int    iwx_send_phy_cfg_cmd(struct iwx_softc *);
    int    iwx_load_ucode_wait_alive(struct iwx_softc *);
    int    iwx_send_dqa_cmd(struct iwx_softc *);
    int    iwx_run_init_mvm_ucode(struct iwx_softc *, int);
    int    iwx_config_ltr(struct iwx_softc *);
    void    iwx_update_rx_desc(struct iwx_softc *, struct iwx_rx_ring *, int);
    int    iwx_rx_addbuf(struct iwx_softc *, int, int);
    int    iwx_rxmq_get_signal_strength(struct iwx_softc *, struct iwx_rx_mpdu_desc *);
    void    iwx_rx_rx_phy_cmd(struct iwx_softc *, struct iwx_rx_packet *,
            struct iwx_rx_data *);
    int    iwx_get_noise(const struct iwx_statistics_rx_non_phy *);
    int    iwx_ccmp_decap(struct iwx_softc *, mbuf_t,
           struct ieee80211_node *);
    void    iwx_rx_frame(struct iwx_softc *, mbuf_t, int, uint32_t, int, int,
           uint32_t, struct ieee80211_rxinfo *, struct mbuf_list *);
    void iwx_rx_mpdu_mq(struct iwx_softc *sc, mbuf_t m, void *pktdata,
                        size_t maxlen, struct mbuf_list *ml);
    void    iwx_rx_tx_cmd_single(struct iwx_softc *, struct iwx_rx_packet *,
            struct iwx_node *);
    void iwx_txd_done(struct iwx_softc *sc, struct iwx_tx_data *txd);
    void    iwx_rx_tx_cmd(struct iwx_softc *, struct iwx_rx_packet *,
            struct iwx_rx_data *);
    void    iwx_rx_bmiss(struct iwx_softc *, struct iwx_rx_packet *,
            struct iwx_rx_data *);
    int    iwx_binding_cmd(struct iwx_softc *, struct iwx_node *, uint32_t);
    int    iwx_phy_ctxt_cmd_uhb(struct iwx_softc *, struct iwx_phy_ctxt *, uint8_t,
                                uint8_t, uint32_t, uint32_t);
    int    iwx_phy_ctxt_cmd(struct iwx_softc *, struct iwx_phy_ctxt *, uint8_t,
            uint8_t, uint32_t, uint32_t);
    int    iwx_send_cmd(struct iwx_softc *, struct iwx_host_cmd *);
    int    iwx_send_cmd_pdu(struct iwx_softc *, uint32_t, uint32_t, uint16_t,
            const void *);
    int    iwx_send_cmd_status(struct iwx_softc *, struct iwx_host_cmd *,
            uint32_t *);
    int    iwx_send_cmd_pdu_status(struct iwx_softc *, uint32_t, uint16_t,
            const void *, uint32_t *);
    void    iwx_free_resp(struct iwx_softc *, struct iwx_host_cmd *);
    void    iwx_cmd_done(struct iwx_softc *, int, int, int);
    const struct iwx_rate *iwx_tx_fill_cmd(struct iwx_softc *, struct iwx_node *,
            struct ieee80211_frame *, struct iwx_tx_cmd_gen2 *);
    void    iwx_tx_update_byte_tbl(struct iwx_tx_ring *, int, uint16_t, uint16_t);
    int    iwx_tx(struct iwx_softc *, mbuf_t, struct ieee80211_node *, int);
    int    iwx_flush_tx_path(struct iwx_softc *);
    int    iwx_beacon_filter_send_cmd(struct iwx_softc *,
            struct iwx_beacon_filter_cmd *);
    int    iwx_update_beacon_abort(struct iwx_softc *, struct iwx_node *, int);
    void    iwx_power_build_cmd(struct iwx_softc *, struct iwx_node *,
            struct iwx_mac_power_cmd *);
    int    iwx_power_mac_update_mode(struct iwx_softc *, struct iwx_node *);
    int    iwx_power_update_device(struct iwx_softc *);
    int    iwx_enable_beacon_filter(struct iwx_softc *, struct iwx_node *);
    int    iwx_disable_beacon_filter(struct iwx_softc *);
    int    iwx_add_sta_cmd(struct iwx_softc *, struct iwx_node *, int);
    int    iwx_add_aux_sta(struct iwx_softc *);
    int    iwx_rm_sta_cmd(struct iwx_softc *, struct iwx_node *);
    uint8_t iwx_umac_scan_fill_channels(struct iwx_softc *sc,
                                struct iwx_scan_channel_cfg_umac *chan, int n_ssids, int bgscan);
    int iwx_fill_probe_req_v1(struct iwx_softc *sc, struct iwx_scan_probe_req_v1 *preq1);
    int    iwx_fill_probe_req(struct iwx_softc *, struct iwx_scan_probe_req *);
    int    iwx_config_umac_scan(struct iwx_softc *);
    int iwx_umac_scan_size(struct iwx_softc *sc);
    struct iwx_scan_umac_chan_param *iwx_get_scan_req_umac_chan_param(struct iwx_softc *sc, struct iwx_scan_req_umac *req);
    void *iwx_get_scan_req_umac_data(struct iwx_softc *sc, struct iwx_scan_req_umac *req);
    int    iwx_umac_scan(struct iwx_softc *, int);
    void    iwx_mcc_update(struct iwx_softc *, struct iwx_mcc_chub_notif *);
    uint8_t    iwx_ridx2rate(struct ieee80211_rateset *, int);
    int    iwx_rval2ridx(int);
    void    iwx_ack_rates(struct iwx_softc *, struct iwx_node *, int *, int *);
    void    iwx_mac_ctxt_cmd_common(struct iwx_softc *, struct iwx_node *,
            struct iwx_mac_ctx_cmd *, uint32_t);
    void    iwx_mac_ctxt_cmd_fill_sta(struct iwx_softc *, struct iwx_node *,
            struct iwx_mac_data_sta *, int);
    int    iwx_mac_ctxt_cmd(struct iwx_softc *, struct iwx_node *, uint32_t, int);
    int    iwx_clear_statistics(struct iwx_softc *);
    int    iwx_update_quotas(struct iwx_softc *, struct iwx_node *, int);
    void    iwx_add_task(struct iwx_softc *, struct taskq *, struct task *);
    void    iwx_del_task(struct iwx_softc *, struct taskq *, struct task *);
    int    iwx_scan(struct iwx_softc *);
    static int    iwx_bgscan(struct ieee80211com *);
    int    iwx_umac_scan_abort(struct iwx_softc *);
    int    iwx_scan_abort(struct iwx_softc *);
    int    iwx_rs_rval2idx(uint8_t);
    uint16_t iwx_rs_ht_rates(struct iwx_softc *, struct ieee80211_node *, int);
    int    iwx_rs_init(struct iwx_softc *, struct iwx_node *);
    void iwx_rs_update(struct iwx_softc *sc, struct iwx_tlc_update_notif *notif);
    int    iwx_enable_data_tx_queues(struct iwx_softc *);
    int    iwx_auth(struct iwx_softc *);
    int    iwx_deauth(struct iwx_softc *);
    int    iwx_assoc(struct iwx_softc *);
    int    iwx_disassoc(struct iwx_softc *);
    int    iwx_run(struct iwx_softc *);
    int    iwx_run_stop(struct iwx_softc *);
    static struct ieee80211_node *iwx_node_alloc(struct ieee80211com *);
    static int    iwx_set_key(struct ieee80211com *, struct ieee80211_node *,
           struct ieee80211_key *);
    static void    iwx_delete_key(struct ieee80211com *,
           struct ieee80211_node *, struct ieee80211_key *);
    int    iwx_media_change(struct ifnet *);
    static void    iwx_newstate_task(void *);
    static int    iwx_newstate(struct ieee80211com *, enum ieee80211_state, int);
    void    iwx_endscan(struct iwx_softc *);
    void    iwx_fill_sf_command(struct iwx_softc *, struct iwx_sf_cfg_cmd *,
            struct ieee80211_node *);
    int    iwx_sf_config(struct iwx_softc *, int);
    int    iwx_send_bt_init_conf(struct iwx_softc *);
    int    iwx_send_soc_conf(struct iwx_softc *);
    int    iwx_send_update_mcc_cmd(struct iwx_softc *, const char *);
    int    iwx_send_temp_report_ths_cmd(struct iwx_softc *);
    int    iwx_init_hw(struct iwx_softc *);
    int    iwx_init(struct ifnet *);
    static void    iwx_start(struct ifnet *);
    void    iwx_stop(struct ifnet *);
    static void    iwx_watchdog(struct ifnet *);
    static int    iwx_ioctl(struct ifnet *, u_long, caddr_t);
    const char *iwx_desc_lookup(uint32_t);
    void    iwx_nic_error(struct iwx_softc *);
    void    iwx_nic_umac_error(struct iwx_softc *);
    int    iwx_rx_pkt_valid(struct iwx_rx_packet *);
    void    iwx_rx_pkt(struct iwx_softc *, struct iwx_rx_data *,
            struct mbuf_list *);
    void    iwx_notif_intr(struct iwx_softc *);
    static int    iwx_intr(OSObject *object, IOInterruptEventSource* sender, int count);
    static int    iwx_intr_msix(OSObject *object, IOInterruptEventSource* sender, int count);
    int    iwx_match(IOPCIDevice *);
    int    iwx_preinit(struct iwx_softc *);
    void    iwx_attach_hook(struct device *);
    bool    iwx_attach(struct iwx_softc *, struct pci_attach_args *);
    static void    iwx_init_task(void *);
    int    iwx_activate(struct iwx_softc *, int);
    int    iwx_resume(struct iwx_softc *);
    
public:
    IOInterruptEventSource* fInterrupt;
    IOTimerEventSource *watchdogTimer;
    struct pci_attach_args pci;
    struct iwx_softc com;
    itlwmx_interface *fNetIf;
    IONetworkStats *fpNetStats;
    IOWorkLoop *fWatchdogWorkLoop;
    
    IOLock *_fwLoadLock;
    void *lastSleepChan;
    
    //pm
    thread_call_t powerOnThreadCall;
    thread_call_t powerOffThreadCall;
    UInt32 pmPowerState;
    IOService *pmPolicyMaker;
    UInt8 pmPCICapPtr;
    bool magicPacketEnabled;
    bool magicPacketSupported;
};

struct ResourceCallbackContext
{
    itlwmx* context;
    OSData* resource;
};

#endif
