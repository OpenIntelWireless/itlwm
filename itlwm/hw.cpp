//
//  hw.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "itlwm.hpp"

void itlwm::
iwm_enable_rfkill_int(struct iwm_softc *sc)
{
    sc->sc_intmask = IWM_CSR_INT_BIT_RF_KILL;
    IWM_WRITE(sc, IWM_CSR_INT_MASK, sc->sc_intmask);
}

int itlwm::
iwm_check_rfkill(struct iwm_softc *sc)
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
    v = IWM_READ(sc, IWM_CSR_GP_CNTRL);
    rv = (v & IWM_CSR_GP_CNTRL_REG_FLAG_HW_RF_KILL_SW) == 0;
    if (rv) {
        sc->sc_flags |= IWM_FLAG_RFKILL;
    } else {
        sc->sc_flags &= ~IWM_FLAG_RFKILL;
    }

    splx(s);
    return rv;
}

void itlwm::
iwm_enable_interrupts(struct iwm_softc *sc)
{
    sc->sc_intmask = IWM_CSR_INI_SET_MASK;
    IWM_WRITE(sc, IWM_CSR_INT_MASK, sc->sc_intmask);
}

void
iwm_restore_interrupts(struct iwm_softc *sc)
{
    IWM_WRITE(sc, IWM_CSR_INT_MASK, sc->sc_intmask);
}

void itlwm::
iwm_disable_interrupts(struct iwm_softc *sc)
{
    int s = splnet();

    IWM_WRITE(sc, IWM_CSR_INT_MASK, 0);

    /* acknowledge all interrupts */
    IWM_WRITE(sc, IWM_CSR_INT, ~0);
    IWM_WRITE(sc, IWM_CSR_FH_INT_STATUS, ~0);

    splx(s);
}

void itlwm::
iwm_ict_reset(struct iwm_softc *sc)
{
    iwm_disable_interrupts(sc);

    memset(sc->ict_dma.vaddr, 0, IWM_ICT_SIZE);
    sc->ict_cur = 0;

    /* Set physical address of ICT (4KB aligned). */
    IWM_WRITE(sc, IWM_CSR_DRAM_INT_TBL_REG,
        IWM_CSR_DRAM_INT_TBL_ENABLE
        | IWM_CSR_DRAM_INIT_TBL_WRAP_CHECK
        | IWM_CSR_DRAM_INIT_TBL_WRITE_POINTER
        | sc->ict_dma.paddr >> IWM_ICT_PADDR_SHIFT);

    /* Switch to ICT interrupt mode in driver. */
    sc->sc_flags |= IWM_FLAG_USE_ICT;

    IWM_WRITE(sc, IWM_CSR_INT, ~0);
    iwm_enable_interrupts(sc);
}

#define IWM_HW_READY_TIMEOUT 50
int itlwm::
iwm_set_hw_ready(struct iwm_softc *sc)
{
    int ready;

    IWM_SETBITS(sc, IWM_CSR_HW_IF_CONFIG_REG,
        IWM_CSR_HW_IF_CONFIG_REG_BIT_NIC_READY);

    ready = iwm_poll_bit(sc, IWM_CSR_HW_IF_CONFIG_REG,
        IWM_CSR_HW_IF_CONFIG_REG_BIT_NIC_READY,
        IWM_CSR_HW_IF_CONFIG_REG_BIT_NIC_READY,
        IWM_HW_READY_TIMEOUT);
    if (ready)
        IWM_SETBITS(sc, IWM_CSR_MBOX_SET_REG,
            IWM_CSR_MBOX_SET_REG_OS_ALIVE);

    return ready;
}
#undef IWM_HW_READY_TIMEOUT

int itlwm::
iwm_prepare_card_hw(struct iwm_softc *sc)
{
    int t = 0;

    if (iwm_set_hw_ready(sc))
        return 0;

    DELAY(100);

    /* If HW is not ready, prepare the conditions to check again */
    IWM_SETBITS(sc, IWM_CSR_HW_IF_CONFIG_REG,
        IWM_CSR_HW_IF_CONFIG_REG_PREPARE);

    do {
        if (iwm_set_hw_ready(sc))
            return 0;
        DELAY(200);
        t += 200;
    } while (t < 150000);

    return ETIMEDOUT;
}

void itlwm::
iwm_apm_config(struct iwm_softc *sc)
{
    pcireg_t reg;

    reg = pci_conf_read(sc->sc_pct, sc->sc_pcitag,
        sc->sc_cap_off + PCI_PCIE_LCSR);
    if (reg & PCI_PCIE_LCSR_ASPM_L1) {
        /* Um the Linux driver prints "Disabling L0S for this one ... */
        IWM_SETBITS(sc, IWM_CSR_GIO_REG,
            IWM_CSR_GIO_REG_VAL_L0S_ENABLED);
    } else {
        /* ... and "Enabling" here */
        IWM_CLRBITS(sc, IWM_CSR_GIO_REG,
            IWM_CSR_GIO_REG_VAL_L0S_ENABLED);
    }
}

/*
 * Start up NIC's basic functionality after it has been reset
 * e.g. after platform boot or shutdown.
 * NOTE:  This does not load uCode nor start the embedded processor
 */
int itlwm::
iwm_apm_init(struct iwm_softc *sc)
{
    int err = 0;

    /* Disable L0S exit timer (platform NMI workaround) */
    if (sc->sc_device_family != IWM_DEVICE_FAMILY_8000)
        IWM_SETBITS(sc, IWM_CSR_GIO_CHICKEN_BITS,
            IWM_CSR_GIO_CHICKEN_BITS_REG_BIT_DIS_L0S_EXIT_TIMER);

    /*
     * Disable L0s without affecting L1;
     *  don't wait for ICH L0s (ICH bug W/A)
     */
    IWM_SETBITS(sc, IWM_CSR_GIO_CHICKEN_BITS,
        IWM_CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX);

    /* Set FH wait threshold to maximum (HW error during stress W/A) */
    IWM_SETBITS(sc, IWM_CSR_DBG_HPET_MEM_REG, IWM_CSR_DBG_HPET_MEM_REG_VAL);

    /*
     * Enable HAP INTA (interrupt from management bus) to
     * wake device's PCI Express link L1a -> L0s
     */
    IWM_SETBITS(sc, IWM_CSR_HW_IF_CONFIG_REG,
        IWM_CSR_HW_IF_CONFIG_REG_BIT_HAP_WAKE_L1A);

    iwm_apm_config(sc);

#if 0 /* not for 7k/8k */
    /* Configure analog phase-lock-loop before activating to D0A */
    if (trans->cfg->base_params->pll_cfg_val)
        IWM_SETBITS(trans, IWM_CSR_ANA_PLL_CFG,
            trans->cfg->base_params->pll_cfg_val);
#endif

    /*
     * Set "initialization complete" bit to move adapter from
     * D0U* --> D0A* (powered-up active) state.
     */
    IWM_SETBITS(sc, IWM_CSR_GP_CNTRL, IWM_CSR_GP_CNTRL_REG_FLAG_INIT_DONE);

    /*
     * Wait for clock stabilization; once stabilized, access to
     * device-internal resources is supported, e.g. iwm_write_prph()
     * and accesses to uCode SRAM.
     */
    if (!iwm_poll_bit(sc, IWM_CSR_GP_CNTRL,
        IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
        IWM_CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY, 25000)) {
        printf("%s: timeout waiting for clock stabilization\n",
            DEVNAME(sc));
        err = ETIMEDOUT;
        goto out;
    }

    if (sc->host_interrupt_operation_mode) {
        /*
         * This is a bit of an abuse - This is needed for 7260 / 3160
         * only check host_interrupt_operation_mode even if this is
         * not related to host_interrupt_operation_mode.
         *
         * Enable the oscillator to count wake up time for L1 exit. This
         * consumes slightly more power (100uA) - but allows to be sure
         * that we wake up from L1 on time.
         *
         * This looks weird: read twice the same register, discard the
         * value, set a bit, and yet again, read that same register
         * just to discard the value. But that's the way the hardware
         * seems to like it.
         */
        if (iwm_nic_lock(sc)) {
            iwm_read_prph(sc, IWM_OSC_CLK);
            iwm_read_prph(sc, IWM_OSC_CLK);
            iwm_nic_unlock(sc);
        }
        iwm_set_bits_prph(sc, IWM_OSC_CLK, IWM_OSC_CLK_FORCE_CONTROL);
        if (iwm_nic_lock(sc)) {
            iwm_read_prph(sc, IWM_OSC_CLK);
            iwm_read_prph(sc, IWM_OSC_CLK);
            iwm_nic_unlock(sc);
        }
    }

    /*
     * Enable DMA clock and wait for it to stabilize.
     *
     * Write to "CLK_EN_REG"; "1" bits enable clocks, while "0" bits
     * do not disable clocks.  This preserves any hardware bits already
     * set by default in "CLK_CTRL_REG" after reset.
     */
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000) {
        if (iwm_nic_lock(sc)) {
            iwm_write_prph(sc, IWM_APMG_CLK_EN_REG,
                IWM_APMG_CLK_VAL_DMA_CLK_RQT);
            iwm_nic_unlock(sc);
        }
        DELAY(20);

        /* Disable L1-Active */
        iwm_set_bits_prph(sc, IWM_APMG_PCIDEV_STT_REG,
            IWM_APMG_PCIDEV_STT_VAL_L1_ACT_DIS);

        /* Clear the interrupt in APMG if the NIC is in RFKILL */
        if (iwm_nic_lock(sc)) {
            iwm_write_prph(sc, IWM_APMG_RTC_INT_STT_REG,
                IWM_APMG_RTC_INT_STT_RFKILL);
            iwm_nic_unlock(sc);
        }
    }
 out:
    if (err)
        printf("%s: apm init error %d\n", DEVNAME(sc), err);
    return err;
}

void itlwm::
iwm_apm_stop(struct iwm_softc *sc)
{
    /* stop device's busmaster DMA activity */
    IWM_SETBITS(sc, IWM_CSR_RESET, IWM_CSR_RESET_REG_FLAG_STOP_MASTER);

    if (!iwm_poll_bit(sc, IWM_CSR_RESET,
        IWM_CSR_RESET_REG_FLAG_MASTER_DISABLED,
        IWM_CSR_RESET_REG_FLAG_MASTER_DISABLED, 100))
        printf("%s: timeout waiting for master\n", DEVNAME(sc));
}

int itlwm::
iwm_start_hw(struct iwm_softc *sc)
{
    XYLog("%s\n", __func__);
    int err;

    err = iwm_prepare_card_hw(sc);
    if (err)
        return err;

    /* Reset the entire device */
    IWM_WRITE(sc, IWM_CSR_RESET, IWM_CSR_RESET_REG_FLAG_SW_RESET);
    DELAY(10);

    err = iwm_apm_init(sc);
    if (err)
        return err;

    iwm_enable_rfkill_int(sc);
    iwm_check_rfkill(sc);

    return 0;
}


void itlwm::
iwm_stop_device(struct iwm_softc *sc)
{
    XYLog("%s\n", __func__);
    int chnl, ntries;
    int qid;

    iwm_disable_interrupts(sc);
    sc->sc_flags &= ~IWM_FLAG_USE_ICT;

    /* Stop all DMA channels. */
    if (iwm_nic_lock(sc)) {
        /* Deactivate TX scheduler. */
        iwm_write_prph(sc, IWM_SCD_TXFACT, 0);

        for (chnl = 0; chnl < IWM_FH_TCSR_CHNL_NUM; chnl++) {
            IWM_WRITE(sc,
                IWM_FH_TCSR_CHNL_TX_CONFIG_REG(chnl), 0);
            for (ntries = 0; ntries < 200; ntries++) {
                uint32_t r;

                r = IWM_READ(sc, IWM_FH_TSSR_TX_STATUS_REG);
                if (r & IWM_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE(
                    chnl))
                    break;
                DELAY(20);
            }
        }
        iwm_nic_unlock(sc);
    }
    iwm_disable_rx_dma(sc);

    iwm_reset_rx_ring(sc, &sc->rxq);

    for (qid = 0; qid < nitems(sc->txq); qid++)
        iwm_reset_tx_ring(sc, &sc->txq[qid]);

    if (iwm_nic_lock(sc)) {
        /* Power-down device's busmaster DMA clocks */
        iwm_write_prph(sc, IWM_APMG_CLK_DIS_REG,
            IWM_APMG_CLK_VAL_DMA_CLK_RQT);
        iwm_nic_unlock(sc);
    }
    DELAY(5);

    /* Make sure (redundant) we've released our request to stay awake */
    IWM_CLRBITS(sc, IWM_CSR_GP_CNTRL,
        IWM_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
    if (sc->sc_nic_locks > 0)
        printf("%s: %d active NIC locks forcefully cleared\n",
            DEVNAME(sc), sc->sc_nic_locks);
    sc->sc_nic_locks = 0;

    /* Stop the device, and put it in low power state */
    iwm_apm_stop(sc);

    /*
     * Upon stop, the APM issues an interrupt if HW RF kill is set.
     * Clear the interrupt again.
     */
    iwm_disable_interrupts(sc);

    /* Reset the on-board processor. */
    IWM_WRITE(sc, IWM_CSR_RESET, IWM_CSR_RESET_REG_FLAG_SW_RESET);

    /* Even though we stop the HW we still want the RF kill interrupt. */
    iwm_enable_rfkill_int(sc);
    iwm_check_rfkill(sc);
}

void itlwm::
iwm_nic_config(struct iwm_softc *sc)
{
    uint8_t radio_cfg_type, radio_cfg_step, radio_cfg_dash;
    uint32_t reg_val = 0;

    radio_cfg_type = (sc->sc_fw_phy_config & IWM_FW_PHY_CFG_RADIO_TYPE) >>
        IWM_FW_PHY_CFG_RADIO_TYPE_POS;
    radio_cfg_step = (sc->sc_fw_phy_config & IWM_FW_PHY_CFG_RADIO_STEP) >>
        IWM_FW_PHY_CFG_RADIO_STEP_POS;
    radio_cfg_dash = (sc->sc_fw_phy_config & IWM_FW_PHY_CFG_RADIO_DASH) >>
        IWM_FW_PHY_CFG_RADIO_DASH_POS;

    reg_val |= IWM_CSR_HW_REV_STEP(sc->sc_hw_rev) <<
        IWM_CSR_HW_IF_CONFIG_REG_POS_MAC_STEP;
    reg_val |= IWM_CSR_HW_REV_DASH(sc->sc_hw_rev) <<
        IWM_CSR_HW_IF_CONFIG_REG_POS_MAC_DASH;

    /* radio configuration */
    reg_val |= radio_cfg_type << IWM_CSR_HW_IF_CONFIG_REG_POS_PHY_TYPE;
    reg_val |= radio_cfg_step << IWM_CSR_HW_IF_CONFIG_REG_POS_PHY_STEP;
    reg_val |= radio_cfg_dash << IWM_CSR_HW_IF_CONFIG_REG_POS_PHY_DASH;

    IWM_WRITE(sc, IWM_CSR_HW_IF_CONFIG_REG, reg_val);

    /*
     * W/A : NIC is stuck in a reset state after Early PCIe power off
     * (PCIe power is lost before PERST# is asserted), causing ME FW
     * to lose ownership and not being able to obtain it back.
     */
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000)
        iwm_set_bits_mask_prph(sc, IWM_APMG_PS_CTRL_REG,
            IWM_APMG_PS_CTRL_EARLY_PWR_OFF_RESET_DIS,
            ~IWM_APMG_PS_CTRL_EARLY_PWR_OFF_RESET_DIS);
}

int itlwm::
iwm_nic_rx_init(struct iwm_softc *sc)
{
    memset(sc->rxq.stat, 0, sizeof(*sc->rxq.stat));

    iwm_disable_rx_dma(sc);

    if (!iwm_nic_lock(sc))
        return EBUSY;

    /* reset and flush pointers */
    IWM_WRITE(sc, IWM_FH_MEM_RCSR_CHNL0_RBDCB_WPTR, 0);
    IWM_WRITE(sc, IWM_FH_MEM_RCSR_CHNL0_FLUSH_RB_REQ, 0);
    IWM_WRITE(sc, IWM_FH_RSCSR_CHNL0_RDPTR, 0);
    IWM_WRITE(sc, IWM_FH_RSCSR_CHNL0_RBDCB_WPTR_REG, 0);

    /* Set physical address of RX ring (256-byte aligned). */
    IWM_WRITE(sc,
        IWM_FH_RSCSR_CHNL0_RBDCB_BASE_REG, sc->rxq.desc_dma.paddr >> 8);

    /* Set physical address of RX status (16-byte aligned). */
    IWM_WRITE(sc,
        IWM_FH_RSCSR_CHNL0_STTS_WPTR_REG, sc->rxq.stat_dma.paddr >> 4);

    /* Enable RX. */
    IWM_WRITE(sc, IWM_FH_MEM_RCSR_CHNL0_CONFIG_REG,
        IWM_FH_RCSR_RX_CONFIG_CHNL_EN_ENABLE_VAL        |
        IWM_FH_RCSR_CHNL0_RX_IGNORE_RXF_EMPTY        |  /* HW bug */
        IWM_FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_INT_HOST_VAL    |
        IWM_FH_RCSR_CHNL0_RX_CONFIG_SINGLE_FRAME_MSK    |
        (IWM_RX_RB_TIMEOUT << IWM_FH_RCSR_RX_CONFIG_REG_IRQ_RBTH_POS) |
        IWM_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_4K        |
        IWM_RX_QUEUE_SIZE_LOG << IWM_FH_RCSR_RX_CONFIG_RBDCB_SIZE_POS);

    IWM_WRITE_1(sc, IWM_CSR_INT_COALESCING, IWM_HOST_INT_TIMEOUT_DEF);

    /* W/A for interrupt coalescing bug in 7260 and 3160 */
    if (sc->host_interrupt_operation_mode)
        IWM_SETBITS(sc, IWM_CSR_INT_COALESCING, IWM_HOST_INT_OPER_MODE);

    /*
     * This value should initially be 0 (before preparing any RBs),
     * and should be 8 after preparing the first 8 RBs (for example).
     */
    IWM_WRITE(sc, IWM_FH_RSCSR_CHNL0_WPTR, 8);

    iwm_nic_unlock(sc);

    return 0;
}

int itlwm::
iwm_nic_tx_init(struct iwm_softc *sc)
{
    int qid;

    if (!iwm_nic_lock(sc))
        return EBUSY;

    /* Deactivate TX scheduler. */
    iwm_write_prph(sc, IWM_SCD_TXFACT, 0);

    /* Set physical address of "keep warm" page (16-byte aligned). */
    IWM_WRITE(sc, IWM_FH_KW_MEM_ADDR_REG, sc->kw_dma.paddr >> 4);

    for (qid = 0; qid < nitems(sc->txq); qid++) {
        struct iwm_tx_ring *txq = &sc->txq[qid];

        /* Set physical address of TX ring (256-byte aligned). */
        IWM_WRITE(sc, IWM_FH_MEM_CBBC_QUEUE(qid),
            txq->desc_dma.paddr >> 8);
    }

    iwm_write_prph(sc, IWM_SCD_GP_CTRL, IWM_SCD_GP_CTRL_AUTO_ACTIVE_MODE);

    iwm_nic_unlock(sc);

    return 0;
}

int itlwm::
iwm_nic_init(struct iwm_softc *sc)
{
    int err;

    iwm_apm_init(sc);
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000)
        iwm_set_bits_mask_prph(sc, IWM_APMG_PS_CTRL_REG,
            IWM_APMG_PS_CTRL_VAL_PWR_SRC_VMAIN,
            ~IWM_APMG_PS_CTRL_MSK_PWR_SRC);

    iwm_nic_config(sc);

    err = iwm_nic_rx_init(sc);
    if (err)
        return err;

    err = iwm_nic_tx_init(sc);
    if (err)
        return err;

    IWM_SETBITS(sc, IWM_CSR_MAC_SHADOW_REG_CTRL, 0x800fffff);

    return 0;
}

void itlwm::
iwm_restore_interrupts(struct iwm_softc *sc)
{
    IWM_WRITE(sc, IWM_CSR_INT_MASK, sc->sc_intmask);
}
