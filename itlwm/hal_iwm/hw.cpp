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

void ItlIwm::
iwm_enable_rfkill_int(struct iwm_softc *sc)
{
    if (!sc->sc_msix) {
        sc->sc_intmask = IWM_CSR_INT_BIT_RF_KILL;
        IWM_WRITE(sc, IWM_CSR_INT_MASK, sc->sc_intmask);
    } else {
        IWM_WRITE(sc, IWM_CSR_MSIX_FH_INT_MASK_AD,
                  sc->sc_fh_init_mask);
        IWM_WRITE(sc, IWM_CSR_MSIX_HW_INT_MASK_AD,
                  ~IWM_MSIX_HW_INT_CAUSES_REG_RF_KILL);
        sc->sc_hw_mask = IWM_MSIX_HW_INT_CAUSES_REG_RF_KILL;
    }
    
    if (sc->sc_device_family >= IWM_DEVICE_FAMILY_9000)
        IWM_SETBITS(sc, IWM_CSR_GP_CNTRL,
                    IWM_CSR_GP_CNTRL_REG_FLAG_RFKILL_WAKE_L1A_EN);
}

int ItlIwm::
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

void ItlIwm::
iwm_enable_interrupts(struct iwm_softc *sc)
{
    if (!sc->sc_msix) {
        sc->sc_intmask = IWM_CSR_INI_SET_MASK;
        IWM_WRITE(sc, IWM_CSR_INT_MASK, sc->sc_intmask);
    } else {
        /*
         * fh/hw_mask keeps all the unmasked causes.
         * Unlike msi, in msix cause is enabled when it is unset.
         */
        sc->sc_hw_mask = sc->sc_hw_init_mask;
        sc->sc_fh_mask = sc->sc_fh_init_mask;
        IWM_WRITE(sc, IWM_CSR_MSIX_FH_INT_MASK_AD,
                  ~sc->sc_fh_mask);
        IWM_WRITE(sc, IWM_CSR_MSIX_HW_INT_MASK_AD,
                  ~sc->sc_hw_mask);
    }
}

void ItlIwm::
iwm_enable_fwload_interrupt(struct iwm_softc *sc)
{
    if (!sc->sc_msix) {
        sc->sc_intmask = IWM_CSR_INT_BIT_FH_TX;
        IWM_WRITE(sc, IWM_CSR_INT_MASK, sc->sc_intmask);
    } else {
        IWM_WRITE(sc, IWM_CSR_MSIX_HW_INT_MASK_AD,
                  sc->sc_hw_init_mask);
        IWM_WRITE(sc, IWM_CSR_MSIX_FH_INT_MASK_AD,
                  ~IWM_MSIX_FH_INT_CAUSES_D2S_CH0_NUM);
        sc->sc_fh_mask = IWM_MSIX_FH_INT_CAUSES_D2S_CH0_NUM;
    }
}

void
iwm_restore_interrupts(struct iwm_softc *sc)
{
    IWM_WRITE(sc, IWM_CSR_INT_MASK, sc->sc_intmask);
}

void ItlIwm::
iwm_disable_interrupts(struct iwm_softc *sc)
{
    int s = splnet();
    
    if (!sc->sc_msix) {
        IWM_WRITE(sc, IWM_CSR_INT_MASK, 0);
        
        /* acknowledge all interrupts */
        IWM_WRITE(sc, IWM_CSR_INT, ~0);
        IWM_WRITE(sc, IWM_CSR_FH_INT_STATUS, ~0);
    } else {
        IWM_WRITE(sc, IWM_CSR_MSIX_FH_INT_MASK_AD,
                  sc->sc_fh_init_mask);
        IWM_WRITE(sc, IWM_CSR_MSIX_HW_INT_MASK_AD,
                  sc->sc_hw_init_mask);
    }
    
    splx(s);
}

void ItlIwm::
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
int ItlIwm::
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

int ItlIwm::
iwm_prepare_card_hw(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int t = 0;
    
    if (iwm_set_hw_ready(sc))
        return 0;
    
    IWM_SETBITS(sc, IWM_CSR_DBG_LINK_PWR_MGMT_REG,
                IWM_CSR_RESET_LINK_PWR_MGMT_DISABLED);
    DELAY(1000);
    
    
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

void ItlIwm::
iwm_apm_config(struct iwm_softc *sc)
{
    pcireg_t lctl, cap;
    
    /*
     * L0S states have been found to be unstable with our devices
     * and in newer hardware they are not officially supported at
     * all, so we must always set the L0S_DISABLED bit.
     */
    lctl = pci_conf_read(sc->sc_pct, sc->sc_pcitag,
                         sc->sc_cap_off + PCI_PCIE_LCSR);
    IWM_SETBITS(sc, IWM_CSR_GIO_REG, IWM_CSR_GIO_REG_VAL_L0S_DISABLED);
    
    cap = pci_conf_read(sc->sc_pct, sc->sc_pcitag,
                        sc->sc_cap_off + PCI_PCIE_DCSR2);
    sc->sc_ltr_enabled = (cap & PCI_PCIE_DCSR2_LTREN) ? 1 : 0;
    XYLog("%s: L1 %sabled - LTR %sabled\n",
          DEVNAME(sc),
          (lctl & PCI_PCIE_LCSR_ASPM_L1) ? "En" : "Dis",
          sc->sc_ltr_enabled ? "En" : "Dis");
}

/*
 * Start up NIC's basic functionality after it has been reset
 * e.g. after platform boot or shutdown.
 * NOTE:  This does not load uCode nor start the embedded processor
 */
int ItlIwm::
iwm_apm_init(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int err = 0;
    
    /* Disable L0S exit timer (platform NMI workaround) */
    if (sc->sc_device_family < IWM_DEVICE_FAMILY_8000)
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
        XYLog("%s: timeout waiting for clock stabilization\n",
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
        XYLog("%s: apm init error %d\n", DEVNAME(sc), err);
    return err;
}

void ItlIwm::
iwm_apm_stop(struct iwm_softc *sc)
{
    IWM_SETBITS(sc, IWM_CSR_DBG_LINK_PWR_MGMT_REG,
                IWM_CSR_RESET_LINK_PWR_MGMT_DISABLED);
    IWM_SETBITS(sc, IWM_CSR_HW_IF_CONFIG_REG,
                IWM_CSR_HW_IF_CONFIG_REG_PREPARE |
                IWM_CSR_HW_IF_CONFIG_REG_ENABLE_PME);
    DELAY(1000);
    IWM_CLRBITS(sc, IWM_CSR_DBG_LINK_PWR_MGMT_REG,
                IWM_CSR_RESET_LINK_PWR_MGMT_DISABLED);
    DELAY(5000);
    
    /* stop device's busmaster DMA activity */
    IWM_SETBITS(sc, IWM_CSR_RESET, IWM_CSR_RESET_REG_FLAG_STOP_MASTER);
    
    if (!iwm_poll_bit(sc, IWM_CSR_RESET,
                      IWM_CSR_RESET_REG_FLAG_MASTER_DISABLED,
                      IWM_CSR_RESET_REG_FLAG_MASTER_DISABLED, 100))
        XYLog("%s: timeout waiting for master\n", DEVNAME(sc));
    
    /*
     * Clear "initialization complete" bit to move adapter from
     * D0A* (powered-up Active) --> D0U* (Uninitialized) state.
     */
    IWM_CLRBITS(sc, IWM_CSR_GP_CNTRL,
                IWM_CSR_GP_CNTRL_REG_FLAG_INIT_DONE);
}

void ItlIwm::
iwm_init_msix_hw(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    iwm_conf_msix_hw(sc, 0);
    
    if (!sc->sc_msix)
        return;
    
    sc->sc_fh_init_mask = ~IWM_READ(sc, IWM_CSR_MSIX_FH_INT_MASK_AD);
    sc->sc_fh_mask = sc->sc_fh_init_mask;
    sc->sc_hw_init_mask = ~IWM_READ(sc, IWM_CSR_MSIX_HW_INT_MASK_AD);
    sc->sc_hw_mask = sc->sc_hw_init_mask;
}

void ItlIwm::
iwm_conf_msix_hw(struct iwm_softc *sc, int stopped)
{
    XYLog("%s\n", __FUNCTION__);
    int vector = 0;
    
    if (!sc->sc_msix) {
        /* Newer chips default to MSIX. */
        if (sc->sc_mqrx_supported && !stopped && iwm_nic_lock(sc)) {
            iwm_write_prph(sc, IWM_UREG_CHICK,
                           IWM_UREG_CHICK_MSI_ENABLE);
            iwm_nic_unlock(sc);
        }
        return;
    }
    
    if (!stopped && iwm_nic_lock(sc)) {
        iwm_write_prph(sc, IWM_UREG_CHICK, IWM_UREG_CHICK_MSIX_ENABLE);
        iwm_nic_unlock(sc);
    }
    
    /* Disable all interrupts */
    IWM_WRITE(sc, IWM_CSR_MSIX_FH_INT_MASK_AD, ~0);
    IWM_WRITE(sc, IWM_CSR_MSIX_HW_INT_MASK_AD, ~0);
    
    /* Map fallback-queue (command/mgmt) to a single vector */
    IWM_WRITE_1(sc, IWM_CSR_MSIX_RX_IVAR(0),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    /* Map RSS queue (data) to the same vector */
    IWM_WRITE_1(sc, IWM_CSR_MSIX_RX_IVAR(1),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    
    /* Enable the RX queues cause interrupts */
    IWM_CLRBITS(sc, IWM_CSR_MSIX_FH_INT_MASK_AD,
                IWM_MSIX_FH_INT_CAUSES_Q0 | IWM_MSIX_FH_INT_CAUSES_Q1);
    
    /* Map non-RX causes to the same vector */
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_D2S_CH0_NUM),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_D2S_CH1_NUM),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_S2D),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_FH_ERR),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_REG_ALIVE),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_REG_WAKEUP),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_REG_IML),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_REG_CT_KILL),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_REG_RF_KILL),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_REG_PERIODIC),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_REG_SW_ERR),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_REG_SCD),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_REG_FH_TX),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_REG_HW_ERR),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    IWM_WRITE_1(sc, IWM_CSR_MSIX_IVAR(IWM_MSIX_IVAR_CAUSE_REG_HAP),
                vector | IWM_MSIX_NON_AUTO_CLEAR_CAUSE);
    
    /* Enable non-RX causes interrupts */
    IWM_CLRBITS(sc, IWM_CSR_MSIX_FH_INT_MASK_AD,
                IWM_MSIX_FH_INT_CAUSES_D2S_CH0_NUM |
                IWM_MSIX_FH_INT_CAUSES_D2S_CH1_NUM |
                IWM_MSIX_FH_INT_CAUSES_S2D |
                IWM_MSIX_FH_INT_CAUSES_FH_ERR);
    IWM_CLRBITS(sc, IWM_CSR_MSIX_HW_INT_MASK_AD,
                IWM_MSIX_HW_INT_CAUSES_REG_ALIVE |
                IWM_MSIX_HW_INT_CAUSES_REG_WAKEUP |
                IWM_MSIX_HW_INT_CAUSES_REG_IML |
                IWM_MSIX_HW_INT_CAUSES_REG_CT_KILL |
                IWM_MSIX_HW_INT_CAUSES_REG_RF_KILL |
                IWM_MSIX_HW_INT_CAUSES_REG_PERIODIC |
                IWM_MSIX_HW_INT_CAUSES_REG_SW_ERR |
                IWM_MSIX_HW_INT_CAUSES_REG_SCD |
                IWM_MSIX_HW_INT_CAUSES_REG_FH_TX |
                IWM_MSIX_HW_INT_CAUSES_REG_HW_ERR |
                IWM_MSIX_HW_INT_CAUSES_REG_HAP);
}

int ItlIwm::
iwm_start_hw(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    int err;
    
    err = iwm_prepare_card_hw(sc);
    if (err)
        return err;
    
    /* Reset the entire device */
    IWM_WRITE(sc, IWM_CSR_RESET, IWM_CSR_RESET_REG_FLAG_SW_RESET);
    DELAY(5000);
    
    err = iwm_apm_init(sc);
    if (err)
        return err;
    
    iwm_init_msix_hw(sc);
    
    iwm_enable_rfkill_int(sc);
    iwm_check_rfkill(sc);
    
    return 0;
}


void ItlIwm::
iwm_stop_device(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
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
    
    if (sc->sc_device_family == IWM_DEVICE_FAMILY_7000) {
        if (iwm_nic_lock(sc)) {
            /* Power-down device's busmaster DMA clocks */
            iwm_write_prph(sc, IWM_APMG_CLK_DIS_REG,
                           IWM_APMG_CLK_VAL_DMA_CLK_RQT);
            iwm_nic_unlock(sc);
        }
        DELAY(5);
    }
    
    /* Make sure (redundant) we've released our request to stay awake */
    IWM_CLRBITS(sc, IWM_CSR_GP_CNTRL,
                IWM_CSR_GP_CNTRL_REG_FLAG_MAC_ACCESS_REQ);
    if (sc->sc_nic_locks > 0)
        XYLog("%s: %d active NIC locks forcefully cleared\n",
              DEVNAME(sc), sc->sc_nic_locks);
    sc->sc_nic_locks = 0;
    
    /* Stop the device, and put it in low power state */
    iwm_apm_stop(sc);
    
    /* Reset the on-board processor. */
    IWM_WRITE(sc, IWM_CSR_RESET, IWM_CSR_RESET_REG_FLAG_SW_RESET);
    DELAY(5000);
    
    /*
     * Upon stop, the IVAR table gets erased, so msi-x won't
     * work. This causes a bug in RF-KILL flows, since the interrupt
     * that enables radio won't fire on the correct irq, and the
     * driver won't be able to handle the interrupt.
     * Configure the IVAR table again after reset.
     */
    iwm_conf_msix_hw(sc, 1);
    
    /*
     * Upon stop, the APM issues an interrupt if HW RF kill is set.
     * Clear the interrupt again.
     */
    iwm_disable_interrupts(sc);
    
    /* Even though we stop the HW we still want the RF kill interrupt. */
    iwm_enable_rfkill_int(sc);
    iwm_check_rfkill(sc);
    
    iwm_prepare_card_hw(sc);
}

void ItlIwm::
iwm_nic_config(struct iwm_softc *sc)
{
    uint8_t radio_cfg_type, radio_cfg_step, radio_cfg_dash;
    uint32_t mask, val, reg_val = 0;
    
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
    
    mask = IWM_CSR_HW_IF_CONFIG_REG_MSK_MAC_DASH |
    IWM_CSR_HW_IF_CONFIG_REG_MSK_MAC_STEP |
    IWM_CSR_HW_IF_CONFIG_REG_MSK_PHY_STEP |
    IWM_CSR_HW_IF_CONFIG_REG_MSK_PHY_DASH |
    IWM_CSR_HW_IF_CONFIG_REG_MSK_PHY_TYPE |
    IWM_CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI |
    IWM_CSR_HW_IF_CONFIG_REG_BIT_MAC_SI;
    
    val = IWM_READ(sc, IWM_CSR_HW_IF_CONFIG_REG);
    val &= ~mask;
    val |= reg_val;
    IWM_WRITE(sc, IWM_CSR_HW_IF_CONFIG_REG, val);
    
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

int ItlIwm::
iwm_nic_rx_init(struct iwm_softc *sc)
{
    if (sc->sc_mqrx_supported)
        return iwm_nic_rx_mq_init(sc);
    else
        return iwm_nic_rx_legacy_init(sc);
}

int ItlIwm::
iwm_nic_rx_mq_init(struct iwm_softc *sc)
{
    int enabled;
    
    if (!iwm_nic_lock(sc))
        return EBUSY;
    
    /* Stop RX DMA. */
    iwm_write_prph(sc, IWM_RFH_RXF_DMA_CFG, 0);
    /* Disable RX used and free queue operation. */
    iwm_write_prph(sc, IWM_RFH_RXF_RXQ_ACTIVE, 0);
    
    iwm_write_prph64(sc, IWM_RFH_Q0_FRBDCB_BA_LSB,
                     sc->rxq.free_desc_dma.paddr);
    iwm_write_prph64(sc, IWM_RFH_Q0_URBDCB_BA_LSB,
                     sc->rxq.used_desc_dma.paddr);
    iwm_write_prph64(sc, IWM_RFH_Q0_URBD_STTS_WPTR_LSB,
                     sc->rxq.stat_dma.paddr);
    iwm_write_prph(sc, IWM_RFH_Q0_FRBDCB_WIDX, 0);
    iwm_write_prph(sc, IWM_RFH_Q0_FRBDCB_RIDX, 0);
    iwm_write_prph(sc, IWM_RFH_Q0_URBDCB_WIDX, 0);
    
    /* We configure only queue 0 for now. */
    enabled = ((1 << 0) << 16) | (1 << 0);
    
    /* Enable RX DMA, 4KB buffer size. */
    iwm_write_prph(sc, IWM_RFH_RXF_DMA_CFG,
                   IWM_RFH_DMA_EN_ENABLE_VAL |
                   IWM_RFH_RXF_DMA_RB_SIZE_4K |
                   IWM_RFH_RXF_DMA_MIN_RB_4_8 |
                   IWM_RFH_RXF_DMA_DROP_TOO_LARGE_MASK |
                   IWM_RFH_RXF_DMA_RBDCB_SIZE_512);
    
    /* Enable RX DMA snooping. */
    iwm_write_prph(sc, IWM_RFH_GEN_CFG,
                   IWM_RFH_GEN_CFG_RFH_DMA_SNOOP |
                   IWM_RFH_GEN_CFG_SERVICE_DMA_SNOOP |
                   (sc->sc_integrated ? IWM_RFH_GEN_CFG_RB_CHUNK_SIZE_64 :
                    IWM_RFH_GEN_CFG_RB_CHUNK_SIZE_128));
    
    /* Enable the configured queue(s). */
    iwm_write_prph(sc, IWM_RFH_RXF_RXQ_ACTIVE, enabled);
    
    iwm_nic_unlock(sc);
    
    IWM_WRITE_1(sc, IWM_CSR_INT_COALESCING, IWM_HOST_INT_TIMEOUT_DEF);
    
    IWM_WRITE(sc, IWM_RFH_Q0_FRBDCB_WIDX_TRG, 8);
    
    return 0;
}

int ItlIwm::
iwm_nic_rx_legacy_init(struct iwm_softc *sc)
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
              IWM_FH_RSCSR_CHNL0_RBDCB_BASE_REG, sc->rxq.free_desc_dma.paddr >> 8);
    
    /* Set physical address of RX status (16-byte aligned). */
    IWM_WRITE(sc,
              IWM_FH_RSCSR_CHNL0_STTS_WPTR_REG, sc->rxq.stat_dma.paddr >> 4);
    
    /* Enable RX. */
    IWM_WRITE(sc, IWM_FH_MEM_RCSR_CHNL0_CONFIG_REG,
              IWM_FH_RCSR_RX_CONFIG_CHNL_EN_ENABLE_VAL        |
              IWM_FH_RCSR_CHNL0_RX_IGNORE_RXF_EMPTY        |  /* HW bug */
              IWM_FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_INT_HOST_VAL    |
              (IWM_RX_RB_TIMEOUT << IWM_FH_RCSR_RX_CONFIG_REG_IRQ_RBTH_POS) |
              IWM_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_4K        |
              IWM_RX_QUEUE_SIZE_LOG << IWM_FH_RCSR_RX_CONFIG_RBDCB_SIZE_POS);
    
    IWM_WRITE_1(sc, IWM_CSR_INT_COALESCING, IWM_HOST_INT_TIMEOUT_DEF);
    
    /* W/A for interrupt coalescing bug in 7260 and 3160 */
    if (sc->host_interrupt_operation_mode)
        IWM_SETBITS(sc, IWM_CSR_INT_COALESCING, IWM_HOST_INT_OPER_MODE);
    
    iwm_nic_unlock(sc);
    
    /*
     * This value should initially be 0 (before preparing any RBs),
     * and should be 8 after preparing the first 8 RBs (for example).
     */
    IWM_WRITE(sc, IWM_FH_RSCSR_CHNL0_WPTR, 8);
    
    return 0;
}

int ItlIwm::
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
    
    iwm_set_bits_prph(sc, IWM_SCD_GP_CTRL,
                      IWM_SCD_GP_CTRL_AUTO_ACTIVE_MODE |
                      IWM_SCD_GP_CTRL_ENABLE_31_QUEUES);
    
    iwm_nic_unlock(sc);
    
    return 0;
}

int ItlIwm::
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

void ItlIwm::
iwm_restore_interrupts(struct iwm_softc *sc)
{
    IWM_WRITE(sc, IWM_CSR_INT_MASK, sc->sc_intmask);
}
