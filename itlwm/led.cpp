//
//  led.cpp
//  itlwm
//
//  Created by 钟先耀 on 2020/2/19.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#include "itlwm.hpp"

void itlwm::
iwm_led_enable(struct iwm_softc *sc)
{
    IWM_WRITE(sc, IWM_CSR_LED_REG, IWM_CSR_LED_REG_TURN_ON);
}

void itlwm::
iwm_led_disable(struct iwm_softc *sc)
{
    IWM_WRITE(sc, IWM_CSR_LED_REG, IWM_CSR_LED_REG_TURN_OFF);
}

int itlwm::
iwm_led_is_enabled(struct iwm_softc *sc)
{
    return (IWM_READ(sc, IWM_CSR_LED_REG) == IWM_CSR_LED_REG_TURN_ON);
}

#define IWM_LED_BLINK_TIMEOUT_MSEC    200

void itlwm::
iwm_led_blink_timeout(void *arg)
{
    struct iwm_softc *sc = (struct iwm_softc *)arg;
    itlwm *that = container_of(sc, itlwm, com);

    if (that->iwm_led_is_enabled(sc))
        that->iwm_led_disable(sc);
    else
        that->iwm_led_enable(sc);

    timeout_add_msec(&sc->sc_led_blink_to, IWM_LED_BLINK_TIMEOUT_MSEC);
}

void itlwm::
iwm_led_blink_start(struct iwm_softc *sc)
{
    timeout_add_msec(&sc->sc_led_blink_to, IWM_LED_BLINK_TIMEOUT_MSEC);
    iwm_led_enable(sc);
}

void itlwm::
iwm_led_blink_stop(struct iwm_softc *sc)
{
    timeout_del(&sc->sc_led_blink_to);
    iwm_led_disable(sc);
}
