//
//  ItlGate.hpp
//  itlwm
//
//  Helper for kicking the TX start task from the itlwm output thread.
//

#ifndef ItlGate_hpp
#define ItlGate_hpp

#include <IOKit/IOCommandGate.h>
#include <IOKit/IOLib.h>

/*
 * attemptAction() never waits for the command gate, so a TX start that races
 * with the workloop is silently skipped until the next trigger. Retry for a
 * short, bounded time (at most about 1 ms) instead of blocking.
 *
 * Do not replace this with runAction() on the itlwm output thread:
 * itlwm::setLinkStatus() calls stopOutputThread() from the workloop while the
 * gate is held, and a runAction() waiting for that gate could then deadlock.
 */
static inline IOReturn
itlAttemptActionRetry(IOCommandGate *gate, IOCommandGate::Action action, void *arg0)
{
      IOReturn ret = gate->attemptAction(action, arg0);
      for (unsigned tries = 0; ret == kIOReturnCannotLock && tries < 40; tries++) {
          IODelay(25);
          ret = gate->attemptAction(action, arg0);
      }
      return ret;
}
 
#endif
