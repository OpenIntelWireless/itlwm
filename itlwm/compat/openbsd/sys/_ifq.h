//
//  _ifq.h
//  itlwm
//
//  Created by qcwap on 2020/3/1.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifndef _ifq_h
#define _ifq_h
#include <net/if_var.h>

//static inline int
//ifq_is_priq(struct ifqueue *ifq)
//{
//    return (ifq->ifq_ops == ifq_priq_ops);
//}
//
//static inline void
//ifq_set_oactive(struct ifqueue *ifq)
//{
//    ifq->ifq_oactive = 1;
//}
//
//static inline void
//ifq_clr_oactive(struct ifqueue *ifq)
//{
//    ifq->ifq_oactive = 0;
//}
//
//static inline unsigned int
//ifq_is_oactive(struct ifqueue *ifq)
//{
//    return (ifq->ifq_oactive);
//}
//
//static inline void
//ifq_restart(struct ifqueue *ifq)
//{
//    ifq_serialize(ifq, &ifq->ifq_restart);
//}
//
//static inline unsigned int
//ifq_idx(struct ifqueue *ifq, unsigned int nifqs, const struct mbuf *m)
//{
//    return ((*ifq->ifq_ops->ifqop_idx)(nifqs, m));
//}

#endif /* _ifq_h */
