//
//  _ifq.h
//  itlwm
//
//  Created by qcwap on 2020/3/1.
//  Copyright © 2020 钟先耀. All rights reserved.
//
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
