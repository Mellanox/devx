/*
* Copyright (C) Mellanox Technologies Ltd, 2001-2018. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef __DEVX_DPDK_H__
#define __DEVX_DPDK_H__

#include "devx.h"
#include <rte_bus_pci.h>

#ifdef __cplusplus
extern "C" {
#endif

int devx_device_to_pci_addr(const struct devx_device *device,
			    struct rte_pci_addr *pci_addr);

#ifdef __cplusplus
}
#endif

#endif
