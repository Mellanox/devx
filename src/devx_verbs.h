/*
* Copyright (C) Mellanox Technologies Ltd, 2001-2018. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef __DEVX_VERBS_H__
#define __DEVX_VERBS_H__

#include <infiniband/verbs.h>

#ifdef __cplusplus
extern "C" {
#endif

void *devx_from_ibv(struct ibv_context *ibctx);

#ifdef __cplusplus
}
#endif

#endif
