/*
* Copyright (C) Mellanox Technologies Ltd, 2001-2018. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include <unistd.h>
#include "infiniband/verbs.h"
#include "../providers/mlx5/mlx5.h"
#include "devx.h"
#include "devx_priv.h"

void *devx_from_ibv(struct ibv_context *ibctx)
{
	struct devx_context	*ctx;
	struct mlx5_context	*mctx = to_mctx(ibctx);

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->cmd_fd		= dup(ibctx->cmd_fd);
	ctx->page_size		= to_mdev(ibctx->device)->page_size;
	ctx->num_uars_per_page	= mctx->num_uars_per_page;
	ctx->cache_line_size	= mctx->cache_line_size;
	ctx->num_uars		= mctx->num_dyn_bfregs /
				  MLX5_NUM_NON_FP_BFREGS_PER_UAR;

	ctx->uars = calloc(ctx->num_uars, sizeof(*ctx->uars));

	if (!ctx->uars)
		goto err;

	return ctx;

err:
	free(ctx->uars);
	free(ctx);
	return NULL;
}

