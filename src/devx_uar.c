#include <sys/mman.h>
#include <errno.h>
#include "devx_ioctl.h"
#include <rdma/mlx5_user_ioctl_cmds.h>
#include "devx.h"
#include "devx_priv.h"

int devx_alloc_uar(void *context, uint32_t *idx, void **addr, off_t *off)
{
	struct devx_context *ctx = (struct devx_context *)context;
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX,
			       MLX5_IB_METHOD_DEVX_QUERY_UAR,
			       2);
	int index = -1;
	uint32_t uar_page_index;
	int mmap_index;
	off_t offset;
	uint32_t i;
	int ret;

	for (i = 0; i < ctx->num_uars; i++) {
		if (!ctx->uars[i].used) {
			index = i;
			break;
		}
	}

	if (index < 0)
		return -ENOENT;

	ctx->uars[index].used = 1;

	uar_page_index = index / ctx->num_uars_per_page;
	offset = (MLX5_MMAP_ALLOC_WC << 8);
	offset |= (uar_page_index & 0xff) | ((uar_page_index >> 8) << 16);
	offset *= ctx->page_size;

	if (ctx->uars[index].reg)
		goto ret;

	mmap_index = uar_page_index * ctx->num_uars_per_page;

	if (ctx->uars[mmap_index].uar)
		goto set_reg;

	ctx->uars[mmap_index].uar = mmap(*addr, ctx->page_size,
					 PROT_WRITE, MAP_SHARED,
					 ctx->cmd_fd, offset);
	if (ctx->uars[mmap_index].uar == MAP_FAILED) {
		ctx->uars[mmap_index].uar = NULL;
		ret = -errno;
		goto err;
	}

set_reg:
	fill_attr_in_uint32(cmd, MLX5_IB_ATTR_DEVX_QUERY_UAR_USER_IDX,
			    index * MLX5_NUM_NON_FP_BFREGS_PER_UAR);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_QUERY_UAR_DEV_IDX,
		      &ctx->uars[index].uuarn, sizeof(uint32_t));
	ret = execute_ioctl(((struct devx_context *)ctx)->cmd_fd, cmd);
	if (ret)
		goto err;

	ctx->uars[index].reg = ctx->uars[mmap_index].uar +
		index % ctx->num_uars_per_page * MLX5_ADAPTER_PAGE_SIZE;

ret:
	*idx = ctx->uars[index].uuarn;
	*addr = ctx->uars[index].reg;
	if (off)
		*off = offset;
	return 0;
err:
	ctx->uars[index].used = 0;
	return ret;
}

void devx_free_uar(void *context, void* addr)
{
	struct devx_context *ctx = (struct devx_context *)context;
	uint32_t i;

	for (i = 0; i < ctx->num_uars; i++)
		if (ctx->uars[i].reg == addr)
			ctx->uars[i].used = 0;
}

