#ifndef __DEVX_PRIV_H__
#define __DEVX_PRIV_H__

#include <linux/limits.h>

struct devx_uar {
	void			       *reg;
	uint32_t			uuarn;
	uint8_t			       *uar;
	int				used;
};

struct devx_db_page;

struct devx_context {
	int				cmd_fd;
	size_t				page_size;
	int				num_uars_per_page;
	int				cache_line_size;
	uint32_t			num_uars;
	struct devx_uar		       *uars;
	struct devx_db_page	       *db_list;
	char				ibdev_path[PATH_MAX];
};

struct devx_obj_handle {
	struct devx_context	       *ctx;
	uint32_t			handle;
};

#ifndef MLX5_ABI_H
enum {
	MLX5_NUM_NON_FP_BFREGS_PER_UAR = 2,
	MLX5_ADAPTER_PAGE_SIZE	       = 4096,
	MLX5_MMAP_ALLOC_WC	       = 6,
};
#endif

#endif
