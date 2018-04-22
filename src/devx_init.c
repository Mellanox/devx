#define _GNU_SOURCE
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <fnmatch.h>
#include <sys/mman.h>
#include <errno.h>

#include "devx.h"
#include "devx_priv.h"
#include <rdma/ib_user_verbs.h>
#include <rdma/mlx5-abi.h>

static int read_file(const char *dir, const char *file,
		     char *buf, size_t size)
{
	char *path;
	int fd;
	size_t len;

	if (asprintf(&path, "%s/%s", dir, file) < 0)
		return -1;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		free(path);
		return -1;
	}

	len = read(fd, buf, size);

	close(fd);
	free(path);

	if (len > 0) {
		if (buf[len - 1] == '\n')
			buf[--len] = '\0';
		else if (len < size)
			buf[len] = '\0';
		else
			return -1;
	}

	return len;
}

#define __snprintf(buf, len, fmt, ...) ({ \
	int __rc = snprintf(buf, len, fmt, ##__VA_ARGS__); \
	(size_t)__rc < len && __rc >= 0; })

#define MLX_VENDOR_ID 0x15b3

static uint16_t hca_devices[] = {
	0x1011,	/* MT4113 Connect-IB */
	0x1012,	/* Connect-IB Virtual Function */
	0x1013,	/* ConnectX-4 */
	0x1014,	/* ConnectX-4 Virtual Function */
	0x1015,	/* ConnectX-4LX */
	0x1016,	/* ConnectX-4LX Virtual Function */
	0x1017,	/* ConnectX-5, PCIe 3.0 */
	0x1018,	/* ConnectX-5 Virtual Function */
	0x1019, /* ConnectX-5 Ex */
	0x101a,	/* ConnectX-5 Ex VF */
	0x101b, /* ConnectX-6 */
	0x101c,	/* ConnectX-6 VF */
	0xa2d2,	/* BlueField integrated ConnectX-5 network controller */
	0xa2d3,	/* BlueField integrated ConnectX-5 network controller VF */
};

static const char *sysfs = "/sys";

static int match(char *name_ma) {
	char pci_ma[100];
	size_t i;

	for (i = 0; i < sizeof(hca_devices) / sizeof(uint16_t); i++) {
		snprintf(pci_ma, sizeof(pci_ma), "pci:v%08Xd%08Xsv*",
			MLX_VENDOR_ID, hca_devices[i]);
		if (fnmatch(pci_ma, name_ma, 0) == 0)
			return 1;
	}

	return 0;
}

struct devx_device **devx_get_device_list(int *num) {
	DIR *class_dir;
	struct dirent *dent;
	char class_path[PATH_MAX];
	char sysfs_path[PATH_MAX];
	char ibdev_path[PATH_MAX];
	char sysfs_name[NAME_MAX];
	char ibdev_name[NAME_MAX];
	char modalias[512];
	struct devx_device **res = NULL;
	int curr = 0;
	size_t size = 0;

	if (!__snprintf(class_path, sizeof(class_path),
			    "%s/class/infiniband_verbs", sysfs)) {
		errno = ENOMEM;
		return NULL;
	}

	class_dir = opendir(class_path);
	if (!class_dir) {
		errno = ENOSYS;
		return NULL;
	}

	while ((dent = readdir(class_dir))) {
		struct stat buf;

		if (dent->d_name[0] == '.')
			continue;

		if (!__snprintf(sysfs_path, sizeof(sysfs_path),
				    "%s/%s", class_path, dent->d_name))
			continue;

		if (stat(sysfs_path, &buf)) {
			fprintf(stderr, "Warning: couldn't stat '%s'.\n",
				sysfs_path);
			continue;
		}

		if (!S_ISDIR(buf.st_mode))
			continue;

		if (!__snprintf(sysfs_name, sizeof(sysfs_name),
				    "%s", dent->d_name))
			continue;

		if (read_file(sysfs_path, "ibdev", ibdev_name,
					sizeof(ibdev_name)) < 0) {
			fprintf(stderr, "Warning: no ibdev class attr for '%s'.\n",
				dent->d_name);
			continue;
		}

		if (!__snprintf(ibdev_path, sizeof(ibdev_path),
			"%s/class/infiniband/%s", sysfs, ibdev_name))
			continue;

		if (stat(ibdev_path, &buf)) {
			fprintf(stderr, "Warning: couldn't stat '%s'.\n",
				ibdev_path);
			continue;
		}

		if (read_file(sysfs_path, "device/modalias", modalias,
					sizeof(modalias)) <= 0) {
			fprintf(stderr, "Warning: no modalias for '%s'.\n",
				dent->d_name);
			continue;
		}

		if (!match(modalias))
			continue;

		if (size < (curr + 1) * sizeof(struct devx_device*)) {
			void *old = res;
			size += sizeof(struct devx_device*) * 8;
			res = realloc(res, size);
			if (!res) {
				res = old;
				goto err;
			}
		}

		res[curr] = calloc(1, sizeof(struct devx_device));
		if (!res[curr])
		       goto err;

		strcpy(res[curr]->dev_name,   sysfs_name);
		strcpy(res[curr]->dev_path,   sysfs_path);
		strcpy(res[curr]->name,       ibdev_name);
		strcpy(res[curr]->ibdev_path, ibdev_path);

		curr++;
	}

	closedir(class_dir);

	if (res)
		res[curr] = NULL;
	if (num)
		*num = curr;

	return res;
err:
	closedir(class_dir);
	devx_free_device_list(res);
	errno = ENOMEM;
	return NULL;
}

void devx_free_device_list(struct devx_device **list)
{
	int i;

	for(i = 0; list[i]; i++)
		free(list[i]);
	free(list);
}

enum {
	MLX5_CQE_VERSION_V0,
	MLX5_CQE_VERSION_V1,
};

void *devx_open_device(struct devx_device *device)
{
	char *devpath;
	struct {
		struct ib_uverbs_cmd_hdr		hdr;
		struct ib_uverbs_get_context		ib;
		struct mlx5_ib_alloc_ucontext_req_v2	drv;
	} req;
	struct {
		struct ib_uverbs_get_context_resp	ib;
		struct mlx5_ib_alloc_ucontext_resp	drv;
	} resp;
	struct devx_context	*ctx;

	if (asprintf(&devpath, "/dev/infiniband/%s", device->dev_name) < 0)
		return NULL;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->cmd_fd = open(devpath, O_RDWR | O_CLOEXEC);
	free(devpath);

	if (ctx->cmd_fd < 0)
		goto err_free;

	memset(&req,  0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	req.drv.total_num_bfregs	= 1;
	req.drv.num_low_latency_bfregs	= 0;
	req.drv.flags			= MLX5_DEVX;
	req.drv.max_cqe_version		= MLX5_CQE_VERSION_V1;
	req.drv.lib_caps		= MLX5_LIB_CAP_4K_UAR;

	req.hdr.command			= IB_USER_VERBS_CMD_GET_CONTEXT;
	req.hdr.in_words		= sizeof(req) / 4;
	req.hdr.out_words		= sizeof(resp) / 4;
	req.ib.response			= (uintptr_t)&resp;

	if (write(ctx->cmd_fd, &req, sizeof(req)) != (sizeof(req)))
		goto err;

	ctx->page_size			= sysconf(_SC_PAGESIZE);
	ctx->num_uars_per_page		= resp.drv.num_uars_per_page;
	ctx->cache_line_size		= resp.drv.cache_line_size;
	ctx->num_uars			= resp.drv.num_dyn_bfregs /
					  MLX5_NUM_NON_FP_BFREGS_PER_UAR;

	ctx->uars = calloc(ctx->num_uars, sizeof(*ctx->uars));

	if (!ctx->uars)
		goto err;

	strcpy(ctx->ibdev_path, device->ibdev_path);

	return ctx;
err:
	close(ctx->cmd_fd);
err_free:
	free(ctx->uars);
	free(ctx);
	return NULL;
}

int devx_close_device(void *context)
{
	struct devx_context *ctx = (struct devx_context *)context;
	int page_size = ctx->page_size;
	uint32_t i;

	for (i = 0; i < ctx->num_uars; i++) {
		if (ctx->uars[i].uar)
			munmap(ctx->uars[i].uar, page_size);
	}

	free(ctx->uars);
	close(ctx->cmd_fd);
	free(ctx);

	return 0;
}

int devx_query_gid(void *context, uint8_t port_num,
		   int index, uint8_t *gid)
{
	struct devx_context *ctx = (struct devx_context *)context;
	char name[24];
	char attr[41];
	uint16_t val;
	int i;

	snprintf(name, sizeof name, "ports/%d/gids/%d", port_num, index);

	if (read_file(ctx->ibdev_path, name, attr, sizeof(attr)) < 0)
		return -1;

	for (i = 0; i < 8; ++i) {
		if (sscanf(attr + i * 5, "%hx", &val) != 1)
			return -1;
		gid[i * 2    ] = val >> 8;
		gid[i * 2 + 1] = val & 0xff;
	}

	return 0;
}
