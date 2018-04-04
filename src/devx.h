#ifndef __DEVX_H__
#define __DEVX_H__

#include <linux/limits.h>
#include <linux/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct devx_device {
	char			name[NAME_MAX];
	char			dev_name[NAME_MAX];
	char			dev_path[PATH_MAX];
	char			ibdev_path[PATH_MAX];
};

struct devx_device **devx_get_device_list(int *num_devices);
void devx_free_device_list(struct devx_device **list);
void *devx_open_device(struct devx_device *device);
int devx_close_device(void *context);

int devx_cmd(void *ctx,
	     void *in, size_t inlen,
	     void *out, size_t outlen);

int devx_alloc_uar(void *ctx, uint32_t *idx, void **addr);
void devx_free_uar(void *ctx, void* addr);

int devx_query_eqn(void *ctx, uint32_t vector, uint32_t *eqn);

struct devx_obj_handle;

struct devx_obj_handle *devx_obj_create(void *ctx,
					void *in, size_t inlen,
					void *out, size_t outlen);
int devx_obj_destroy(struct devx_obj_handle *obj);

struct devx_obj_handle *devx_umem_reg(void *ctx,
				      void *addr, size_t size,
				      int access,
				      uint32_t *id);
int devx_umem_unreg(struct devx_obj_handle *obj);

struct devx_obj_handle *devx_fs_rule_add(void *ctx,
					 void *in, uint32_t inlen);
int devx_fs_rule_del(struct devx_obj_handle *obj);

void *devx_alloc_dbrec(void *ctx, uint32_t *mem_id, size_t *off);
void devx_free_dbrec(void *ctx, void *db);

#ifdef __cplusplus
}
#endif

#endif
