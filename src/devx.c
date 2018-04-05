#include <stdlib.h>
#include <errno.h>
#include "devx_ioctl.h"
#include <rdma/mlx5_user_ioctl_cmds.h>
#include "devx.h"
#include "devx_priv.h"

int devx_cmd(void *ctx,
	     void *in, size_t inlen,
	     void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX,
			       MLX5_IB_METHOD_DEVX_OTHER,
			       2);

	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OTHER_CMD_IN, in, inlen);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OTHER_CMD_OUT, out, outlen);
	return execute_ioctl(((struct devx_context *)ctx)->cmd_fd, cmd);
}

int devx_query_eqn(void *ctx, uint32_t vector, uint32_t *eqn)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX,
			       MLX5_IB_METHOD_DEVX_QUERY_EQN,
			       2);

	fill_attr_in_uint32(cmd, MLX5_IB_ATTR_DEVX_QUERY_EQN_USER_VEC, vector);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_QUERY_EQN_DEV_EQN, eqn, sizeof(*eqn));
	return execute_ioctl(((struct devx_context *)ctx)->cmd_fd, cmd);
}

struct devx_obj_handle *devx_obj_create(void *ctx,
					void *in, size_t inlen,
					void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_OBJ_DEVX_CREATE,
			       3);
	struct ib_uverbs_attr *handle;
	struct devx_obj_handle *obj;
	int ret = ENOMEM;

	obj = (struct devx_obj_handle *)malloc(sizeof(*obj));
	if (!obj)
		goto err;
	obj->ctx = ctx;

	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_CREATE_DEVX_OBJ_HANDLE);
	fill_attr_in(cmd, MLX5_IB_ATTR_CREATE_DEVX_OBJ_CMD_IN, in, inlen);
	fill_attr_in(cmd, MLX5_IB_ATTR_CREATE_DEVX_OBJ_CMD_OUT, out, outlen);

	ret = execute_ioctl(obj->ctx->cmd_fd, cmd);
	if (ret)
		goto err;
	obj->handle = handle->data;

	return obj;
err:
	free(obj);
	errno = ret;
	return NULL;
}

int devx_obj_destroy(struct devx_obj_handle *obj)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_OBJ_DEVX_DESTROY,
			       1);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DESTROY_DEVX_OBJ_HANDLE, obj->handle);
	return execute_ioctl(obj->ctx->cmd_fd, cmd);
}

struct devx_obj_handle *devx_umem_reg(void *ctx,
				      void *addr, size_t size,
				      int access,
				      uint32_t *id)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_UMEM,
			       MLX5_IB_METHOD_UMEM_DEVX_REG,
			       5);
	struct ib_uverbs_attr *handle;
	struct devx_obj_handle *obj;
	int ret = ENOMEM;

	obj = (struct devx_obj_handle *)malloc(sizeof(*obj));
	if (!obj)
		goto err;
	obj->ctx = ctx;

	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_REG_UMEM_DEVX_HANDLE);
	fill_attr_in_uint64(cmd, MLX5_IB_ATTR_REG_UMEM_DEVX_ADDR, (intptr_t)addr);
	fill_attr_in_uint64(cmd, MLX5_IB_ATTR_REG_UMEM_DEVX_LEN, size);
	fill_attr_in_uint32(cmd, MLX5_IB_ATTR_REG_UMEM_DEVX_ACCESS, access);
	fill_attr_out(cmd, MLX5_IB_ATTR_REG_UMEM_DEVX_OUT_ID, id, sizeof(*id));

	ret = execute_ioctl(obj->ctx->cmd_fd, cmd);
	if (ret)
		goto err;
	obj->handle = handle->data;

	return obj;
err:
	free(obj);
	errno = ret;
	return NULL;
}

int devx_umem_dereg(struct devx_obj_handle *obj)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_UMEM,
			       MLX5_IB_METHOD_UMEM_DEVX_DEREG,
			       1);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEREG_UMEM_DEVX_HANDLE, obj->handle);
	return execute_ioctl(obj->ctx->cmd_fd, cmd);
}

struct devx_obj_handle *devx_fs_rule_add(void *ctx,
					 void *in, uint32_t inlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_FS_RULE,
			       MLX5_IB_METHOD_FS_RULE_DEVX_ADD,
			       2);
	struct ib_uverbs_attr *handle;
	struct devx_obj_handle *obj;
	int ret = ENOMEM;

	obj = (struct devx_obj_handle *)malloc(sizeof(*obj));
	if (!obj)
		goto err;
	obj->ctx = ctx;

	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_ADD_DEVX_FS_RULE_HANDLE);
	fill_attr_in(cmd, MLX5_IB_ATTR_ADD_DEVX_FS_RULE_CMD_IN, in, inlen);

	ret = execute_ioctl(obj->ctx->cmd_fd, cmd);
	if (ret)
		goto err;
	obj->handle = handle->data;

	return obj;
err:
	free(obj);
	errno = ret;
	return NULL;
}

int devx_fs_rule_del(struct devx_obj_handle *obj)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_FS_RULE,
			       MLX5_IB_METHOD_FS_RULE_DEVX_DEL,
			       1);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEL_DEVX_FS_RULE_HANDLE, obj->handle);
	return execute_ioctl(obj->ctx->cmd_fd, cmd);
}

