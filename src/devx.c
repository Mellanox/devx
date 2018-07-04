/*
* Copyright (C) Mellanox Technologies Ltd, 2001-2018. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include <stdlib.h>
#include <errno.h>
#include "devx_ioctl.h"
#include <rdma/mlx5_user_ioctl_cmds.h>
#include "devx.h"
#include "devx_priv.h"
#include "devx_prm.h"

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
			       MLX5_IB_METHOD_DEVX_OBJ_CREATE,
			       3);
	struct ib_uverbs_attr *handle;
	struct devx_obj_handle *obj;
	int ret = ENOMEM;

	obj = (struct devx_obj_handle *)malloc(sizeof(*obj));
	if (!obj)
		goto err;
	obj->ctx = ctx;

	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_CREATE_HANDLE);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_CREATE_CMD_IN, in, inlen);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_CREATE_CMD_OUT, out, outlen);

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

int devx_obj_query(struct devx_obj_handle *obj,
		   void *in, size_t inlen,
		   void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_QUERY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_HANDLE, obj->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_IN, in, inlen);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_QUERY_CMD_OUT, out, outlen);

	return execute_ioctl(obj->ctx->cmd_fd, cmd);
}

int devx_obj_modify(struct devx_obj_handle *obj,
		    void *in, size_t inlen,
		    void *out, size_t outlen)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_MODIFY,
			       3);

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_HANDLE, obj->handle);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_IN, in, inlen);
	fill_attr_in(cmd, MLX5_IB_ATTR_DEVX_OBJ_MODIFY_CMD_OUT, out, outlen);

	return execute_ioctl(obj->ctx->cmd_fd, cmd);
}

int devx_obj_destroy(struct devx_obj_handle *obj)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_OBJ,
			       MLX5_IB_METHOD_DEVX_OBJ_DESTROY,
			       1);
	int ret;

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_OBJ_DESTROY_HANDLE, obj->handle);
	ret = execute_ioctl(obj->ctx->cmd_fd, cmd);

	if (ret)
		return ret;
	free(obj);
	return 0;
}

struct devx_obj_handle *devx_umem_reg(void *ctx,
				      void *addr, size_t size,
				      int access,
				      uint32_t *id)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_DEVX_UMEM,
			       MLX5_IB_METHOD_DEVX_UMEM_REG,
			       5);
	struct ib_uverbs_attr *handle;
	struct devx_obj_handle *obj;
	int ret = ENOMEM;

	obj = (struct devx_obj_handle *)malloc(sizeof(*obj));
	if (!obj)
		goto err;
	obj->ctx = ctx;

	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_DEVX_UMEM_REG_HANDLE);
	fill_attr_in_uint64(cmd, MLX5_IB_ATTR_DEVX_UMEM_REG_ADDR, (intptr_t)addr);
	fill_attr_in_uint64(cmd, MLX5_IB_ATTR_DEVX_UMEM_REG_LEN, size);
	fill_attr_in_uint32(cmd, MLX5_IB_ATTR_DEVX_UMEM_REG_ACCESS, access);
	fill_attr_out(cmd, MLX5_IB_ATTR_DEVX_UMEM_REG_OUT_ID, id, sizeof(*id));

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
			       MLX5_IB_METHOD_DEVX_UMEM_DEREG,
			       1);
	int ret;

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DEVX_UMEM_DEREG_HANDLE, obj->handle);
	ret = execute_ioctl(obj->ctx->cmd_fd, cmd);
	if (ret)
		return ret;
	free(obj);
	return 0;
}

struct devx_fs_rule_handle {
	struct devx_obj_handle		flow;
	uint32_t			matcher_handle;
};

#include<stdio.h>

static int __matcher_create(struct devx_fs_rule_handle *obj, void* in)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_FLOW_MATCHER,
			       MLX5_IB_METHOD_FLOW_MATCHER_CREATE,
			       6);
	struct ib_uverbs_attr *handle;
	uint32_t dummy = 0, prio;
	int ret;

	prio = DEVX_GET(fs_rule_add_in, in, prio);

	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_FLOW_MATCHER_CREATE_HANDLE);
	fill_attr_in(cmd,
		     MLX5_IB_ATTR_FLOW_MATCHER_MATCH_MASK,
		     DEVX_ADDR_OF(fs_rule_add_in, in, flow_spec.match_criteria),
		     DEVX_FLD_SZ_BYTES(fs_rule_add_in, flow_spec.match_criteria));
	fill_attr_in_enum(cmd,
			  MLX5_IB_ATTR_FLOW_MATCHER_FLOW_TYPE,
			  MLX5_IB_FLOW_TYPE_NORMAL,
			  &prio, sizeof(prio));
	fill_attr_in(cmd,
		     MLX5_IB_ATTR_FLOW_MATCHER_MATCH_CRITERIA,
		     DEVX_ADDR_OF(fs_rule_add_in, in, flow_spec.match_criteria_enable),
		     DEVX_FLD_SZ_BYTES(fs_rule_add_in, flow_spec.match_criteria_enable));
	fill_attr_in(cmd,
		     MLX5_IB_ATTR_FLOW_MATCHER_FLAGS,
		     &dummy, sizeof(uint32_t));
	fill_attr_in(cmd,
		     MLX5_IB_ATTR_FLOW_MATCHER_PORT,
		     &dummy, sizeof(uint8_t));

	ret = execute_ioctl(obj->flow.ctx->cmd_fd, cmd);
	if (ret)
		return ret;
	obj->matcher_handle = handle->data;
	return 0;
}

static int __matcher_destroy(struct devx_fs_rule_handle *obj)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       MLX5_IB_OBJECT_FLOW_MATCHER,
			       MLX5_IB_METHOD_FLOW_MATCHER_DESTROY,
			       1);
	fill_attr_in_obj(cmd,
			 MLX5_IB_ATTR_FLOW_MATCHER_DESTROY_HANDLE,
			 obj->matcher_handle);
	return execute_ioctl(obj->flow.ctx->cmd_fd, cmd);
}

struct devx_obj_handle *devx_fs_rule_add(void *ctx, void *in,
					 struct devx_obj_handle *dest)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       UVERBS_OBJECT_FLOW,
			       MLX5_IB_METHOD_CREATE_FLOW,
			       4);
	struct devx_fs_rule_handle *obj;
	struct ib_uverbs_attr *handle;
	int ret = ENOMEM;

	obj = (struct devx_fs_rule_handle *)malloc(sizeof(*obj));
	if (!obj)
		goto err;
	obj->flow.ctx = ctx;

	ret = __matcher_create(obj, in);
	if (ret)
		goto err;

	handle = fill_attr_out_obj(cmd, MLX5_IB_ATTR_CREATE_FLOW_HANDLE);
	fill_attr_in(cmd,
		     MLX5_IB_ATTR_CREATE_FLOW_MATCH_VALUE,
		     DEVX_ADDR_OF(fs_rule_add_in, in, flow_spec.match_value),
		     DEVX_FLD_SZ_BYTES(fs_rule_add_in, flow_spec.match_value));
	fill_attr_in_obj(cmd,
			 MLX5_IB_ATTR_CREATE_FLOW_MATCHER,
			 obj->matcher_handle);
	fill_attr_in_obj(cmd,
			 MLX5_IB_ATTR_CREATE_FLOW_DEST_DEVX,
			 dest->handle);

	ret = execute_ioctl(obj->flow.ctx->cmd_fd, cmd);
	if (ret)
		goto err_cmd;
	obj->flow.handle = handle->data;

	return &obj->flow;

err_cmd:
	__matcher_destroy(obj);
err:
	free(obj);
	errno = ret;
	return NULL;
}

int devx_fs_rule_del(struct devx_obj_handle *fobj)
{
	DECLARE_COMMAND_BUFFER(cmd,
			       UVERBS_OBJECT_FLOW,
			       MLX5_IB_METHOD_DESTROY_FLOW,
			       1);
	struct devx_fs_rule_handle *obj = (void *)fobj;
	int ret;

	fill_attr_in_obj(cmd, MLX5_IB_ATTR_DESTROY_FLOW_HANDLE, obj->flow.handle);
	ret = execute_ioctl(obj->flow.ctx->cmd_fd, cmd);
	if (ret)
		return ret;

	ret =__matcher_destroy(obj);
	if (ret)
		return ret;

	free(obj);
	return 0;
}

