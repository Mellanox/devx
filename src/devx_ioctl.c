/*
 * Copyright (c) 2018 Mellanox Technologies, Ltd.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "devx_ioctl.h"

#include <errno.h>
#include <sys/ioctl.h>

/* Number of attrs in this and all the link'd buffers */
unsigned int _ioctl_final_num_attrs(unsigned int num_attrs,
				   struct ibv_command_buffer *link)
{
	for (; link; link = link->next)
		num_attrs += link->next_attr - link->hdr.attrs;

	return num_attrs;
}

/* Linearize the link'd buffers into this one */
static void prepare_attrs(struct ibv_command_buffer *cmd)
{
	struct ib_uverbs_attr *end = cmd->next_attr;
	struct ibv_command_buffer *link;

	for (link = cmd->next; link; link = link->next) {
		struct ib_uverbs_attr *cur;

		assert(cmd->hdr.object_id == link->hdr.object_id);
		assert(cmd->hdr.method_id == link->hdr.method_id);

		/*
		 * Keep track of where the uhw_in lands in the final array if
		 * we copy it from a link
		 */
		if (!VERBS_IOCTL_ONLY && link->uhw_in_idx != _UHW_NO_INDEX) {
			assert(cmd->uhw_in_idx == _UHW_NO_INDEX);
			cmd->uhw_in_idx =
				link->uhw_in_idx + (end - cmd->hdr.attrs);
		}

		for (cur = link->hdr.attrs; cur != link->next_attr; cur++)
			*end++ = *cur;

		assert(end <= cmd->last_attr);
	}

	cmd->hdr.num_attrs = end - cmd->hdr.attrs;

	/*
	 * We keep the in UHW uninlined until directly before sending to
	 * support the compat path. See _fill_attr_in_uhw
	 */
	if (!VERBS_IOCTL_ONLY && cmd->uhw_in_idx != _UHW_NO_INDEX) {
		struct ib_uverbs_attr *uhw = &cmd->hdr.attrs[cmd->uhw_in_idx];

		assert(uhw->attr_id == UVERBS_ATTR_UHW_IN);

		if (uhw->len <= sizeof(uhw->data))
			memcpy(&uhw->data, (void *)(uintptr_t)uhw->data,
			       uhw->len);
	}
}

static void finalize_attr(struct ib_uverbs_attr *attr __attribute__((__unused__)))
{
}

/*
 * Copy the link'd attrs back to their source and make all output buffers safe
 * for VALGRIND
 */
static void finalize_attrs(struct ibv_command_buffer *cmd)
{
	struct ibv_command_buffer *link;
	struct ib_uverbs_attr *end;

	for (end = cmd->hdr.attrs; end != cmd->last_attr; end++)
		finalize_attr(end);

	for (link = cmd->next; link; link = link->next) {
		struct ib_uverbs_attr *cur;

		for (cur = link->hdr.attrs; cur != link->next_attr; cur++) {
			finalize_attr(end);
			*cur = *end++;
		}
	}
}


int execute_ioctl(int cmd_fd, struct ibv_command_buffer *cmd)
{
	prepare_attrs(cmd);
	cmd->hdr.length = sizeof(cmd->hdr) +
		sizeof(cmd->hdr.attrs[0]) * cmd->hdr.num_attrs;
	cmd->hdr.reserved1 = 0;
	cmd->hdr.reserved2 = 0;

	cmd->hdr.driver_id = RDMA_DRIVER_MLX5;
	if (ioctl(cmd_fd, RDMA_VERBS_IOCTL, &cmd->hdr))
		return errno;

	finalize_attrs(cmd);

	return 0;
}

/*
 * The compat scheme for UHW IN requires a pointer in .data, however the
 * kernel protocol requires pointers < 8 to be inlined into .data. We defer
 * that transformation until directly before the ioctl.
 */
static inline struct ib_uverbs_attr *
_fill_attr_in_uhw(struct ibv_command_buffer *cmd, uint16_t attr_id,
		 const void *data, size_t len)
{
	struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

	assert(len <= UINT16_MAX);

	attr->len = len;
	attr->data = ioctl_ptr_to_u64(data);

	return attr;
}

