/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
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
#define _GNU_SOURCE
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "devx.h"
#include "devx_priv.h"

struct devx_db_page {
	struct devx_db_page	       *prev, *next;
	uint8_t			       *buf;
	int				num_db;
	int				use_cnt;
	struct devx_obj_handle	       *mem;
	uint32_t			mem_id;
	unsigned long			free[0];
};

static struct devx_db_page *__add_page(void *ctx)
{
	struct devx_context *context = (struct devx_context *)ctx;
	uintptr_t ps = context->page_size;
	struct devx_db_page *page;
	int pp;
	int i;
	int nlong;
	int ret;

	pp = ps / context->cache_line_size;
	nlong = (pp + 8 * sizeof(long) - 1) / (8 * sizeof(long));

	page = malloc(sizeof *page + nlong * sizeof(long));
	if (!page)
		return NULL;

	ret = posix_memalign((void **)&page->buf, ps, ps);
	if (ret) {
		free(page);
		return NULL;
	}

	page->num_db  = pp;
	page->use_cnt = 0;
	for (i = 0; i < nlong; ++i)
		page->free[i] = ~0;

	page->mem = devx_umem_reg(ctx, page->buf, ps, 7, &page->mem_id);

	page->prev = NULL;
	page->next = context->db_list;
	context->db_list = page;
	if (page->next)
		page->next->prev = page;

	return page;
}

void *devx_alloc_dbrec(void *ctx, uint32_t *mem_id, size_t *off)
{
	struct devx_context *context = (struct devx_context *)ctx;
	struct devx_db_page *page;
	void *db = NULL;
	int i, j;

	for (page = context->db_list; page; page = page->next)
		if (page->use_cnt < page->num_db)
			goto found;

	page = __add_page(ctx);
	if (!page)
		goto out;

found:
	++page->use_cnt;

	for (i = 0; !page->free[i]; ++i)
		/* nothing */;

	j = ffsl(page->free[i]);
	--j;
	page->free[i] &= ~(1UL << j);

	*mem_id = page->mem_id;
	*off = (i * 8 * sizeof(long) + j) * context->cache_line_size;
	db = page->buf + *off;
out:
	return db;
}

void devx_free_dbrec(void *ctx, void *db)
{
	struct devx_context *context = (struct devx_context *)ctx;
	uintptr_t ps = context->page_size;
	struct devx_db_page *page;
	int i;

	for (page = context->db_list; page; page = page->next)
		if (((uintptr_t) db & ~(ps - 1)) == (uintptr_t) page->buf)
			break;

	if (!page)
		return;

	i = ((uint8_t *)db - page->buf) / context->cache_line_size;
	page->free[i / (8 * sizeof(long))] |= 1UL << (i % (8 * sizeof(long)));

	if (!--page->use_cnt) {
		if (page->prev)
			page->prev->next = page->next;
		else
			context->db_list = page->next;
		if (page->next)
			page->next->prev = page->prev;

		devx_umem_dereg(page->mem);
		free(page->buf);
		free(page);
	}
}
