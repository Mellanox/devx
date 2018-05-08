#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <errno.h>

#include <infiniband/mlx5dv.h>

#include "devx.h"
#include "devx_prm.h"
#include "devx_priv.h"

enum {
	MLX5_HCA_CAP_OPMOD_GET_MAX	= 0,
	MLX5_HCA_CAP_OPMOD_GET_CUR	= 1,
};

enum {
	MLX5_CAP_GENERAL = 0,
	MLX5_CAP_ETHERNET_OFFLOADS,
	MLX5_CAP_ODP,
	MLX5_CAP_ATOMIC,
	MLX5_CAP_ROCE,
	MLX5_CAP_IPOIB_OFFLOADS,
	MLX5_CAP_IPOIB_ENHANCED_OFFLOADS,
	MLX5_CAP_FLOW_TABLE,
	MLX5_CAP_ESWITCH_FLOW_TABLE,
	MLX5_CAP_ESWITCH,
	MLX5_CAP_RESERVED,
	MLX5_CAP_VECTOR_CALC,
	MLX5_CAP_QOS,
	MLX5_CAP_FPGA,
};


int test_query(void *ctx);
int test_query(void *ctx) {
	uint32_t in[DEVX_ST_SZ_DW(query_hca_cap_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(query_hca_cap_out)] = {0};
	int ret;

	DEVX_SET(query_hca_cap_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod, MLX5_HCA_CAP_OPMOD_GET_MAX | (MLX5_CAP_GENERAL << 1));
	ret = devx_cmd(ctx, in, sizeof(in), out, sizeof(out));
	return DEVX_GET(query_hca_cap_out, out,
			capability.cmd_hca_cap.log_max_cq_sz);
}

int alloc_pd(void *ctx);
int alloc_pd(void *ctx) {
	uint32_t in[DEVX_ST_SZ_DW(alloc_pd_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(alloc_pd_out)] = {0};
	struct devx_obj_handle *pd;

	DEVX_SET(alloc_pd_in, in, opcode, MLX5_CMD_OP_ALLOC_PD);
	pd = devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!pd)
		return -1;

	return DEVX_GET(alloc_pd_out, out, pd);
}

int reg_mr(void *ctx, int pd, void *buff, size_t size);
int reg_mr(void *ctx, int pd, void *buff, size_t size) {
	uint32_t in[DEVX_ST_SZ_DW(create_mkey_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(create_mkey_out)] = {0};
	struct devx_obj_handle *mem, *mr;
	uint32_t mem_id;

	mem = devx_umem_reg(ctx, buff, size, 7, &mem_id);
	if (!mem)
		return 0;

	DEVX_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.access_mode_1_0, MLX5_MKC_ACCESS_MODE_MTT);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.a, 1);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.rw, 1);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.rr, 1);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.lw, 1);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.lr, 1);
	DEVX_SET64(create_mkey_in, in, memory_key_mkey_entry.start_addr, (intptr_t)buff);
	DEVX_SET64(create_mkey_in, in, memory_key_mkey_entry.len, size);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.pd, pd);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.translations_octword_size, 1);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.log_page_size, 12);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.qpn, 0xffffff);
	DEVX_SET(create_mkey_in, in, memory_key_mkey_entry.mkey_7_0, 0x42);
	DEVX_SET(create_mkey_in, in, translations_octword_actual_size, 1);
	DEVX_SET(create_mkey_in, in, pg_access, 1);
	DEVX_SET(create_mkey_in, in, mkey_umem_id, mem_id);

	mr = devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!mr)
		return 0;
	return DEVX_GET(create_mkey_out, out, mkey_index) << 8 | 0x42;
}

struct mlx5_eqe_comp {
	__be32	reserved[6];
	__be32	cqn;
};

union ev_data {
	__be32				raw[7];
	struct mlx5_eqe_comp		comp;
};

struct mlx5_eqe {
	u8		rsvd0;
	u8		type;
	u8		rsvd1;
	u8		sub_type;
	__be32		rsvd2[7];
	union ev_data	data;
	__be16		rsvd3;
	u8		signature;
	u8		owner;
};

int create_eq(void *ctx, void **buff_out, uint32_t uar_id);
int create_eq(void *ctx, void **buff_out, uint32_t uar_id)
{
	uint32_t in[DEVX_ST_SZ_DW(create_eq_in) + DEVX_ST_SZ_DW(pas_umem)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(create_eq_out)] = {0};
	struct mlx5_eqe *eqe;
	struct devx_obj_handle *pas, *eq;
	uint32_t pas_id;
	uint8_t *buff;
	void *eqc, *up;
	int i;

	buff = (uint8_t *)memalign(0x1000, 0x1000);
	memset(buff, 0, 0x1000);
	for (i = 0; i < (1<<6); i++) {
		eqe = (struct mlx5_eqe *)(buff + i * sizeof(*eqe));
		eqe->owner = 1;
	}

	pas = devx_umem_reg(ctx, buff, 0x1000, 7, &pas_id);
	if (!pas)
		return 0;

	DEVX_SET(create_eq_in, in, opcode, MLX5_CMD_OP_CREATE_EQ);

	eqc = DEVX_ADDR_OF(create_eq_in, in, eq_context_entry);
	DEVX_SET(eqc, eqc, log_eq_size, 6);
	DEVX_SET(eqc, eqc, uar_page, uar_id);

	up = DEVX_ADDR_OF(create_eq_in, in, pas);
	DEVX_SET(pas_umem, up, pas_umem_id, pas_id);

	eq = devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!eq)
		return 0;

	*buff_out = buff;
	return DEVX_GET(create_eq_out, out, eq_number);
}

int create_cq(void *ctx, void **buff_out, uint32_t uar_id, uint32_t **dbr_out, uint32_t eq);
int create_cq(void *ctx, void **buff_out, uint32_t uar_id, uint32_t **dbr_out, uint32_t eq) {
	uint32_t in[DEVX_ST_SZ_DW(create_cq_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(create_cq_out)] = {0};
	struct mlx5_cqe64 *cqe;
	struct devx_obj_handle *pas, *cq;
	uint32_t pas_id, dbr_id;
	uint8_t *buff;
	void *dbr, *uar_ptr;
	size_t dbr_off;
	int ret = 0;
	int i;

	buff = (uint8_t *)memalign(0x1000, 0x1000);
	memset(buff, 0, 0x1000);
	for (i = 0; i < (1<<5); i++) {
		cqe = (struct mlx5_cqe64 *)(buff + i * sizeof(*cqe));
		cqe->op_own = MLX5_CQE_INVALID << 4;
	}

	if (!eq)
		ret = devx_query_eqn(ctx, 0, &eq);
	if (!uar_id)
		ret = devx_alloc_uar(ctx, &uar_id, &uar_ptr, NULL);
	pas = devx_umem_reg(ctx, buff, 0x1000, 7, &pas_id);
	dbr = devx_alloc_dbrec(ctx, &dbr_id, &dbr_off);

	if (ret || !pas || !dbr)
		return 0;

	DEVX_SET(create_cq_in, in, opcode, MLX5_CMD_OP_CREATE_CQ);
	DEVX_SET(create_cq_in, in, cq_context.c_eqn, eq);
	DEVX_SET(create_cq_in, in, cq_context.cqe_sz, 0);
	DEVX_SET(create_cq_in, in, cq_context.log_cq_size, 5);
	DEVX_SET(create_cq_in, in, cq_context.uar_page, uar_id);
	DEVX_SET(create_cq_in, in, cq_umem_id, pas_id);
	DEVX_SET(create_cq_in, in, cq_context.dbr_umem_id, dbr_id);
	DEVX_SET64(create_cq_in, in, cq_context.dbr_addr, dbr_off);

	cq = devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!cq)
		return 0;

	if (dbr_out)
		*dbr_out = (uint32_t *)dbr;
	if (buff_out)
		*buff_out = buff;

	return DEVX_GET(create_cq_out, out, cqn);
}

int query_lid(void *ctx) {
	uint32_t in[DEVX_ST_SZ_DW(query_hca_vport_context_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(query_hca_vport_context_out)] = {0};
	int err;

	DEVX_SET(query_hca_vport_context_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT);
	DEVX_SET(query_hca_vport_context_in, in, port_num, 1);

	err = devx_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err)
		return -1;

	return DEVX_GET(query_hca_vport_context_out, out, hca_vport_context.lid);
}

enum mlx5_qp_optpar {
	MLX5_QP_OPTPAR_ALT_ADDR_PATH		= 1 << 0,
	MLX5_QP_OPTPAR_RRE			= 1 << 1,
	MLX5_QP_OPTPAR_RAE			= 1 << 2,
	MLX5_QP_OPTPAR_RWE			= 1 << 3,
	MLX5_QP_OPTPAR_PKEY_INDEX		= 1 << 4,
	MLX5_QP_OPTPAR_Q_KEY			= 1 << 5,
	MLX5_QP_OPTPAR_RNR_TIMEOUT		= 1 << 6,
	MLX5_QP_OPTPAR_PRIMARY_ADDR_PATH	= 1 << 7,
	MLX5_QP_OPTPAR_SRA_MAX			= 1 << 8,
	MLX5_QP_OPTPAR_RRA_MAX			= 1 << 9,
	MLX5_QP_OPTPAR_PM_STATE			= 1 << 10,
	MLX5_QP_OPTPAR_RETRY_COUNT		= 1 << 12,
	MLX5_QP_OPTPAR_RNR_RETRY		= 1 << 13,
	MLX5_QP_OPTPAR_ACK_TIMEOUT		= 1 << 14,
	MLX5_QP_OPTPAR_PRI_PORT			= 1 << 16,
	MLX5_QP_OPTPAR_SRQN			= 1 << 18,
	MLX5_QP_OPTPAR_CQN_RCV			= 1 << 19,
	MLX5_QP_OPTPAR_DC_HS			= 1 << 20,
	MLX5_QP_OPTPAR_DC_KEY			= 1 << 21,
};

enum mlx5_qp_state {
	MLX5_QP_STATE_RST			= 0,
	MLX5_QP_STATE_INIT			= 1,
	MLX5_QP_STATE_RTR			= 2,
	MLX5_QP_STATE_RTS			= 3,
	MLX5_QP_STATE_SQER			= 4,
	MLX5_QP_STATE_SQD			= 5,
	MLX5_QP_STATE_ERR			= 6,
	MLX5_QP_STATE_SQ_DRAINING		= 7,
	MLX5_QP_STATE_SUSPENDED			= 9,
	MLX5_QP_NUM_STATE,
	MLX5_QP_STATE,
	MLX5_QP_STATE_BAD,
};

enum {
	MLX5_QP_ST_RC				= 0x0,
	MLX5_QP_ST_UC				= 0x1,
	MLX5_QP_ST_UD				= 0x2,
	MLX5_QP_ST_XRC				= 0x3,
	MLX5_QP_ST_MLX				= 0x4,
	MLX5_QP_ST_DCI				= 0x5,
	MLX5_QP_ST_DCT				= 0x6,
	MLX5_QP_ST_QP0				= 0x7,
	MLX5_QP_ST_QP1				= 0x8,
	MLX5_QP_ST_RAW_ETHERTYPE		= 0x9,
	MLX5_QP_ST_RAW_IPV6			= 0xa,
	MLX5_QP_ST_SNIFFER			= 0xb,
	MLX5_QP_ST_SYNC_UMR			= 0xe,
	MLX5_QP_ST_PTP_1588			= 0xd,
	MLX5_QP_ST_REG_UMR			= 0xc,
	MLX5_QP_ST_MAX
};

enum {
	MLX5_QP_PM_MIGRATED			= 0x3,
	MLX5_QP_PM_ARMED			= 0x0,
	MLX5_QP_PM_REARM			= 0x1
};


enum {
	MLX5_RES_SCAT_DATA32_CQE	= 0x1,
	MLX5_RES_SCAT_DATA64_CQE	= 0x2,
	MLX5_REQ_SCAT_DATA32_CQE	= 0x11,
	MLX5_REQ_SCAT_DATA64_CQE	= 0x22,
};

#define RQ_SIZE (1 << 6)
#define SQ_SIZE (1 << 6)
#define CQ_SIZE (1 << 6)
#define EQ_SIZE (1 << 6)

int create_qp(void *ctx, void **buff_out, int uar_id, uint32_t **dbr_out,
	      int cqn, int pd, struct devx_obj_handle **q);
int create_qp(void *ctx, void **buff_out, int uar_id, uint32_t **dbr_out,
	      int cqn, int pd, struct devx_obj_handle **q) {
	u8 in[DEVX_ST_SZ_BYTES(create_qp_in)] = {0};
	u8 out[DEVX_ST_SZ_BYTES(create_qp_out)] = {0};
	struct devx_obj_handle *pas;
	uint32_t pas_id, dbr_id;
	void *buff, *uar_ptr = NULL, *dbr, *qpc;
	size_t dbr_off;
	int ret;

	buff = memalign(0x1000, 0x2000);
	memset(buff, 0, 0x2000);
	pas = devx_umem_reg(ctx, buff, 0x2000, 7, &pas_id);
	dbr = devx_alloc_dbrec(ctx, &dbr_id, &dbr_off);

	if (!pas || !dbr)
		return 0;

	DEVX_SET(create_qp_in, in, opcode, MLX5_CMD_OP_CREATE_QP);

	qpc = DEVX_ADDR_OF(create_qp_in, in, qpc);
	DEVX_SET(qpc, qpc, st, MLX5_QP_ST_RC);
	DEVX_SET(qpc, qpc, pm_state, MLX5_QP_PM_MIGRATED);
	DEVX_SET(qpc, qpc, pd, pd);
	DEVX_SET(qpc, qpc, uar_page, uar_id);
	DEVX_SET(qpc, qpc, cqn_snd, cqn);
	DEVX_SET(qpc, qpc, cqn_rcv, cqn);
	DEVX_SET(qpc, qpc, log_sq_size, 6);
	DEVX_SET(qpc, qpc, log_rq_stride, 2);
	DEVX_SET(qpc, qpc, log_rq_size, 6);
	DEVX_SET(qpc, qpc, cs_req, MLX5_REQ_SCAT_DATA32_CQE);
	DEVX_SET(qpc, qpc, cs_res, MLX5_RES_SCAT_DATA32_CQE);
	DEVX_SET(create_qp_in, in, wq_umem_id, pas_id);
	DEVX_SET(qpc, qpc, dbr_umem_id, dbr_id);
	DEVX_SET64(qpc, qpc, dbr_addr, dbr_off);

	*q = devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));
	if (!*q)
		return 0;

	*dbr_out = (uint32_t *)dbr;
	*buff_out = buff;

	return DEVX_GET(create_qp_out, out, qpn);
}

int to_init(struct devx_obj_handle *obj, int qp) {
	uint32_t in[DEVX_ST_SZ_DW(rst2init_qp_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(rst2init_qp_out)] = {0};
	void *qpc = DEVX_ADDR_OF(rst2init_qp_in, in, qpc);

	DEVX_SET(rst2init_qp_in, in, opcode, MLX5_CMD_OP_RST2INIT_QP);
	DEVX_SET(rst2init_qp_in, in, qpn, qp);

	DEVX_SET(qpc, qpc, primary_address_path.vhca_port_num, 1);

	return devx_obj_modify(obj, in, sizeof(in), out, sizeof(out));
}

int to_rtr(struct devx_obj_handle *obj, int qp, int lid) {
	uint32_t in[DEVX_ST_SZ_DW(init2rtr_qp_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(init2rtr_qp_out)] = {0};
	void *qpc = DEVX_ADDR_OF(rst2init_qp_in, in, qpc);

	DEVX_SET(init2rtr_qp_in, in, opcode, MLX5_CMD_OP_INIT2RTR_QP);
	DEVX_SET(init2rtr_qp_in, in, qpn, qp);

	DEVX_SET(qpc, qpc, mtu, 2);
	DEVX_SET(qpc, qpc, log_msg_max, 30);
	DEVX_SET(qpc, qpc, remote_qpn, qp);
	DEVX_SET(qpc, qpc, primary_address_path.rlid, lid);
	DEVX_SET(qpc, qpc, primary_address_path.vhca_port_num, 1);
	DEVX_SET(qpc, qpc, rre, 1);
	DEVX_SET(qpc, qpc, rwe, 1);
	DEVX_SET(qpc, qpc, min_rnr_nak, 12);

	return devx_obj_modify(obj, in, sizeof(in), out, sizeof(out));
}

int to_rts(struct devx_obj_handle *obj, int qp) {
	uint32_t in[DEVX_ST_SZ_DW(rtr2rts_qp_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(rtr2rts_qp_out)] = {0};
	void *qpc = DEVX_ADDR_OF(rst2init_qp_in, in, qpc);

	DEVX_SET(rtr2rts_qp_in, in, opcode, MLX5_CMD_OP_RTR2RTS_QP);
	DEVX_SET(rtr2rts_qp_in, in, qpn, qp);

	DEVX_SET(qpc, qpc, log_ack_req_freq, 8);
	DEVX_SET(qpc, qpc, retry_count, 7);
	DEVX_SET(qpc, qpc, rnr_retry, 7);
	DEVX_SET(qpc, qpc, primary_address_path.ack_timeout, 14);

	return devx_obj_modify(obj, in, sizeof(in), out, sizeof(out));
}

int recv(uint8_t *rq, uint32_t *rqi, uint32_t *qp_dbr,
	 uint32_t mkey, void *addr, size_t size) {
	struct mlx5_wqe_data_seg *dseg = (struct mlx5_wqe_data_seg *)(rq + *rqi % RQ_SIZE * MLX5_SEND_WQE_BB);
	mlx5dv_set_data_seg(dseg, size, mkey, (intptr_t)addr);
	mlx5dv_set_data_seg(dseg + 1, 0, MLX5_INVALID_LKEY, 0);
	(*rqi)++;
	asm volatile("" ::: "memory");
	qp_dbr[MLX5_RCV_DBR] = htobe32(*rqi & 0xffff);
	return 0;
}

int xmit(uint8_t *sq, uint32_t *sqi, uint32_t *qp_dbr,
	 uint32_t mkey, void *addr, size_t size,
	 void *uar_ptr, uint32_t qp) {
	struct mlx5_wqe_ctrl_seg *ctrl = (struct mlx5_wqe_ctrl_seg *)(sq + *sqi % SQ_SIZE * MLX5_SEND_WQE_BB);
	mlx5dv_set_ctrl_seg(ctrl, *sqi, MLX5_OPCODE_SEND, 0,
			    qp, MLX5_WQE_CTRL_CQ_UPDATE,
			    2, 0, 0);
	struct mlx5_wqe_data_seg *dseg = (struct mlx5_wqe_data_seg *)(ctrl + 1);
	mlx5dv_set_data_seg(dseg, size, mkey, (intptr_t)addr);
	(*sqi)++;
	asm volatile("" ::: "memory");
	qp_dbr[MLX5_SND_DBR] = htobe32(*sqi & 0xffff);
	asm volatile("" ::: "memory");
	*(uint64_t *)((uint8_t *)uar_ptr + 0x800) = *(uint64_t *)ctrl;
	asm volatile("" ::: "memory");
	return 0;
}

enum {
	MLX5_CQ_SET_CI	= 0,
	MLX5_CQ_ARM_DB	= 1,
};

int arm_cq(uint32_t cq, uint32_t cqi, uint32_t *cq_dbr, void *uar_ptr) {
	uint64_t doorbell;
	uint32_t sn;
	uint32_t ci;
	uint32_t cmd;

	sn  = cqi & 3;
	ci  = cqi & 0xffffff;
	cmd = MLX5_CQ_DB_REQ_NOT;

	doorbell = sn << 28 | cmd | ci;
	doorbell <<= 32;
	doorbell |= cq;

	cq_dbr[MLX5_CQ_ARM_DB] = htobe32(sn << 28 | cmd | ci);
	asm volatile("" ::: "memory");

	*(uint64_t *)((uint8_t *)uar_ptr + 0x20) = htobe64(doorbell);
	asm volatile("" ::: "memory");

	return 0;
}

int poll_cq(uint8_t *cq_buff, uint32_t *cqi, uint32_t *cq_dbr) {
	struct mlx5_cqe64 *cqe = (struct mlx5_cqe64 *)(cq_buff + *cqi % CQ_SIZE * sizeof(*cqe));
	int retry = 1600000;

	while (--retry && (mlx5dv_get_cqe_opcode(cqe) == MLX5_CQE_INVALID ||
		((cqe->op_own & MLX5_CQE_OWNER_MASK) ^ !!(*cqi & CQ_SIZE))))
		asm volatile("" ::: "memory");

	if (!retry)
		return 1;

	(*cqi)++;
	asm volatile("" ::: "memory");
	cq_dbr[MLX5_CQ_SET_CI] = htobe32(*cqi & 0xffffff);
	printf("CQ op %d size %d\n", mlx5dv_get_cqe_opcode(cqe), be32toh(cqe->byte_cnt));
	return 0;
}

int poll_eq(uint8_t *eq_buff, uint32_t *eqi) {
	struct mlx5_eqe *eqe = (struct mlx5_eqe *)(eq_buff + *eqi % EQ_SIZE * sizeof(*eqe));
	int retry = 1600000;
	while (--retry && (eqe->owner & 1) ^ !!(*eqi & EQ_SIZE))
		asm volatile("" ::: "memory");

	if (!retry)
		return 1;

	(*eqi)++;
	asm volatile("" ::: "memory");
	printf("EQ cq %x\n", be32toh(eqe->data.comp.cqn));

	return 0;
}

int arm_eq(uint32_t eq, uint32_t eqi, void *uar_ptr) {
	uint32_t doorbell = (eqi & 0xffffff) | (eq << 24);

	*(uint32_t *)((uint8_t *)uar_ptr + 0x48) = htobe32(doorbell);
	asm volatile("" ::: "memory");
	return 0;
}

#include "gtest/gtest.h"

TEST(devx, smoke) {
	int num, devn = 0;
	struct devx_device **list = devx_get_device_list(&num);
	void *ctx;

	if (getenv("DEVN"))
		devn = atoi(getenv("DEVN"));

	ASSERT_GT(num, devn);
	ctx = devx_open_device(list[devn]);
	ASSERT_TRUE(ctx);
	devx_free_device_list(list);

	EXPECT_EQ(test_query(ctx), 22);
}

TEST(devx, send) {
	int num, devn = 0;
	struct devx_device **list = devx_get_device_list(&num);
	void *ctx;
	struct devx_contex *dctx = (struct devx_contex *)ctx;
	unsigned char buff[0x1000];
	for(int i = 0; i < 0x60; i++)
		buff[i] = i + 0x20;

	int ret, lid;

	if (getenv("DEVN"))
		devn = atoi(getenv("DEVN"));

	ASSERT_GT(num, devn);
	ctx = devx_open_device(list[devn]);
	ASSERT_TRUE(ctx);
	devx_free_device_list(list);

	uint32_t uar_id;
	void *uar_ptr = NULL;
	ret = devx_alloc_uar(ctx, &uar_id, &uar_ptr, NULL);
	ASSERT_FALSE(ret);

	int pd = alloc_pd(ctx);
	ASSERT_TRUE(pd);

	void *eq_buff;
	int eq = create_eq(ctx, &eq_buff, uar_id);
	ASSERT_TRUE(eq);

	void *cq_buff;
	uint32_t *cq_dbr;
	int cq = create_cq(ctx, &cq_buff, uar_id, &cq_dbr, eq);
	ASSERT_TRUE(cq);
	int mkey = reg_mr(ctx, pd, buff, sizeof(buff));
	ASSERT_TRUE(mkey);

	lid = query_lid(ctx);
	ASSERT_LE(0, lid);

	void *qp_buff;
	uint32_t *qp_dbr;
	struct devx_obj_handle *q;
	int qp = create_qp(ctx, &qp_buff, uar_id, &qp_dbr, cq, pd, &q);
	ASSERT_TRUE(qp);
	ASSERT_FALSE(to_init(q, qp));
	ASSERT_FALSE(to_rtr(q, qp, lid));
	ASSERT_FALSE(to_rts(q, qp));

	uint8_t *rq = (uint8_t *)qp_buff;
	uint8_t *sq = (uint8_t *)qp_buff + MLX5_SEND_WQE_BB * RQ_SIZE;
	uint32_t rqi = 0, sqi = 0, cqi = 0, eqi = 0;

	ASSERT_FALSE(arm_eq(eq, eqi, uar_ptr));
	ASSERT_FALSE(arm_cq(cq, cqi, cq_dbr, uar_ptr));

	ASSERT_TRUE(poll_eq((uint8_t *)eq_buff, &eqi));
	ASSERT_TRUE(poll_cq((uint8_t *)cq_buff, &cqi, cq_dbr));

	ASSERT_FALSE(recv(rq, &rqi, qp_dbr, mkey, buff, 0x30));
	ASSERT_FALSE(xmit(sq, &sqi, qp_dbr, mkey, buff + 0x30, 0x30, uar_ptr, qp));

	ASSERT_FALSE(poll_eq((uint8_t *)eq_buff, &eqi));
	ASSERT_FALSE(poll_cq((uint8_t *)cq_buff, &cqi, cq_dbr));
	ASSERT_FALSE(arm_eq(eq, eqi, uar_ptr));
	ASSERT_FALSE(arm_cq(cq, cqi, cq_dbr, uar_ptr));
	ASSERT_FALSE(poll_eq((uint8_t *)eq_buff, &eqi));
	ASSERT_FALSE(poll_cq((uint8_t *)cq_buff, &cqi, cq_dbr));
	ASSERT_FALSE(arm_eq(eq, eqi, uar_ptr));
	ASSERT_FALSE(arm_cq(cq, cqi, cq_dbr, uar_ptr));
}

int test_rq(void *ctx, int cqn, int pd);
int test_rq(void *ctx, int cqn, int pd) {
	u8 in[DEVX_ST_SZ_BYTES(create_rq_in)] = {0};
	u8 out[DEVX_ST_SZ_BYTES(create_rq_out)] = {0};
	struct devx_obj_handle *pas, *q;
	uint32_t pas_id, dbr_id, uar_id;
	void *buff, *uar_ptr = NULL, *dbr;
	void *rqc, *wq;
	int ret;

	buff = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
	pas = devx_umem_reg(ctx, buff, 0x10000, 7, &pas_id);

	dbr = devx_umem_reg(ctx, memalign(64, 8), 8, 7, &dbr_id);
	if (!dbr)
		return 0;
	ret = devx_alloc_uar(ctx, &uar_id, &uar_ptr, NULL);
	if (ret)
		return 0;

	DEVX_SET(create_rq_in, in, opcode, MLX5_CMD_OP_CREATE_RQ);

	rqc = DEVX_ADDR_OF(create_rq_in, in, ctx);
	DEVX_SET(rqc, rqc, vsd, 1);
	DEVX_SET(rqc, rqc, mem_rq_type, MLX5_RQC_MEM_RQ_TYPE_MEMORY_RQ_INLINE);
	DEVX_SET(rqc, rqc, state, MLX5_RQC_STATE_RST);
	DEVX_SET(rqc, rqc, flush_in_error_en, 1);
	DEVX_SET(rqc, rqc, user_index, 1);
	DEVX_SET(rqc, rqc, cqn, cqn);

	wq = DEVX_ADDR_OF(rqc, rqc, wq);
	DEVX_SET(wq, wq, wq_type, 1);
	DEVX_SET(wq, wq, pd, pd);
	DEVX_SET(wq, wq, log_wq_stride, 6);
	DEVX_SET(wq, wq, log_wq_sz, 6);

	DEVX_SET(create_rq_in, in, ctx.wq.wq_umem_id, pas_id);
	DEVX_SET(create_rq_in, in, ctx.wq.dbr_umem_id, dbr_id);

	q = devx_obj_create(ctx, in, sizeof(in), out, sizeof(out));

	return DEVX_GET(create_rq_out, out, rqn);
}

int test_td(void *ctx);
int test_td(void *ctx) {
	u8 in[DEVX_ST_SZ_BYTES(alloc_transport_domain_in)]   = {0};
	u8 out[DEVX_ST_SZ_BYTES(alloc_transport_domain_out)] = {0};

	DEVX_SET(alloc_transport_domain_in, in, opcode,
		 MLX5_CMD_OP_ALLOC_TRANSPORT_DOMAIN);

	if (!devx_obj_create(ctx, in, sizeof(in), out, sizeof(out)))
		return 0;

	return DEVX_GET(alloc_transport_domain_out, out, transport_domain);
}

int test_tir(void *ctx, int rq, int td);
int test_tir(void *ctx, int rq, int td) {
	u8 in[DEVX_ST_SZ_BYTES(create_tir_in)]   = {0};
	u8 out[DEVX_ST_SZ_BYTES(create_tir_out)] = {0};
	void *tirc;

	DEVX_SET(create_tir_in, in, opcode, MLX5_CMD_OP_CREATE_TIR);
	tirc = DEVX_ADDR_OF(create_tir_in, in, ctx);
	DEVX_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_DIRECT);
	DEVX_SET(tirc, tirc, inline_rqn, rq);
	DEVX_SET(tirc, tirc, transport_domain, td);

	if (!devx_obj_create(ctx, in, sizeof(in), out, sizeof(out)))
		return 0;

	return DEVX_GET(create_tir_out, out, tirn);
}

int test_rule(void *ctx, int tir);
int test_rule(void *ctx, int tir) {
	u8 in[DEVX_ST_SZ_BYTES(fs_rule_add_in)] = {0};
	struct devx_obj_handle *rule;
	__be32 src_ip = 0x01020304;
	__be32 dst_ip = 0x05060708;
	void *headers_c, *headers_v;

	DEVX_SET(fs_rule_add_in, in, prio, 4);

	headers_c = DEVX_ADDR_OF(fs_rule_add_in, in,
			flow_spec.match_criteria.outer_headers);
	headers_v = DEVX_ADDR_OF(fs_rule_add_in, in,
			flow_spec.match_value.outer_headers);

	DEVX_SET(fte_match_set_lyr_2_4, headers_c, ip_version, 0xf);
	DEVX_SET(fte_match_set_lyr_2_4, headers_v, ip_version, 4);

	DEVX_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c,
			 src_ipv4_src_ipv6.ipv4_layout.ipv4);
	memcpy(DEVX_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
			    src_ipv4_src_ipv6.ipv4_layout.ipv4),
			&src_ip, sizeof(src_ip));

	DEVX_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c,
			 dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
	memcpy(DEVX_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
			    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
			&dst_ip, sizeof(dst_ip));

	DEVX_SET(fs_rule_add_in, in, dest.destination_type, MLX5_FLOW_DESTINATION_TYPE_TIR);
	DEVX_SET(fs_rule_add_in, in, dest.destination_id, tir);

	DEVX_SET(fs_rule_add_in, in, flow_spec.match_criteria_enable, 1 << MLX5_CREATE_FLOW_GROUP_IN_MATCH_CRITERIA_ENABLE_OUTER_HEADERS);

	rule = devx_fs_rule_add(ctx, in, sizeof(in));
	if (!rule)
		return 0;
	return 1;
}

enum fs_flow_table_type {
	FS_FT_NIC_RX	      = 0x0,
	FS_FT_NIC_TX	      = 0x1,
	FS_FT_ESW_EGRESS_ACL  = 0x2,
	FS_FT_ESW_INGRESS_ACL = 0x3,
	FS_FT_FDB	      = 0X4,
	FS_FT_SNIFFER_RX	= 0X5,
	FS_FT_SNIFFER_TX	= 0X6,
	FS_FT_MAX_TYPE = FS_FT_SNIFFER_TX,
};

int create_ft(void *ctx);
int create_ft(void *ctx)
{
	uint8_t in[DEVX_ST_SZ_BYTES(create_flow_table_in)] = {0};
	uint8_t out[DEVX_ST_SZ_BYTES(create_flow_table_out)] = {0};
	void *ftc;

	DEVX_SET(create_flow_table_in, in, opcode, MLX5_CMD_OP_CREATE_FLOW_TABLE);
	DEVX_SET(create_flow_table_in, in, table_type, FS_FT_NIC_RX);

	ftc = DEVX_ADDR_OF(create_flow_table_in, in, flow_table_context);
	DEVX_SET(flow_table_context, ftc, table_miss_action, 0); // default table
	DEVX_SET(flow_table_context, ftc, level, 64); // table level
	DEVX_SET(flow_table_context, ftc, log_size, 0);

	if (!devx_obj_create(ctx, in, sizeof(in), out, sizeof(out)))
		return 0;

	return DEVX_GET(create_flow_table_out, out, table_id);
}

int create_fg(void *ctx, int ft);
int create_fg(void *ctx, int ft)
{
	uint8_t in[DEVX_ST_SZ_BYTES(create_flow_group_in)] = {0};
	uint8_t out[DEVX_ST_SZ_BYTES(create_flow_group_out)] = {0};

	DEVX_SET(create_flow_group_in, in, opcode, MLX5_CMD_OP_CREATE_FLOW_GROUP);
	DEVX_SET(create_flow_group_in, in, table_type, FS_FT_NIC_RX);
	DEVX_SET(create_flow_group_in, in, table_id, ft);
	DEVX_SET(create_flow_group_in, in, start_flow_index, 0);
	DEVX_SET(create_flow_group_in, in, end_flow_index, 0);
	DEVX_SET(create_flow_group_in, in, match_criteria_enable, MLX5_CREATE_FLOW_GROUP_IN_MATCH_CRITERIA_ENABLE_OUTER_HEADERS);

	if (!devx_obj_create(ctx, in, sizeof(in), out, sizeof(out)))
		return 0;

	return DEVX_GET(create_flow_group_out, out, group_id);
}

int set_fte(void *ctx, int ft, int fg, int tir);
int set_fte(void *ctx, int ft, int fg, int tir) 
{
	uint8_t in[DEVX_ST_SZ_BYTES(set_fte_in) + DEVX_UN_SZ_BYTES(dest_format_struct_flow_counter_list_auto)] = {0};
	uint8_t out[DEVX_ST_SZ_BYTES(set_fte_out)] = {0};
	void *in_flow_context, *in_dests;

	DEVX_SET(set_fte_in, in, opcode, MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY);
	DEVX_SET(set_fte_in, in, uid, 0); // FIXME !!!!!!
	DEVX_SET(set_fte_in, in, op_mod, 0); // SET = 0, MOD =1
	DEVX_SET(set_fte_in, in, modify_enable_mask, 0);
	DEVX_SET(set_fte_in, in, table_type, FS_FT_NIC_RX);
	DEVX_SET(set_fte_in, in, table_id,   ft);
	DEVX_SET(set_fte_in, in, flow_index, 0);

	DEVX_SET(set_fte_in, in, vport_number, 0);
	DEVX_SET(set_fte_in, in, other_vport, 0);

	in_flow_context = DEVX_ADDR_OF(set_fte_in, in, flow_context);
	DEVX_SET(flow_context, in_flow_context, group_id, fg);
	DEVX_SET(flow_context, in_flow_context, flow_tag, 1);
	DEVX_SET(flow_context, in_flow_context, action, MLX5_FLOW_CONTEXT_ACTION_FWD_DEST);
	DEVX_SET(flow_context, in_flow_context, destination_list_size, 1);

	in_dests = DEVX_ADDR_OF(flow_context, in_flow_context, destination[0].dest_format_struct);
	DEVX_SET(dest_format_struct, in_dests, destination_type, MLX5_FLOW_DESTINATION_TYPE_TIR);
	DEVX_SET(dest_format_struct, in_dests, destination_id, tir);

	if (!devx_obj_create(ctx, in, sizeof(in), out, sizeof(out)))
		return 0;

	return 1;
}

int test_rule_priv(void *ctx, int ft);
int test_rule_priv(void *ctx, int ft) {
	u8 in[DEVX_ST_SZ_BYTES(fs_rule_add_in)] = {0};
	struct devx_obj_handle *rule;
	__be32 src_ip = 0x01020304;
	__be32 dst_ip = 0x05060708;
	void *headers_c, *headers_v;

	DEVX_SET(fs_rule_add_in, in, prio, 5);

	headers_c = DEVX_ADDR_OF(fs_rule_add_in, in,
			flow_spec.match_criteria.outer_headers);
	headers_v = DEVX_ADDR_OF(fs_rule_add_in, in,
			flow_spec.match_value.outer_headers);

	DEVX_SET(fte_match_set_lyr_2_4, headers_c, ip_version, 0xf);
	DEVX_SET(fte_match_set_lyr_2_4, headers_v, ip_version, 4);

	DEVX_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c,
			 src_ipv4_src_ipv6.ipv4_layout.ipv4);
	memcpy(DEVX_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
			    src_ipv4_src_ipv6.ipv4_layout.ipv4),
			&src_ip, sizeof(src_ip));

	DEVX_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c,
			 dst_ipv4_dst_ipv6.ipv4_layout.ipv4);
	memcpy(DEVX_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
			    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
			&dst_ip, sizeof(dst_ip));

	DEVX_SET(fs_rule_add_in, in, dest.destination_type, MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE);
	DEVX_SET(fs_rule_add_in, in, dest.destination_id, ft);

	DEVX_SET(fs_rule_add_in, in, flow_spec.match_criteria_enable, 1 << MLX5_CREATE_FLOW_GROUP_IN_MATCH_CRITERIA_ENABLE_OUTER_HEADERS);

	rule = devx_fs_rule_add(ctx, in, sizeof(in));
	if (!rule)
		return 0;

	return 1;
}

TEST(devx, roce) {
	int num;
	struct devx_device **list = devx_get_device_list(&num);
	void *ctx;
	int devn = 0;
	int pd;
	int cq, rq, td, tir;
	int ft, fg;

	if (getenv("DEVN"))
		devn = atoi(getenv("DEVN"));

	ASSERT_GT(num, devn);
	ctx = devx_open_device(list[devn]);
	ASSERT_TRUE(ctx);
	devx_free_device_list(list);
	ASSERT_EQ(test_query(ctx), 22);

	pd = alloc_pd(ctx);
	ASSERT_TRUE(pd);

	cq = create_cq(ctx, NULL, 0, NULL, 0);
	ASSERT_TRUE(cq);
	rq = test_rq(ctx, cq, pd);
	ASSERT_TRUE(rq);
	td = test_td(ctx);
	ASSERT_TRUE(td);
	tir = test_tir(ctx, rq, td);
	ASSERT_TRUE(tir);

	ASSERT_TRUE(test_rule(ctx, tir));
	ft = create_ft(ctx);
	ASSERT_TRUE(ft);
	fg = create_fg(ctx,ft);
	ASSERT_TRUE(fg);
	ASSERT_TRUE(set_fte(ctx,ft,fg,tir));
	ASSERT_TRUE(test_rule_priv(ctx,ft));
	ASSERT_TRUE(test_rule_priv(ctx,ft));

	devx_close_device(ctx);
}


#ifdef DEVX_VERBS_MIX
#include "devx_verbs.h"

TEST(devx, send_verbs_mr) {
	int num, devn = 0;
	struct ibv_device **list = ibv_get_device_list(&num);
	struct ibv_context *ibctx;
	void *ctx;
	unsigned char buff[0x1000];
	for(int i = 0; i < 0x60; i++)
		buff[i] = i + 0x20;

	int ret, lid;

	if (getenv("DEVN"))
		devn = atoi(getenv("DEVN"));

	ASSERT_GT(num, devn);
	ibctx = ibv_open_device(list[devn]);
	ctx = devx_from_ibv(ibctx);
	ASSERT_TRUE(ibctx);
	ibv_free_device_list(list);

	uint32_t uar_id;
	void *uar_ptr = NULL;
	ret = devx_alloc_uar(ctx, &uar_id, &uar_ptr, NULL);
	ASSERT_FALSE(ret);

	struct ibv_pd *pd = ibv_alloc_pd(ibctx);
	ASSERT_TRUE(pd);
	uint32_t pdn = *(uint32_t *)(pd + 1);

	void *cq_buff, *cq_dbr;
	int cq = create_cq(ctx, &cq_buff, uar_id, &cq_dbr, eq);
	ASSERT_TRUE(cq);
	struct ibv_mr *mr = ibv_reg_mr(pd, buff, sizeof(buff), IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	ASSERT_TRUE(mr);
	uint32_t mkey = mr->lkey;

	lid = query_lid(ctx);
	ASSERT_LE(0, lid);

	void *qp_buff;
	uint32_t *qp_dbr;
	struct devx_obj_handle *q;
	int qp = create_qp(ctx, &qp_buff, uar_id, &qp_dbr, cq, pdn, &q);
	ASSERT_TRUE(qp);
	ASSERT_FALSE(to_init(q, qp));
	ASSERT_FALSE(to_rtr(q, qp, lid));
	ASSERT_FALSE(to_rts(q, qp));

	uint8_t *rq = (u8 *)qp_buff;
	uint8_t *sq = (u8 *)qp_buff + MLX5_SEND_WQE_BB * RQ_SIZE;
	int rqi = 0, sqi = 0;

	ASSERT_FALSE(recv(rq, &rqi, qp_dbr, mkey, buff, 0x30));
	ASSERT_FALSE(xmit(sq, &sqi, qp_dbr, mkey, buff + 0x30, 0x30, uar_ptr, qp));

	int cqi = 0;
	ASSERT_FALSE(poll_cq((uint8_t *)cq_buff, &cqi, cq_dbr));
	ASSERT_FALSE(poll_cq((uint8_t *)cq_buff, &cqi, cq_dbr));
}

#endif

