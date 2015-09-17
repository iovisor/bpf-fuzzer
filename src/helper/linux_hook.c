/*
 * helper functions using kernel data structures
 *
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <net/netlink.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/netdevice.h>
#include <net/sch_generic.h>

#define LOG_BUF_SIZE 65536
char bpf_log_buf[LOG_BUF_SIZE];

static void __user *u64_to_ptr(__u64 val)
{
        return (void __user *) (unsigned long) val;
}

static __u64 ptr_to_u64(void *ptr)
{
        return (__u64) (unsigned long) ptr;
}

const struct bpf_func_proto bpf_skb_store_bytes_proto = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_CTX,
        .arg2_type      = ARG_ANYTHING,
        .arg3_type      = ARG_PTR_TO_STACK,
        .arg4_type      = ARG_CONST_STACK_SIZE,
        .arg5_type      = ARG_ANYTHING,
};

const struct bpf_func_proto bpf_l3_csum_replace_proto = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_CTX,
        .arg2_type      = ARG_ANYTHING,
        .arg3_type      = ARG_ANYTHING,
        .arg4_type      = ARG_ANYTHING,
        .arg5_type      = ARG_ANYTHING,
};

const struct bpf_func_proto bpf_l4_csum_replace_proto = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_CTX,
        .arg2_type      = ARG_ANYTHING,
        .arg3_type      = ARG_ANYTHING,
        .arg4_type      = ARG_ANYTHING,
        .arg5_type      = ARG_ANYTHING,
};

const struct bpf_func_proto bpf_clone_redirect_proto = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_CTX,
        .arg2_type      = ARG_ANYTHING,
        .arg3_type      = ARG_ANYTHING,
};

static const struct bpf_func_proto bpf_get_cgroup_classid_proto = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_CTX,
};

static const struct bpf_func_proto bpf_skb_vlan_push_proto_t = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_CTX,
        .arg2_type      = ARG_ANYTHING,
        .arg3_type      = ARG_ANYTHING,
};

static const struct bpf_func_proto bpf_skb_vlan_pop_proto_t = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_CTX,
};

static const struct bpf_func_proto bpf_skb_get_tunnel_key_proto = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_CTX,
        .arg2_type      = ARG_PTR_TO_STACK,
        .arg3_type      = ARG_CONST_STACK_SIZE,
        .arg4_type      = ARG_ANYTHING,
};

static const struct bpf_func_proto bpf_skb_set_tunnel_key_proto = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_CTX,
        .arg2_type      = ARG_PTR_TO_STACK,
        .arg3_type      = ARG_CONST_STACK_SIZE,
        .arg4_type      = ARG_ANYTHING,
};

static const struct bpf_func_proto bpf_map_lookup_elem_proto_k = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_PTR_TO_MAP_VALUE_OR_NULL,
        .arg1_type      = ARG_CONST_MAP_PTR,
        .arg2_type      = ARG_PTR_TO_MAP_KEY,
};

static const struct bpf_func_proto bpf_map_update_elem_proto_k = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_CONST_MAP_PTR,
        .arg2_type      = ARG_PTR_TO_MAP_KEY,
        .arg3_type      = ARG_PTR_TO_MAP_VALUE,
        .arg4_type      = ARG_ANYTHING,
};

static const struct bpf_func_proto bpf_map_delete_elem_proto_k = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_CONST_MAP_PTR,
        .arg2_type      = ARG_PTR_TO_MAP_KEY,
};

static const struct bpf_func_proto bpf_get_prandom_u32_proto_k = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
};

static const struct bpf_func_proto bpf_get_smp_processor_id_proto_k = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
};

static const struct bpf_func_proto bpf_ktime_get_ns_proto_k = {
        .func           = NULL,
        .gpl_only       = true,
        .ret_type       = RET_INTEGER,
};

static const struct bpf_func_proto bpf_get_current_pid_tgid_proto_k = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
};

static const struct bpf_func_proto bpf_get_current_uid_gid_proto_k = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
};

static const struct bpf_func_proto bpf_get_current_comm_proto_k = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_STACK,
        .arg2_type      = ARG_CONST_STACK_SIZE,
};

static const struct bpf_func_proto bpf_tail_call_proto_k = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_VOID,
        .arg1_type      = ARG_PTR_TO_CTX,
        .arg2_type      = ARG_CONST_MAP_PTR,
        .arg3_type      = ARG_ANYTHING,
};

static const struct bpf_func_proto bpf_trace_printk_proto_k = {
        .func           = NULL,
        .gpl_only       = true,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_STACK,
        .arg2_type      = ARG_CONST_STACK_SIZE,
};

static const struct bpf_func_proto *
sk_filter_func_proto(enum bpf_func_id func_id)
{
        switch (func_id) {
        case BPF_FUNC_map_lookup_elem:
                return &bpf_map_lookup_elem_proto_k;
        case BPF_FUNC_map_update_elem:
                return &bpf_map_update_elem_proto_k;
        case BPF_FUNC_map_delete_elem:
                return &bpf_map_delete_elem_proto_k;
        case BPF_FUNC_get_prandom_u32:
                return &bpf_get_prandom_u32_proto_k;
        case BPF_FUNC_get_smp_processor_id:
                return &bpf_get_smp_processor_id_proto_k;
        case BPF_FUNC_tail_call:
                return &bpf_tail_call_proto_k;
        case BPF_FUNC_ktime_get_ns:
                return &bpf_ktime_get_ns_proto_k;
        case BPF_FUNC_trace_printk:
#if 0
                return bpf_get_trace_printk_proto();
#else
		return &bpf_trace_printk_proto_k;
#endif
        default:
                return NULL;
        }
}

static const struct bpf_func_proto *
tc_cls_act_func_proto(enum bpf_func_id func_id)
{
        switch (func_id) {
        case BPF_FUNC_skb_store_bytes:
                return &bpf_skb_store_bytes_proto;
        case BPF_FUNC_l3_csum_replace:
                return &bpf_l3_csum_replace_proto;
        case BPF_FUNC_l4_csum_replace:
                return &bpf_l4_csum_replace_proto;
        case BPF_FUNC_clone_redirect:
                return &bpf_clone_redirect_proto;
        case BPF_FUNC_get_cgroup_classid:
                return &bpf_get_cgroup_classid_proto;
        case BPF_FUNC_skb_vlan_push:
                return &bpf_skb_vlan_push_proto_t;
        case BPF_FUNC_skb_vlan_pop:
                return &bpf_skb_vlan_pop_proto_t;
        case BPF_FUNC_skb_get_tunnel_key:
                return &bpf_skb_get_tunnel_key_proto;
        case BPF_FUNC_skb_set_tunnel_key:
#if 0
                return bpf_get_skb_set_tunnel_key_proto();
#else
		return &bpf_skb_set_tunnel_key_proto;
#endif
        default:
                return sk_filter_func_proto(func_id);
        }
}

static u32 convert_skb_access(int skb_field, int dst_reg, int src_reg,
                              struct bpf_insn *insn_buf)
{
        struct bpf_insn *insn = insn_buf;

        switch (skb_field) {
        case SKF_AD_MARK:
                BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, mark) != 4);

                *insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg,
                                      offsetof(struct sk_buff, mark));
                break;

        case SKF_AD_PKTTYPE:
                *insn++ = BPF_LDX_MEM(BPF_B, dst_reg, src_reg, PKT_TYPE_OFFSET());
                *insn++ = BPF_ALU32_IMM(BPF_AND, dst_reg, PKT_TYPE_MAX);
#ifdef __BIG_ENDIAN_BITFIELD
                *insn++ = BPF_ALU32_IMM(BPF_RSH, dst_reg, 5);
#endif
                break;

        case SKF_AD_QUEUE:
                BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, queue_mapping) != 2);

                *insn++ = BPF_LDX_MEM(BPF_H, dst_reg, src_reg,
                                      offsetof(struct sk_buff, queue_mapping));
                break;

        case SKF_AD_VLAN_TAG:
        case SKF_AD_VLAN_TAG_PRESENT:
#if 1
#define	VLAN_TAG_PRESENT	0x1000
#endif
                BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, vlan_tci) != 2);
                BUILD_BUG_ON(VLAN_TAG_PRESENT != 0x1000);

                /* dst_reg = *(u16 *) (src_reg + offsetof(vlan_tci)) */
                *insn++ = BPF_LDX_MEM(BPF_H, dst_reg, src_reg,
                                      offsetof(struct sk_buff, vlan_tci));
                if (skb_field == SKF_AD_VLAN_TAG) {
                        *insn++ = BPF_ALU32_IMM(BPF_AND, dst_reg,
                                                ~VLAN_TAG_PRESENT);
                } else {
                        /* dst_reg >>= 12 */
                        *insn++ = BPF_ALU32_IMM(BPF_RSH, dst_reg, 12);
                        /* dst_reg &= 1 */
                        *insn++ = BPF_ALU32_IMM(BPF_AND, dst_reg, 1);
                }
                break;
        }


        return insn - insn_buf;
}

static bool __is_valid_access(int off, int size, enum bpf_access_type type)
{
        /* check bounds */
        if (off < 0 || off >= sizeof(struct __sk_buff))
                return false;

        /* disallow misaligned access */
        if (off % size != 0)
                return false;

        /* all __sk_buff fields are __u32 */
        if (size != 4)
                return false;

        return true;
}

static bool sk_filter_is_valid_access(int off, int size,
                                      enum bpf_access_type type)
{
        if (type == BPF_WRITE) {
                switch (off) {
                case offsetof(struct __sk_buff, cb[0]) ...
                        offsetof(struct __sk_buff, cb[4]):
                        break;
                default:
                        return false;
                }
        }

        return __is_valid_access(off, size, type);
}

static bool tc_cls_act_is_valid_access(int off, int size,
                                       enum bpf_access_type type)
{
        if (type == BPF_WRITE) {
                switch (off) {
                case offsetof(struct __sk_buff, mark):
                case offsetof(struct __sk_buff, tc_index):
                case offsetof(struct __sk_buff, cb[0]) ...
                        offsetof(struct __sk_buff, cb[4]):
                        break;
                default:
                        return false;
                }
        }
        return __is_valid_access(off, size, type);
}

static u32 bpf_net_convert_ctx_access(enum bpf_access_type type, int dst_reg,
                                      int src_reg, int ctx_off,
                                      struct bpf_insn *insn_buf)
{
        struct bpf_insn *insn = insn_buf;

        switch (ctx_off) {
        case offsetof(struct __sk_buff, len):
                BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, len) != 4);

                *insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg,
                                      offsetof(struct sk_buff, len));
                break;

        case offsetof(struct __sk_buff, protocol):
                BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, protocol) != 2);

                *insn++ = BPF_LDX_MEM(BPF_H, dst_reg, src_reg,
                                      offsetof(struct sk_buff, protocol));
                break;

        case offsetof(struct __sk_buff, vlan_proto):
                BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, vlan_proto) != 2);

                *insn++ = BPF_LDX_MEM(BPF_H, dst_reg, src_reg,
                                      offsetof(struct sk_buff, vlan_proto));
                break;

        case offsetof(struct __sk_buff, priority):
                BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, priority) != 4);

                *insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg,
                                      offsetof(struct sk_buff, priority));
                break;

        case offsetof(struct __sk_buff, ingress_ifindex):
                BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, skb_iif) != 4);

                *insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg,
                                      offsetof(struct sk_buff, skb_iif));
                break;

        case offsetof(struct __sk_buff, ifindex):
                BUILD_BUG_ON(FIELD_SIZEOF(struct net_device, ifindex) != 4);

                *insn++ = BPF_LDX_MEM(bytes_to_bpf_size(FIELD_SIZEOF(struct sk_buff, dev)),
                                      dst_reg, src_reg,
                                      offsetof(struct sk_buff, dev));
                *insn++ = BPF_JMP_IMM(BPF_JEQ, dst_reg, 0, 1);
                *insn++ = BPF_LDX_MEM(BPF_W, dst_reg, dst_reg,
                                      offsetof(struct net_device, ifindex));
                break;

        case offsetof(struct __sk_buff, hash):
                BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, hash) != 4);

                *insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg,
                                      offsetof(struct sk_buff, hash));
                break;

        case offsetof(struct __sk_buff, mark):
                BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, mark) != 4);

                if (type == BPF_WRITE)
                        *insn++ = BPF_STX_MEM(BPF_W, dst_reg, src_reg,
                                              offsetof(struct sk_buff, mark));
                else
                        *insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg,
                                              offsetof(struct sk_buff, mark));
                break;

        case offsetof(struct __sk_buff, pkt_type):
                return convert_skb_access(SKF_AD_PKTTYPE, dst_reg, src_reg, insn);

        case offsetof(struct __sk_buff, queue_mapping):
                return convert_skb_access(SKF_AD_QUEUE, dst_reg, src_reg, insn);

        case offsetof(struct __sk_buff, vlan_present):
                return convert_skb_access(SKF_AD_VLAN_TAG_PRESENT,
                                          dst_reg, src_reg, insn);

        case offsetof(struct __sk_buff, vlan_tci):
                return convert_skb_access(SKF_AD_VLAN_TAG,
                                          dst_reg, src_reg, insn);

        case offsetof(struct __sk_buff, cb[0]) ...
                offsetof(struct __sk_buff, cb[4]):
                BUILD_BUG_ON(FIELD_SIZEOF(struct qdisc_skb_cb, data) < 20);

                ctx_off -= offsetof(struct __sk_buff, cb[0]);
                ctx_off += offsetof(struct sk_buff, cb);
                ctx_off += offsetof(struct qdisc_skb_cb, data);
                if (type == BPF_WRITE)
                        *insn++ = BPF_STX_MEM(BPF_W, dst_reg, src_reg, ctx_off);
                else
                        *insn++ = BPF_LDX_MEM(BPF_W, dst_reg, src_reg, ctx_off);
                break;

        case offsetof(struct __sk_buff, tc_index):
		/* FIXME: CONFIG_NET_SCHED */
                BUILD_BUG_ON(FIELD_SIZEOF(struct sk_buff, tc_index) != 2);

                if (type == BPF_WRITE)
                        *insn++ = BPF_STX_MEM(BPF_H, dst_reg, src_reg,
                                              offsetof(struct sk_buff, tc_index));
                else
                        *insn++ = BPF_LDX_MEM(BPF_H, dst_reg, src_reg,
                                              offsetof(struct sk_buff, tc_index));
                break;
        }

        return insn - insn_buf;
}

const struct bpf_func_proto bpf_perf_event_read_proto = {
        .func           = NULL,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_CONST_MAP_PTR,
        .arg2_type      = ARG_ANYTHING,
};

static const struct bpf_func_proto bpf_probe_read_proto = {
        .func           = NULL,
        .gpl_only       = true,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_PTR_TO_STACK,
        .arg2_type      = ARG_CONST_STACK_SIZE,
        .arg3_type      = ARG_ANYTHING,
};

static const struct bpf_func_proto *kprobe_prog_func_proto(enum bpf_func_id func_id)
{
        switch (func_id) {
        case BPF_FUNC_map_lookup_elem:
                return &bpf_map_lookup_elem_proto_k;
        case BPF_FUNC_map_update_elem:
                return &bpf_map_update_elem_proto_k;
        case BPF_FUNC_map_delete_elem:
                return &bpf_map_delete_elem_proto_k;
        case BPF_FUNC_probe_read:
                return &bpf_probe_read_proto;
        case BPF_FUNC_ktime_get_ns:
                return &bpf_ktime_get_ns_proto_k;
        case BPF_FUNC_tail_call:
                return &bpf_tail_call_proto_k;
        case BPF_FUNC_get_current_pid_tgid:
                return &bpf_get_current_pid_tgid_proto_k;
        case BPF_FUNC_get_current_uid_gid:
                return &bpf_get_current_uid_gid_proto_k;
        case BPF_FUNC_get_current_comm:
                return &bpf_get_current_comm_proto_k;
        case BPF_FUNC_trace_printk:
#if 0
                return bpf_get_trace_printk_proto();
#else
		return &bpf_trace_printk_proto_k;
#endif
        case BPF_FUNC_get_smp_processor_id:
                return &bpf_get_smp_processor_id_proto_k;
        case BPF_FUNC_perf_event_read:
                return &bpf_perf_event_read_proto;
        default:
                return NULL;
        }
}

static bool kprobe_prog_is_valid_access(int off, int size, enum bpf_access_type type)
{
        /* check bounds */
        if (off < 0 || off >= sizeof(struct pt_regs))
                return false;

        /* only read is allowed */
        if (type != BPF_READ)
                return false;

        /* disallow misaligned access */
        if (off % size != 0)
                return false;

        return true;
}

static const struct bpf_verifier_ops sk_filter_ops = {
        .get_func_proto = sk_filter_func_proto,
        .is_valid_access = sk_filter_is_valid_access,
        .convert_ctx_access = bpf_net_convert_ctx_access,
};

static const struct bpf_verifier_ops tc_cls_act_ops = {
        .get_func_proto = tc_cls_act_func_proto,
        .is_valid_access = tc_cls_act_is_valid_access,
        .convert_ctx_access = bpf_net_convert_ctx_access,
};

static struct bpf_verifier_ops kprobe_prog_ops = {
        .get_func_proto  = kprobe_prog_func_proto,
        .is_valid_access = kprobe_prog_is_valid_access,
};

static struct bpf_prog_type_list sk_filter_type __read_mostly = {
        .ops = &sk_filter_ops,
        .type = BPF_PROG_TYPE_SOCKET_FILTER,
};

static struct bpf_prog_type_list sched_cls_type __read_mostly = {
        .ops = &tc_cls_act_ops,
        .type = BPF_PROG_TYPE_SCHED_CLS,
};

static struct bpf_prog_type_list sched_act_type __read_mostly = {
        .ops = &tc_cls_act_ops,
        .type = BPF_PROG_TYPE_SCHED_ACT,
};

static struct bpf_prog_type_list kprobe_tl = {
        .ops    = &kprobe_prog_ops,
        .type   = BPF_PROG_TYPE_KPROBE,
};

struct bpf_prog_type_info {
	enum bpf_prog_type type;
	struct bpf_verifier_ops *ops;
	struct bpf_prog_type_info *next;
};
static struct bpf_prog_type_info *bpf_prog_type_node = NULL;

static struct bpf_prog_type_info *register_prog_type_k(
	struct bpf_prog_type_list *tl) {
	struct bpf_prog_type_info *b = (struct bpf_prog_type_info *)
		malloc(sizeof(struct bpf_prog_type_info));
	b->type = tl->type;
	b->ops = tl->ops;
	return b;
}

static int find_prog_type_k(enum bpf_prog_type type, struct bpf_prog *prog)
{
	struct bpf_prog_type_info *m, *n;

	if (bpf_prog_type_node == NULL) {
		/* first call, let us do initialization */
		n = register_prog_type_k(&kprobe_tl);
		n->next = NULL;

		m = register_prog_type_k(&sched_act_type);
		m->next = n;
		n = m;

		m = register_prog_type_k(&sched_cls_type);
		m->next = n;
		n = m;

		m = register_prog_type_k(&sk_filter_type);
		m->next = n;
		bpf_prog_type_node = m;
	}

	/* the callback functions are assigned here */
	for (n = bpf_prog_type_node; n != NULL; n = n->next) {
		if (n->type == type) {
			prog->aux->ops = n->ops;
			prog->type = type;
			return 0;
		}
	}

        return -EINVAL;
}

/* functions used by test_verifier.c */
static struct bpf_prog *bpf_prog_alloc_k(unsigned int size)
{
        struct bpf_prog_aux *aux;
        struct bpf_prog *fp;

        size = round_up(size, PAGE_SIZE);
        fp = vmalloc(size);
        if (fp == NULL)
                return NULL;

        aux = kzalloc(sizeof(*aux), GFP_KERNEL);
        if (aux == NULL) {
                vfree(fp);
                return NULL;
        }

        fp->pages = size / PAGE_SIZE;
        fp->aux = aux;

        return fp;
}

static void bpf_prog_free_k(struct bpf_prog *fp)
{
        kfree(fp->aux);
        vfree(fp);
}       

struct bpf_prog *bpf_prog_realloc_k(struct bpf_prog *fp_old, unsigned int size)
{
	struct bpf_prog *fp;

	size = round_up(size, PAGE_SIZE);
	if (size <= fp_old->pages * PAGE_SIZE)
		return fp_old;

	fp = vmalloc(size);
	if (fp != NULL) {
		memcpy(fp, fp_old, fp_old->pages * PAGE_SIZE);
		fp->pages = size / PAGE_SIZE;
		fp_old->aux = NULL;
		bpf_prog_free_k(fp_old);	
	}

	return fp;
}

/* create a map - but not really going into the kernel */
struct bpf_map_node {
	int fd;
	struct bpf_map *map;
	struct bpf_map_node *next;
};
static struct bpf_map_node *map_head = NULL;
static int fd_num = 1;

int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
                   int max_entries)
{
	struct bpf_map *m;
	struct bpf_map_node *n;
	int cur_fd;

	m = (struct bpf_map *)vmalloc(sizeof(struct bpf_map));
	m->map_type = map_type;
	m->key_size = key_size;
	m->value_size = value_size;
	m->max_entries = max_entries;
	m->ops = NULL;

	n = (struct bpf_map_node *)vmalloc(sizeof(struct bpf_map_node));
	cur_fd = fd_num++;
	n->fd = cur_fd;
	n->map = m;

	if (map_head == NULL) {
		n->next = NULL;
		map_head = n;
	} else {
		n->next = map_head;
		map_head = n;
	}

	return cur_fd;
}

void bpf_free_map(int fd)
{
	struct bpf_map_node *c, *p;

	c = p = map_head;
	while (c != NULL) {
		if (c->fd == fd) {
			vfree(c->map);
			if (c == p)
				map_head = c->next;
			else
				p->next = c->next;
			vfree(c);
			break;
		}
		p = c;
		c = c->next;
	}
}

void bpf_map_put_k(struct bpf_map *map)
{
	return;
}

unsigned long __fdget_k(unsigned int fd)
{
	struct bpf_map_node *n;

	for (n = map_head; n != NULL; n = n->next) {
		if (n->fd == fd)
			return (unsigned long)n->map;
	}

	return -1;
}

/* load a bpf program - do verification only */
int bpf_prog_load(enum bpf_prog_type prog_type,
                  const struct bpf_insn *insns, int prog_len,
                  const char *license, int kern_version)
{

        union bpf_attr attr = {
                .prog_type = prog_type,
                .insns = ptr_to_u64((void *) insns),
                .insn_cnt = prog_len / sizeof(struct bpf_insn),
                .license = ptr_to_u64((void *) license),
                .log_buf = ptr_to_u64(bpf_log_buf),
                .log_size = LOG_BUF_SIZE,
                .log_level = 1,
        };
        enum bpf_prog_type type = attr.prog_type;
        struct bpf_prog *prog;
        int err;

        attr.kern_version = kern_version;
        bpf_log_buf[0] = 0;

        if (attr.insn_cnt >= BPF_MAXINSNS)
                return -EINVAL;

        /* plain bpf_prog allocation */
        prog = bpf_prog_alloc_k(bpf_prog_size(attr.insn_cnt));
        if (!prog)
                return -ENOMEM;

        prog->len = attr.insn_cnt;

        memcpy(prog->insns, u64_to_ptr(attr.insns), prog->len * sizeof(struct bpf_insn));
        prog->orig_prog = NULL;
        prog->jited = false;

        atomic_set(&prog->aux->refcnt, 1);
        prog->gpl_compatible = 1;

        /* find program type: socket_filter vs tracing_filter */
        err = find_prog_type_k(type, prog);
        if (err >= 0) {
        	/* run eBPF verifier */
		err = bpf_check(&prog, &attr);

		/* this is a workaround for userspace verifier.
		 * in kernel, the env->prog->aux->used_maps will be
		 * freed when the map itself is freed.
		 */
		kfree(prog->aux->used_maps);
	}
        bpf_prog_free_k(prog);
        return err;
}
