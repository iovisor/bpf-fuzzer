/*
 * Testsuite for eBPF verifier
 *
 * Copyright (c) 2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <stdio.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <errno.h>
#include <linux/unistd.h>
#include <string.h>
#include <linux/filter.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include "libbpf.h"

#define MAX_INSNS 512
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

struct bpf_test {
	const char *descr;
	struct bpf_insn	insns[MAX_INSNS];
	int fixup[32];
	const char *errstr;
	enum {
		ACCEPT,
		REJECT
	} result;
	enum bpf_prog_type prog_type;
};

static struct bpf_test tests[] = {
	{
		"add+sub+mul",
		.insns = {
			BPF_MOV64_IMM(BPF_REG_1, 1),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 2),
			BPF_MOV64_IMM(BPF_REG_2, 3),
			BPF_ALU64_REG(BPF_SUB, BPF_REG_1, BPF_REG_2),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -1),
			BPF_ALU64_IMM(BPF_MUL, BPF_REG_1, 3),
			BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
			BPF_EXIT_INSN(),
		},
		.result = ACCEPT,
	},
	{
		"unreachable",
		.insns = {
			BPF_EXIT_INSN(),
			BPF_EXIT_INSN(),
		},
		.errstr = "unreachable",
		.result = REJECT,
	},
	{
		"unreachable2",
		.insns = {
			BPF_JMP_IMM(BPF_JA, 0, 0, 1),
			BPF_JMP_IMM(BPF_JA, 0, 0, 0),
			BPF_EXIT_INSN(),
		},
		.errstr = "unreachable",
		.result = REJECT,
	},
	{
		"out of range jump",
		.insns = {
			BPF_JMP_IMM(BPF_JA, 0, 0, 1),
			BPF_EXIT_INSN(),
		},
		.errstr = "jump out of range",
		.result = REJECT,
	},
	{
		"out of range jump2",
		.insns = {
			BPF_JMP_IMM(BPF_JA, 0, 0, -2),
			BPF_EXIT_INSN(),
		},
		.errstr = "jump out of range",
		.result = REJECT,
	},
	{
		"test1 ld_imm64",
		.insns = {
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 1),
			BPF_LD_IMM64(BPF_REG_0, 0),
			BPF_LD_IMM64(BPF_REG_0, 0),
			BPF_LD_IMM64(BPF_REG_0, 1),
			BPF_LD_IMM64(BPF_REG_0, 1),
			BPF_MOV64_IMM(BPF_REG_0, 2),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid BPF_LD_IMM insn",
		.result = REJECT,
	},
	{
		"test2 ld_imm64",
		.insns = {
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 1),
			BPF_LD_IMM64(BPF_REG_0, 0),
			BPF_LD_IMM64(BPF_REG_0, 0),
			BPF_LD_IMM64(BPF_REG_0, 1),
			BPF_LD_IMM64(BPF_REG_0, 1),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid BPF_LD_IMM insn",
		.result = REJECT,
	},
	{
		"test3 ld_imm64",
		.insns = {
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 1),
			BPF_RAW_INSN(BPF_LD | BPF_IMM | BPF_DW, 0, 0, 0, 0),
			BPF_LD_IMM64(BPF_REG_0, 0),
			BPF_LD_IMM64(BPF_REG_0, 0),
			BPF_LD_IMM64(BPF_REG_0, 1),
			BPF_LD_IMM64(BPF_REG_0, 1),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid bpf_ld_imm64 insn",
		.result = REJECT,
	},
	{
		"test4 ld_imm64",
		.insns = {
			BPF_RAW_INSN(BPF_LD | BPF_IMM | BPF_DW, 0, 0, 0, 0),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid bpf_ld_imm64 insn",
		.result = REJECT,
	},
	{
		"test5 ld_imm64",
		.insns = {
			BPF_RAW_INSN(BPF_LD | BPF_IMM | BPF_DW, 0, 0, 0, 0),
		},
		.errstr = "invalid bpf_ld_imm64 insn",
		.result = REJECT,
	},
	{
		"no bpf_exit",
		.insns = {
			BPF_ALU64_REG(BPF_MOV, BPF_REG_0, BPF_REG_2),
		},
		.errstr = "jump out of range",
		.result = REJECT,
	},
	{
		"loop (back-edge)",
		.insns = {
			BPF_JMP_IMM(BPF_JA, 0, 0, -1),
			BPF_EXIT_INSN(),
		},
		.errstr = "back-edge",
		.result = REJECT,
	},
	{
		"loop2 (back-edge)",
		.insns = {
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_0),
			BPF_MOV64_REG(BPF_REG_3, BPF_REG_0),
			BPF_JMP_IMM(BPF_JA, 0, 0, -4),
			BPF_EXIT_INSN(),
		},
		.errstr = "back-edge",
		.result = REJECT,
	},
	{
		"conditional loop",
		.insns = {
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_0),
			BPF_MOV64_REG(BPF_REG_3, BPF_REG_0),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, -3),
			BPF_EXIT_INSN(),
		},
		.errstr = "back-edge",
		.result = REJECT,
	},
	{
		"read uninitialized register",
		.insns = {
			BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
			BPF_EXIT_INSN(),
		},
		.errstr = "R2 !read_ok",
		.result = REJECT,
	},
	{
		"read invalid register",
		.insns = {
			BPF_MOV64_REG(BPF_REG_0, -1),
			BPF_EXIT_INSN(),
		},
		.errstr = "R15 is invalid",
		.result = REJECT,
	},
	{
		"program doesn't init R0 before exit",
		.insns = {
			BPF_ALU64_REG(BPF_MOV, BPF_REG_2, BPF_REG_1),
			BPF_EXIT_INSN(),
		},
		.errstr = "R0 !read_ok",
		.result = REJECT,
	},
	{
		"program doesn't init R0 before exit in all branches",
		.insns = {
			BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 0, 2),
			BPF_MOV64_IMM(BPF_REG_0, 1),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 2),
			BPF_EXIT_INSN(),
		},
		.errstr = "R0 !read_ok",
		.result = REJECT,
	},
	{
		"stack out of bounds",
		.insns = {
			BPF_ST_MEM(BPF_DW, BPF_REG_10, 8, 0),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid stack",
		.result = REJECT,
	},
	{
		"invalid call insn1",
		.insns = {
			BPF_RAW_INSN(BPF_JMP | BPF_CALL | BPF_X, 0, 0, 0, 0),
			BPF_EXIT_INSN(),
		},
		.errstr = "BPF_CALL uses reserved",
		.result = REJECT,
	},
	{
		"invalid call insn2",
		.insns = {
			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 1, 0),
			BPF_EXIT_INSN(),
		},
		.errstr = "BPF_CALL uses reserved",
		.result = REJECT,
	},
	{
		"invalid function call",
		.insns = {
			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, 1234567),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid func 1234567",
		.result = REJECT,
	},
	{
		"uninitialized stack1",
		.insns = {
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_LD_MAP_FD(BPF_REG_1, 0),
			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
			BPF_EXIT_INSN(),
		},
		.fixup = {2},
		.errstr = "invalid indirect read from stack",
		.result = REJECT,
	},
	{
		"uninitialized stack2",
		.insns = {
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, -8),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid read from stack",
		.result = REJECT,
	},
	{
		"check valid spill/fill",
		.insns = {
			/* spill R1(ctx) into stack */
			BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -8),

			/* fill it back into R2 */
			BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_10, -8),

			/* should be able to access R0 = *(R2 + 8) */
			/* BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, 8), */
			BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
			BPF_EXIT_INSN(),
		},
		.result = ACCEPT,
	},
	{
		"check corrupted spill/fill",
		.insns = {
			/* spill R1(ctx) into stack */
			BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -8),

			/* mess up with R1 pointer on stack */
			BPF_ST_MEM(BPF_B, BPF_REG_10, -7, 0x23),

			/* fill back into R0 should fail */
			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, -8),

			BPF_EXIT_INSN(),
		},
		.errstr = "corrupted spill",
		.result = REJECT,
	},
	{
		"invalid src register in STX",
		.insns = {
			BPF_STX_MEM(BPF_B, BPF_REG_10, -1, -1),
			BPF_EXIT_INSN(),
		},
		.errstr = "R15 is invalid",
		.result = REJECT,
	},
	{
		"invalid dst register in STX",
		.insns = {
			BPF_STX_MEM(BPF_B, 14, BPF_REG_10, -1),
			BPF_EXIT_INSN(),
		},
		.errstr = "R14 is invalid",
		.result = REJECT,
	},
	{
		"invalid dst register in ST",
		.insns = {
			BPF_ST_MEM(BPF_B, 14, -1, -1),
			BPF_EXIT_INSN(),
		},
		.errstr = "R14 is invalid",
		.result = REJECT,
	},
	{
		"invalid src register in LDX",
		.insns = {
			BPF_LDX_MEM(BPF_B, BPF_REG_0, 12, 0),
			BPF_EXIT_INSN(),
		},
		.errstr = "R12 is invalid",
		.result = REJECT,
	},
	{
		"invalid dst register in LDX",
		.insns = {
			BPF_LDX_MEM(BPF_B, 11, BPF_REG_1, 0),
			BPF_EXIT_INSN(),
		},
		.errstr = "R11 is invalid",
		.result = REJECT,
	},
	{
		"junk insn",
		.insns = {
			BPF_RAW_INSN(0, 0, 0, 0, 0),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid BPF_LD_IMM",
		.result = REJECT,
	},
	{
		"junk insn2",
		.insns = {
			BPF_RAW_INSN(1, 0, 0, 0, 0),
			BPF_EXIT_INSN(),
		},
		.errstr = "BPF_LDX uses reserved fields",
		.result = REJECT,
	},
	{
		"junk insn3",
		.insns = {
			BPF_RAW_INSN(-1, 0, 0, 0, 0),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid BPF_ALU opcode f0",
		.result = REJECT,
	},
	{
		"junk insn4",
		.insns = {
			BPF_RAW_INSN(-1, -1, -1, -1, -1),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid BPF_ALU opcode f0",
		.result = REJECT,
	},
	{
		"junk insn5",
		.insns = {
			BPF_RAW_INSN(0x7f, -1, -1, -1, -1),
			BPF_EXIT_INSN(),
		},
		.errstr = "BPF_ALU uses reserved fields",
		.result = REJECT,
	},
	{
		"misaligned read from stack",
		.insns = {
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, -4),
			BPF_EXIT_INSN(),
		},
		.errstr = "misaligned access",
		.result = REJECT,
	},
	{
		"invalid map_fd for function call",
		.insns = {
			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
			BPF_ALU64_REG(BPF_MOV, BPF_REG_2, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_LD_MAP_FD(BPF_REG_1, 0),
			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_delete_elem),
			BPF_EXIT_INSN(),
		},
		.errstr = "fd 0 is not pointing to valid bpf_map",
		.result = REJECT,
	},
	{
		"don't check return value before access",
		.insns = {
			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_LD_MAP_FD(BPF_REG_1, 0),
			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
			BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 0),
			BPF_EXIT_INSN(),
		},
		.fixup = {3},
		.errstr = "R0 invalid mem access 'map_value_or_null'",
		.result = REJECT,
	},
	{
		"access memory with incorrect alignment",
		.insns = {
			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_LD_MAP_FD(BPF_REG_1, 0),
			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
			BPF_ST_MEM(BPF_DW, BPF_REG_0, 4, 0),
			BPF_EXIT_INSN(),
		},
		.fixup = {3},
		.errstr = "misaligned access",
		.result = REJECT,
	},
	{
		"sometimes access memory with incorrect alignment",
		.insns = {
			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_LD_MAP_FD(BPF_REG_1, 0),
			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
			BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 0),
			BPF_EXIT_INSN(),
			BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 1),
			BPF_EXIT_INSN(),
		},
		.fixup = {3},
		.errstr = "R0 invalid mem access",
		.result = REJECT,
	},
	{
		"jump test 1",
		.insns = {
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, -8),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 1),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 1, 1),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -16, 1),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 2, 1),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 2),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 3, 1),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -16, 3),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 4, 1),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 4),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 5, 1),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -32, 5),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_EXIT_INSN(),
		},
		.result = ACCEPT,
	},
	{
		"jump test 2",
		.insns = {
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 2),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
			BPF_JMP_IMM(BPF_JA, 0, 0, 14),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 1, 2),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -16, 0),
			BPF_JMP_IMM(BPF_JA, 0, 0, 11),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 2, 2),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -32, 0),
			BPF_JMP_IMM(BPF_JA, 0, 0, 8),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 3, 2),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -40, 0),
			BPF_JMP_IMM(BPF_JA, 0, 0, 5),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 4, 2),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -48, 0),
			BPF_JMP_IMM(BPF_JA, 0, 0, 2),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 5, 1),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -56, 0),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_EXIT_INSN(),
		},
		.result = ACCEPT,
	},
	{
		"jump test 3",
		.insns = {
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 3),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -8, 0),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_JMP_IMM(BPF_JA, 0, 0, 19),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 1, 3),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -16, 0),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16),
			BPF_JMP_IMM(BPF_JA, 0, 0, 15),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 2, 3),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -32, 0),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -32),
			BPF_JMP_IMM(BPF_JA, 0, 0, 11),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 3, 3),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -40, 0),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -40),
			BPF_JMP_IMM(BPF_JA, 0, 0, 7),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 4, 3),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -48, 0),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -48),
			BPF_JMP_IMM(BPF_JA, 0, 0, 3),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 5, 0),
			BPF_ST_MEM(BPF_DW, BPF_REG_2, -56, 0),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -56),
			BPF_LD_MAP_FD(BPF_REG_1, 0),
			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_delete_elem),
			BPF_EXIT_INSN(),
		},
		.fixup = {24},
		.result = ACCEPT,
	},
	{
		"jump test 4",
		.insns = {
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 1),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 2),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 3),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 4),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 1),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 2),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 3),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 4),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 1),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 2),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 3),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 4),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 1),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 2),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 3),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 4),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 1),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 2),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 3),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 4),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 1),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 2),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 3),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 4),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 1),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 2),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 3),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 4),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 1),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 2),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 3),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 4),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 1),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 2),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 3),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 4),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 0),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 0),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 0),
			BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, BPF_REG_10, 0),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_EXIT_INSN(),
		},
		.result = ACCEPT,
	},
	{
		"jump test 5",
		.insns = {
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_MOV64_REG(BPF_REG_3, BPF_REG_2),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 0, 2),
			BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_3, -8),
			BPF_JMP_IMM(BPF_JA, 0, 0, 2),
			BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_2, -8),
			BPF_JMP_IMM(BPF_JA, 0, 0, 0),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 0, 2),
			BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_3, -8),
			BPF_JMP_IMM(BPF_JA, 0, 0, 2),
			BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_2, -8),
			BPF_JMP_IMM(BPF_JA, 0, 0, 0),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 0, 2),
			BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_3, -8),
			BPF_JMP_IMM(BPF_JA, 0, 0, 2),
			BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_2, -8),
			BPF_JMP_IMM(BPF_JA, 0, 0, 0),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 0, 2),
			BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_3, -8),
			BPF_JMP_IMM(BPF_JA, 0, 0, 2),
			BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_2, -8),
			BPF_JMP_IMM(BPF_JA, 0, 0, 0),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 0, 2),
			BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_3, -8),
			BPF_JMP_IMM(BPF_JA, 0, 0, 2),
			BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_2, -8),
			BPF_JMP_IMM(BPF_JA, 0, 0, 0),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_EXIT_INSN(),
		},
		.result = ACCEPT,
	},
	{
		"access skb fields ok",
		.insns = {
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, len)),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 0, 1),
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, mark)),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 0, 1),
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, pkt_type)),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 0, 1),
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, queue_mapping)),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 0, 0),
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, protocol)),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 0, 0),
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, vlan_present)),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 0, 0),
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, vlan_tci)),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 0, 0),
			BPF_EXIT_INSN(),
		},
		.result = ACCEPT,
	},
	{
		"access skb fields bad1",
		.insns = {
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, -4),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid bpf_context access",
		.result = REJECT,
	},
	{
		"access skb fields bad2",
		.insns = {
			BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 0, 9),
			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_LD_MAP_FD(BPF_REG_1, 0),
			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
			BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
			BPF_EXIT_INSN(),
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, pkt_type)),
			BPF_EXIT_INSN(),
		},
		.fixup = {4},
		.errstr = "different pointers",
		.result = REJECT,
	},
	{
		"access skb fields bad3",
		.insns = {
			BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 0, 2),
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, pkt_type)),
			BPF_EXIT_INSN(),
			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_LD_MAP_FD(BPF_REG_1, 0),
			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
			BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
			BPF_EXIT_INSN(),
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
			BPF_JMP_IMM(BPF_JA, 0, 0, -12),
		},
		.fixup = {6},
		.errstr = "different pointers",
		.result = REJECT,
	},
	{
		"access skb fields bad4",
		.insns = {
			BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 0, 3),
			BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_1,
				    offsetof(struct __sk_buff, len)),
			BPF_MOV64_IMM(BPF_REG_0, 0),
			BPF_EXIT_INSN(),
			BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
			BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
			BPF_LD_MAP_FD(BPF_REG_1, 0),
			BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
			BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
			BPF_EXIT_INSN(),
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
			BPF_JMP_IMM(BPF_JA, 0, 0, -13),
		},
		.fixup = {7},
		.errstr = "different pointers",
		.result = REJECT,
	},
	{
		"check skb->mark is not writeable by sockets",
		.insns = {
			BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_1,
				    offsetof(struct __sk_buff, mark)),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid bpf_context access",
		.result = REJECT,
	},
	{
		"check skb->tc_index is not writeable by sockets",
		.insns = {
			BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_1,
				    offsetof(struct __sk_buff, tc_index)),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid bpf_context access",
		.result = REJECT,
	},
	{
		"check non-u32 access to cb",
		.insns = {
			BPF_STX_MEM(BPF_H, BPF_REG_1, BPF_REG_1,
				    offsetof(struct __sk_buff, cb[0])),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid bpf_context access",
		.result = REJECT,
	},
	{
		"check out of range skb->cb access",
		.insns = {
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, cb[60])),
			BPF_EXIT_INSN(),
		},
		.errstr = "invalid bpf_context access",
		.result = REJECT,
		.prog_type = BPF_PROG_TYPE_SCHED_ACT,
	},
	{
		"write skb fields from socket prog",
		.insns = {
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, cb[4])),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 0, 1),
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, mark)),
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, tc_index)),
			BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 0, 1),
			BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_1,
				    offsetof(struct __sk_buff, cb[0])),
			BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_1,
				    offsetof(struct __sk_buff, cb[2])),
			BPF_EXIT_INSN(),
		},
		.result = ACCEPT,
	},
	{
		"write skb fields from tc_cls_act prog",
		.insns = {
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, cb[0])),
			BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_0,
				    offsetof(struct __sk_buff, mark)),
			BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1,
				    offsetof(struct __sk_buff, tc_index)),
			BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_0,
				    offsetof(struct __sk_buff, tc_index)),
			BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_0,
				    offsetof(struct __sk_buff, cb[3])),
			BPF_EXIT_INSN(),
		},
		.result = ACCEPT,
		.prog_type = BPF_PROG_TYPE_SCHED_CLS,
	},
	{
		"PTR_TO_STACK store/load",
		.insns = {
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -10),
			BPF_ST_MEM(BPF_DW, BPF_REG_1, 2, 0xfaceb00c),
			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 2),
			BPF_EXIT_INSN(),
		},
		.result = ACCEPT,
	},
	{
		"PTR_TO_STACK store/load - bad alignment on off",
		.insns = {
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
			BPF_ST_MEM(BPF_DW, BPF_REG_1, 2, 0xfaceb00c),
			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 2),
			BPF_EXIT_INSN(),
		},
		.result = REJECT,
		.errstr = "misaligned access off -6 size 8",
	},
	{
		"PTR_TO_STACK store/load - bad alignment on reg",
		.insns = {
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -10),
			BPF_ST_MEM(BPF_DW, BPF_REG_1, 8, 0xfaceb00c),
			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 8),
			BPF_EXIT_INSN(),
		},
		.result = REJECT,
		.errstr = "misaligned access off -2 size 8",
	},
	{
		"PTR_TO_STACK store/load - out of bounds low",
		.insns = {
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -80000),
			BPF_ST_MEM(BPF_DW, BPF_REG_1, 8, 0xfaceb00c),
			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 8),
			BPF_EXIT_INSN(),
		},
		.result = REJECT,
		.errstr = "invalid stack off=-79992 size=8",
	},
	{
		"PTR_TO_STACK store/load - out of bounds high",
		.insns = {
			BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
			BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
			BPF_ST_MEM(BPF_DW, BPF_REG_1, 8, 0xfaceb00c),
			BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, 8),
			BPF_EXIT_INSN(),
		},
		.result = REJECT,
		.errstr = "invalid stack off=0 size=8",
	},
};

static int probe_filter_length(struct bpf_insn *fp)
{
	int len = 0;

	for (len = MAX_INSNS - 1; len > 0; --len)
		if (fp[len].code != 0 || fp[len].imm != 0)
			break;

	return len + 1;
}

static int create_map(void)
{
	long long key, value = 0;
	int map_fd;

	map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value), 1024);
	if (map_fd < 0) {
		printf("failed to create map '%s'\n", strerror(errno));
	}

	return map_fd;
}

static int gen_fuzzer_tests(char *test_dir, int plen)
{
	char fname[plen + 12], tmp_buf[12];
	int i, fd, len;

	len = strlen(test_dir);
	strcpy(fname, test_dir);

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		struct bpf_insn *prog = tests[i].insns;
		int prog_len = probe_filter_length(prog);

		sprintf(tmp_buf, "/init_%d", i);
		strcpy(&fname[len], tmp_buf);

		fd = open(fname, O_CREAT | O_WRONLY | O_TRUNC, S_IREAD | S_IWUSR);
		if (fd == -1) {
			fprintf(stderr, "open %s error: %s\n", fname, strerror(errno));
			return 1;
		}
		write(fd, prog, prog_len * sizeof(struct bpf_insn));
		close(fd);
	}

	return 0;
}

static int test(void)
{
	int prog_fd, i, pass_cnt = 0, err_cnt = 0;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		struct bpf_insn *prog = tests[i].insns;
		int prog_type = tests[i].prog_type;
		int prog_len = probe_filter_length(prog);
		int *fixup = tests[i].fixup;
		int map_fd = -1;

		if (*fixup) {
			map_fd = create_map();

			do {
				prog[*fixup].imm = map_fd;
				fixup++;
			} while (*fixup);
		}
		printf("#%d %s ", i, tests[i].descr);

		prog_fd = bpf_prog_load(prog_type ?: BPF_PROG_TYPE_SOCKET_FILTER,
					prog, prog_len * sizeof(struct bpf_insn),
					"GPL", 0);

		if (tests[i].result == ACCEPT) {
			if (prog_fd < 0) {
				printf("FAIL\nfailed to load prog '%s'\n",
				       strerror(errno));
				printf("%s", bpf_log_buf);
				err_cnt++;
				goto fail;
			}
		} else {
			if (prog_fd >= 0) {
				printf("FAIL\nunexpected success to load\n");
				printf("%s", bpf_log_buf);
				err_cnt++;
				goto fail;
			}
			if (strstr(bpf_log_buf, tests[i].errstr) == 0) {
				printf("FAIL\nunexpected error message: %s",
				       bpf_log_buf);
				err_cnt++;
				goto fail;
			}
		}

		pass_cnt++;
		printf("OK\n");
fail:
#ifdef TEST_WORKAROUND
		(void)1;
#else
		if (map_fd >= 0)
			close(map_fd);
		close(prog_fd);
#endif

	}
	printf("Summary: %d PASSED, %d FAILED\n", pass_cnt, err_cnt);

	return 0;
}

static void usage(char *prog)
{
	printf("%s [-g fuzzer_corpus_dir]\n", prog);
}

int main(int argc, char **argv)
{
	if (argc > 1) {
		if (argc == 3 && strcmp(argv[1], "-g") == 0) {
			/* generate test cases for fuzzer, no need to run the test */
			int ret;
			char *test_dir = argv[2];
			ret = mkdir(test_dir, 0755);
			if (ret != 0 && errno != EEXIST) {
				fprintf(stderr, "mkdir error: %s\n", strerror(errno));
				return 1;
			}
			return gen_fuzzer_tests(test_dir, strlen(test_dir));
		} else {
			usage(argv[0]);
			return 1;
		}
	}

	return test();
}
