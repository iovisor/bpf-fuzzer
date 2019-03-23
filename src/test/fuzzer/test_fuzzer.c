/*
 * LLVM fuzzer test callback implementation
 *
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/bpf.h>

int bpf_prog_load(enum bpf_prog_type prog_type,
                  const struct bpf_insn *insns, int insn_len,
                  const char *license, int kern_version);

int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size,
                   int max_entries);

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

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
        struct bpf_insn *prog = data, *prog_c, *insn;
        int i, prog_len = size / sizeof(struct bpf_insn);

	/* If there are any map instructions, we want to create map now. */
	insn = prog;
	for (i = 0; i < prog_len; i++, insn++) {
		if ((insn[0].code == (BPF_LD | BPF_IMM | BPF_DW)) &&
		    insn->src_reg == BPF_PSEUDO_MAP_FD) {
			int map_fd = create_map();
			insn->imm = map_fd;
		}
	}
	/* keep a copy of instructions since verifier may modify it */
	prog_c = malloc(size);
	memcpy(prog_c, data, size);

        (void)bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
                            prog, prog_len * sizeof(struct bpf_insn),
                            "GPL", 0);
	memcpy(prog, prog_c, size);
        (void)bpf_prog_load(BPF_PROG_TYPE_SCHED_CLS,
                            prog, prog_len * sizeof(struct bpf_insn),
                            "GPL", 0);
	memcpy(prog, prog_c, size);
        (void)bpf_prog_load(BPF_PROG_TYPE_SCHED_ACT,
                            prog, prog_len * sizeof(struct bpf_insn),
                            "GPL", 0);
	memcpy(prog, prog_c, size);
        (void)bpf_prog_load(BPF_PROG_TYPE_KPROBE,
                            prog, prog_len * sizeof(struct bpf_insn),
                            "GPL", 0);

	/* remove the created maps */
	insn = prog_c;
	for (i = 0; i < prog_len; i++, insn++) {
		if ((insn[0].code == (BPF_LD | BPF_IMM | BPF_DW)) &&
		    insn->src_reg == BPF_PSEUDO_MAP_FD) {
			bpf_free_map(insn->imm);
		}
	}
	free(prog_c);
	return 0;
}
