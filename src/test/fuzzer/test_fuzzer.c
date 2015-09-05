#include <linux/bpf.h>

int bpf_prog_load(enum bpf_prog_type prog_type,
                  const struct bpf_insn *insns, int insn_len,
                  const char *license, int kern_version);

void LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
        struct bpf_insn *prog = data;
        int prog_len = size / sizeof(struct bpf_insn);

	/* really dummy test, does not handle maps as well. */
        (void)bpf_prog_load(BPF_PROG_TYPE_SOCKET_FILTER,
                            prog, prog_len * sizeof(struct bpf_insn),
                            "GPL", 0);
        (void)bpf_prog_load(BPF_PROG_TYPE_SCHED_CLS,
                            prog, prog_len * sizeof(struct bpf_insn),
                            "GPL", 0);
        (void)bpf_prog_load(BPF_PROG_TYPE_SCHED_ACT,
                            prog, prog_len * sizeof(struct bpf_insn),
                            "GPL", 0);
        (void)bpf_prog_load(BPF_PROG_TYPE_KPROBE,
                            prog, prog_len * sizeof(struct bpf_insn),
                            "GPL", 0);
}
