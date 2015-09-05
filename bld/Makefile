ifeq ($(KERNEL_TREE_ROOT),)
  $(error Linux kernel tree root is not configured, use "make KERNEL_TREE_ROOT=<> ...")
endif

BLD=$(PWD)
SRC=$(PWD)/..

CFLAGS=-O1 -g -fsanitize=address -fsanitize-coverage=edge -fno-omit-frame-pointer
FUZZER_CFLAGS=-g -O2 -std=c++11

.PHONY:	setup test_hook test_verifier all

setup:
	# kernel hook 
	ln -sf $(SRC)/src/helper/linux_hook.c $(KERNEL_TREE_ROOT)/kernel/bpf/linux_hook.c
	# user hook
	ln -sf $(SRC)/src/helper/test_hook.c .
	# fuzzer
	svn co http://llvm.org/svn/llvm-project/llvm/trunk/lib/Fuzzer
	clang -c $(FUZZER_CFLAGS) Fuzzer/*.cpp -IFuzzer
	
test_hook: $(KERNEL_TREE_ROOT)/kernel/bpf/verifier.c $(SRC)/src/helper/linux_hook.c $(SRC)/src/helper/test_hook.c
	cd $(KERNEL_TREE_ROOT); make HOSTCC=clang CC=clang kernel/bpf/verifier.i kernel/bpf/linux_hook.i
	cd $(BLD)
	ln -sf $(KERNEL_TREE_ROOT)/kernel/bpf/verifier.i .
	ln -sf $(KERNEL_TREE_ROOT)/kernel/bpf/linux_hook.i .
	clang $(CFLAGS) -c -I$(KERNEL_TREE_ROOT)/usr/include \
		test_hook.c verifier.i linux_hook.i

test_verifier: $(SRC)/src/test/linux-samples-bpf/test_verifier.c
	ln -sf $(SRC)/src/test/linux-samples-bpf/* .
	clang $(CFLAGS) -o $@ -I$(KERNEL_TREE_ROOT)/usr/include \
		test_verifier.c test_hook.c verifier.i linux_hook.i

test_fuzzer: $(SRC)/src/test/fuzzer/test_fuzzer.c
	ln -sf $(SRC)/src/test/fuzzer/* .
	clang $(CFLAGS) -c -I$(KERNEL_TREE_ROOT)/usr/include \
		test_fuzzer.c test_hook.c verifier.i linux_hook.i
	clang++ $(CFLAGS) -o $@ \
		test_fuzzer.o test_hook.o verifier.o linux_hook.o \
		Fuzzer*.o

all: test_hook test_verifier test_fuzzer
