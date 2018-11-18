CC=gcc
#LDOPT=-ldl -lgmp -pthread -lrt
current_dir = $(shell pwd)
LDOPT=-lm
PREFIX=build/
ASAN_PREFIX=asan/
INSTALL_DIR?=/home/number_four/projects/spec/benchspec/CPU2006

ASAN_SRC = $(wildcard *_asan.s)
SRC = $(filter-out $(ASAN_SRC), $(wildcard *.s))

PROGS = $(patsubst %.s,$(PREFIX)%,$(SRC))
ASAN_PROGS = $(patsubst %.s,$(ASAN_PREFIX)%,$(ASAN_SRC))

all: $(PROGS) $(ASAN_PROGS)

$(ASAN_PREFIX)%_asan: %_asan.s
	-$(CC) -g -o $@ -O2 $< -pie -lasan $(LDOPT)

$(PREFIX)%: %.s
	-$(CC) -g -o $@ -O2 $< -pie $(LDOPT)

.PHONY: install
install:
	install -m 557 $(PREFIX)perlbench* --target-directory $(INSTALL_DIR)/400.perlbench/exe/
	install -m 557 $(PREFIX)bzip2* --target-directory $(INSTALL_DIR)/401.bzip2/exe/
	install -m 557 $(PREFIX)gcc* --target-directory $(INSTALL_DIR)/403.gcc/exe/
	install -m 557 $(PREFIX)mcf* --target-directory $(INSTALL_DIR)/429.mcf/exe/
	install -m 557 $(PREFIX)milc* --target-directory $(INSTALL_DIR)/433.milc/exe/
	install -m 557 $(PREFIX)gobmk* --target-directory $(INSTALL_DIR)/445.gobmk/exe/
	install -m 557 $(PREFIX)hmmer* --target-directory $(INSTALL_DIR)/456.hmmer/exe/
	install -m 557 $(PREFIX)sjeng* --target-directory $(INSTALL_DIR)/458.sjeng/exe/
	install -m 557 $(PREFIX)libquantum* --target-directory $(INSTALL_DIR)/462.libquantum/exe/
	install -m 557 $(PREFIX)h264ref* --target-directory $(INSTALL_DIR)/464.h264ref/exe/
	install -m 557 $(PREFIX)lbm* --target-directory $(INSTALL_DIR)/470.lbm/exe/
	install -m 557 $(PREFIX)sphinx* --target-directory $(INSTALL_DIR)/482.sphinx3/exe/

.PHONY: asan_install
asan_install:
	-install -m 557 $(ASAN_PREFIX)perlbench* $(INSTALL_DIR)/400.perlbench/exe/perlbench_base.gcc-asan
	-install -m 557 $(ASAN_PREFIX)bzip2* $(INSTALL_DIR)/401.bzip2/exe/bzip2_base.gcc-asan
	-install -m 556 $(ASAN_PREFIX)gcc*  $(INSTALL_DIR)/403.gcc/exe/gcc_base.gcc-asan
	-install -m 557 $(ASAN_PREFIX)mcf*  $(INSTALL_DIR)/429.mcf/exe/mcf_base.gcc-asan
	-install -m 557 $(ASAN_PREFIX)milc*  $(INSTALL_DIR)/433.milc/exe/milc_base.gcc-asan
	-install -m 557 $(ASAN_PREFIX)gobmk*  $(INSTALL_DIR)/445.gobmk/exe/gobmk_base.gcc-asan
	-install -m 557 $(ASAN_PREFIX)hmmer*  $(INSTALL_DIR)/456.hmmer/exe/hmmer_base.gcc-asan
	-install -m 557 $(ASAN_PREFIX)sjeng*  $(INSTALL_DIR)/458.sjeng/exe/sjeng_base.gcc-asan
	-install -m 557 $(ASAN_PREFIX)libquantum*  $(INSTALL_DIR)/462.libquantum/exe/libquantum_base.gcc-asan
	-install -m 557 $(ASAN_PREFIX)h264ref*  $(INSTALL_DIR)/464.h264ref/exe/h264ref_base.gcc-asan
	-install -m 557 $(ASAN_PREFIX)lbm*  $(INSTALL_DIR)/470.lbm/exe/lbm_base.gcc-asan
	-install -m 557 $(ASAN_PREFIX)sphinx*  $(INSTALL_DIR)/482.sphinx3/exe/sphinx_livepretend_base.gcc-asan


clean:
	-rm $(PREFIX)*
