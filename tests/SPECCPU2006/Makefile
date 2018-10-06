CC=gcc
#LDOPT=-ldl -lgmp -pthread -lrt
current_dir = $(shell pwd)
LDOPT=-lm
PREFIX=build/
INSTALL_DIR?=/home/number_four/projects/spec/benchspec/CPU2006

SRC = $(wildcard *.s)
PROGS = $(patsubst %.s,$(PREFIX)%,$(SRC))

all: $(PROGS)

$(PREFIX)%: %.s
	-$(CC) -g -o $@ -O2 $< -pie $(LDOPT)

.PHONY: install
install:
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


clean:
	-rm $(PREFIX)*
