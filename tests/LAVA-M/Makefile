CC=gcc
AFL_CC=/home/number_four/projects/afl-2.52b/afl-gcc
current_dir = $(shell pwd)
LDOPT=
PREFIX=build/
AFL_PREFIX=afl/
INSTALL_DIR?=/home/number_four/projects/lava_corpus/LAVA-M
SRC = $(filter-out $(ASAN_SRC), $(wildcard *.s))

PROGS = $(patsubst %.s,$(PREFIX)%,$(SRC))

all: $(PROGS)

.PHONY: afl
afl:
	-$(AFL_CC) -g -o $(AFL_PREFIX)base64-afl base64.s
	-$(AFL_CC) -g -o $(AFL_PREFIX)md5sum-afl md5sum.s
	-$(AFL_CC) -g -o $(AFL_PREFIX)who-afl who.s
	-$(AFL_CC) -g -o $(AFL_PREFIX)uniq-afl uniq.s

$(PREFIX)%: %.s
	-$(CC) -g -o $@ -O2 $< -pie $(LDOPT)

.PHONY: install
install:
	install -m 557 $(PREFIX)base64 --target-directory $(INSTALL_DIR)/base64/coreutils-8.24-lava-safe/lava-install/bin/
	install -m 557 $(PREFIX)who --target-directory $(INSTALL_DIR)/who/coreutils-8.24-lava-safe/lava-install/bin/
	install -m 557 $(PREFIX)md5sum --target-directory $(INSTALL_DIR)/md5sum/coreutils-8.24-lava-safe/lava-install/bin/
	install -m 557 $(PREFIX)uniq --target-directory $(INSTALL_DIR)/uniq/coreutils-8.24-lava-safe/lava-install/bin/

clean:
	-rm $(PREFIX)*
	-rm $(AFL_PREFIX)*
