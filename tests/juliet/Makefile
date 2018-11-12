CC=gcc
current_dir = $(shell pwd)
LDOPT=-pthread -lasan
PREFIX=build/
INSTALL_DIR?=/home/number_four/projects/lava_corpus/LAVA-M
SRC = $(filter-out $(ASAN_SRC), $(wildcard *.s))

PROGS = $(patsubst %.s,$(PREFIX)%,$(SRC))

all: $(PROGS)

$(PREFIX)%: %.s
	-$(CC) -g -o $@ -O2 $< -pie $(LDOPT)

.PHONY: install
install:

clean:
	-rm $(PREFIX)*
	-rm $(AFL_PREFIX)*
