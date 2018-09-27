CC=gcc
LDOPT=-ldl# -lgmp -pthread -lrt
PREFIX=build/

SRC = $(wildcard *.s)
PROGS = $(patsubst %.s,$(PREFIX)%,$(SRC))
current_dir = $(shell pwd)

all: $(PROGS)

$(PREFIX)%: %.s
	$(CC) -g -o $@ $< -pie $(LDOPT)

clean:
	rm $(PREFIX)*
