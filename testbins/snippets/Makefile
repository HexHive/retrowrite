CC=gcc

SRC = $(wildcard *.s)
PROGS = $(patsubst %.s,build/%,$(SRC))
current_dir = $(shell pwd)

all: $(PROGS)

build/%: %.s
	$(CC) -g -o $@ -masm=intel $<

clean:
	rm build/*
