CC=clang
OPT=-O0 -ggdb -Wall -Wpedantic -Wextra -fPIC -fPIE -pie

all: heap stack

heap: heap.c
	${CC} ${OPT} heap.c -o heap

heap.asan: heap
	PYTHONPATH=../../ python3 -m rwtools.asan.asantool ./heap ./heap.asan
	sed -i 's/asan_init_v4/asan_init/g' heap.asan.s
	${CC} heap.asan.s -lasan -o heap.asan

.PHONY=heaptest
heaptest: heap heap.asan
	./heap 1
	./heap.asan 1; true
	./heap 2
	./heap.asan 2; true

stack: stack.c
	${CC} ${OPT} stack.c -o stack

stack.asan: stack
	PYTHONPATH=../../ python3 -m rwtools.asan.asantool ./stack ./stack.asan
	sed -i 's/asan_init_v4/asan_init/g' stack.asan.s
	${CC} stack.asan.s -lasan -o stack.asan

.PHONY=stacktest
stacktest: stack stack.asan
	./stack 1
	./stack.asan 1; true
	./stack 2
	./stack.asan 2; true

.PHONY=test
test: heaptest stacktest

.PHONY=clean
clean:
	rm -f heap heap.asan heap.asan.s heap.asan.analysis_cache stack stack.asan stack.asan.s stack.asan.analysis_cache
