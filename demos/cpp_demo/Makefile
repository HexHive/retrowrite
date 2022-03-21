CC=clang++
OPT=-O0 -ggdb -Wall -Wpedantic -Wextra -fPIC -fPIE -pie

all: simple_inheritance

simple_inheritance: simple_inheritance.cpp
	${CC} ${OPT} simple_inheritance.cpp -o simple_inheritance

simple_inheritance.asan: simple_inheritance
	retrowrite --asan ./simple_inheritance ./simple_inheritance.asan.s
	sed -i 's/asan_init_v4/asan_init/g' simple_inheritance.asan.s
	${CC} simple_inheritance.asan.s -lasan -o simple_inheritance.asan

.PHONY=clean
clean:
	rm -f simple_inheritance simple_inheritance.asan simple_inheritance.asan.s
