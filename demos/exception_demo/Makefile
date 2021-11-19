CC=clang++
OPT=-O0 -ggdb -Wall -Wpedantic -Wextra -fPIC -fPIE -pie -gdwarf

all: exception

exception: exception.cpp
	${CC} ${OPT} exception.cpp -oexception 

exception.asan:exception 
	retrowrite --asan ./exception ./exception.asan.s
	sed -i 's/asan_init_v4/asan_init/g' exception.asan.s
	${CC} exception.asan.s -lasan -o exception.asan

.PHONY=clean
clean:
	rm -f exception exception.asan exception.asan.s
