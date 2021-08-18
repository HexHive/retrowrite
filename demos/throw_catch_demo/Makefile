CC=clang++
OPT=-O0 -ggdb -Wall -Wpedantic -Wextra -fPIC -fPIE -pie

all: throw_catch

throw_catch: throw_catch.cpp
	${CC} ${OPT} throw_catch.cpp -o throw_catch

throw_catch.asan: throw_catch
	# retrowrite --asan ./throw_catch ./throw_catch.asan.s
	retrowrite ./throw_catch ./throw_catch.asan.s
	sed -i 's/asan_init_v4/asan_init/g' throw_catch.asan.s
	# ${CC} throw_catch.asan.s -lasan -o throw_catch.asan
	${CC} throw_catch.asan.s -o throw_catch.asan

.PHONY=clean
clean:
	rm -f throw_catch throw_catch.asan throw_catch.asan.s
