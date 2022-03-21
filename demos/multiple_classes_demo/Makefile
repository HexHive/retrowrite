CC=clang++
OPT=-O0 -ggdb -Wall -Wpedantic -Wextra -fPIC -fPIE -pie

all: multiple_classes multiple_classes.asan

multiple_classes: multiple_classes.cpp
	${CC} ${OPT} multiple_classes.cpp -omultiple_classes 

multiple_classes.asan: multiple_classes 
	retrowrite --asan ./multiple_classes ./multiple_classes.asan.s
	sed -i 's/asan_init_v4/asan_init/g' multiple_classes.asan.s
	${CC} multiple_classes.asan.s -lasan -o multiple_classes.asan

.PHONY=clean
clean:
	rm -f multiple_classes multiple_classes.asan multiple_classes.asan.s
