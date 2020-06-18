CC=clang
OPT=-O0 -ggdb -Wall -Wpedantic -Wextra -fPIC

.PHONY: redo
%_rw: redo
	$(eval BASE=$(subst _rw,,$@))
	${CC} ${OPT} ${BASE}.c -o ${BASE}.out
	PYTHONPATH=../ python3 -m arm.rwtools.asan.asantool ./${BASE}.out ./$@.s
	${CC} $@.s -lasan -o $@
	echo wow | ./$@



all: hello_rw

clean:
	rm *.out
	rm *_rw*

.PHONY=clean all
