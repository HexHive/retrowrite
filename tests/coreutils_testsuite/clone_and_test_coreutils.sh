#!/bin/bash

# clones coreutils source, compiles, rewrites every single binary,
# and runs the test suite "make check"

set -e

apt install autoconf automake bison gettext rsync git autopoint gperf texi2html texinfo -y

function clone_coreutils() {
	git clone git://git.sv.gnu.org/coreutils
}


[[ ! -d "coreutils" ]] && clone_coreutils;


cd coreutils
./bootstrap

FORCE_UNSAFE_CONFIGURE=1 ./configure

make -j 7

for f in $(find src -type f -executable); do
	file $f | grep -q ELF || continue;
	[[ ! -f "${f}_original" ]] && cp ${f} ${f}_original
	~/retrowrite/retrowrite ${f}_original ${f}.s

	[[ "$f" =~ "src/libstdbuf.so" ]] && \
		echo "// SHARED" >> ${f}.s && \
		sed -i "s/\.section \.fake\.init_array/\.section \.init_array/" ${f}.s

	~/retrowrite/retrowrite -a ${f}.s ${f};
done

make check  # run the test suite with the rewritten binaries
