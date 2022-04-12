#!/bin/bash

# clones coreutils source, compiles, rewrites every single binary, 
# and runs the test suite "make check"

set -e

function clone_coreutils() {
	git clone git://git.sv.gnu.org/coreutils
}


[[ ! -d "coreutils" ]] && clone_coreutils;

apt install autopoint gperf texi2html texinfo

cd coreutils
./bootstrap

make -j 7

for f in $(find src -type f -executable); do
	[[ ! -f "${f}_original" ]] && cp ${f} ${f}_original
	../../../retrowrite ${f}_original ${f}.s 
	../../../retrowrite -a ${f}.s ${f}; 
done

make check  # run the test suite with the rewritten binaries
