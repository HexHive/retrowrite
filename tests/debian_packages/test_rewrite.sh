#!/bin/bash 

set -ex
cd repo;
for f in $(find . -type f -executable); do
	echo $f;
	[[ $(stat -c "%s" "$f" ) -ge 10000000 ]] && continue; # max 10MB

	[[ ! -f "${f}_original" ]] && cp ${f} ${f}_original

	~/retrowrite/retrowrite ${f}_original ${f}.s
	~/retrowrite/retrowrite ${f}.s -a ${f}

	timeout -k 0.5 0.5 ${f} --help > ${f}.log2
done
