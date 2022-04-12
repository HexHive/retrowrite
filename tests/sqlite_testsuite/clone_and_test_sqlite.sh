#!/bin/bash

# download sqlite3 source code, and run sqlite testing suite on its rewritten binaries.

set -ex

function clone_sqlite() {
	url="https://www.sqlite.org/2022/sqlite-src-3380200.zip"
	echo -e "\x1b[31m Warning: \x1b[0m Using URL \x1b[1m $url \x1b[0m. Change it if necessary."

	wget $url -O "source.zip"
	unzip "source.zip"
};


source_folder=$(find . -maxdepth 1 -type d | grep sqlite-src || true)
[[ -z $source_folder ]]  && clone_sqlite;
source_folder=$(find . -maxdepth 1 -type d | grep sqlite-src || true)



cd $source_folder

apt install tcl
./configure
make test -j 7 # generate binaries used by sqlite3 testing

for f in dbhash sqldiff sqlite3_analyzer sqlite3_analyzer sessionfuzz; do 
	[[ ! -f "${f}_original" ]] && cp ${f} ${f}_original
	../../../retrowrite ${f}_original ${f}.s 
	../../../retrowrite -a ${f}.s ${f}; 
done

make test -j 7 # finally, run testsuite with rewritten binaries
