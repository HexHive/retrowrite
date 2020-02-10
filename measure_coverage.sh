#!/bin/bash

set -euo pipefail

WORKDIR=`pwd`
KRWDIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)

if [[ "$WORKDIR" -ef "$KRWDIR" ]]; then
	echo "Run the script from the parent directly: bash $KRWDIR/fuzz-module.sh"
	exit 1
fi

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <module to measure coverage on>"
	exit 1
fi

LINUX_DIR="$WORKDIR/linux"
IMAGE_DIR="$WORKDIR/image"
MODULE_CAMPAIGNS_DIR="$WORKDIR/campaigns/$1"
SYZKALLER_DIR="$GOPATH/src/github.com/google/syzkaller"
SYZ_DB="$SYZKALLER_DIR/bin/syz-db"
SYZ_EXECPROG="$SYZKALLER_DIR/bin/linux_amd64/syz-execprog"
SYZ_EXECUTOR="$SYZKALLER_DIR/bin/linux_amd64/syz-executor"

if [[ ! -d $MODULE_CAMPAIGNS_DIR ]]; then
	echo "There are no campaigns for this module"
	exit 1
fi

pushd "$LINUX_DIR"
	# Build kernel with kcov
	cp "$KRWDIR/linux-config-coverage" .config
	make -j$(nproc)
popd

# Use the btrfs image for btrfs, and the ext4 image for everything else
IMAGE_PATH=""
case $1 in
	btrfs)
		IMAGE_PATH="$IMAGE_DIR/stretch_btrfs.img"
		;;
	*)
		IMAGE_PATH="$IMAGE_DIR/stretch_ext4.img"
		;;
esac

for c in "$MODULE_CAMPAIGNS_DIR"/{source,binary}/*; do
	# Skip everything except directories
	if [[ ! -d "$c" ]]; then
		continue
	fi

	echo "Computing coverage for $c..."

	pushd "$c"
		"$SYZ_DB" unpack corpus.db input
		cp "$KRWDIR/run_cov.sh" input
		cp "$SYZ_EXECPROG" input
		cp "$SYZ_EXECUTOR" input

		mkdir coverage

		# Run the VM and collect coverage
		expect run_cov.expect
	popd
done
