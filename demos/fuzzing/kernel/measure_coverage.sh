#!/bin/bash

# Measure_coverage IIRC replays all the test cases and checks which basic blocks are hit

# call run_cov.expect which run in the vm run_cov.sh

set -euo pipefail

WORKDIR=`pwd`
KRWDIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)


if [[ "$WORKDIR" -ef "$KRWDIR" ]]; then
	echo "Run the script from the retrowrite root directly: bash ./fuzzing/kernel/fuzz-module.sh"
	exit 1
fi

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <module to measure coverage on>"
	exit 1
fi

KRWDIR=`pwd`
VMS_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)/vms_files
LINUX_DIR="$VMS_DIR/linux"
IMAGE_DIR="$VMS_DIR/image"

MODULE_CAMPAIGNS_DIR="$WORKDIR/fuzzing/kernel/campaigns/$1"


GOPATH="$WORKDIR/retro/go"
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
	cp "$VMS_DIR/linux-config-coverage" .config
	make -j$(nproc)
popd

# Use the btrfs image for btrfs, and the ext4 image for everything else
IMAGE_PATH=""
case $1 in
	btrfs)
		IMAGE_PATH="$IMAGE_DIR/stretch_btrfs_10g.img"
		;;
	*)
		IMAGE_PATH="$IMAGE_DIR/stretch_ext4_10g.img"
		;;
esac

for c in "$MODULE_CAMPAIGNS_DIR"/{source,binary}/*; do
	# Skip everything except directories
	if [[ ! -d "$c" ]]; then
		continue
	fi

	echo "Computing coverage for $c..."

	pushd "$c"
		"$SYZ_DB" unpack workdir/corpus.db input
		cp "$VMS_DIR/run_cov.sh" input
		cp "$SYZ_EXECPROG" input
		cp "$SYZ_EXECUTOR" input

		mkdir -p coverage

		# Run the VM and collect coverage
		expect "$VMS_DIR/run_cov.expect" "$LINUX_DIR" "$IMAGE_PATH" "$c" "$KRWDIR"
	popd
done
