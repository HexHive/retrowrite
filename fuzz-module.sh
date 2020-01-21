#!/bin/bash

set -euxo pipefail

WORKDIR=`pwd`
KRWDIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)

if [[ "$WORKDIR" -ef "$KRWDIR" ]]; then
	echo "Run the script from the parent directly: bash $KRWDIR/fuzz-module.sh"
	exit 1
fi

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <module to fuzz>"
	exit 1
fi

LINUX_VERSION="5.5.0-rc6"

LINUX_DIR="$WORKDIR/linux"
INITRAMFS_DIR="$WORKDIR/initramfs"
MODULES_DIR="$WORKDIR/modules"
IMAGE_DIR="$WORKDIR/image"
CAMPAIGNS_DIR="$WORKDIR/campaigns"
SYZKALLER_ORIG_CONFIG="$KRWDIR/config/$1.cfg"
SYZKALLER_DIR="$GOPATH/src/github.com/google/syzkaller"
PLAIN_MODULE="$MODULES_DIR/$1_plain.ko"
SOURCE_MODULE="$MODULES_DIR/$1_kasan_kcov_source.ko"
BINARY_MODULE="$MODULES_DIR/$1_kasan_kcov_rw.ko"
MODULE_ASM="$MODULES_DIR/$1_kasan_kcov_rw.S"

TIMEOUT="3h"
NUM_RUNS=10
VMS=8

if [[ ! -e $MODULES_DIR ]]; then
	mkdir "$MODULES_DIR"
fi

if [[ ! -e "$CAMPAIGNS_DIR/$1" ]]; then
	mkdir -p "$CAMPAIGNS_DIR/$1"
fi

# Build module
pushd "$LINUX_DIR"
	# Build module with KASan and kcov
	cp "$KRWDIR/linux-config" .config
	make modules -j`nproc`

	find "$LINUX_DIR" -name "$1.ko" -type f -exec cp {} "$SOURCE_MODULE" \;

	# Build module without KASan and kcov
	cp "$KRWDIR/linux-config-noinst" .config
	make modules -j`nproc`

	find "$LINUX_DIR" -name "$1.ko" -type f -exec cp {} "$PLAIN_MODULE" \;
popd

# Instrument module with kRetroWrite
pushd $KRWDIR
	. retro/bin/activate	
	python -m rwtools.kasan.asantool --kcov "$PLAIN_MODULE" "$MODULE_ASM"
	deactivate
popd
pushd $MODULES_DIR
	as -o "$BINARY_MODULE" "$MODULE_ASM"
popd

pushd "$CAMPAIGNS_DIR/$1"

	for ((i=0; i < $NUM_RUNS; i++)); do
		echo "Running source campaign $i..."
		mkdir -p "source/$i/workdir"

		# Remake initramfs
		pushd "$INITRAMFS_DIR"
			cp "$SOURCE_MODULE" "lib/modules/$LINUX_VERSION/$1.ko"
			find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
		popd

		pushd "source/$i"
			# Generate the configuration
			"$KRWDIR/generate_config.py" \
				--workdir `pwd`/workdir \
				--kernel "$LINUX_DIR" \
				--initramfs "$WORKDIR/initramfs.cpio.gz" \
				--image "$IMAGE_DIR/stretch_$i.img" \
				--sshkey "$IMAGE_DIR/stretch.id_rsa" \
				--syzkaller "$SYZKALLER_DIR"  \
				--vms "$VMS" > "config.cfg"

			# Run syzkaller
			TMPDIR="/tmp" timeout \
				-s INT \
				"$DURATION" \
				"$SYZKALLER_DIR/bin/syz-manager" \
				-config `pwd`/config.cfg 2> log.txt
		popd

		echo "Running binary campaign $i..."
		mkdir -p "binary/$i/workdir"

		# Remake initramfs
		pushd "$INITRAMFS_DIR"
			cp "$BINARY_MODULE" "lib/modules/$LINUX_VERSION/$1.ko"
			find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
		popd

		pushd "binary/$i"
			# Generate the configuration
			"$KRWDIR/generate_config.py" \
				--workdir `pwd`/workdir \
				--kernel "$LINUX_DIR" \
				--initramfs "$WORKDIR/initramfs.cpio.gz" \
				--image "$IMAGE_DIR/stretch_$i.img" \
				--sshkey "$IMAGE_DIR/stretch.id_rsa" \
				--syzkaller "$SYZKALLER_DIR" \
				--vms "$VMS" > "config.cfg"

			# Run syzkaller
			TMPDIR="/tmp" timeout \
				-s INT \
				"$DURATION" \
				"$SYZKALLER_DIR/bin/syz-manager" \
				-config `pwd`/config.cfg 2> log.txt
		popd
	done
popd

