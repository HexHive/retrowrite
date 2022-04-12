#!/bin/bash

# create and prepare a campaign
# of a module from a modules in the linux sources

# get .ko of the module, instrument it with rwtools.kasan.asantool and

set -euo pipefail

CAMPAIGN_DURATION="3h"
NUM_RUNS=10
NB_VMS=4
CPU_VMS=2
MEMORY_VMS=2048



WORKDIR=`pwd`
KRWDIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)

if [[ "$WORKDIR" -ef "$KRWDIR" ]]; then
	echo "Run the script from the retrowrite root directly: bash ./fuzzing/kernel/fuzz-module.sh"
	exit 1
fi

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <module to fuzz>"
	exit 1
fi

LINUX_VERSION="5.5.0-rc6"


KRWDIR=`pwd`
WORKDIR=`pwd`
VMS_DIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)/vms_files
LINUX_DIR="$VMS_DIR/linux"

INITRAMFS_DIR="$VMS_DIR/initramfs"
IMAGE_DIR="$VMS_DIR/image"
GOPATH="$KRWDIR/retro/go"
SYZKALLER_DIR="$GOPATH/src/github.com/google/syzkaller"


MODULES_DIR="$WORKDIR/fuzzing/kernel/modules"
CAMPAIGNS_DIR="$WORKDIR/fuzzing/kernel/campaigns"
CONFIG_BASE="$KRWDIR/fuzzing/kernel/syzkaller-configs/$1.cfg"


PLAIN_MODULE="$MODULES_DIR/$1_plain.ko"
SOURCE_MODULE="$MODULES_DIR/$1_kasan_kcov_source.ko"
BINARY_MODULE="$MODULES_DIR/$1_kasan_kcov_rw.ko"
MODULE_ASM="$MODULES_DIR/$1_kasan_kcov_rw.S"



if [[ ! -d $MODULES_DIR ]]; then
	mkdir "$MODULES_DIR"
fi

if [[ ! -d "$CAMPAIGNS_DIR/$1" ]]; then
	mkdir -p "$CAMPAIGNS_DIR/$1"
fi

# Build module
pushd "$LINUX_DIR"
	# Build module with KASan and kcov
	cp "$VMS_DIR/linux-config" .config
	make -j`nproc`

	find "$LINUX_DIR" -name "$1.ko" -type f -exec cp {} "$SOURCE_MODULE" \;

	# Build module without KASan and kcov
	cp "$VMS_DIR/linux-config-noinst" .config
	make modules -j`nproc`

	find "$LINUX_DIR" -name "$1.ko" -type f -exec cp {} "$PLAIN_MODULE" \;
popd

# Instrument module with kRetroWrite
pushd $WORKDIR
	# Work around a virtualenv bug
	set +u
	source retro/bin/activate
	set -u

	python3 -m rwtools.kasan.asantool --kcov "$PLAIN_MODULE" "$MODULE_ASM"

	set +u
	deactivate
	set -u
popd
pushd $MODULES_DIR
	as -o "$BINARY_MODULE" "$MODULE_ASM"
popd

# Use the btrfs image when fuzzing btrfs, and the ext4 image for everything else
IMAGE_PATH=""
case $1 in
	btrfs)
		IMAGE_PATH="$IMAGE_DIR/stretch_btrfs.img"
		;;
	*)
		IMAGE_PATH="$IMAGE_DIR/stretch_ext4.img"
		;;
esac

pushd "$CAMPAIGNS_DIR/$1"

	for ((i=0; i < $NUM_RUNS; i++)); do
		if [[ ! -d "source/$i" ]]; then
			echo "Running source campaign $i..."
			mkdir -p "source/$i/workdir"
			mkdir -p $CAMPAIGNS_DIR/$1/workdir/
			# Remake initramfs
			pushd "$INITRAMFS_DIR"
				cp "$SOURCE_MODULE" "lib/modules/$LINUX_VERSION/$1.ko"
				find . -print0 | cpio --null -ov --format=newc 2> /dev/null | gzip -9 > $CAMPAIGNS_DIR/$1/workdir/initramfs.cpio.gz
			popd

			pushd "source/$i"
				# Generate the configuration
				"$KRWDIR/fuzzing/kernel/syzkaller-configs/generate_config.py" \
					--workdir $CAMPAIGNS_DIR/$1/workdir/ \
					--kernel "$LINUX_DIR" \
					--initramfs "$CAMPAIGNS_DIR/$1/workdir/initramfs.cpio.gz" \
					--image "$IMAGE_PATH" \
					--sshkey "$IMAGE_DIR/stretch.id_rsa" \
					--syzkaller "$SYZKALLER_DIR"  \
					--vms "$NB_VMS" \
					--cpus "$CPU_VMS" \
					--mem "$MEMORY_VMS"\
					"$CONFIG_BASE" > "config.cfg"

				# Run syzkaller
				TMPDIR="/tmp" timeout \
					--preserve-status \
					--foreground \
					-s INT \
					"$CAMPAIGN_DURATION" \
					"$SYZKALLER_DIR/bin/syz-manager" \
					-config `pwd`/config.cfg 2> log.txt
			popd
		fi

		if [[ ! -d "binary/$i" ]]; then
			echo "Running binary campaign $i..."
			mkdir -p "binary/$i/workdir"

			# Remake initramfs
			pushd "$INITRAMFS_DIR"
				cp "$BINARY_MODULE" "lib/modules/$LINUX_VERSION/$1.ko"
				find . -print0 | cpio --null -ov --format=newc 2> /dev/null | gzip -9 > $CAMPAIGNS_DIR/$1/workdir/initramfs.cpio.gz
			popd

			pushd "binary/$i"
				# Generate the configuration
				"$KRWDIR/fuzzing/kernel/syzkaller-configs/generate_config.py" \
					--workdir `pwd`/workdir \
					--kernel "$LINUX_DIR" \
					--initramfs "$CAMPAIGNS_DIR/$1/workdir/initramfs.cpio.gz" \
					--image "$IMAGE_PATH" \
					--sshkey "$IMAGE_DIR/stretch.id_rsa" \
					--syzkaller "$SYZKALLER_DIR" \
					--vms "$NB_VMS" \
					--cpus "$CPU_VMS" \
					--mem "$MEMORY_VMS" \
					"$CONFIG_BASE" > "config.cfg"

				# Run syzkaller
				TMPDIR="/tmp" timeout \
					--preserve-status \
					--foreground \
					-s INT \
					"$CAMPAIGN_DURATION" \
					"$SYZKALLER_DIR/bin/syz-manager" \
					-config `pwd`/config.cfg 2> log.txt
			popd
		fi
	done
popd
