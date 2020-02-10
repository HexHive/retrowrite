#!/bin/bash

set -euo pipefail

LINUX_VERSION="5.5.0-rc6"
# Why does the tarball version not have .0 in the version number? Whatever
LINUX_TARBALL_VERSION="5.5-rc6"
BUSYBOX_VERSION="1.27.2"
SYZKALLER_COMMIT="3de7aabbb79a6c2267f5d7ee8a8aaa83f63305b7"
DEBIAN_VERSION="stretch"

KRWDIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)
WORKDIR=`pwd`
LINUX_DIR="$WORKDIR/linux"
BUSYBOX_DIR="$WORKDIR/busybox"
INITRAMFS_DIR="$WORKDIR/initramfs"
IMAGE_DIR="$WORKDIR/image"

if [[ "$WORKDIR" -ef "$KRWDIR" ]]; then
	echo "Run the script from the parent directory: bash $KRWDIR/setup.sh"
	exit 1
fi

# Install dependencies
sudo apt update
sudo apt install -y \
	git \
	build-essential \
	flex \
	bison \
	libncurses-dev \
	openssl \
	libssl-dev \
	libelf-dev \
	autoconf \
	qemu-system-x86 \
	debootstrap \
	btrfs-progs \
	pypy3 \
	pypy3-dev \
	cpio \
	expect


# Build Linux
if [[ ! -e $LINUX_DIR ]]; then
	wget -O linux.tar.gz "https://git.kernel.org/torvalds/t/linux-$LINUX_TARBALL_VERSION.tar.gz"
	tar xf linux.tar.gz
	rm linux.tar.gz
	mv "linux-$LINUX_TARBALL_VERSION" "$LINUX_DIR"
	cp "$KRWDIR/linux-config" "$LINUX_DIR/.config"

	pushd $LINUX_DIR
		make -j`nproc`
	popd
fi

# Build Busybox
if [[ ! -e $BUSYBOX_DIR ]]; then
	wget -O busybox.tar.bz2 "https://www.busybox.net/downloads/busybox-$BUSYBOX_VERSION.tar.bz2"
	tar xf busybox.tar.bz2
	rm busybox.tar.bz2
	mv "busybox-$BUSYBOX_VERSION" "$BUSYBOX_DIR"
	cp "$KRWDIR/busybox-config" "$BUSYBOX_DIR/.config"

	pushd $BUSYBOX_DIR
		make -j`nproc`
		make install
	popd
fi

# Make initramfs
if [[ ! -e $INITRAMFS_DIR ]]; then
	mkdir "$INITRAMFS_DIR"
	pushd $INITRAMFS_DIR
		mkdir -p bin sbin etc proc sys usr/bin usr/sbin mnt/root "lib/modules/$LINUX_VERSION"
		cp -r $BUSYBOX_DIR/_install/* .
		cp "$KRWDIR/vm_init" init
		chmod +x init
		find "$LINUX_DIR" -name "*.ko" -type f -exec cp {} "$INITRAMFS_DIR/lib/modules/$LINUX_VERSION" \;
	popd
fi

# Make image
if [[ ! -e $IMAGE_DIR ]]; then
	mkdir "$IMAGE_DIR"
	pushd "$IMAGE_DIR"
		wget -O create-image.sh "https://github.com/google/syzkaller/raw/$SYZKALLER_COMMIT/tools/create-image.sh"
		chmod +x create-image.sh
		./create-image.sh -d "$DEBIAN_VERSION" --feature full

		# Build btrfs image
		mv "$DEBIAN_VERSION.img" "${DEBIAN_VERSION}_ext4.img"

		dd if=/dev/zero "of=${DEBIAN_VERSION}_btrfs.img" bs=1M seek=2047 count=1
		sudo mkfs.btrfs "${DEBIAN_VERSION}_btrfs.img"
		sudo mount -o loop "${DEBIAN_VERSION}_btrfs.img" /mnt/chroot
		sudo cp -a chroot/. /mnt/chroot/.
		sudo umount /mnt/chroot
	popd
fi

# Download Go
if [[ ! -e go1.12 ]]; then
	wget https://dl.google.com/go/go1.12.linux-amd64.tar.gz
	tar xf go1.12.linux-amd64.tar.gz
	rm go1.12.linux-amd64.tar.gz
	mv go go1.12
fi

export GOPATH="$WORKDIR/go"
export GOROOT="$WORKDIR/go1.12"
export PATH="$GOPATH/bin:$GOROOT/bin:$KRWDIR/cftool:$PATH"

echo "export GOPATH=\"$GOPATH\"" > .vars
echo "export GOROOT=\"$GOROOT\"" >> .vars
echo "export PATH=\"$GOPATH/bin:$GOROOT/bin:$KRWDIR/cftool:\$PATH\"" >> .vars

# Build cftoool
pushd "$KRWDIR/cftool"
	go build
popd

SYZKALLER_DIR="$GOPATH/src/github.com/google/syzkaller"

# Build Syzkaller
if [[ ! -e "$SYZKALLER_DIR" ]]; then
	go get -u -d github.com/google/syzkaller/...

	pushd "$SYZKALLER_DIR"
		git checkout "$SYZKALLER_COMMIT"
		make
	popd
fi


# Setup RetroWrite
if [[ ! -e "$KRWDIR/retro" ]]; then
	pushd "$KRWDIR"
		pypy3 -m venv retro

		# Work around a virtualenv bug :\
		set +u
		source retro/bin/activate
		set -u

		pip install --upgrade pip
		pip install -r requirements.txt
		git submodule update --init --checkout third-party/capstone
		cd third-party/capstone
		make -j`nproc`
		cd bindings/python/ && make && make install

		set +u
		deactivate
		set -u
	popd
fi

echo "[+] All done and ready to go"
