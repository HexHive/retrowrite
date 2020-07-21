#!/bin/bash

set -euo pipefail

WORKDIR=$(cd $(dirname "${BASH_SOURCE[0]}") && pwd)
KRWDIR=`pwd`
echo "Working dir : $WORKDIR "
echo "Retrowrite dir : $KRWDIR "

if [[  "$WORKDIR" -ef "$KRWDIR" ]]; then
	echo "Run the script from the retrowrite root directory: cd ../ && ./fuzzing/setup_fuz.sh"
	exit 1
fi

if [[(( $# == 1 )&& ("$1" == "help")  )]]; then
  echo "Usage of the script : $0 [kernel(optional)]"
  exit
fi


if [[ ! -e "./retro" ]]; then
  echo "please run setup.sh from retrowrite root before this script"
  exit
else
  # Work around a virtualenv bug :\
  set +u
  source retro/bin/activate
  set -u
  pip3 install -r $WORKDIR/requirements_fuzz.txt

  set +u
  deactivate
  set -u
  echo "python requirement installed"
fi

# install kernel version
if [[ (( $# == 1 )&&  ("$1" == 'kernel')) ]]; then
  echo 'setting up for the kernel evaluation'

  LINUX_VERSION="5.5.0-rc6"
	# Why does the tarball version not have .0 in the version number? Whatever
	LINUX_TARBALL_VERSION="5.5-rc6"
	BUSYBOX_VERSION="1.27.2"
	SYZKALLER_COMMIT="8a9f1e7dbdb76a9c0af0dc6e3e75e446a7838dc8"
	DEBIAN_VERSION="stretch"


	VMS_DIR="$WORKDIR/kernel/vms_files"
	LINUX_DIR="$VMS_DIR/linux"
	BUSYBOX_DIR="$VMS_DIR/busybox"
	INITRAMFS_DIR="$VMS_DIR/initramfs"
	IMAGE_DIR="$VMS_DIR/image"

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
		cpio \
		expect
	# current user need to be added in the kvm group to be able to user qemu
	# sudo usermod -a -G kvm $USER


	# Build Linux
	if [[ ! -e $LINUX_DIR ]]; then
		echo "Installing the linux files"
		wget -O $VMS_DIR/linux.tar.gz "https://git.kernel.org/torvalds/t/linux-$LINUX_TARBALL_VERSION.tar.gz"
		echo $VMS_DIR
		tar xf  $VMS_DIR/linux.tar.gz -C $VMS_DIR
		rm $VMS_DIR/linux.tar.gz
		mv "$VMS_DIR/linux-$LINUX_TARBALL_VERSION" "$LINUX_DIR"
		cp "$VMS_DIR/linux-config" "$LINUX_DIR/.config"
		echo "Will compile"
		pushd $LINUX_DIR
			make -j`nproc`
		popd
		echo "End compile"
	fi

	# Build Busybox
	if [[ ! -e $BUSYBOX_DIR ]]; then
		wget -O $VMS_DIR/busybox.tar.bz2 "https://www.busybox.net/downloads/busybox-$BUSYBOX_VERSION.tar.bz2"
		tar xf $VMS_DIR/busybox.tar.bz2 -C $VMS_DIR
		rm $VMS_DIR/busybox.tar.bz2
		mv "$VMS_DIR/busybox-$BUSYBOX_VERSION" "$BUSYBOX_DIR"
		cp "$VMS_DIR/busybox-config" "$BUSYBOX_DIR/.config"

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
			cp "$VMS_DIR/vm_init" init
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
			mv "$DEBIAN_VERSION.img" "${DEBIAN_VERSION}_ext4.img"

			# Build ext4 big images
			dd if=/dev/zero "of=${DEBIAN_VERSION}_ext4_10g.img" bs=1M seek=10240 count=1
			sudo mkfs.ext4 -F "${DEBIAN_VERSION}_ext4_10g.img"
			sudo mount -o loop "${DEBIAN_VERSION}_ext4_10g.img" /mnt/chroot
			sudo cp -a chroot/. /mnt/chroot/.
			sudo umount /mnt/chroot

			# Build btrfs images
			dd if=/dev/zero "of=${DEBIAN_VERSION}_btrfs.img" bs=1M seek=2047 count=1
			dd if=/dev/zero "of=${DEBIAN_VERSION}_btrfs_10g.img" bs=1M seek=10240 count=1

			sudo mkfs.btrfs "${DEBIAN_VERSION}_btrfs.img"
			sudo mkfs.btrfs "${DEBIAN_VERSION}_btrfs_10g.img"

			sudo mount -o loop "${DEBIAN_VERSION}_btrfs.img" /mnt/chroot
			sudo cp -a chroot/. /mnt/chroot/.
			sudo umount /mnt/chroot

			sudo mount -o loop "${DEBIAN_VERSION}_btrfs_10g.img" /mnt/chroot
			sudo cp -a chroot/. /mnt/chroot/.
			sudo umount /mnt/chroot
		popd
	fi

	export GOPATH="$KRWDIR/retro/go"
	export GOROOT="$KRWDIR/retro/go1.14"
	SYZKALLER_DIR="$GOPATH/src/github.com/google/syzkaller"

	echo "export PYTHONPATH=\"$KRWDIR\"" > $KRWDIR/retro/bin/postactivate
  echo "export GOPATH=\"$GOPATH\"" >> $KRWDIR/retro/bin/postactivate
  echo "export GOROOT=\"$GOROOT\"" >> $KRWDIR/retro/bin/postactivate
  echo "export PATH=\"$SYZKALLER_DIR/bin:$GOPATH/bin:$GOROOT/bin:$KRWDIR/cftool:\$PATH\"" >> $KRWDIR/retro/bin/postactivate
	export PATH="$GOPATH/bin:$GOROOT/bin:$KRWDIR/cftool:$PATH"

	 # apply changes on the syzkaller configuration

  sed -i -e "s|SYZKALLER_WORKDIR|$SYZKALLER_DIR/workdir|g" $WORKDIR/kernel/syzkaller-configs/e1000.cfg
  sed -i -e "s|KERNEL_OBJ|$LINUX_DIR|g" $WORKDIR/kernel/syzkaller-configs/e1000.cfg
  sed -i -e "s|IMAGE|$IMAGE_DIR${DEBIAN_VERSION}_ext4.img|g" $WORKDIR/kernel/syzkaller-configs/e1000.cfg
  sed -i -e "s|SSH_KEY|$IMAGE_DIR$DEBIAN_VERSION.id_rsa|g" $WORKDIR/kernel/syzkaller-configs/e1000.cfg
  sed -i -e "s|SYZKALLER_DIR|$SYZKALLER_DIR|g" $WORKDIR/kernel/syzkaller-configs/e1000.cfg
  sed -i -e "s|KERNEL|$LINUX_DIR/arch/x86/boot/bzImage|g" $WORKDIR/kernel/syzkaller-configs/e1000.cfg
  sed -i -e "s|INITRAMFS|$INITRAMFS_DIR.cpio.gz|g" $WORKDIR/kernel/syzkaller-configs/e1000.cfg

  sed -i -e "s|SYZKALLER_WORKDIR|$SYZKALLER_DIR/workdir|g" $WORKDIR/kernel/syzkaller-configs/ext4.cfg
  sed -i -e "s|KERNEL_OBJ|$LINUX_DIR|g" $WORKDIR/kernel/syzkaller-configs/ext4.cfg
  sed -i -e "s|IMAGE|$IMAGE_DIR${DEBIAN_VERSION}_ext4.img|g" $WORKDIR/kernel/syzkaller-configs/ext4.cfg
  sed -i -e "s|SSH_KEY|$IMAGE_DIR$DEBIAN_VERSION.id_rsa|g" $WORKDIR/kernel/syzkaller-configs/ext4.cfg
  sed -i -e "s|SYZKALLER_DIR|$SYZKALLER_DIR|g" $WORKDIR/kernel/syzkaller-configs/ext4.cfg
  sed -i -e "s|KERNEL|$LINUX_DIR/arch/x86/boot/bzImage|g" $WORKDIR/kernel/syzkaller-configs/ext4.cfg
  sed -i -e "s|INITRAMFS|$INITRAMFS_DIR.cpio.gz|g" $WORKDIR/kernel/syzkaller-configs/ext4.cfg




	# Build Syzkaller
	# https://github.com/google/syzkaller/blob/master/docs/linux/setup.md
	if [[ ! -e "$SYZKALLER_DIR" ]]; then
		go get -u -d -v github.com/google/syzkaller/prog
		pushd "$SYZKALLER_DIR"
			git checkout "$SYZKALLER_COMMIT"
			echo ' Checked out all'
			make -j `nproc`
		popd
	fi




	echo "[+] All done and ready to go"
	echo "[ ] You might need to reboot to apply qemu install"
	echo "[ ] And add the current user into kvm group with the command: sudo usermod -a -G kvm \$USER"
	echo "[ ] Otherwise you can start run : source ./retro/bin/activate"

fi