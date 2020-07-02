#!/bin/bash

set -euxo pipefail

BUSYBOX_DIR="./busybox"
INITRAMFS_DIR="./initramfs"

BUSYBOX_VERSION="1.27.2"
LINUX_VERSION="5.5.0-rc6"
	# Why does the tarball version not have .0 in the version number? Whatever
LINUX_TARBALL_VERSION="5.5-rc6"

# Build Busybox
if [[ ! -e $BUSYBOX_DIR ]]; then
  wget -O ./busybox.tar.bz2 "https://www.busybox.net/downloads/busybox-$BUSYBOX_VERSION.tar.bz2"
  tar xf busybox.tar.bz2
  rm ./busybox.tar.bz2
  mv "./busybox-$BUSYBOX_VERSION" "$BUSYBOX_DIR"
  cp "../../fuzzing/kernel/vms_files/busybox-config" "$BUSYBOX_DIR/.config"

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
    cp -r ../$BUSYBOX_DIR/_install/* .
    cp "../../../fuzzing/kernel/vms_files/vm_init" init
    chmod +x init
    find "../linux-5.5-rc6" -name "*.ko" -type f -exec cp {} "lib/modules/$LINUX_VERSION" \;
  popd
fi


cp module/*.ko initramfs/lib/modules/5.5.0-rc6
echo "#!/bin/sh

mount -t devtmpfs devtmpfs /dev
mount -t proc none /proc
mount -t sysfs none /sys
sleep 2
echo 'To load the classic module : modprobe demo_module'
echo 'To unload the module : rmmod demo_module'
echo 'To load the instrumented module : modprobe demo_module_asan'
echo 'The module create a file where you can write in it : echo 1234 > /dev/demo'
echo 'You can generate a bufferover flow with : echo 1337 > /dev/demo'

/bin/sh" > ./initramfs/init
cd initramfs
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
cd ..

qemu-system-x86_64 \
  -kernel linux-5.5-rc6/arch/x86/boot/bzImage \
  -append "console=ttyS0 rw debug earlyprintk=serial slub_debug=QUZ"\
  -initrd initramfs.cpio.gz \
  -enable-kvm \
  -nographic \
  -m 512M \
  2>&1

rm initramfs.cpio.gz
