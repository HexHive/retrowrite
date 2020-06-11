#!/bin/bash

set -euxo pipefail

# setup local Linux files (to not disturb everything else)
if [[ ! -e "./initramfs" ]]; then
  cp ../../vms_files/initramfs ./ -r
fi
if [[ ! -e "./linux" ]]; then
  cp ../../vms_files/linux ./ -r
  cd linux
  cp ../../../vms_files/linux-config .config
  make -j $(nproc)
  cd ..
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
  -kernel linux/arch/x86/boot/bzImage \
  -append "console=ttyS0 rw debug earlyprintk=serial slub_debug=QUZ"\
  -initrd initramfs.cpio.gz \
  -enable-kvm \
  -nographic \
  -m 512M \
  2>&1

rm initramfs.cpio.gz
