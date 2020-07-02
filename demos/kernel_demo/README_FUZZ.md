# Run fuzzing campaing

This is a description of how to run a fuzzing campaign for an out-of-tree kernel module with the demo module.

It contains information about how to add the module into the kernel/syzkaller image, and all the config files needed.

To run properly this demo you will need to run [fuzzing/setup_fuzz.sh](/fuzzing/setup_fuzz.sh) script before.

(Bonus)
Here are few useful links about kernel modules:
- <https://www.kernel.org/doc/Documentation/kbuild/modules.txt>
- <http://tldp.org/LDP/lkmpg/2.6/html/lkmpg.html>
- <https://www.cs.bham.ac.uk/~exr/teaching/lectures/systems/07_08/kernelProgramming.php>

## Prepare the kernel
```bash
mkdir -p kernel/lib/modules/ && cd kernel/lib/modules/
wget https://git.kernel.org/torvalds/t/linux-5.5-rc6.tar.gz
tar xvf linux-5.5-rc6.tar.gz

mv linux-5.5-rc6 5.5.0-rc6

cp ../../../../../fuzzing/kernel/vms_files/linux-config ./
cp linux-config 5.5.0-rc6/.config

cd 5.5.0-rc6/
make -j 8
cd ../../../../

cd module && make && cd ..

./instrument_module.sh module/demo_module.c
cd module
#  compile and install into the kernel
make -C ../kernel/lib/modules/5.5.0-rc6/  M=$PWD
make -C ../kernel/lib/modules/5.5.0-rc6/  M=$PWD modules_install INSTALL_MOD_PATH=../../..
cd ../
cp module/demo_module_asan.ko kernel/lib/modules/5.5.0-rc6/extra

cd ../kernel/lib/modules/5.5.0-rc6
make -j 8
cd ../../../../#
```

## Add the modules into the syzkaller filesystem

To add the modules into the linux image:
```bash
cp ../../fuzzing/kernel/vms_files/image/stretch_ext4_10g.img ./
sudo qemu-nbd -c /dev/nbd0 stretch_ext4_10g.img
mkdir mounted_disk
sudo mount /dev/nbd0 mounted_disk

sudo mkdir -p mounted_disk/lib/modules/5.5.0-rc6/extra
sudo cp kernel/lib/modules/5.5.0-rc6/module* mounted_disk/lib/modules/5.5.0-rc6/

sudo cp module/*.ko mounted_disk/lib/modules/5.5.0-rc6/extra/

sudo umount mounted_disk
sudo qemu-nbd -d /dev/nbd0

rm -r mounted_disk
```
## Prepare Initramfs:
```
cp ../../vms_files/initramfs ./ -r
cp module/*.ko initramfs/lib/modules/5.5.0-rc6
echo '#!/bin/sh

mount -t devtmpfs devtmpfs /dev
mount -t proc none /proc
mount -t sysfs none /sys
# Needed to communicate with syzkaller
modprobe ext4
modprobe e1000
modprobe isofs
modprobe btrfs
# activate module to fuzz
modprobe demo_module_asan

mount -o ro /dev/sda /mnt/root

umount /proc
umount /sys

exec switch_root /mnt/root /sbin/init' > initramfs/init

cd initramfs
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
cd ..
```

## Test the vm
```
qemu-system-x86_64 \
        -kernel "kernel/lib/modules/5.5.0-rc6/arch/x86/boot/bzImage" \
        -append "console=ttyS0 rw debug root=/dev/sda debug earlyprintk=serial slub_debug=QUZ" \
        -hda "stretch_ext4_10g.img" \
        -snapshot \
        -initrd initramfs.cpio.gz \
        -enable-kvm \
        -nographic \
        -cpu host \
        -m 2G \
        -smp 2
[...]
Debian GNU/Linux 9 syzkaller ttyS0                                                                    

syzkaller login: root
root@syzkaller:~# echo 133 > /dev/demo                  
[   19.611571] 41                                       
root@syzkaller:~# echo 1337 > /dev/demo   
[   23.588393] ==================================================================
[   23.590832] BUG: KASAN: slab-out-of-bounds in demo_write+0x593/0x5a0 [demo_module]
[   23.593345] Read of size 1 at addr ffff888069d1a020 by task bash/279
[...]

```

(Bonus)

To preload (apply modification without reboot) the available modules : `depmod -a`

to load module not in a classic folder : `insmod /root/demo_module.ko`



## Syzkaller config

Now that the modules is working inside the syzkaller vm you need to create the syzkaller config files.

As our module is not a classic linux module (hand made), the syscall doesn't exist in a classic linux kernel and we need to add them into the syzkaller sources.

Here are usefull link we used for creating the syscall file:
- <https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions.md>
- <https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions.md#describing-new-system-calls>
- <https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions_syntax.md>

We took as example the `/dev/kvm` [config file](https://github.com/google/syzkaller/blob/master/sys/linux/dev_kvm.txt) for file descriptor in /dev.

And created the file [dev_demo.txt](dev_demo.txt) to add it you can use the following commands:

```bash
$ source ../../retro/bin/activate
(retro) $ cp dev_demo.txt ../../retro/go/src/github.com/google/syzkaller/sys/linux/
(retro) $ cd ../../retro/go/src/github.com/google/syzkaller/
(retro) $ make extract TARGETOS=linux SOURCEDIR=./
(retro) $ make generate
(retro) $ make
(retro) $ cd $PYTHONPATH
```
## Syzkaller run

Now syzkaller should know about your new syscall.

The syzkaller config file for the fuzzing campaign is in [demo_module.cfg](demo_module.cfg), you can see that only the demo module syscall are enable.

Now, we are ready to start the fuzzing campaign on this demo module:
```
(retro) $ syz-manager --config demo_module.cfg
2020/06/22 18:15:03 loading corpus...
2020/06/22 18:15:03 serving http on http://127.0.0.1:56741
2020/06/22 18:15:03 serving rpc on tcp://[::]:43049
2020/06/22 18:15:03 booting test machines...
2020/06/22 18:15:03 wait for the connection from test machine...
2020/06/22 18:15:14 machine check:
2020/06/22 18:15:14 syscalls                : 2/3363
2020/06/22 18:15:14 code coverage           : enabled
2020/06/22 18:15:14 comparison tracing      : CONFIG_KCOV_ENABLE_COMPARISONS is not enabled
2020/06/22 18:15:14 extra coverage          : enabled
2020/06/22 18:15:14 setuid sandbox          : enabled
2020/06/22 18:15:14 namespace sandbox       : enabled
2020/06/22 18:15:14 Android sandbox         : enabled
2020/06/22 18:15:14 fault injection         : CONFIG_FAULT_INJECTION is not enabled
2020/06/22 18:15:14 leak checking           : CONFIG_DEBUG_KMEMLEAK is not enabled
2020/06/22 18:15:14 net packet injection    : /dev/net/tun does not exist
2020/06/22 18:15:14 net device setup        : enabled
2020/06/22 18:15:14 concurrency sanitizer   : /sys/kernel/debug/kcsan does not exist
2020/06/22 18:15:14 devlink PCI setup       : PCI device 0000:00:10.0 is not available
2020/06/22 18:15:14 USB emulation           : /dev/raw-gadget does not exist
2020/06/22 18:15:14 corpus                  : 0 (deleted 0 broken)
2020/06/22 18:15:23 VMs 1, executed 2, cover 1335, crashes 0, repro 0
2020/06/22 18:15:33 VMs 2, executed 3947, cover 1425, crashes 0, repro 0
2020/06/22 18:15:43 VMs 3, executed 13231, cover 1450, crashes 0, repro 0
2020/06/22 18:15:53 VMs 4, executed 20456, cover 1462, crashes 0, repro 0
[...]
```

After few minutes you will get the first crash.



