# Demo time!

This directory contains one module to demonstrate ASan instrumentation with KRetroWrite.
If you want to see how to run a fuzzing campaign for this modules please see [README_FUZZ.md](README_FUZZ.md)


# Usage
> **_NOTE:_** You need to have run the setup and install script before try out this demo.


To prepare the environment, compile and instrument the demo module :
```bash
cd module
make
cd ..
```
To instrument the compiled module:
```bash
./instrument_module.sh module/demo_module.ko
```
To see the differences between the instrumented and classic binary you can use the command `objdump`:
* `objdump -d module/demo_module.ko`
* `objdump -d module/demo_module_asan.ko`

Test of the module:

You will need to compile the linux kernel with `kasan` (automated in the launch script).

(Bonus) To exit virtual qemu machine : `ctrl+a x`

```bash
$ ./launch_vm.sh
[...]
To load the classic module : modprobe demo_module
To unload the module : rmmod demo_module
To load the instrumented module : modprobe demo_module_asan
The module create a file where you can write in it : echo 1234 > /dev/demo
You can generate a bufferover flow with : echo 1337 > /dev/demo

# modprobe demo_module
[   14.531827] demo_module: loading out-of-tree module taints kernel.
[   14.533619] Demo module loaded
[   14.534287] modprobe (99) used greatest stack depth: 28128 bytes left

# echo 1234 > /dev/demo
[   24.110295] 41

# echo 1337 > /dev/demo
[   31.125213] ffffffcc

# rmmod demo_module
[   38.319314] Demo module unloaded

# modprobe demo_module_asan
[   71.832343] Demo module loaded

# echo 1234 > /dev/demo
[   76.083920] 41

# echo 1337 > /dev/demo
[   79.211877] ==================================================================
[   79.212716] BUG: KASAN: slab-out-of-bounds in demo_write+0x29c/0x2b0 [demo_module]
[   79.212716] Read of size 1 at addr ffff888018e0fe80 by task sh/98
[   79.212716]
[   79.212716] CPU: 0 PID: 98 Comm: sh Tainted: G           O      5.5.0-rc6 #12
[   79.212716] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.10.2-1ubuntu1 04/01/2014
[   79.212716] Call Trace:
[   79.212716]  dump_stack+0x94/0xce
[   79.212716]  ? demo_write+0x29c/0x2b0 [demo_module]
[   79.212716]  print_address_description.constprop.5+0x16/0x310
[   79.212716]  ? demo_write+0x29c/0x2b0 [demo_module]
[   79.212716]  ? demo_write+0x29c/0x2b0 [demo_module]
[   79.212716]  __kasan_report+0x158/0x1b7
[   79.212716]  ? demo_write+0x29c/0x2b0 [demo_module]
[   79.212716]  kasan_report+0xe/0x20
[   79.212716]  demo_write+0x29c/0x2b0 [demo_module]
[   79.212716]  ? 0xffffffffa0000000
[   79.212716]  __vfs_write+0x7c/0x100
[   79.212716]  vfs_write+0x168/0x4a0
[   79.212716]  ksys_write+0x175/0x200
[   79.212716]  ? __ia32_sys_read+0xb0/0xb0
[   79.212716]  ? __close_fd+0x208/0x2d0
[   79.212716]  do_syscall_64+0x9c/0x390
[   79.212716]  ? prepare_exit_to_usermode+0x17a/0x230
[   79.212716]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
[   79.212716] RIP: 0033:0x4ceb81
[   79.212716] Code: f7 d8 64 89 02 48 c7 c0 ff ff ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 66 90 8b 05 06 95 3f 00 85 c0 75 16 b8 01 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 57 f3 c3 0f 1f 44 00 00 41 54 55 49 89 d4 53
[   79.212716] RSP: 002b:00007ffd5868e1e8 EFLAGS: 00000246 ORIG_RAX: 0000000000000001
[   79.212716] RAX: ffffffffffffffda RBX: 00000000012348a0 RCX: 00000000004ceb81
[   79.212716] RDX: 0000000000000005 RSI: 0000000001238710 RDI: 0000000000000001
[   79.212716] RBP: 0000000000000001 R08: fefefefefefefeff R09: fefefeff36323230
[   79.212716] R10: 0000000000000000 R11: 0000000000000246 R12: 0000000001238710
[   79.212716] R13: 0000000000000005 R14: 0000000000000001 R15: 00007ffd5868e250
[   79.212716]
[   79.212716] Allocated by task 98:
[   79.212716]  save_stack+0x19/0x80
[   79.212716]  __kasan_kmalloc.constprop.4+0xa0/0xd0
[   79.212716]  demo_write+0x4b/0x2b0 [demo_module]
[   79.212716]  __vfs_write+0x7c/0x100
[   79.212716]  vfs_write+0x168/0x4a0
[   79.212716]  ksys_write+0x175/0x200
[   79.212716]  do_syscall_64+0x9c/0x390
[   79.212716]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
[   79.212716]
[   79.212716] Freed by task 0:
[   79.212716] (stack is not available)
[   79.212716]
[   79.212716] The buggy address belongs to the object at ffff888018e0fe70
[   79.212716]  which belongs to the cache kmalloc-16 of size 16
[   79.212716] The buggy address is located 0 bytes to the right of
[   79.212716]  16-byte region [ffff888018e0fe70, ffff888018e0fe80)
[   79.212716] The buggy address belongs to the page:
[   79.212716] page:ffffea00006383c0 refcount:1 mapcount:0 mapping:ffff88801940f780 index:0xffff888018e0f180
[   79.212716] raw: 0100000000000200 ffff888019400450 ffff888019400450 ffff88801940f780
[   79.212716] raw: ffff888018e0f180 00000000000b0002 00000001ffffffff 0000000000000000
[   79.212716] page dumped because: kasan: bad access detected
[   79.212716]
[   79.212716] Memory state around the buggy address:
[   79.212716]  ffff888018e0fd80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   79.212716]  ffff888018e0fe00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc 00 00
[   79.212716] >ffff888018e0fe80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   79.212716]                    ^
[   79.212716]  ffff888018e0ff00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   79.212716]  ffff888018e0ff80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   79.212716] ==================================================================
[   79.212716] Disabling lock debugging due to kernel taint
[   79.260436] ffffffcc
```


