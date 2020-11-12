obj-m = demo_module.o

default:
	make -C ../linux  M=$$PWD

clean:
	rm -rf *.o .*.cmd *.ko *.mod *.mod.c modules.order Module.symvers built-in.a demo_module_asan.S demo_module
