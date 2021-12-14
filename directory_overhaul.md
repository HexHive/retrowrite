
# directory tree reworking proposal

├── arm
│   ├── librw
│   │   ├── analysis
│   │   ├── container.py
│   │   ├── disasm.py
│   │   ├── __init__.py
│   │   ├── kcontainer.py
│   │   ├── kloader.py
│   │   ├── krw.py
│   │   ├── loader.py
│   │   ├── __pycache__
│   │   └── rw.py
│   └── rwtools
│       ├── asan
│       ├── __init__.py
│       ├── kasan
│       ├── kcov
│       └── __pycache__
├── bin
│   ├── activate
│   ├── activate.csh
│   ├── activate.fish
│   ├── Activate.ps1
│   ├── easy_install
│   ├── easy_install-3.8
│   ├── f2py
│   ├── f2py3
│   ├── f2py3.8
│   ├── futurize
│   ├── iptest
│   ├── iptest3
│   ├── ipython
│   ├── ipython3
│   ├── pasteurize
│   ├── pip
│   ├── pip3
│   ├── pip3.8
│   ├── __pycache__
│   │   └── readelf.cpython-38.pyc
│   ├── pygmentize
│   ├── py.test
│   ├── pytest
│   ├── python -> python3
│   ├── python3 -> /usr/bin/python3
│   ├── readelf.py
│   └── yapf
├── cftool # needs to go
│   └── main.go
├── debug # needs to go
│   ├── ddbg.py
│   └── __init__.py
├── demos # needs to be moved
│   ├── kernel_demo
│   │   ├── instrument_module.sh
│   │   ├── launch_vm.sh
│   │   ├── module
│   │   └── README.md
│   └── user_demo
│       ├── heap
│       ├── heap.asan.analysis_cache
│       ├── heap.asan.s
│       ├── heap.c
│       ├── Makefile
│       ├── README.md
│       └── stack.c
├── docker
│   ├── afl-2.52b-patched.tar.gz
│   ├── afl-dyninst.patch
│   ├── build.py
│   ├── build.yaml
│   ├── Dockerfile
│   ├── fuzz-config.yaml
│   ├── fuzz.py
│   ├── fuzz-save.py
│   ├── fuzz-seeds.zip
│   ├── README.md
│   └── requirements.txt
├── evaluation
│   ├── afl_evaluation_runner.sh
│   ├── analyze_afl_results.py
│   ├── analyze_juliet_results.py
│   ├── analyze_spec_results.py
│   ├── get_unique_bugs.sh
│   ├── google-fuzzer-suite
│   │   └── Dockerfile
│   └── __init__.py
├── __init__.py # delete 

├── lib
│   └── python3.8
│       └── site-packages
├── lib64 -> lib

├── librw
│   ├── analysis
│   │   ├── __init__.py
│   │   ├── kregister.py
│   │   ├── kstackframe.py
│   │   ├── __pycache__
│   │   ├── register.py
│   │   └── stackframe.py
│   ├── container.py
│   ├── disasm.py
│   ├── __init__.py
│   ├── kcontainer.py
│   ├── kloader.py
│   ├── krw.py
│   ├── loader.py
│   ├── __pycache__
│   │   ├── container.cpython-38.pyc
│   │   ├── disasm.cpython-38.pyc
│   │   ├── __init__.cpython-38.pyc
│   │   ├── kcontainer.cpython-38.pyc
│   │   ├── kloader.cpython-38.pyc
│   │   ├── krw.cpython-38.pyc
│   │   ├── loader.cpython-38.pyc
│   │   └── rw.cpython-38.pyc
│   └── rw.py
├── LICENSE

├── mytest
│   ├── hello.c
│   ├── hello.out
│   ├── hello_rw
│   ├── hello_rw.s
│   ├── Makefile
│   └── README.md
├── pytest.ini
├── pyvenv.cfg
├── README.md
├── requirements_kernel.txt # needs to be merged into a single requirements.txt
├── requirements_user.txt # needs to be merged into a single requirements.txt
├── rwtools # needs to be merged inside librw, we need to have a single "src"-like directory
│   ├── asan
│   │   ├── asantool.py
│   │   ├── __init__.py
│   │   ├── instrument.py
│   │   ├── __pycache__
│   │   └── snippets.py
│   ├── __init__.py
│   ├── kasan
│   │   ├── asantool.py
│   │   ├── __init__.py
│   │   ├── instrument.py
│   │   ├── __pycache__
│   │   └── snippets.py
│   ├── kcov
│   │   ├── __init__.py
│   │   ├── instrument.py
│   │   └── kcovtool.py
│   └── __pycache__
│       └── __init__.cpython-38.pyc
├── setup.sh # not really sure of this

├── share # some pip stuff, ignored
│   └── man
│       └── man1
├── syzkaller-configs # needs to go
│   ├── btrfs.cfg
│   ├── e1000.cfg
│   ├── ext4.cfg
│   └── generate_config.py
├── testbins # needs to go
│   ├── memac
│   │   ├── Makefile
│   │   ├── memac.c
│   │   └── memac_sib.c
│   ├── snippets
│   │   ├── Makefile
│   │   ├── optimized_save.s
│   │   └── simple_save.s
│   ├── tiny
│   │   ├── Makefile
│   │   ├── stack_example.c
│   │   ├── tiny.c
│   │   ├── tinylib.c
│   │   └── tinylib.h
│   └── tiny-afl
│       ├── Makefile
│       ├── tiny.c
│       ├── tinylib.c
│       └── tinylib.h
├── tests # needs to go 
│   ├── analysis
│   │   ├── __init__.py
│   │   ├── test_asan_memcheck.py
│   │   └── test_register_analysis.py
│   ├── binutils
│   │   ├── Makefile
│   │   └── rewrite.json
│   ├── __init__.py
│   ├── juliet
│   │   ├── juliet.json
│   │   └── Makefile
│   ├── LAVA-M
│   │   ├── lavam.json
│   │   └── Makefile
│   ├── rw_all.py
│   └── SPECCPU2006
│       ├── Makefile
│       └── specrw.json
├── third-party # empty folder
│   └── capstone
└── vms_files
    ├── busybox-config
    ├── fuzz-module.sh
    ├── linux
    │   ├── arch
    │   ├── block
    │   ├── certs
    │   ├── COPYING
    │   ├── CREDITS
    │   ├── crypto
    │   ├── Documentation
    │   ├── drivers
    │   ├── fs
    │   ├── include
    │   ├── init
    │   ├── ipc
    │   ├── Kbuild
    │   ├── Kconfig
    │   ├── kernel
    │   ├── lib
    │   ├── LICENSES
    │   ├── MAINTAINERS
    │   ├── Makefile
    │   ├── mm
    │   ├── modules.builtin
    │   ├── modules.builtin.modinfo
    │   ├── modules.order
    │   ├── Module.symvers
    │   ├── my_module.c
    │   ├── net
    │   ├── README
    │   ├── samples
    │   ├── scripts
    │   ├── security
    │   ├── sound
    │   ├── System.map
    │   ├── tools
    │   ├── usr
    │   ├── virt
    │   ├── vmlinux
    │   └── vmlinux.o
    ├── linux-config
    ├── linux-config-coverage
    ├── linux-config-noinst
    ├── measure_coverage.sh
    ├── my_module
    │   ├── Makefile
    │   ├── modules.order
    │   ├── Module.symvers
    │   ├── my_module.c
    │   ├── my_module.ko
    │   ├── my_module.mod
    │   ├── my_module.mod.c
    │   ├── my_module.mod.o
    │   └── my_module.o
    ├── run_cov.expect
    ├── run_cov.sh
    ├── run_qemu_cov.sh
    └── vm_init

78 directories, 180 files
