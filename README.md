# Retrowrite

Code repository for "Retrowrite: Statically Instrumenting COTS Binaries for
Fuzzing and Sanitization" (in *IEEE S&P'20*). Please refer to the
[paper](https://nebelwelt.net/publications/files/20Oakland.pdf) for
technical details. There's also a
[36c3 presentation](http://nebelwelt.net/publications/files/19CCC-presentation.pdf)
and [36c3 video](https://media.ccc.de/v/36c3-10880-no_source_no_problem_high_speed_binary_fuzzing)
to get you started.

This project contains 2 different version of retrowrite :
* [Retrowrite](#retrowrite-1) to rewrite classic userspace binaries, and
* [KRetrowrite](#kretrowrite) to rewrite and fuzz kernel modules.

The two versions can be used independently of each other or at the same time.
In case you want to use both please follow the instructions for KRetrowrite.

## General setup

Retrowrite is implemented in python3 (3.6). Make sure python3 and python3-venv
is installed on system. Retrowrite depends on
[capstone](https://github.com/aquynh/capstone). The version
available from the Ubuntu 18.04 repositories 
is not compatible with this version. The setup
script pulls the latest version of capstone from the repository and builds it.
Make sure that your system meets the requirements to build capstone.

#### Requirements for target binary

The target binary
* must be compiled as position independent code (PIC/PIE)
* must be x86_64 (32 bit at your own risk)
* must contain symbols (i.e., not stripped; if stripped, please recover
  symbols first)
* must not contain C++ exceptions (i.e., C++ exception tables are not
  recovered and simply stripped during lifting)

#### Command line helper

The individual tools also have command line help which describes all the
options, and may be accessed with `-h`. 
To start with use retrowrite command:

```bash
(retro) $ retrowrite --help
usage: retrowrite [-h] [-a] [-s] [-k] [--kcov] [-c] bin outfile

positional arguments:
  bin             Input binary to load
  outfile         Symbolized ASM output

optional arguments:
  -h, --help      show this help message and exit
  -a, --asan      Add binary address sanitizer instrumentation
  -s, --assembly  Generate Symbolized Assembly
  -k, --kernel    Instrument a kernel module
  --kcov          Instrument the kernel module with kcov
  -c, --cache     Save/load register analysis cache (only used with --asan)
  --ignore-no-pie     Ignore position-independent-executable check (use with
                  caution)
  --ignore-stripped  Ignore stripped executable check (use with caution)


```

In case you load a non position independent code you will get the following message:
```
(retro) $ retrowrite stack stack.c 
***** RetroWrite requires a position-independent executable. *****
It looks like stack is not position independent
If you really want to continue, because you think retrowrite has made a mistake, pass --ignore-no-pie.
```
In the case you think retrowrite is mistaking you can use the argument `--ignore-no-pie`.


## Retrowrite
### Quick Usage Guide

This section highlights the steps to get you up to speed to use userspace retrowrite for rewriting PIC binaries.

Retrowrite ships with an utility with the following features:
* Generate symbolized assembly files from binaries without source code
* BASan: Instrument binary with binary-only Address Sanitizer 
* Support for symbolizing (linux) kernel modules 
* KCovariance instrumentation support

### Setup

Run `setup.sh`:

* `./setup.sh user`

Activate the virtualenv (from root of the repository):

* `source retro/bin/activate`

(Bonus) To exit virtualenv when you're done with retrowrite:
* `deactivate`


### Usage

#### Commands




##### a. Instrument Binary with Binary-Address Sanitizer (BASan)

`retrowrite --asan </path/to/binary/> </path/to/output/binary>`

Note: Make sure that the binary is position-independent and is not stripped.
This can be checked using `file` command (the output should say `ELF shared object`).

Example, create an instrumented version of `/bin/ls`:

`retrowrite --asan /bin/ls ls-basan-instrumented`

This will generate an assembly (`.s`) file that can be assembled and linked
using any compiler, example:

`gcc ls-basan-instrumented.s -lasan -o ls-basan-instrumented`

**debug** in case you get the error ```undefined reference to `__asan_init_v4'``` , 
replace "asan_init_v4" by "asan_init"  in the assembly file, the following command can help you do that:
```sed -i 's/asan_init_v4/asan_init/g' ls-basan-instrumented.s```

##### b. Generate Symbolized Assembly

To generate symbolized assembly that may be modified by hand or post-processed
by existing tools:

`retrowrite </path/to/binary> <path/to/output/asm/files>`

Post-modification, the asm files may be assembled to working binaries as
described above.

While retrowrite is interoperable with other tools, we
strongly encourage researchers to use the retrowrite API for their binary
instrumentation / modification needs! This saves the additional effort of
having to load and parse binaries or assembly files. Check the developer
sections for more details on getting started.


##### c. Instrument Binary with AFL

To generate an AFL instrumented binary, first generate the symbolized assembly
as described above. Then, recompile the symbolized assembly with `afl-gcc` from
[afl++](https://github.com/vanhauser-thc/AFLplusplus) like this:

```
$ AFL_AS_FORCE_INSTRUMENT=1 afl-gcc foo.s -o foo
```
 or `afl-clang`.


## Docker / Reproducing Results

See [fuzzing/docker](fuzzing/docker) for more information on building a docker image for
fuzzing and reproducing results.



# KRetrowrite
### Quick Usage Guide
### Setup

Run `setup.sh`:

* `./setup.sh kernel`


Activate the virtualenv (from root of the repository):

* `source retro/bin/activate`

(Bonus) To exit virtualenv when you're done with retrowrite:
* `deactivate`


### Usage


#### Commands

##### Classic instrumentation

* Instrument Binary with Binary-Address Sanitizer (BASan)  :`retrowrite --asan --kernel </path/to/module.ko> </path/to/output/module_asan.ko>`
* Generate Symbolized Assembly that may be modified by hand or post-processed by existing tools: `retrowrite </path/to/module.ko> <path/to/output/asm/files>`

##### Fuzzing

For fuzzing campaign please see [fuzzing/](fuzzing/) folder.

# Developer Guide

In general, `librw/` contains the code for loading, disassembly, and
symbolization of binaries and forms the core of all transformations.
Individual transformation passes that build on top this rewriting framework,
such as our binary-only Address Sanitizer (BASan) is contained as individual
tools in `rwtools/`.

The files and folder starting with `k` are linked with the kernel retrowrite version.

# Demos

In the [demos/](demos/) folder, you will find examples for userspace and kernel retrowrite
([demos/user_demo](demos/user_demo) and [demos/kernel_demo](demos/kernel_demo) respectively).


## Cite

The following publications cover different parts of the RetroWrite project:

* *RetroWrite: Statically Instrumenting COTS Binaries for Fuzzing and Sanitization*
  Sushant Dinesh, Nathan Burow, Dongyan Xu, and Mathias Payer.
  **In Oakland'20: IEEE International Symposium on Security and Privacy, 2020**

* *No source, no problem! High speed binary fuzzing*
  Matteo Rizzo, and Mathias Payer.
  **In 36c3'19: Chaos Communication Congress, 2019**


# License -- MIT

The MIT License

Copyright (c) 2019 HexHive Group,
Sushant Dinesh <sushant.dinesh94@gmail.com>,
Matteo Rizzo <matteorizzo.personal@gmail.com>,
Mathias Payer <mathias.payer@nebelwelt.net>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
