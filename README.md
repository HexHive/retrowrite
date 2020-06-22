# Retrowrite

Code repository for "Retrowrite: Statically Instrumenting COTS Binaries for
Fuzzing and Sanitization" (in *IEEE S&P'20*). Please refer to the
[paper](https://nebelwelt.net/publications/files/20Oakland.pdf) for
technical details. There's also a
[36c3 presentation](http://nebelwelt.net/publications/files/19CCC-presentation.pdf)
and [36c3 video](https://media.ccc.de/v/36c3-10880-no_source_no_problem_high_speed_binary_fuzzing)
to get you started.

This project contain 2 different version of retrowrite :
* [Retrowrite](#retrowrite-1) to rewrite classic user space binary
* [KRetrowrite](#kretrowrite) to rewrite and fuzz kernel module compiled libraries

The two version can be used independently of each other or at the same time.
In case you want to use both please follow instruction for KRetrowrite

## General setup

Retrowrite is implemented in python3 (3.6). Make sure python3 and python3-venv
is installed on system. Retrowrite depends on
[capstone](https://github.com/aquynh/capstone). The capstone
shipped with distribution is not compatible with this version. The setup
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

## Retrowrite
### Quick Usage Guide

This section highlights the steps to get you up to speed to use retrowrite for
rewriting PIC binaries.

Retrowrite ships with two utilities to support binary rewriting:
* **rwtools.asan.asantool:** Instrument binary with binary-only Address Sanitizer (BASan).
* **librw.rw :** Generate symbolized assembly files from binaries

### Setup

Run `setup.sh`:

* `./setup.sh user`

Activate the virtualenv (from root of the repository):

* `source retro/bin/activate`

(Bonus) To exit virtualenv when you're done with retrowrite:
* `deactivate`


### Usage

#### Commands

The individual tools also have commandline help which describes all the
options, and may be accessed with `-h`. The below steps should quickly get you
started with using retrowrite.


##### a. Instrument Binary with Binary-Address Sanitizer (BASan)

`python3 -m rwtools.asan.asantool </path/to/binary/> </path/to/output/binary>`

Note: Make sure that the binary is position-independent and is not stripped.
This can be checked using `file` command (the output should say `ELF shared object`).

Example, create an instrumented version of `/bin/ls`:

`python3 -m rwtools.asan.asantool /bin/ls ls-basan-instrumented`

This will generate an assembly (`.s`) file that can be assembled and linked
using any compiler, example:

`gcc ls-basan-instrumented.s -lasan -o ls-basan-instrumented`


##### b. Generate Symbolized Assembly

To generate symbolized assembly that may be modified by hand or post-processed
by existing tools:

`python3 -m librw.rw </path/to/binary> <path/to/output/asm/files>`

Post-modification, the asm files may be assembled to working binaries as
described above.

While retrowrite is interoperable with other tools, we
strongly encourage researchers to use retrowrite API for their binary
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

See [docker](docker) for more information on building a docker image for
fuzzing and reproducing results.



# KRetrowrite
### Quick Usage Guide
### Setup


> **_NOTE:_** This script will setup all the environment (virtual machine file and go install), it take some time to setup and download everything.
>
> It will take about 10 GB on your disk for the virtual machine image disk and go tools, so make sure you have enough space.

Run `setup.sh`:

* `./setup.sh kernel`

This script will create all needed file for the fuzzing campaign:
* [vms_files/linux/](vms_files/linux/) : linux source used  
* [vms_files/busybox/](vms_files/busybox/) :
* [vms_files/initramfs/](vms_files/initramfs/) :
* [vms_files/image/](vms_files/image/) : syzskaller images

Activate the virtualenv (from root of the repository):

* `source retro/bin/activate`

(Bonus) To exit virtualenv when you're done with retrowrite:
* `deactivate`


### Usage
We wrote all script with the assumption that the module tested is in the Linux tree, because that's what we used for the evaluation.

#### Commands


[vms_files/fuzz-module.sh](vms_files/fuzz-module.sh) : create, prepare and run a fuzzing campaign of a module from a modules in the linux sources.

You might want to setup the variables `CAMPAIGN_DURATION` , `NUM_RUNS`, `NB_VMS`, `CPU_VMS` and `MEMORY_VMS` depending of your available resources.

An exemple to fuzz ext4 modules
* `./vms_files/fuzz-module.sh ext4`

(is it really usefull section >????? )It will create the directly campaign containing the results of your fuzzing campaign.

here is an architecture exemple of the files generated for ext4:
* campaigns/ext4/binary
* source
* workdir
* ..


[vms_files/measure_coverage.sh](vms_files/measure_coverage.sh) : measure the coverage of the fuzzing campaign, by replaying all the test cases and checking which basic blocks are hit. This script will need the `campaign/` folder containing the finished fuzzing campaign generated by `./vms_files/fuzz-module.sh`.

An exemple to measure our fuzzing:
* `./vms_files/measure_coverage.sh ext4`

#### For custom module

*work in progress*

# Developer Guide

In general, `librw/` contains the code for loading, disassembly, and
symbolization of binaries and forms the core of all transformations.
Individual transformation passes that build on top this rewriting framework,
such as our binary-only Address Sanitizer (BASan) is contained as individual
tools in `rwtools/`.

The files and folder starting with `k` are linked with the kernel retrowrite version.

list of retrowrite files :
* [librw/container.py](librw/container.py) :
* [librw/disasm.py](librw/disasm.py)
* [librw/kcontainer.py](librw/kcontainer.py)
* [librw/kloader.py](librw/kloader.py) :
* [librw/krw.py](librw/krw.py) :
* [librw/loader.py](librw/loader.py) :
* [librw/rw.py](librw/rw.py) :
* [librw/analysis/kregister.py](librw/analysis/kregister.py) :
* [librw/analysis/kstackframe.py](librw/analysis/kstackframe.py) :
* [librw/analysis/register.py](librw/analysis/register.py) :
* [librw/analysis/stackframe.py](librw/analysis/stackframe.py) :
* [rwtools/kcov/instrument.py](rwtools/kcov/instrument.py) :
* [rwtools/kcov/kcovtool.py](rwtools/kcov/kcovtool.py) :
* [rwtools/asan/asantool.py](rwtools/asan/asantool.py) :
* [rwtools/asan/snippets.py](rwtools/asan/snippets.py) :
* [rwtools/asan/instrument.py](rwtools/asan/instrument.py) :
* [rwtools/kasan/asantool.py](rwtools/kasan/asantool.py) :
* [rwtools/kasan/snippets.py](rwtools/kasan/snippets.py) :
* [rwtools/kasan/instrument.py](rwtools/kasan/instrument.py) :

## Demos

You will find in the [demos/](demos/) folder, files to try out respectively, [demos/user_demo](demos/user_demo) and [demos/kernel_demo](demos/kernel_demo)

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
