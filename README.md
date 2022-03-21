# Retrowrite

Retrowrite is a static binary rewriter for x64 and aarch64. It works without
heuristics, does not introduce overhead and uses the *symbolization* technique
(also known as *reassemblable assembly*) to insert instrumentation to binaries
without the need for source code.

Please note that the x64 version and the arm64 version use different rewriting algorithms and
support a different set of features. 

For technical details, you can read the 
[paper](https://nebelwelt.net/publications/files/20Oakland.pdf)
(in *IEEE S&P'20*) for the x64 version and this [thesis](https://hexhive.epfl.ch/theses/20-dibartolomeo-thesis.pdf) 
for the arm64 version. 

[KRetrowrite](#kretrowrite) is a variant of the x64 version that supports the rewriting
of Linux kernel modules. 

<!--Code repository for "Retrowrite: Statically Instrumenting COTS Binaries for-->
<!--Fuzzing and Sanitization" (in *IEEE S&P'20*). Please refer to the-->
<!--[paper](https://nebelwelt.net/publications/files/20Oakland.pdf) for-->
<!--technical details. There's also a-->
<!--[36c3 presentation](http://nebelwelt.net/publications/files/19CCC-presentation.pdf)-->
<!--and [36c3 video](https://media.ccc.de/v/36c3-10880-no_source_no_problem_high_speed_binary_fuzzing)-->
<!--to get you started.-->

<!--This project contains 2 different version of retrowrite :-->
<!--* [Retrowrite](#retrowrite-1) to rewrite classic userspace binaries, and-->
<!--* [KRetrowrite](#kretrowrite) to rewrite and fuzz kernel modules.-->

<!--The two versions can be used independently of each other or at the same time.-->
<!--In case you want to use both please follow the instructions for KRetrowrite.-->

## General setup

Retrowrite is implemented in python3 (3.6). It depends on `pyelftools` and `capstone`.
To install the dependencies, please run:
```python
pip install -r requirements.txt
```
It is not recommended to install the dependencies from your distro's package managers, as they
might be outdated.


<!--Make sure python3 and python3-venv-->
<!--is installed on system. Retrowrite depends on-->
<!--[capstone](https://github.com/aquynh/capstone). The version-->
<!--available from the Ubuntu 18.04 repositories -->
<!--is not compatible with this version. The setup-->
<!--script pulls the latest version of capstone from the repository and builds it.-->
<!--Make sure that your system meets the requirements to build capstone.-->

#### Features

|                              | retrowrite-x64     | retrowrite-aarch64 |
|------------------------------|--------------------|--------------------|
| stripped binaries            | :x: (WIP)          | :white_check_mark: |
| Non-PIE binaries             | :x:                | :white_check_mark: |
| Non-standard compilers       | :x:                | :white_check_mark: |
| Zero overhead                | :white_check_mark: | :white_check_mark: |
| Kernel modules support       | :white_check_mark: | :x:                |
| AFL-coverage instrumentation | :white_check_mark: | :white_check_mark: |
| ASan instrumentation         | :white_check_mark: | :white_check_mark: |
| C++ support                  | :x: (WIP)          | :x: (WIP)          |


#### Command line options

```bash
(retro) $ retrowrite --help
usage: retrowrite [-h] [-a] [-A] [-m MODULE] [-k] [--kcov] [-c] [--ignore-no-pie] [--ignore-stripped] [-v] bin outfile

positional arguments:
  bin                   Input binary to load
  outfile               Symbolized ASM output

optional arguments:
  -h, --help            show this help message and exit
  -a, --assemble        Assemble instrumented assembly file into instrumented binary
  -A, --asan            Add binary address sanitizer instrumentation
  -m MODULE, --module MODULE
                        Use specified instrumentation pass/module in rwtools directory
  -k, --kernel          Instrument a kernel module
  --kcov                Instrument the kernel module with kcov
  -c, --cache           Save/load register analysis cache (only used with --asan)
  --ignore-no-pie       Ignore position-independent-executable check (use with caution)
  --ignore-stripped     Ignore stripped executable check (use with caution)
  -v, --verbose         Verbose output
```

### Instrumentation passes

Select the instrumentation pass you would like to apply with `retrowrite -m <pass>`
You can find the available instrumentation passes in folders `rwtools_x64` and `rwtools_arm64`.

Available instrumentation passes for x64:
	- AddressSanitizer
	- AFL-coverage information

Available instrumentation passes for aarch64:
	- AddressSanitizer
	- AFL-coverage information + forkserver
	- Coarse grained control flow integrity on function entries




<!--In case you load a non position independent code you will get the following message:-->
<!--```-->
<!--(retro) $ retrowrite stack stack.c -->
<!--***** RetroWrite requires a position-independent executable. *****-->
<!--It looks like stack is not position independent-->
<!--If you really want to continue, because you think retrowrite has made a mistake, pass --ignore-no-pie.-->
<!--```-->
<!--In the case you think retrowrite is mistaking you can use the argument `--ignore-no-pie`.-->


<!--## Retrowrite-->
<!--### Quick Usage Guide-->

<!--This section highlights the steps to get you up to speed to use userspace retrowrite for rewriting PIC binaries.-->

<!--Retrowrite ships with an utility with the following features:-->
<!--* Generate symbolized assembly files from binaries without source code-->
<!--* BASan: Instrument binary with binary-only Address Sanitizer -->
<!--* Support for symbolizing (linux) kernel modules -->
<!--* KCovariance instrumentation support-->

<!--### Usage-->

<!--#### Commands-->



## Example usage

#### a. Instrument Binary with Binary-Address Sanitizer (BASan)

`retrowrite --asan </path/to/binary/> </path/to/output/binary>`

Note: If on x64, make sure that the binary is position-independent and is not stripped.
This can be checked using `file` command (the output should say `ELF shared object`).

Example, create an instrumented version of `/bin/ls`:

`retrowrite --asan /bin/ls ls-basan-instrumented.s`

This will generate an assembly (`.s`) file. 
To recompile the assembly back into a binary, it depends on the architecture:

##### x64
The generated assembly can be assembled and linked
using any compiler, like:

`gcc ls-basan-instrumented.s -lasan -o ls-basan-instrumented`

**debug** in case you get the error ```undefined reference to `__asan_init_v4'``` , 
replace "asan_init_v4" by "asan_init"  in the assembly file, the following command can help you do that:
```sed -i 's/asan_init_v4/asan_init/g' ls-basan-instrumented.s```

##### aarch64
On aarch64, we also rely on standard compilers to assemble and link but the collection of compiler 
flags is slightly more involved and so we provide the `-a` switch on the main `retrowrite` 
executable to do that for you:

`retrowrite -a ls-basan-instrumented.s -lasan -o ls-basan-instrumented`


#### b. Instrument a binary with coverage information and fuzz with AFL

##### x64

To generate an AFL-instrumented binary, first generate the symbolized assembly
as described above. Then, recompile the symbolized assembly with `afl-gcc` from
[afl++](https://github.com/vanhauser-thc/AFLplusplus) like this:

```
$ AFL_AS_FORCE_INSTRUMENT=1 afl-gcc foo.s -o foo
```
 or `afl-clang`.

##### aarch64

To instrument a binary with coverage information, use the coverage instrumentation pass
with `retrowrite -m coverage <input file> <output asm>`.  Re-assemble the binary 
with `retrowrite -a <output asm> <new binary>`.

The binary can now be fuzzed with:
```bash
afl-fuzz -i <seed folder> -o <out folder> <new binary>
```

Retrowrite also tries to add instrumentation to act as a forkserver for AFL; in case this 
causes problems, you can disable this behaviour by using `export AFL_NO_FORKSERVER=1`

#### c. Generate Symbolized Assembly

To generate symbolized assembly that may be modified by hand or post-processed
by existing tools, just do not specify any instrumentation pass:

`retrowrite </path/to/binary> <path/to/output/asm/files>`

The output asm files can be freely edited by hand or by other tools.
Post-modification, the asm files may be assembled to working binaries as
described above.

While retrowrite is interoperable with other tools, we
strongly encourage researchers to use the retrowrite API for their binary
instrumentation / modification needs! This saves the additional effort of
having to load and parse binaries or assembly files. 

<!--## Docker / Reproducing Results-->

<!--See [fuzzing/docker](fuzzing/docker) for more information on building a docker image for-->
<!--fuzzing and reproducing results.-->



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
