"é# Retrowrite

Code repository for "Retrowrite: Statically Instrumenting COTS Binaries for
Fuzzing and Sanitization" (in *IEEE S&P'20*). Please refer to the
[paper](https://nebelwelt.net/publications/files/20Oakland.pdf) for
technical details. There's also a
[36c3 presentation](http://nebelwelt.net/publications/files/19CCC-presentation.pdf)
and [36c3 video](https://media.ccc.de/v/36c3-10880-no_source_no_problem_high_speed_binary_fuzzing)
to get you started.

Retrowrite ships with two utilities to support binary rewriting:
* **rwtools.asan.asantool:** Instrument binary with binary-only Address Sanitizer (BASan).
* **librw.rw :** Generate symbolized assembly files from binaries



# Quick Usage Guide

This section highlights the steps to get you up to speed to use retrowrite for
rewriting PIC binaries.


## Setup

Retrowrite is implemented in python3 (3.6). Make sure python3 and python3-venv
is installed on system. Retrowrite depends on
[capstone](https://github.com/aquynh/capstone). The capstone
shipped with distribution is not compatible with this version. The setup
script pulls the latest version of capstone from the repository and builds it.
Make sure that your system meets the requirements to build capstone.

Run `setup.sh`:

* `./setup.sh`

Activate the virtualenv (from root of the repository):

* `source retro/bin/activate`

(Bonus) To exit virtualenv when you're done with retrowrite:
* `deactivate`


## Usage

### Requirements for target binary

The target binary
* must be compiled as position independent code (PIC/PIE)
* must be x86_64 (32 bit at your own risk)
* must contain symbols (i.e., not stripped; if stripped, please recover
  symbols first)
* must not contain C++ exceptions (i.e., C++ exception tables are not
  recovered and simply stripped during lifting)


### Commands

The individual tools also have commandline help which describes all the
options, and may be accessed with `-h`. The below steps should quickly get you
started with using retrowrite.


#### a. Instrument Binary with Binary-Address Sanitizer (BASan)

`python3 -m rwtools.asan.asantool </path/to/binary/> </path/to/output/binary>`

Note: Make sure that the binary is position-independent and is not stripped.
This can be checked using `file` command (the output should say `ELF shared object`).

Example, create an instrumented version of `/bin/ls`:

`python3 -m rwtools.asan.asantool /bin/ls ls-basan-instrumented`

This will generate an assembly (`.s`) file that can be assembled and linked
using any compiler, example:

`gcc ls-basan-instrumented.s -lasan -o ls-basan-instrumented`


#### b. Generate Symbolized Assembly

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


#### c. Instrument Binary with AFL

To generate an AFL instrumented binary, first generate the symbolized assembly
as described above. Then, recompile the symbolized assembly with `afl-gcc` from
[afl++](https://github.com/vanhauser-thc/AFLplusplus) like this:

```
$ AFL_AS_FORCE_INSTRUMENT=1 afl-gcc foo.s -o foo
```
 or `afl-clang`.

# Developer Guide

In general, `librw/` contains the code for loading, disassembly, and
symbolization of binaries and forms the core of all transformations.
Individual transformation passes that build on top this rewriting framework,
such as our binary-only Address Sanitizer (BASan) is contained as individual
tools in `rwtools/`.


# Docker / Reproducing Results

See [docker](docker) for more information on building a docker image for
fuzzing and reproducing results.


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
