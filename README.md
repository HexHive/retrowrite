# Retrowrite

Code repository for "Retrowrite: Statically Instrumenting COTS Binaries for
Fuzzing and Sanitization" (to appear in *IEEE S&P'20*). Please refer to the
paper for technical details: [paper]().

Retrowrite ships with three utilities to support binary rewriting:
* **rwtools.asan.asantool:** Instrument binary with binary-only Address Sanitizer (BASan).
* **rwtools.afl:** TODO
* **librw.rw :** Generate symbolized assembly files from binaries

# Quick Usage Guide

This section highlights the steps to get you up to speed to use retrowrite for
rewriting PIC binaries.

## Setup

Retrowrite is implemented in python3 (3.6). Make sure python3 and python3-venv
is installed on system.

Run `setup.sh`:

* `./setup.sh`

Activate the virtualenv (from root of the repository):

* `source retro/bin/activate`

(Bonus) To exit virtualenv when you're done with retrowrite:
* `deactivate`

## Usage

The individual tools also have commandline help which describes all the
options, and may be accessed with `-h`. The below steps should quickly get you
started with using retrowrite.

#### a. Instrument Binary with Binary-Address Sanitizer (BASan)

`python3 -m rwtools.asan.asantool </path/to/binary/> </path/to/output/binary>`

Note: Make sure that the binary is position-independent. This can be checked
using `file` command (the output should say `ELF shared object`).

Example, create an instrumented version of `/bin/ls`:

`python3 -m rwtools.asan.asantool /bin/ls ls-basan-instrumented`

This will generate an assembly (`.s`) file that can be assembled and linked
using any compiler, example:

`gcc ls-basan-instrumented.s -o ls-basan-instrumented`

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

# Developer Guide

In general, `librw/` contains the code for loading, disassembly, and
symbolization of binaries and forms the core of all transformations.
Individual transformation passes that build on top this rewriting framework,
such as our binary-only Address Sanitizer (BASan) is contained as individual
tools in `rwtools/`.

## Cite



## License -- MIT
The MIT License

Copyright (c) 2019 HexHive Group, Sushant Dinesh <sushant.dinesh94@gmail.com>.

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
