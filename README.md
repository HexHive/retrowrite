# RetroWrite

Code repository for "Retrowrite: Statically Instrumenting COTS Binaries for
Fuzzing and Sanitization" (to appear in *IEEE S&P'20*). Please refer to the
paper for technical details: [paper]().

Retrowrite ships with three utilities to support binary rewriting:
* *librw.rw :* Generate symbolized assembly files from binaries
* *rwtools.asan.asantool:* Instrument binary with binary-ony Address Sanitizer (BASan).
* *rwtools.afl:* TODO


# Quick Usage Guide

This section highlights the steps to get you up to speed to use retrowrite for
rewriting PIC binaries.

## Setup

Retrowrite is implemented in python3 (3.6). Make sure python3 and python3-venv
is installed on system.

Run `setup.sh`:

* `./setup.sh`

Activate the virtualenv:

* `source retro/bin/activate`

## Usage

The individual tools also have commandline help which describes all the
options, and may be accessed with `-h`. The below steps should quickly get you
started with using retrowrite.

#### a. Instrument Binary with BASan

`python3 -m rwtools.asan.asantool </path/to/binary/> </path/to/output/binary>`

Example, create an instrumented version of `/bin/ls`:
Note: Make sure that the binary is position-independent. This can be checked
using `file` command (the output should say `ELF shared object`).

`python3 -m rwtools.asan.asantool /bin/ls ls-basan-instrumented`

This will generate an assembly (`.s`) file that can be assembled and linked
using any compiler, example:

`gcc ls-basan-instrumented.s -o ls-basan-instrumented`

#### b. Generate Symbolized Assembly

To generate symbolized assmebly that may be modified by hand or post-processed
by exisiting tools:

`python3 -m librw.rw </path/to/binary> <path/to/output/asm/files>`

Post-modification, the asm files may be assembled to working binaries as
described above. 

While retrowrite is interoperable with other tools, we
strongly encourage researchers to use retrowrite API for their binary
instrumentation / modification needs! This saves you the additional effort of
having to load and parse binaries or assembly files. Check the developer
sections for more details on getting started.

# Developer Guide

In general, `librw/` contains the code for loading, disassembly, and
symbolization of binaries and forms the core of all transformations.
Individual transformation passes that build on top this rewriting framework,
such as our binary-only Address Sanitizer (BASan) is contained as individual
tools in `rwtools/`.


## Cite
