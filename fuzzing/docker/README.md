# Docker Build Steps

Make sure `docker` is installed on your system. This guide will not go over
setting up docker and assumes it has been setup with non-root access. 
Run commands as root if any command needs it. 

Before you build, customize the `build.yaml` and `fuzz_config.yaml` to add,
remove, or modify the fuzz targets.

The requirements to build docker container are:

* (Included) `fuzz-seeds.zip`: Fuzzing seeds for all benchmarks. `unzip`
before building the docker image.

* (Included) `afl-dyninst.patch`: Build patch for afl-dyninst

* (Included) `afl-2.52b-patched.tar.gz`: Patched version of AFL

* (Required) `clang-built.tar.gz`: Prebuilt clang-8.0 binaries, required
for afl-clang-fast (there seems to be a bug with afl-clang-fast and
Ubuntu included clang. It is recommended to compile LLVM yourself as
release version for Ubuntu does not seem to work).

    - To build clang, follow the official [build steps](https://llvm.org/docs/CMake.html) 
      In the build step, configure clang to install to a local directory.
    - Create a tar of the install directory

* (Required) `retrowrite.bundle`: Bundled version of retrowrite. Created
using `git bundle create retrowrite.bundle --all`



* (Required) : LAVA-M/ directory of lava_corpus, [download](http://panda.moyix.net/~moyix/lava_corpus.tar.xz), 
extract and rename the directory to LAVA-M



Once these files are in the docker directory, build using: 
`docker build -t retrowrite-docker .`

To run the container:
`docker run --privileged --network="host" -it retrowrite-docker:latest`


# Analyzing and Reproducing Results

The retrowrite docker / fuzz infrastructure is designed to run on multiple
systems by coordinating jobs through `beanstalk`.

Note: Configure `fuzz_config.yaml` to point to the correct beanstalk queue to
pull fuzz jobs from.

Requirements:

1. Beanstalk. Refer to beanstalk manual for install.
2. Start `beanstalkd`.

From within the container, load the jobs into the beanstalk queue:
* `python fuzz.py --load fuzz_config.yaml fuzz.yaml`

Start fuzzing from a single or multiple machines using the command:
* `python fuzz.py --fuzz fuzz_config.yaml fuzz.yaml`

Fuzzers terminate after running for some time as defined in `fuzz_config.yaml`.
All results can be found inside `/results` inside the docker container.
To make it easier to save results to host, mount a local directory to
`/results` while starting up the docker contianer using:

`docker run --privileged --network="host" -v <local_dir>:/results -it retrowrite-docker:latest`

Post run, the result files can be analyzed using scripts from `evaluation/`.
