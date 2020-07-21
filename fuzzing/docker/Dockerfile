FROM ubuntu:18.04

ARG clang=/clang-4.0.0
ARG afl=/afl

# Basic dependencies
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y make autoconf automake libtool shtool wget curl \
                       xz-utils gcc g++ cmake \
                       ninja-build zlib1g make python \
                       build-essential git ca-certificates \
                       tar gzip vim libelf-dev libelf1 libiberty-dev \
                       libboost-all-dev python3-pip python3-venv \
                       libpcap-dev libbz2-dev liblzo2-dev liblzma-dev liblz4-dev libz-dev \
                       libxml2-dev libssl-dev libacl1-dev libattr1-dev zip \
                       unzip libtool-bin bison

RUN pip3 install wheel greenstalk

# Setup directories
RUN mkdir -p $afl
RUN mkdir -p /results

#########################################
## Setup compilers and build-tools
#########################################

# Setup AFL and afl-clang-fast
COPY clang-built.tar.gz /clang-built.tar.gz
RUN tar -xvf /clang-built.tar.gz --strip-components=1 -C / \
    && rm /clang-built.tar.gz

COPY afl-2.52b-patched.tar.gz /
RUN tar -xvf /afl-2.52b-patched.tar.gz \
    && mv afl-2.52b/* $afl/ \
    && cd $afl \
    && rm Makefile \
    && wget https://raw.githubusercontent.com/mirrorer/afl/master/Makefile \
    && make clean \
    && make clean -C llvm_mode \
    && make install \
    && make -C llvm_mode \
    && cd ./qemu_mode && ./build_qemu_support.sh && cd ../ \
    && make install &&  rm /afl-2.52b-patched.tar.gz

# Install dyninst
RUN git clone https://github.com/dyninst/dyninst.git && \
    cd dyninst && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make && \
    make install

RUN cp -r dyninst/build/elfutils/* /usr/local/ && \
    cp -r dyninst/build/tbb/* /usr/local/

COPY afl-dyninst.patch /afl-dyninst.patch

# Make and install afl-dyninst
RUN git clone https://github.com/talos-vulndev/afl-dyninst.git && \
    cd afl-dyninst && \
    git apply /afl-dyninst.patch && \
    make && make install && cd .. \
	&& echo "/usr/local/lib" > /etc/ld.so.conf.d/dyninst.conf && ldconfig \
	&& echo "export DYNINSTAPI_RT_LIB=/usr/local/lib/libdyninstAPI_RT.so" >> .bashrc \
    && sed -i 's/export AFL_EXIT_WHEN_DONE=1/#&/g' /usr/local/bin/afl-fuzz-dyninst.sh

ENV DYNINSTAPI_RT_LIB=/usr/local/lib/libdyninstAPI_RT.so

###############################################################
## Done setting up compilers. Now, setup evaluation targets
###############################################################

COPY build.py /build/build.py
COPY requirements.txt /build/requirements.txt
COPY build.yaml /build/build.yaml
RUN  pip3 install -r /build/requirements.txt

######################################################################
## Setup retrowrite
######################################################################

COPY retrowrite.bundle /
RUN git clone retrowrite.bundle && cd /retrowrite && ./setup.sh
ENV PYTHONPATH=:/retrowrite/

RUN apt-get install -y texinfo flex
RUN mkdir -p /fuzz/
COPY LAVA-M/ /src

ENV FORCE_UNSAFE_CONFIGURE=1

RUN cd /build/ && \
    python3 build.py build.yaml && \
    ./build-all.sh && \
    cp fuzz.yaml /fuzz/fuzz.yaml

######################################################################
## Copy fuzzer stuff
######################################################################

COPY file-fuzz.zip png-fuzz.zip tcpdump-fuzz.zip tiff-fuzz.zip libarchive-fuzz.zip bzip2-fuzz.zip binutils-fuzz.zip /seeds/
COPY fuzz.py /fuzz/fuzz.py
COPY fuzz-config.yaml /fuzz/fuzz_config.yaml
COPY base64-fuzz.zip md5sum-fuzz.zip uniq-fuzz.zip who-fuzz.zip /seeds/

RUN apt-get install -y screen

RUN echo "echo core >/proc/sys/kernel/core_pattern; cd /sys/devices/system/cpu && echo performance | tee cpu*/cpufreq/scaling_governor" >> .bashrc

WORKDIR /fuzz/
