#!/bin/bash

PATH=`pwd`

python3 -m venv retro
source retro/bin/activate
pip install --upgrade pip
pip install -r reqruirements.txt
git submodule update --init --checkout third-party/capstone
cd third-party/capstone
make
cd bindings/python/ && make && make install
cd $PATH
