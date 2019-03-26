#!/bin/bash

PFX=/home/number_four/projects/retrowrite-afl-libraries-evaluation/lava-m-results
LAVA=/home/number_four/projects/binary-infrastructure/misc/lava-m-built

BASE=$PFX/base64-*.tar.gz
MD=$PFX/md5sum-*.tar.gz
UNIQ=$PFX/uniq-*.tar.gz
WHO=$PFX/who-*.tar.gz

for tarf in $BASE; do
    ./get_unique_bugs.sh $tarf `pwd`/crash-results $LAVA/base64 -d
done;

for tarf in $MD; do
    ./get_unique_bugs.sh $tarf `pwd`/crash-results $LAVA/md5sum -c
done;

for tarf in $UNIQ; do
    ./get_unique_bugs.sh $tarf `pwd`/crash-results $LAVA/uniq
done;

for tarf in $WHO; do
    ./get_unique_bugs.sh $tarf `pwd`/crash-results $LAVA/who
done;
