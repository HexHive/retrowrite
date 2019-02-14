#!/bin/bash

PFX=/home/number_four/projects/retrowrite-afl-evaluation-latest/results
LAVA=/home/number_four/projects/lava_corpus/LAVA-M/built-lavam-pie

BASE=$PFX/base64/*.tar.gz
MD=$PFX/md5sum/*.tar.gz
UNIQ=$PFX/uniq/*.tar.gz
WHO=$PFX/who/*.tar.gz

for tarf in $BASE; do
    ./get_unique_bugs.sh $tarf base64 $LAVA/base64 -d
done;

for tarf in $MD; do
    ./get_unique_bugs.sh $tarf md5sum $LAVA/md5sum -c
done;

for tarf in $UNIQ; do
    ./get_unique_bugs.sh $tarf uniq $LAVA/uniq
done;

for tarf in $WHO; do
    ./get_unique_bugs.sh $tarf who $LAVA/who
done;
