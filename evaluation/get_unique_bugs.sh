#!/bin/bash

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <tar-file> <out-pfx> <cmd>..."
    exit
fi

CMD="${*:3}"

TARF=$1
TDIR=$(mktemp -d)

xbase=${TARF##*/}
xpref=${xbase%.*}
xpref=${xpref%.*}


tmpf=$(mktemp)

LOGF="$2/$xpref.log"
echo "" > $LOGF

tar -xf $TARF -C $TDIR

shopt -s nullglob
shopt -s globstar

INPUTS=$TDIR/**/crashes/id:*
for inp in "$TDIR"/**/crashes/id:*; do
    echo "[*] Running $inp"
    { $CMD $inp >> $tmpf 2> /dev/null ;}
    echo "" >> $tmpf
done

echo "[*] Reducing ..."
cat $tmpf | sed -n -e 's/^.*Successfully triggered bug \([0-9]\+\), .*$/\1/p' | sort | uniq > $LOGF

rm -rf $TDIR
rm $tmpf
