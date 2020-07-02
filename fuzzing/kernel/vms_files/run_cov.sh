#!/bin/bash
# executed from the vms
set -euo pipefail

cp -r /mnt/input corpus

# Unmount the network share so that it doesn't interfere with coverage
umount /mnt/input

rm corpus/run_cov.sh
mv corpus/syz-executor .
mv corpus/syz-execprog .

# Replay all the test cases
mkdir cover
pushd corpus
	for f in *; do
		../syz-execprog -executor ../syz-executor -coverfile "../cover/$f" $f
	done
popd

# Copy the coverage data to the host
mkdir -p /mnt/output
mount -t 9p -o trans=virtio,version=9p2000.L output /mnt/output
cp cover/* /mnt/output
umount /mnt/output

poweroff
