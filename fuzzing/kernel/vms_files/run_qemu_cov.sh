#!/bin/bash

# this script run the syzskaller vms, no needs to start it by hands, it is ran from measure_coverage.sh (via run_cov.expect)

set -euo pipefail

qemu-system-x86_64 \
	-kernel "$1/arch/x86/boot/bzImage" \
	-append "console=ttyS0 rw debug root=/dev/sda debug earlyprintk=serial slub_debug=QUZ" \
	-hda "$2" \
	-snapshot \
	-virtfs "local,path=$3/input,security_model=none,mount_tag=input,readonly" \
	-virtfs "local,path=$3/coverage,security_model=none,mount_tag=output" \
	-enable-kvm \
	-nographic \
	-cpu host \
	-m 2G \
	-smp 2 \
	2>&1 | tee cover_log.txt
