#!/bin/bash

# This script needs to be run in the "retrowrite" source folder

set -ue

[[ -d ~/bins ]] || { echo "~/bins folder not found, exiting..." && exit 1 ; }

mkdir -p bins_rw

for binary_full in ~/bins/*; do
	binary=$(basename $binary_full)
	[[ $binary =~ "ldecod" ]] && continue
	[[ $binary =~ "diffwrf" ]] && continue

	if [[ $1 == "nothing" ]]; then
		echo "Not touching ${binary}..."
		cp ${binary_full} bins_rw/

	elif [[ $1 == "asan" ]]; then
		if [[ ! $(hostname) =~ "cloudlab" ]]; then
			[[ $binary =~ "gcc" ]] && continue # run gcc only on cloudlab with asan
		fi

		echo "rewriting ${binary}.s ..."
		./retrowrite --asan $binary_full bins_rw/prova_${binary}.s

		echo "assembling ${binary}.s ..."
		./retrowrite -a bins_rw/prova_${binary}.s bins_rw/${binary}_rw && echo Done

	elif [[ $1 == "counter" ]]; then
		echo "rewriting ${binary}.s ..."
		./retrowrite -m counter $binary_full bins_rw/prova_${binary}.s

		echo "assembling ${binary}.s ..."
		./retrowrite -a bins_rw/prova_${binary}.s bins_rw/${binary}_rw && echo Done

	elif [[ $1 == "asan_trampoline" ]]; then
		echo "rewriting ${binary}.s ..."
		./retrowrite -m asan_trampoline $binary_full bins_rw/prova_${binary}.s

		echo "assembling ${binary}.s ..."
		./retrowrite -a bins_rw/prova_${binary}.s bins_rw/${binary}_rw && echo Done

	else
		echo "rewriting ${binary}.s ..."
		./retrowrite $binary_full bins_rw/prova_${binary}.s

		echo "assembling ${binary}.s ..."
		./retrowrite -a bins_rw/prova_${binary}.s bins_rw/${binary}_rw && echo Done
	fi
done;
