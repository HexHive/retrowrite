#!/bin/bash

# this script will download all debian packages that can fit in under 50 mbs
# it will create repo/$pkg folders and for each file downloaded that is an executable
# it will create a .log file that contains the output of the "--help" command

#set -x

apt install file bc -y

apt list --installed > installed
[[ $(grep -c "resolvconf" installed) -eq 1 ]] && timeout -k 10 10 apt remove resolvconf -y 

function clone_package () {
	pkg="$1"
	[[ $(grep -c "$pkg" installed) -ge 1 ]] && echo -e "package $pkg already installed" && return
	[[ $(grep "$pkg" too_big -c) -ge 1 ]] && echo package $pkg too large && return
	[[ $(grep "$pkg" conflicts -c) -ge 1 ]] && echo package $pkg in conflicts && return

	rm -rf /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock /var/cache/debconf/config.dat /var/cache/debconf
	cat /dev/urandom | timeout -k 10 10 dpkg --configure -a # reset dpkg if it gets stuck


	#apt remove  $pkg  -y
	output=$(echo 'n' | timeout -k 5 5 apt-get install --assume-no  -- "$pkg" | grep "After this" )
	size=$(echo $output | awk '{ print $4 }')
	kb_mb=$(echo $output | awk '{ print $5 }')
	echo -n $size $kb_mb
	[[ ! -z $size ]] && [[ "$kb_mb" == "MB" ]] && (( $( echo "$size > 50.0" | bc -l) )) && \
		echo -e "package $pkg too large" && echo "$pkg" >> too_big && return

	echo -e "\x1b[33;1;5mCloning started for $pkg\x1b[0m"
	DEBIAN_FRONTEND=noninteractive timeout -k 20 20 apt install --no-install-recommends -y -- "$pkg" < <(echo 'y') | tee output.txt

	[[ $(grep "unmet dependencies" output.txt -c) -ge 1 ]] && echo "$pkg" >> conflicts && return


	for i in  $(dpkg -L $pkg | \
	  xargs -I {} file {} | \
	  grep "executable, ARM aarch64" | \
	  awk -F ":" '{print $1}'); do
	  mkdir -p "repo/$pkg"
	  cp "$i" "./repo/$pkg"
	  #"$i" --help > $(echo -n -- "$i" | awk -F "/" '{print $NF".log"}');
	  timeout 0.5 "$i" --help &> repo/$pkg/$(basename "$i").log;
	###
	# Rewrite them with ARMW
	###
	# Do the diff with previous log
	done
}



pack="./ListPack"

while IFS=$'\n' read -r pkg
do
  clone_package $pkg
done < "$pack"


