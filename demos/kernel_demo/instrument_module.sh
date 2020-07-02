#!/bin/bash




if [ $# != 1 ]; then
  echo "Usage of the script : $0 [module-name-path]"
  exit
fi

if [[ !($1 =~ ".c") ]]; then
  echo "Wrong given file, "
  echo "Expecting a source module,"
  echo "File extension should be .c"
  echo "Usage of the script : $0 [module-name-path]"
  exit
fi

if [[ ! -e "./linux-5.5-rc6" ]]; then
  wget  "https://git.kernel.org/torvalds/t/linux-5.5-rc6.tar.gz"
  tar xf linux-5.5-rc6.tar.gz
  rm linux-5.5-rc6.tar.gz
  cd linux-5.5-rc6
  cp ../../../fuzzing/kernel/vms_files/linux-config .config
  make -j $(nproc)
  cd ..
fi

cd $(dirname $1)
make clean
make
cd ..



. ./../../retro/bin/activate

COMPILED=`echo $1 | sed -e "s/\.c/\.ko/"`
ls $COMPILED
ASM_FILE=`echo $COMPILED | sed -e "s/\.ko/_asan\.S/"`
INSTR_MODULE=`echo $COMPILED | sed -e "s/\.ko/_asan\.ko/"`

python -m rwtools.kasan.asantool $COMPILED $ASM_FILE

as -o $INSTR_MODULE $ASM_FILE

deactivate
