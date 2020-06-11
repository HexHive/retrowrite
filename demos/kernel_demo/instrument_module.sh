#!/bin/bash

if [ $# != 1 ]; then
  echo "Usage of the script : $0 [module-name-path]"
  exit
fi
if [[ !($1 =~ ".ko") ]]; then
  echo "Wrong given file, "
  echo "Expecting a compiled module,"
  echo "File extension should be .ko"
  echo "Usage of the script : $0 [module-name-path]"
  exit
fi

. ./../../retro/bin/activate

ASM_FILE=`echo $1 | sed -e "s/\.ko/_asan\.S/"`
INSTR_MODULE=`echo $1 | sed -e "s/\.ko/_asan\.ko/"`

python -m rwtools.kasan.asantool $1 $ASM_FILE

as -o $INSTR_MODULE $ASM_FILE

deactivate
