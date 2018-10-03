#!/bin/sh

if [ $# -eq 0 ]
  then
    echo "Usage: $0 <path to glibc>"
    echo "The script will fetch all debug/*_chk.c files from glibc and copy it to current working dir"
    echo "and launch a clang format over all files"
    exit 1;
fi

find $1/debug -name '*_chk.c' -exec cp {} . \;

declare -a problematic_imports=(
    '#include "../libio/libioP.h"'
    '#include <libioP.h>'
    '#include "libioP.h"'
    '#include "../libio/strfile.h"'
    '#include <memcopy.h>'
    '#include <setjmp.h>'
    '#include <setjmp/longjmp.c>'
    '#include <setjmpP.h>'
    '#include <support/test-driver.c>'
)

# Helper function to test if array contains given element
# copied from https://stackoverflow.com/questions/3685970/check-if-a-bash-array-contains-a-value
contains_element () {
  local e match="$1"
  shift
  for e; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}


touch fortified_functions.h
for cfile in $(ls *.c); do
    while read -r line
    do
        contains_element "$line" "${problematic_imports[@]}"
        if [ $? -eq 1 ]; then
            echo "$line" >> fortified_functions
        fi
    done < "$cfile"
done
# Concatenate all files BUT remove all problematic imports!
cat *.c > fortified_functions.h


