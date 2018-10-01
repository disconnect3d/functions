#!/bin/sh

if [ $# -eq 0 ]
  then
    echo "Usage: $0 <path to glibc>"
    echo "The script will fetch all debug/*_chk.c files from glibc and copy it to current working dir"
    echo "and launch a clang format over all files"
    exit 1;
fi

find $1/debug -name '*_chk.c' -exec cp {} . \;

cat *.c > fortified_functions.h
