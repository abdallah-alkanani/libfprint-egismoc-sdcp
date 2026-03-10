#!/bin/bash

library1=$1
library2=$2

function cleanup_results() {
    grep -F -w '.text' | cut -s -f2 | awk '{print $(NF)}'
}

function dump_exported_symbols() {
    objdump -TC "$1" | cleanup_results
}

function in_array() {
  local target=$1
  shift

  local i;
  for i in "$@"; do
    if [[ "$i" == "$target" ]]; then
        return 0
    fi
  done

  return 1
}

function is_fatal() {
    if [[ "$1" == "fp_"* ]] || [[ "$1" == "fpi_"* ]]; then
        return 0
    fi
    return 1
}

lib1_exported=($(dump_exported_symbols "$library1"))
lib2_exported=($(dump_exported_symbols "$library2"))

valid=true

for f in ${lib1_exported[*]}; do
    if in_array "$f" ${lib2_exported[*]}; then
        echo -n "$f function exported in both $library1 and $library2"
        if is_fatal "$f"; then
            echo " (fatal)"
            valid=false
        else
            echo
        fi
    fi
done

[[ "$valid" == true ]] && exit 0
