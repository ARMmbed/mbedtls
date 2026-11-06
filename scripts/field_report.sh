#!/bin/sh

# Usage example:
# scripts/field_report.sh -t armv6m-unknown-eabi -I build-m0plus/include -I ~/Packages/ARMCompiler6.6/include >fields-baremetal-m0plus.csv

set -eu

script_dir=$(dirname -- "$0")
lib_dir=.
if [ ! -d "$lib_dir/library" ] && [ -d "${lib_dir%/*}/library" ]; then
  lib_dir=${lib_dir%/*}
fi

"$script_dir/field_report.py" \
  -DMBEDTLS_ALLOW_PRIVATE_ACCESS \
  "$@" \
  -I "$lib_dir/include" \
  "$lib_dir/include"/*/*.h "$lib_dir/library"/*.[hc]
