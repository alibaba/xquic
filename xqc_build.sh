#!/bin/sh
# Copyright (c) 2022, Alibaba Group Holding Limited

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

echo "xqc_build.sh is deprecated; use xqc_mobile_build.sh for mobile builds" >&2
exec "${script_dir}/xqc_mobile_build.sh" "$@"
