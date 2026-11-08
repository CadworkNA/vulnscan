#!/bin/sh
# Run every fuzz target for FUZZ_SECONDS each (default 60), starting from generated seeds. Corpora and crashing
# inputs are written below the current directory (corpus/<target>, crashes/<target>); exits non-zero on a crash.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
secs=${FUZZ_SECONDS:-60}
for target in binary paths; do
  mkdir -p "corpus/$target" "crashes/$target"
  python "$here/seeds.py" "$target" "corpus/$target"
  python "$here/fuzz_$target.py" -max_total_time="$secs" -timeout=10 -print_final_stats=1 \
    -artifact_prefix="crashes/$target/" "corpus/$target"
done
