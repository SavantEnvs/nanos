#!/usr/bin/env bash
#
# mayhem/test.sh — run nanos' own host test suite (built by mayhem/build.sh with upstream's
# normal flags) and a known-answer mkfs -> dump round trip of a TFS image.
#  * test/unit/*_test (upstream `make -C test/unit test`; network_test/udp_test are skipped
#    upstream too, they need live sockets): each must exit 0.
#  * tfs_roundtrip_*: build an image with tools/mkfs from a manifest, read it back with
#    tools/dump, and compare the printed metadata and the extracted file contents
#    against known values.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

passed=0; failed=0; skipped=0
ok()   { echo "PASS: $1"; passed=$((passed + 1)); }
fail() { echo "FAIL: $1"; failed=$((failed + 1)); }

UNIT="$SRC/output/test/unit/bin"
TOOLS="$SRC/output/tools/bin"
for b in "$TOOLS/mkfs" "$TOOLS/dump"; do
  [ -x "$b" ] || { echo "missing $b — run mayhem/build.sh first" >&2; emit_ctrf nanos-unit 0 1; exit 1; }
done

UNIT_TESTS="bitmap_test buffer_test closure_test id_heap_test memops_test objcache_test
  pageheap_test parser_test pqueue_test queue_test range_test rbtree_test
  table_test tuple_test vector_test"
# random_test pipes its output through the external `ent` entropy tool, absent from the image
echo "SKIP: random_test (needs the external 'ent' tool)"; skipped=$((skipped + 1))
for t in $UNIT_TESTS; do
  if [ ! -x "$UNIT/$t" ]; then fail "$t (not built)"; continue; fi
  if (cd "$UNIT" && "./$t" > "/tmp/nanos-$t.log" 2>&1); then ok "$t"; else fail "$t"; tail -5 "/tmp/nanos-$t.log"; fi
done

# --- known-answer TFS round trip -------------------------------------------------------
work="$(mktemp -d "${TMPDIR:-/tmp}/nanos-rt.XXXXXX")"
trap 'rm -rf "$work"' EXIT
cd "$work"
printf 'hello nanos\n' > a.txt
seq 1 2000 > big.txt
echo '(children:(a.txt:(contents:(host:a.txt)) dir:(children:(big:(contents:(host:big.txt)) link:(symlink:../a.txt))) empty:(children:())) program:/a.txt environment:(USER:fuzz))' \
  | "$TOOLS/mkfs" -l rtlabel img > mkfs.out 2>&1
if [ -s img ] && grep -q '^ program:/a.txt)$' mkfs.out; then ok tfs_roundtrip_mkfs; else fail tfs_roundtrip_mkfs; cat mkfs.out; fi

cat > dump.expected <<'EOF'
Label: rtlabel
metadata
(..:<visited>
 children:(a.txt:(extents:(0:(allocated:1
                              length:1
                              offset:N))
                  filelength:12)
           dir:(..:<visited>
                children:(big:(extents:(0:(allocated:18
                                           length:18
                                           offset:N))
                               filelength:8893)
                          link:(symlink:../a.txt)))
           empty:(..:<visited>
                  children:()))
 environment:(USER:fuzz)
 program:/a.txt)
EOF
"$TOOLS/dump" -d out img 2>&1 | grep -v '^UUID: ' | sed -E 's/offset:[0-9]+/offset:N/' > dump.out
if diff -u dump.expected dump.out; then ok tfs_roundtrip_metadata; else fail tfs_roundtrip_metadata; fi
if cmp -s out/a.txt a.txt && cmp -s out/dir/big big.txt && [ -d out/empty ]; then
  ok tfs_roundtrip_contents
else
  fail tfs_roundtrip_contents
fi
cd "$SRC"

emit_ctrf nanos-unit "$passed" "$failed" "$skipped"
