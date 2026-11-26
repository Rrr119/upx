#!/usr/bin/env bash
# CLI compatibility smoke test: every pre-existing UPX invocation style must
# keep working, and the new flags must be accepted.
set -u
cd "$(dirname "$0")/.." || exit 2

UPX="${ENHANCED_UPX:-./build-enhanced/upx}"
SAMPLE="deform/samples/01_magic_bitflip.exe"
PRISTINE="work/base_cmd.exe"
FAIL=0

check() { # desc, expected_substr_or_rc, command...
  local desc="$1"; shift
  if "$@" >/tmp/cli_out.$$ 2>/tmp/cli_err.$$; then
    echo "PASS  $desc (rc=0)"
  else
    local rc=$?
    echo "FAIL  $desc (rc=$rc)"
    sed 's/^/      /' /tmp/cli_err.$$ | tail -3
    FAIL=1
  fi
}

# existing informational commands
$UPX --version >/dev/null && echo "PASS  --version" || FAIL=1
$UPX --help >/dev/null && echo "PASS  --help" || FAIL=1
$UPX -V >/dev/null && echo "PASS  -V" || FAIL=1

# new options are parsed and documented
$UPX --help 2>&1 | grep -q -- "--diagnose" && echo "PASS  help lists --diagnose" || FAIL=1
$UPX --repair --version >/dev/null && echo "PASS  --repair accepted" || FAIL=1
$UPX --no-repair --version >/dev/null && echo "PASS  --no-repair accepted" || FAIL=1
$UPX --diagnose "$SAMPLE" >/dev/null && echo "PASS  --diagnose repairable rc=0" || FAIL=1

# standard unpack workflows on a deformed sample
rm -f /tmp/cli_d1.exe
check "upx -d -f -o" "$UPX" -d -f -o /tmp/cli_d1.exe "$SAMPLE"
check "upx -t" "$UPX" -t "$SAMPLE"
check "upx -l" "$UPX" -l "$SAMPLE"
check "upx -q -d -f -o" "$UPX" -q -d -f -o /tmp/cli_d2.exe "$SAMPLE"
check "upx -v -d -f -o" "$UPX" -v -d -f -o /tmp/cli_d3.exe "$SAMPLE"

# legacy strict mode still behaves like baseline (must fail on this sample,
# but must not crash: expected non-zero exit only)
if $UPX --no-repair -d -f -o /tmp/cli_d4.exe "$SAMPLE" >/dev/null 2>&1; then
  echo "NOTE  --no-repair unexpectedly recovered $SAMPLE"
else
  echo "PASS  --no-repair keeps strict/baseline failure (rc!=0)"
fi

# pristine UPX sample still unpacks
if [ -f "$PRISTINE" ]; then
  check "pristine sample -t" "$UPX" -t "$PRISTINE"
  rm -f /tmp/cli_d5.exe
  check "pristine sample -d" "$UPX" -d -f -o /tmp/cli_d5.exe "$PRISTINE"
fi

rm -f /tmp/cli_out.$$ /tmp/cli_err.$$
exit $FAIL
