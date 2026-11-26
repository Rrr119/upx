# Deformed UPX shell recovery - acceptance kit

This directory contains the 20-sample acceptance benchmark for tolerant
recognition/unpacking of deformed ("反脱壳"/tampered) UPX shells and damaged
headers.

## Result

| UPX build | unpack success on 20 deformed samples |
|-----------|----------------------------------------:|
| pristine baseline (`deform/upx-baseline`) | **0 / 20 (0%)** |
| this fork (`build-enhanced/upx`) | **19 / 20 (95%)** |

Success is strict: exit code 0 **and** the output is byte-identical
(sha256 `236166bb...`) to the known-good unpacked file.

The single deliberate failure (`20_payload_destroyed`) is a negative control:
a compressed-stream byte was destroyed while the header stayed authentic, so
the stored Adler-32 genuinely does not match. The enhanced binary reports the
**specific** cause instead of a generic `checksum error`:

```
compressed-stream checksum mismatch: header c_adler=09716e6c but computed
cf516f0d over 77414 compressed bytes -- the compressed data is corrupted or
truncated (not just a damaged header)
```

Per-sample comparison: `benchmark/comparison.md`, `comparison.csv`,
`comparison.json`.

## The 20 deformations

* `01-05` UPX magic (`UPX!`) bit-flipped / lower-cased / zeroed / replaced /
  XOR-encoded
* `06-07` header checksum byte zeroed / set to `0xFF`
* `08-14` single header field byte corrupted with the authentic stale
  checksum (level, version, format, method, u/c Adler, u_len)
* `15`    two Adler bytes damaged (multi-byte header corruption)
* `16-19` PE section `UPX0/UPX1/.rsrc` names renamed/zeroed, incl. a combined
  section-name + magic deformation
* `20`    compressed payload byte destroyed (unrecoverable negative control)

## Reproduce

```bash
# 1. build the enhanced binary
cmake -S . -B build-enhanced -DCMAKE_BUILD_TYPE=Release \
      -DUPX_CONFIG_DISABLE_WERROR=ON -DUPX_CONFIG_DISABLE_SANITIZE=ON
cmake --build build-enhanced -j"$(nproc)"

# 2. (re)generate the 20 samples from work/base_cmd.exe
python3 deform/make_samples.py

# 3. run the comparison (uses deform/upx-baseline as pristine reference)
python3 deform/run_benchmark.py

# optional: point at other binaries
BASELINE_UPX=/path/to/pristine/upx ENHANCED_UPX=/path/to/new/upx \
  python3 deform/run_benchmark.py

# CLI compatibility smoke test
bash deform/check_cli.sh
```

`deform/upx-baseline` is a prebuilt pristine binary from this exact source
tree before the recovery changes.

## New CLI surface (fully additive)

* `upx --diagnose <file...>` - print UPX-header candidates, Hamming distance to
  `UPX!`, stored/computed header checksum, checksum-equation reconstruction
  options, payload Adler result and a specific verdict. Exit codes:
  `0` recoverable, `1` specific unrecoverable damage, `2` no reliable UPX
  signature, `4` unreadable file.
* `--repair` (default) / `--no-repair` - enable or restore strict legacy
  behaviour. Plain `upx -d -f file.exe` benefits from recovery with no new
  flags.

Standard `-d -t -l -q -v -f -o ...` usage is unchanged; all 58 built-in
doctest cases (3932 assertions) and the CTest CLI tests pass.

## How the recovery works

Implementation: `src/repair.h`, `src/repair.cpp`; integration in
`src/packhead.cpp`, `src/packer.cpp`, `src/pefile.cpp`, `src/work.cpp`,
`src/main.cpp`, `src/options.*`, `src/help.cpp`.

1. **Fuzzy identification** - candidate scan combines Hamming distance to
   `UPX!`, version/format/method validity, length sanity and the additive
   header checksum. A strict gate rejects zero-padding/random coincidences.
2. **Checksum-guided byte reconstruction** - the UPX header checksum is
   `sum(p[4..size-2]) mod 251`; with one corrupted byte its value has at most
   two byte solutions, which reconstruct the original field.
3. **Conservative hypotheses + oracles** - untouched / checksum-rebuilt
   headers are preferred; all checksum-valid hypotheses are retained. The
   compressed/output Adler-32 values and the actual decompressed length then
   select the correct hypothesis, so even ambiguous entropy fields resolve.
4. **PE layout independence** - detection no longer requires section 0 to be
   named `UPX*`; canonical slots and a chunked whole-file scan are used, and
   the payload seek uses the absolute recovered header offset.
5. **Specific diagnostics** - a per-file trail of stable reason codes
   (`magic-fuzzy`, `byte-reconstructed`, `checksum-rebuilt`, `alt-cadler`,
   `cadler-unverified`, ...) is printed on recovery and, with concrete
   expected/actual checksums and lengths, on failure.

The same generic header recovery also byte-identically unpacked ad-hoc
PE64 and ELF magic/checksum/format deformations during development.
