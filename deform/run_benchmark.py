#!/usr/bin/env python3
"""Benchmark: unpacking success rate on 20 deformed UPX samples.

Runs two UPX binaries (pristine baseline vs tolerant/repair-enhanced build)
against every sample in deform/samples, then writes:
  deform/benchmark/comparison.json
  deform/benchmark/comparison.csv
  deform/benchmark/comparison.md

Success requires exit code 0 AND a byte-identical unpacked file (sha256 from
manifest.json). For every failure the script records the *specific* reason
printed by the tool, not just "failed".

Environment overrides:
  BASELINE_UPX   path to pristine upx   (default deform/upx-baseline)
  ENHANCED_UPX   path to repaired upx   (default build-enhanced/upx)
"""
from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFORM = ROOT / "deform"
SAMPLES = DEFORM / "samples"
WORK = DEFORM / "benchmark"
BASELINE = Path(os.environ.get("BASELINE_UPX", DEFORM / "upx-baseline"))
ENHANCED = Path(os.environ.get("ENHANCED_UPX", ROOT / "build-enhanced" / "upx"))
TIMEOUT = 40


def run_upx(binary: Path, sample: Path, out_file: Path) -> dict:
    if out_file.exists():
        out_file.unlink()
    cmd = [str(binary), "-d", "-f", "-o", str(out_file), str(sample)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
        rc = p.returncode
        output = (p.stdout or "") + (p.stderr or "")
        timed_out = False
    except subprocess.TimeoutExpired as e:
        rc = -9
        output = (e.stdout or "") + (e.stderr or "") + "\nTIMEOUT after %ss" % TIMEOUT
        timed_out = True
    return {"rc": rc, "output": output, "timed_out": timed_out}


def extract_reason(output: str) -> str:
    """Pick the most specific diagnostic line from UPX output."""
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    specific: list[str] = []
    for ln in lines:
        if "diagnosis [" in ln:
            msg = ln.split("diagnosis ", 1)[1]
            specific.append(msg)
        elif "SPECIFIC FAILURE" in ln:
            specific.append(ln.strip())
        elif re.search(r"(CantUnpack|NotPacked|Checksum|CompressedData|Internal).*Exception:", ln):
            msg = ln.split("Exception:", 1)[1].strip()
            if msg:
                specific.append(msg)
        elif "header corrupted" in ln or "checksum error" in ln:
            specific.append(ln.split("upx:", 2)[-1].strip())
    if specific:
        # de-duplicate while preserving order
        seen: set[str] = set()
        uniq = []
        for s in specific:
            if s not in seen:
                seen.add(s)
                uniq.append(s)
        return " || ".join(uniq[-3:])
    for ln in reversed(lines):
        if "Unpacked" in ln or ln.startswith("upx:"):
            continue
        return ln[:300]
    return "unknown error (no diagnostic line emitted)"


def sha256(path: Path) -> str | None:
    import hashlib

    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def diagnose(binary: Path, sample: Path) -> str:
    try:
        p = subprocess.run(
            [str(binary), "--diagnose", str(sample)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
        return ((p.stdout or "") + (p.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return "(diagnose timed out)"


def main() -> int:
    manifest_path = SAMPLES / "manifest.json"
    if not manifest_path.exists():
        print("samples missing; running deform/make_samples.py ...")
        subprocess.run([sys.executable, str(DEFORM / "make_samples.py")], check=True)
    manifest = json.loads(manifest_path.read_text())
    expected = manifest["expected_unpacked_sha256"]

    if not BASELINE.exists():
        print(f"WARNING: baseline binary not found: {BASELINE}", file=sys.stderr)
    if not ENHANCED.exists():
        print(f"ERROR: enhanced binary not found: {ENHANCED}", file=sys.stderr)
        return 2

    rows = []
    for s in manifest["samples"]:
        sample = ROOT / s["file"]
        row = {"id": s["id"], "mutation": s["mutation"], "category": s["category"],
               "description": s["description"]}
        for label, binary, outdir in (
            ("baseline", BASELINE, WORK / "baseline"),
            ("enhanced", ENHANCED, WORK / "enhanced"),
        ):
            outdir.mkdir(parents=True, exist_ok=True)
            out_file = outdir / f"{s['id']}_{s['mutation']}.exe"
            if not binary.exists():
                row[label] = {"success": False, "reason": "binary missing"}
                continue
            r = run_upx(binary, sample, out_file)
            got_sha = sha256(out_file)
            correct = r["rc"] == 0 and got_sha == expected
            reason = "" if correct else extract_reason(r["output"])
            row[label] = {
                "success": correct,
                "rc": r["rc"],
                "sha256": got_sha,
                "reason": reason,
            }
            (outdir / f"{s['id']}_{s['mutation']}.log").write_text(r["output"])
        if not row["enhanced"]["success"]:
            row["enhanced"]["diagnose"] = diagnose(ENHANCED, sample)
        rows.append(row)
        b = "OK " if row["baseline"]["success"] else "FAIL"
        e = "OK " if row["enhanced"]["success"] else "FAIL"
        print(f"[{s['id']}] baseline={b} enhanced={e}  {s['mutation']}")

    b_ok = sum(r["baseline"]["success"] for r in rows)
    e_ok = sum(r["enhanced"]["success"] for r in rows)
    total = len(rows)

    result = {
        "total": total,
        "expected_unpacked_sha256": expected,
        "baseline_binary": str(BASELINE),
        "enhanced_binary": str(ENHANCED),
        "baseline_success": b_ok,
        "enhanced_success": e_ok,
        "baseline_rate": f"{b_ok}/{total} ({100.0*b_ok/total:.0f}%)",
        "enhanced_rate": f"{e_ok}/{total} ({100.0*e_ok/total:.0f}%)",
        "rows": rows,
    }
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "comparison.json").write_text(json.dumps(result, indent=2) + "\n")

    with (WORK / "comparison.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "mutation", "category", "baseline", "enhanced",
                    "baseline_reason", "enhanced_reason"])
        for r in rows:
            w.writerow([
                r["id"], r["mutation"], r["category"],
                "success" if r["baseline"]["success"] else "fail",
                "success" if r["enhanced"]["success"] else "fail",
                r["baseline"].get("reason", ""),
                r["enhanced"].get("reason", ""),
            ])

    md = []
    md.append("# 20 deformed UPX samples - unpack success comparison\n")
    md.append(f"- Baseline UPX: `{BASELINE}`")
    md.append(f"- Enhanced UPX: `{ENHANCED}`")
    md.append(f"- Correctness criterion: exit code 0 and sha256 identical to the known-good"
              f" unpacked file (`{expected[:16]}...`)\n")
    md.append(f"**Success rate: baseline {b_ok}/{total}"
              f" ({100.0*b_ok/total:.0f}%) -> enhanced {e_ok}/{total}"
              f" ({100.0*e_ok/total:.0f}%)**\n")
    md.append("| # | deformation | class | baseline | enhanced | enhanced specific reason on failure |")
    md.append("|---|-------------|-------|:--------:|:--------:|---------------------------------------|")
    for r in rows:
        bs = "✅" if r["baseline"]["success"] else "❌"
        es = "✅" if r["enhanced"]["success"] else "❌"
        reason = r["enhanced"].get("reason", "")
        reason = reason.replace("|", "\\|")
        if len(reason) > 160:
            reason = reason[:157] + "..."
        md.append(f"| {r['id']} | `{r['mutation']}` | {r['category']} | {bs} | {es} | {reason} |")
    md.append("")
    md.append("## Baseline failure reasons (generic messages)\n")
    for r in rows:
        if not r["baseline"]["success"]:
            md.append(f"- **{r['id']} {r['mutation']}**: {r['baseline'].get('reason','')[:240]}")
    md.append("")
    md.append("## Enhanced failure detail\n")
    for r in rows:
        if not r["enhanced"]["success"]:
            md.append(f"### {r['id']} {r['mutation']}")
            md.append("```")
            md.append(r["enhanced"].get("reason", "(no reason)"))
            diag = r["enhanced"].get("diagnose", "")
            if diag:
                md.append("")
                md.append(diag[-1800:])
            md.append("```")
    (WORK / "comparison.md").write_text("\n".join(md) + "\n")

    print(f"\nBaseline: {b_ok}/{total}   Enhanced: {e_ok}/{total}")
    print(f"Report: {WORK / 'comparison.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
