"""Run registered Timing Analyzer on a sealed fit in a fresh guarded workspace.

The source fit is never executed in place.  This reuses the qualified native
process guard from maxplus2_isolated.py, but has its own TA success contract.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid

import maxplus2_isolated as base


def prepare(source_run: Path, path_count: int, run_id: str | None,
            top: str = "SP2_ACEX", clock: str = "TG42") -> tuple[Path, dict]:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", top):
        raise ValueError("Invalid top name")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", clock):
        raise ValueError("Invalid expected clock name")
    if path_count < 1 or path_count > 10000:
        raise ValueError("LIST_PATH_COUNT must be between 1 and 10000")
    root = base.REPO / "temp_max_run" / "mp2_runs"
    base.plain(root)
    source_run = source_run.resolve(strict=True)
    base.plain(source_run)
    if source_run.parent != root.resolve():
        raise ValueError("Source must be one complete isolated run under temp_max_run/mp2_runs")
    source_review = json.loads((source_run / "logs" / "isolation_review.json").read_text(encoding="utf-8"))
    if source_review.get("status") != "PASS_COMPILE_AND_OBSERVED_ISOLATION":
        raise ValueError("Source compile has no accepted isolation review")
    source_project = source_run / "project"
    for name in (f"{top}.ACF", f"{top}.snf", f"{top}.rpt", f"{top}.sof"):
        if not (source_project / name).is_file():
            raise ValueError(f"Missing sealed fit artifact: {name}")
    exe = base.DEFAULT_EXE.resolve(strict=True)
    exe_hash = base.sha(exe.read_bytes())
    ge_hash = base.sha((exe.parent / "ge.dll").read_bytes())
    if exe_hash != base.QUALIFIED_EXE or ge_hash != base.QUALIFIED_GE:
        raise ValueError("Unqualified native MAX+plus II version")
    guard_path = Path(base.__file__).with_name("maxplus2_file_guard.js")
    guard = base.stable_read(guard_path)
    launcher = base.stable_read(Path(__file__))
    files = sorted(p for p in source_project.iterdir() if p.is_file())
    frozen = [(p, base.stable_read(p)) for p in files]
    if any(p.is_symlink() for p, _ in frozen):
        raise ValueError("Symlink in source fit")
    if run_id is None:
        run_id = datetime.now(timezone.utc).strftime("ta_%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:8]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", run_id):
        raise ValueError("Invalid run ID")
    run = root / run_id
    run.mkdir(exist_ok=False)
    for name in ("control", "ini", "snapshot", "project", "work", "tmp", "logs"):
        (run / name).mkdir()
    manifest = []
    for origin, data in frozen:
        (run / "snapshot" / origin.name).write_bytes(data)
        (run / "project" / origin.name).write_bytes(data)
        manifest.append({"source": str(origin), "file": origin.name, "sha256": base.sha(data)})
    for origin, data in frozen:
        if origin.read_bytes() != data:
            raise RuntimeError(f"Source fit changed during copy: {origin}")
    acf = run / "project" / f"{top}.ACF"
    acf_data, count = re.subn(rb"(?m)^(\s*LIST_PATH_COUNT\s*=\s*)\d+(;)",
                               lambda m: m[1] + str(path_count).encode("ascii") + m[2],
                               acf.read_bytes())
    if count != 1:
        raise ValueError("Expected exactly one LIST_PATH_COUNT assignment")
    acf.write_bytes(acf_data)
    shared_ini = exe.parent / "maxplus2.ini"
    raw_ini = base.stable_read(shared_ini)
    private = base.private_ini(raw_ini, run, exe, top)
    (run / "ini" / "maxplus2.ini").write_bytes(private)
    (run / "control" / "file_guard.js").write_bytes(guard)
    (run / "control" / "launcher.py").write_bytes(launcher)
    record = {
        "operation": "registered_timing", "top": top, "clock": clock, "run": str(run),
        "source_run": str(source_run), "created_utc": datetime.now(timezone.utc).isoformat(),
        "command": [str(exe), "-ta_reg", "-tao", "timing_export", top],
        "cwd": str(run / "project"),
        "environment_overrides": {"MAXPLUS2_INI": str(run / "ini"),
                                  "TEMP": str(run / "tmp"), "TMP": str(run / "tmp")},
        "exe_sha256": exe_hash, "ge_sha256": ge_hash,
        "guard_sha256": base.sha(guard), "launcher_sha256": base.sha(launcher),
        "private_ini_before_sha256": base.sha(private),
        "shared_ini_before_sha256": base.sha(raw_ini),
        "source_snf_sha256": base.sha((source_project / f"{top}.snf").read_bytes()),
        "analysis_acf_sha256": base.sha(acf_data), "path_count": path_count,
        "inputs": manifest,
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"],
                                        cwd=base.REPO, text=True).strip(),
        "status": "PREPARED_NOT_STARTED",
    }
    base.dump(run / "logs" / "prepare.json", record)
    return run, record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-run", required=True, type=Path)
    parser.add_argument("--paths", type=int, default=10000)
    parser.add_argument("--run-id")
    parser.add_argument("--top", default="SP2_ACEX")
    parser.add_argument("--clock", default="TG42")
    args = parser.parse_args()
    run, record = prepare(args.from_run, args.paths, args.run_id, args.top, args.clock)
    print(f"PREPARED {run}", flush=True)
    base.execute(run, record)  # Its compile-specific verdict is superseded below.
    record = json.loads((run / "logs" / "receipt.json").read_text(encoding="utf-8"))
    tao = run / "project" / "timing_export.tao"
    stdout = (run / "logs" / "stdout.log").read_text(encoding="latin-1")
    text = tao.read_text(encoding="latin-1") if tao.is_file() else ""
    snf_ok = base.sha((run / "project" / f"{record['top']}.snf").read_bytes()) == record["source_snf_sha256"]
    record["timing_success"] = bool(
        record.get("exit_code") == 0 and not record.get("error")
        and not record.get("guard_failures") and not record.get("own_process_cleanup_error")
        and "Timing analysis completed" in stdout
        and "REGISTERED PERFORMANCE" in text
        and re.search(r"\b" + re.escape(record["clock"]) + r"\b", text) and snf_ok)
    record["project_snf_unchanged"] = snf_ok
    record["status"] = ("TIMING_COMPLETE_REQUIRES_TRACE_REVIEW" if record["timing_success"]
                        else "TIMING_FAILED_REVIEW_REQUIRED")
    base.dump(run / "logs" / "receipt.json", record)
    print(json.dumps({k: record.get(k) for k in ("run", "pid", "status", "exit_code", "timing_success")}), flush=True)
    return 0 if record["timing_success"] else 1


if __name__ == "__main__":
    sys.exit(main())
