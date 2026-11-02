"""Independently review a guarded MAX+plus II registered timing export."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import re
from pathlib import Path
import sys

from maxplus2_review_run import expected_registry_block, normalized


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def review(run: Path) -> dict:
    run = run.resolve(strict=True)
    record = json.loads((run / "logs" / "receipt.json").read_text(encoding="utf-8"))
    if record.get("operation") != "registered_timing":
        raise ValueError("This is not a registered Timing Analyzer run")
    top, clock = record.get("top"), record.get("clock")
    if not isinstance(top, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", top):
        raise ValueError("Invalid recorded top name")
    if not isinstance(clock, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", clock):
        raise ValueError("Invalid recorded clock name")
    if record.get("command", [])[1:] != ["-ta_reg", "-tao", "timing_export", top]:
        raise ValueError("Recorded top/mode differs from native command")
    messages = [json.loads(line) for line in
                (run / "logs" / "file_events.jsonl").read_text(encoding="utf-8").splitlines()]
    events = [m["payload"] for m in messages if m.get("type") == "send"]
    root = normalized(str(run)) + "\\"
    ini = normalized(str(run / "ini" / "maxplus2.ini"))
    outside_writes, external_reads = [], set()
    for event in events:
        path = event.get("path")
        mode = event.get("mode")
        if not path:
            continue
        target = normalized(path)
        if mode in {"write_capable", "delete", "file_information"} and event.get("reason") != "file_position_only":
            if not target.startswith(root):
                outside_writes.append(event)
            dest = event.get("destination")
            if dest is not None and not normalized(dest).startswith(root):
                outside_writes.append(event)
        if mode == "read_only" and not target.startswith(root) and event.get("result") == 0:
            external_reads.add(target)
    private_reads = sum(e.get("api", "").startswith("GetPrivateProfile")
                        and normalized(e.get("path") or "") == ini for e in events)
    private_writes = sum(e.get("api", "").startswith("WritePrivateProfile")
                         and e.get("result") == 1 and normalized(e.get("path") or "") == ini for e in events)
    snapshot_ok = all(digest(run / "snapshot" / i["file"]) == i["sha256"]
                      for i in record["inputs"])
    frozen_ok = (digest(run / "control" / "file_guard.js") == record["guard_sha256"]
                 and digest(run / "control" / "launcher.py") == record["launcher_sha256"])
    failures = [m for m in messages if m.get("type") == "error"]
    failures += [e for e in events if (e.get("denied") and not expected_registry_block(e))
                 or e.get("type") == "guard_error"]
    sequence_ok = [e.get("seq") for e in events] == list(range(1, len(events) + 1))
    ready = [e for e in events if e.get("type") == "guard_ready" and e.get("failed") is False]
    exited = [e for e in events if e.get("type") == "guard_exit" and e.get("failed") is False]
    exit_ok = (record.get("detach_reason") == "process-terminated"
               and record.get("detach_crash") is None and record.get("exit_code") == 0
               and not record.get("error") and not record.get("own_process_cleanup_error")
               and sum(e.get("type") == "guard_exit" for e in events) <= 1
               and all(e.get("status") == 0 and e.get("failed") is False
                       for e in events if e.get("type") == "guard_exit"))
    identity_ok = (normalized(record["run"]) == normalized(str(run))
                   and all(e.get("pid") == record["pid"] for e in events)
                   and len(ready) == 1
                   and normalized(ready[0].get("root", "")) == normalized(str(run))
                   and events[0] is ready[0] and exit_ok)
    outputs_ok = all((run / i["file"]).is_file()
                     and (run / i["file"]).stat().st_size == i["bytes"]
                     and digest(run / i["file"]) == i["sha256"] for i in record["outputs"])
    source_ok = all(digest(Path(i["source"])) == i["sha256"] for i in record["inputs"])
    snf_ok = (digest(run / "project" / f"{top}.snf") == record["source_snf_sha256"]
              and record.get("project_snf_unchanged") is True)
    acf_ok = digest(run / "project" / f"{top}.ACF") == record["analysis_acf_sha256"]
    stdout = (run / "logs" / "stdout.log").read_text(encoding="latin-1")
    tao_path = run / "project" / "timing_export.tao"
    tao = tao_path.read_text(encoding="latin-1") if tao_path.is_file() else ""
    native_ok = bool(record.get("timing_success") and record.get("exit_code") == 0
                     and record.get("status") == "TIMING_COMPLETE_REQUIRES_TRACE_REVIEW"
                     and "Timing analysis completed" in stdout
                     and "REGISTERED PERFORMANCE" in tao
                     and re.search(r"\b" + re.escape(clock) + r"\b", tao)
                     and outputs_ok and snf_ok and acf_ok)
    shared_ok = record["shared_ini_before_sha256"] == record["shared_ini_after_sha256"]
    private_ok = (record["private_ini_before_sha256"] != record["private_ini_after_sha256"]
                  and private_reads > 0 and private_writes > 0)
    isolation_ok = bool(sequence_ok and identity_ok and not failures and not outside_writes
                        and snapshot_ok and frozen_ok and source_ok and shared_ok and private_ok)
    result = {
        "run": str(run), "source_run": record["source_run"], "top": top, "clock": clock,
        "status": ("PASS_TIMING_AND_OBSERVED_ISOLATION" if native_ok and isolation_ok
                   else "FAIL_OR_INCOMPLETE_OR_PRESERVATION_REVIEW_REQUIRED"),
        "native_timing_success": native_ok, "isolation_trace_pass": isolation_ok,
        "events": len(events), "event_sequence_contiguous": sequence_ok,
        "trace_identity_and_order_valid": identity_ok, "native_exit_valid": exit_ok,
        "guard_ready": len(ready), "guard_exit": len(exited),
        "failures": failures, "outside_write_events": outside_writes,
        "private_ini_reads": private_reads, "private_ini_successful_writes": private_writes,
        "private_ini_changed": record["private_ini_before_sha256"] != record["private_ini_after_sha256"],
        "shared_ini_unchanged": shared_ok, "snapshot_unchanged": snapshot_ok,
        "source_unchanged": source_ok, "frozen_runner_guard_unchanged": frozen_ok,
        "outputs_match_receipt": outputs_ok, "project_snf_unchanged": snf_ok,
        "analysis_acf_unchanged": acf_ok,
        "api_counts": dict(Counter(e.get("api", e.get("type")) for e in events)),
        "external_successful_file_reads": sorted(external_reads),
        "trace_scope": "Observed native APIs after guard installation until Frida termination detach; pre-injection and final DLL teardown are outside this audit.",
    }
    (run / "logs" / "timing_review.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in
                      ("status", "events", "native_timing_success", "isolation_trace_pass",
                       "private_ini_reads", "private_ini_successful_writes", "shared_ini_unchanged")},
                     ensure_ascii=False))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    sys.exit(0 if review(args.run)["status"] == "PASS_TIMING_AND_OBSERVED_ISOLATION" else 1)
