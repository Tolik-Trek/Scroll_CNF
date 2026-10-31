"""Read-only trace acceptance; writes only an audit report in the selected run."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


def expected_registry_block(event):
    return (event.get("api") == "NtSetValueKey" and event.get("mode") == "registry_mutation"
            and event.get("expected_block") is True and event.get("native_executed") is False
            and event.get("denied") is True and event.get("result") == -1073741790)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized(path):
    path = path.replace("/", "\\")
    if path.startswith(("\\??\\", "\\\\?\\")):
        path = path[4:]
    return path.casefold()


def review(run):
    run = run.resolve()
    record = json.loads((run / "logs/receipt.json").read_text(encoding="utf-8"))
    messages = [json.loads(line) for line in (run / "logs/file_events.jsonl").read_text(encoding="utf-8").splitlines()]
    events = [m["payload"] for m in messages if m.get("type") == "send"]
    root = normalized(str(run)) + "\\"
    ini = normalized(str(run / "ini/maxplus2.ini"))
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
            destination = event.get("destination")
            if destination is not None and not normalized(destination).startswith(root):
                outside_writes.append(event)
        if mode == "read_only" and not target.startswith(root) and event.get("result") == 0:
            external_reads.add(target)
    private_reads = sum(e.get("api", "").startswith("GetPrivateProfile") and normalized(e.get("path") or "") == ini for e in events)
    private_writes = sum(e.get("api", "").startswith("WritePrivateProfile") and e.get("result") == 1 and normalized(e.get("path") or "") == ini for e in events)
    snapshot_ok = all(digest(run / "snapshot" / i["file"]) == i["sha256"] for i in record["inputs"])
    frozen_ok = digest(run / "control/file_guard.js") == record["guard_sha256"] and digest(run / "control/launcher.py") == record["launcher_sha256"]
    blocked_registry = [e for e in events if expected_registry_block(e)]
    failures = [m for m in messages if m.get("type") == "error"] + [e for e in events if (e.get("denied") and not expected_registry_block(e)) or e.get("type") == "guard_error"]
    sequence_ok = [e.get("seq") for e in events] == list(range(1, len(events) + 1))
    ready = [e for e in events if e.get("type") == "guard_ready" and e.get("failed") is False]
    exited = [e for e in events if e.get("type") == "guard_exit" and e.get("failed") is False]
    exit_monitor_ok = (record.get("detach_reason") == "process-terminated"
                       and record.get("detach_crash") is None and record.get("exit_code") == 0
                       and not record.get("error")
                       and sum(e.get("type") == "guard_exit" for e in events) <= 1
                       and all(e.get("status") == 0 and e.get("failed") is False
                               for e in events if e.get("type") == "guard_exit"))
    identity_ok = (normalized(record["run"]) == normalized(str(run))
                   and all(e.get("pid") == record["pid"] for e in events)
                   and len(ready) == 1 and normalized(ready[0].get("root", "")) == normalized(str(run))
                   and events[0] is ready[0] and exit_monitor_ok)
    outputs_ok = all((run / i["file"]).is_file() and (run / i["file"]).stat().st_size == i["bytes"]
                     and digest(run / i["file"]) == i["sha256"] for i in record["outputs"])
    top = record["command"][-1]
    stdout = (run / "logs/stdout.log").read_text(encoding="latin-1")
    rpt = run / "project" / (top + ".rpt")
    sof = run / "project" / (top + ".sof")
    native_ok = (record.get("exit_code") == 0 and not record.get("error") and not record.get("own_process_cleanup_error")
                 and record.get("status") == "COMPILE_COMPLETE_REQUIRES_TRACE_REVIEW"
                 and re.findall(r"^\s*(\d+) errors\s*$", stdout, re.MULTILINE) == ["0"]
                 and "Project compilation was successful" in stdout and outputs_ok
                 and rpt.is_file() and "DEVICE SUMMARY" in rpt.read_text(encoding="latin-1")
                 and sof.is_file() and sof.stat().st_size > 0)
    report = {
        "run": str(run), "pid": record["pid"], "native_compile_success": record["compile_success"],
        "events": len(events), "event_sequence_contiguous": sequence_ok,
        "trace_identity_and_order_valid": identity_ok,
        "native_exit_and_frida_termination_agree": exit_monitor_ok,
        "trace_scope": "Observed native APIs after guard installation until Frida termination detach; pre-injection and final DLL teardown are not a complete OS audit.",
        "trace_complete_through_os_exit": False,
        "shutdown_tail_not_observed": True,
        "outputs_match_receipt": outputs_ok, "native_evidence_rechecked": native_ok,
        "expected_registry_writes_blocked": len(blocked_registry),
        "guard_ready": len(ready), "guard_exit": len(exited), "failures": failures,
        "outside_write_events": outside_writes,
        "private_ini_reads": private_reads, "private_ini_successful_writes": private_writes,
        "private_ini_changed": record["private_ini_before_sha256"] != record["private_ini_after_sha256"],
        "shared_ini_unchanged": record["shared_ini_before_sha256"] == record["shared_ini_after_sha256"],
        "snapshot_unchanged": snapshot_ok, "frozen_runner_guard_unchanged": frozen_ok,
        "source_unchanged_after": record["source_unchanged_after"],
        "api_counts": dict(Counter(e.get("api", e.get("type")) for e in events)),
        "external_successful_file_reads": sorted(external_reads),
    }
    report["isolation_trace_pass"] = bool(sequence_ok and identity_ok and not failures and not outside_writes and private_reads and private_writes and snapshot_ok and frozen_ok)
    preserved = report["shared_ini_unchanged"] and report["source_unchanged_after"]
    report["status"] = "PASS_COMPILE_AND_OBSERVED_ISOLATION" if report["isolation_trace_pass"] and native_ok and record["compile_success"] and preserved else "FAIL_OR_INCOMPLETE_OR_PRESERVATION_REVIEW_REQUIRED"
    (run / "logs/isolation_review.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("status", "events", "private_ini_reads", "private_ini_successful_writes", "shared_ini_unchanged", "snapshot_unchanged")}, ensure_ascii=False))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    raise SystemExit(0 if review(args.run)["status"] == "PASS_COMPILE_AND_OBSERVED_ISOLATION" else 1)
