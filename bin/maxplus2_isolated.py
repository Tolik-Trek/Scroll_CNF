"""One fresh, guarded MAX+plus II compile. See INFO_MD/MAXPLUS2_ISOLATED_RUNS.md.

No shared build launcher, environment mutation, global INI write/restore or publish.
The Frida guard observes normal native APIs; it is not a hostile-code sandbox.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import uuid

REPO = Path(__file__).resolve().parents[1]
DEFAULT_EXE = Path(r"C:\tools\Progs\MaxPlus2\maxplus2\maxplus2.exe")
QUALIFIED_EXE = "535ca543f3de1c3255342583da51f83c4490b4d7327d9b5e316493c6b54b0338"
QUALIFIED_GE = "2c79a81912d04b84829f4a66ad57b7c359b0d7029aa1e05960d84531bd789747"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dump(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def plain(path: Path) -> None:
    """Refuse reparse-point ancestry; never put writable outputs behind a junction."""
    for item in (path, *path.parents):
        if item.exists() and item.lstat().st_file_attributes & 0x400:
            raise RuntimeError(f"Reparse point: {item}")


def stable_read(path: Path) -> bytes:
    first = path.read_bytes()
    if path.read_bytes() != first:
        raise RuntimeError(f"Input changed while copying: {path}")
    return first


def private_ini(raw: bytes, run: Path, exe: Path, top: str) -> bytes:
    updates = {
        "WORK_DIR": str(run / "work"),
        "DESIGN_NAME": str(run / "project" / top),
        "AUTO_RELOAD_LAST_PROJECT": "OFF",
        "USER_LIB": str(run / "project"),
        "HELP_FILE_DIR": str(exe.parent),
        "MEGA_LPM": ";".join(str(exe.parent / p) for p in (
            "max2lib/prim", "max2lib/mf", "max2lib/mega_lpm", "max2inc", "max2lib/edif")) + ";",
    }
    output, section, written = [], "", set()
    for line in raw.decode("latin-1").splitlines():
        if line.startswith("["):
            if section == "SYSTEM":
                output.extend(f"{k}={v}" for k, v in updates.items() if k not in written)
            section = line.strip("[]").upper()
        if section == "SYSTEM" and "=" in line:
            key = line.split("=", 1)[0].strip().upper()
            if re.fullmatch(r"PROJECT_NAME\d+", key):
                continue
            if key in updates:
                if key not in written:
                    output.append(f"{key}={updates[key]}")
                    written.add(key)
                continue
        output.append(line)
    if section == "SYSTEM":
        output.extend(f"{k}={v}" for k, v in updates.items() if k not in written)
    if "WORK_DIR" not in written:
        # Existing native INI is required to contain [SYSTEM] and WORK_DIR.
        raise RuntimeError("Unexpected INI structure")
    return ("\r\n".join(output) + "\r\n").encode("latin-1")


def prepare(args: argparse.Namespace) -> tuple[Path, dict]:
    if os.name != "nt":
        raise RuntimeError("Windows only")
    base = REPO / "temp_max_run" / "mp2_runs"
    plain(base)
    base.mkdir(parents=True, exist_ok=True)
    run_id = args.run_id or datetime.now(timezone.utc).strftime("run_%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:8]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", run_id):
        raise RuntimeError("Run ID must be a short ASCII directory name")
    run = base / run_id
    run.mkdir(exist_ok=False)
    for name in ("control", "ini", "snapshot", "project", "work", "tmp", "logs"):
        (run / name).mkdir()
    exe, source, acf = args.exe.resolve(), args.source.resolve(), args.acf.resolve()
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", args.top):
        raise RuntimeError("Invalid top name")
    exe_hash, ge_hash = sha(exe.read_bytes()), sha((exe.parent / "ge.dll").read_bytes())
    if exe_hash != QUALIFIED_EXE or ge_hash != QUALIFIED_GE:
        raise RuntimeError("Unqualified EXE/GE version: perform a new isolation review")
    paths = sorted(p for p in source.iterdir() if p.is_file() and p.suffix.lower() in {".tdf", ".inc", ".mif"})
    if not any(p.name.lower() == args.top.lower() + ".tdf" for p in paths):
        raise RuntimeError("Top TDF missing")
    inputs = [(p, p.name) for p in paths] + [(acf, args.top + ".ACF")]
    cached = [(p, name, stable_read(p)) for p, name in inputs]
    manifest = []
    for origin, name, data in cached:
        for target in (run / "snapshot" / name, run / "project" / name):
            target.write_bytes(data)
        manifest.append({"source": str(origin), "file": name, "sha256": sha(data)})
    # Whole-set check, not just a sequence of individually stable reads.
    for origin, _, data in cached:
        if origin.read_bytes() != data:
            raise RuntimeError(f"Source set changed: {origin}")
    shared_ini = exe.parent / "maxplus2.ini"
    raw_ini = stable_read(shared_ini)
    ini = private_ini(raw_ini, run, exe, args.top)
    (run / "ini" / "maxplus2.ini").write_bytes(ini)
    guard = stable_read(args.guard.resolve())
    (run / "control" / "file_guard.js").write_bytes(guard)
    (run / "control" / "launcher.py").write_bytes(Path(__file__).read_bytes())
    record = {
        "run": str(run), "created_utc": datetime.now(timezone.utc).isoformat(),
        "command": [str(exe), "-c", args.top], "cwd": str(run / "project"),
        "environment_overrides": {"MAXPLUS2_INI": str(run / "ini"), "TEMP": str(run / "tmp"), "TMP": str(run / "tmp")},
        "exe_sha256": exe_hash, "ge_sha256": ge_hash,
        "guard_sha256": sha(guard), "launcher_sha256": sha(Path(__file__).read_bytes()),
        "private_ini_before_sha256": sha(ini), "shared_ini_before_sha256": sha(raw_ini),
        "inputs": manifest,
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "status": "PREPARED_NOT_STARTED",
    }
    dump(run / "logs" / "prepare.json", record)
    return run, record


def execute(run: Path, record: dict) -> bool:
    import frida

    # Windows handle is kept until process exit, so PID reuse cannot change its exit code.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtResumeProcess.argtypes = [ctypes.c_void_p]
    ntdll.NtResumeProcess.restype = ctypes.c_long
    ready, detached = threading.Event(), threading.Event()
    failed = []
    lock = threading.Lock()
    device = frida.get_local_device()
    events = (run / "logs" / "file_events.jsonl").open("w", encoding="utf-8")
    stdout = (run / "logs" / "stdout.log").open("wb")
    stderr = (run / "logs" / "stderr.log").open("wb")
    pid = None
    handle = None
    session = None
    process = None
    resumed = False

    def message(message: dict, data: bytes | None) -> None:
        with lock:
            events.write(json.dumps(message, ensure_ascii=False) + "\n")
            events.flush()
        if message.get("type") == "error":
            failed.append(message)
        payload = message.get("payload", {})
        if isinstance(payload, dict):
            if payload.get("type") == "guard_ready" and payload.get("failed") is False:
                ready.set()
            expected_registry_block = (payload.get("api") == "NtSetValueKey"
                                       and payload.get("mode") == "registry_mutation"
                                       and payload.get("expected_block") is True
                                       and payload.get("native_executed") is False
                                       and payload.get("result") == -1073741790)
            if (payload.get("denied") and not expected_registry_block) or payload.get("type") == "guard_error":
                failed.append(payload)

    def session_detached(reason, crash=None):
        record["detach_reason"] = reason
        record["detach_crash"] = None if crash is None else str(crash)
        detached.set()

    try:
        env = dict(os.environ)
        env.update(record["environment_overrides"])
        # Popen restricts inherited handles to redirected stdio (close_fds=True).
        # Create suspended before any compiler entry; attach our guard, then resume.
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0
        process = subprocess.Popen(record["command"], env=env, cwd=record["cwd"],
                                   stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   close_fds=True, startupinfo=startup,
                                   creationflags=subprocess.CREATE_NO_WINDOW | 0x00000004)
        pid = process.pid
        record.update(pid=pid, status="SPAWNED_SUSPENDED", frida_version=frida.__version__)
        dump(run / "logs" / "process.json", record)
        handle = kernel.OpenProcess(0x00100000 | 0x1000 | 0x800, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        session = device.attach(pid)
        session.on("detached", session_detached)
        source = "globalThis.RUN_ROOT = " + json.dumps(str(run)) + ";\n" + (run / "control" / "file_guard.js").read_text(encoding="utf-8")
        script = session.create_script(source, runtime="qjs")
        script.on("message", message)
        script.load()
        if not ready.wait(15) or failed:
            raise RuntimeError("Guard not ready; refusing to resume")
        record["status"] = "RUNNING_GUARDED"
        dump(run / "logs" / "process.json", record)
        resumed = True
        status = ntdll.NtResumeProcess(handle)
        if status < 0:
            raise RuntimeError(f"NtResumeProcess failed: {status:#x}")
        print(f"RUNNING pid={pid} run={run}", flush=True)
        start = time.monotonic()
        while process.poll() is None:
            if failed:
                raise RuntimeError("Guard failure/denied side effect: stopping only our PID")
            if detached.is_set():
                # A detached instrumentation session is NOT a process-exit event.
                if process.poll() is None:
                    if record.get("detach_reason") != "process-terminated":
                        raise RuntimeError("Lost guard while own process is still alive")
                    # Frida's exit notification can precede the signalled process
                    # handle. Accept only the actual exit, within a bounded wait.
                    process.wait(timeout=5)
                break
            if time.monotonic() - start > 900:
                raise RuntimeError("Own process exceeded 900 seconds")
            detached.wait(0.1)
        code = process.wait()
        detached.wait(2)
        record.update(exit_code=code, status="NATIVE_FINISHED", duration_seconds=round(time.monotonic() - start, 3))
    except Exception as exc:
        record.update(status="FAILED", error=str(exc), resumed=resumed)
        if process is not None and process.poll() is None:
            try:
                # Popen.terminate uses its retained Windows handle, never a PID lookup.
                process.terminate()
                process.wait(timeout=10)
                detached.wait(5)
            except Exception as kill_error:
                record["own_process_cleanup_error"] = str(kill_error)
                record["status"] = "CLEANUP_REQUIRED_HOST_RETAINED"
                dump(run / "logs" / "cleanup_required.json", record)
                print(f"CLEANUP_REQUIRED own_pid={pid}; retaining guard and host until exit", flush=True)
                # Do not return and drop the instrumentation of a surviving process.
                while process.poll() is None:
                    time.sleep(1)
    finally:
        if session is not None and (process is None or process.poll() is not None):
            try:
                session.detach()
            except frida.InvalidOperationError:
                pass
        if handle:
            kernel.CloseHandle(handle)
        with lock:
            events.close()
            stdout.close()
            stderr.close()
    record["guard_failures"] = failed
    record["shared_ini_after_sha256"] = sha((Path(record["command"][0]).parent / "maxplus2.ini").read_bytes())
    record["private_ini_after_sha256"] = sha((run / "ini" / "maxplus2.ini").read_bytes())
    record["source_unchanged_after"] = all(sha(Path(i["source"]).read_bytes()) == i["sha256"] for i in record["inputs"])
    record["outputs"] = [{"file": str(p.relative_to(run)), "bytes": p.stat().st_size, "sha256": sha(p.read_bytes())}
                         for p in sorted((run / "project").iterdir()) if p.is_file()]
    # Native success is independently checked in stdout + RPT + actual bitstream.
    text = (run / "logs" / "stdout.log").read_text(encoding="latin-1")
    rpt = run / "project" / (record["command"][-1] + ".rpt")
    sof = run / "project" / (record["command"][-1] + ".sof")
    counts = re.findall(r"^\s*(\d+) errors\s*$", text, re.MULTILINE)
    rpt_text = rpt.read_text(encoding="latin-1") if rpt.is_file() else ""
    record["compile_success"] = (record.get("exit_code") == 0 and not record.get("error") and counts == ["0"]
                                 and "Project compilation was successful" in text
                                 and "EP1K30" in rpt_text and "DEVICE SUMMARY" in rpt_text
                                 and sof.is_file() and sof.stat().st_size > 0)
    record["status"] = "COMPILE_COMPLETE_REQUIRES_TRACE_REVIEW" if record["compile_success"] and not failed else "FAILED_REVIEW_REQUIRED"
    dump(run / "logs" / "receipt.json", record)
    print(json.dumps({k: record.get(k) for k in ("run", "pid", "status", "exit_code", "compile_success", "duration_seconds", "error")}, ensure_ascii=False), flush=True)
    return record["compile_success"] and not failed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=REPO / "altera" / "acex")
    parser.add_argument("--acf", type=Path, required=True)
    parser.add_argument("--top", default="SP2_ACEX")
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--guard", type=Path, default=Path(__file__).with_name("maxplus2_file_guard.js"))
    parser.add_argument("--run-id")
    args = parser.parse_args()
    run, record = prepare(args)
    print(f"PREPARED {run}", flush=True)
    return 0 if execute(run, record) else 1


if __name__ == "__main__":
    sys.exit(main())
