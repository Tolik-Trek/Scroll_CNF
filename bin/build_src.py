"""Сборка src/SCROLL с обязательной проверкой изоляции, результат в Build/SCSRC."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

from maxplus2_isolated import plain

ROOT = Path(__file__).resolve().parents[1]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', help='Необязательное уникальное имя изолированного запуска')
    args = parser.parse_args()
    run_id = args.run_id or datetime.now(timezone.utc).strftime('src_%Y%m%dT%H%M%SZ_') + uuid.uuid4().hex[:8]
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,60}', run_id):
        raise ValueError('Недопустимое имя запуска')
    run = ROOT / 'temp_max_run/mp2_runs' / run_id
    if run.exists():
        raise FileExistsError(f'Каталог запуска уже существует: {run}')
    source = ROOT / 'src'
    for name, declaration in [('SCROLL.TDF', rb'(?im)^\s*SUBDESIGN\s+SCROLL\b'),
                              ('SCROLL.ACF', rb'(?im)^\s*CHIP\s+SCROLL\b')]:
        if not re.search(declaration, (source / name).read_bytes()):
            raise ValueError(f'{name}: имя верхнего проекта должно быть SCROLL')

    print('=== SCROLL / src / EP1K30QC208-3 ===', flush=True)
    print(f'Исходники: {source}', flush=True)
    compile_result = subprocess.run([
        sys.executable, '-X', 'utf8', '-B', str(ROOT / 'bin/maxplus2_isolated.py'),
        '--source', str(source), '--acf', str(source / 'SCROLL.ACF'),
        '--top', 'SCROLL', '--run-id', run_id,
    ], cwd=ROOT)
    if not (run / 'logs/receipt.json').is_file():
        raise RuntimeError(f'Сборка не создала receipt.json: {run}')
    review_result = subprocess.run([
        sys.executable, '-X', 'utf8', '-B', str(ROOT / 'bin/maxplus2_review_run.py'), str(run)
    ], cwd=ROOT)
    review = json.loads((run / 'logs/isolation_review.json').read_bytes())
    if (compile_result.returncode or review_result.returncode
            or review['status'] != 'PASS_COMPILE_AND_OBSERVED_ISOLATION'):
        raise RuntimeError(f'Компиляция или проверка изоляции не пройдена: {run}')

    project = run / 'project'
    ttf = project / 'SCROLL.ttf'
    # Используем штатный конвертер и независимо сверяем каждый полученный байт.
    acx = project / 'SCROLL.ACX'
    conversion = subprocess.run(
        [str(ROOT / 'bin/transttf.exe'), ttf.name, acx.name], cwd=project,
        capture_output=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
    if conversion.returncode or not acx.is_file():
        raise RuntimeError('TransTTF не создал SCROLL.ACX')
    fields = [x.strip() for x in ttf.read_text(encoding='ascii').split(',') if x.strip()]
    if not fields or any(not re.fullmatch(r'\d+', x) for x in fields):
        raise ValueError('Неожиданный формат TTF')
    expected = bytes(int(x) for x in fields)
    if len(expected) != 59215 or acx.read_bytes() != expected:
        raise ValueError('ACX не соответствует полному TTF для EP1K30')

    report = (project / 'SCROLL.rpt').read_text(encoding='latin-1')
    device = re.search(r'(?m)^\s*SCROLL\s+EP1K30QC208-3\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s*%\s+(\d+)\s+\d+\s*%', report, re.I)
    frequencies = re.findall(r'(?m)^\s*fmax\s+.+?\s+[\d.]+\s+MHz\s+([\d.]+)\s+MHz', report, re.I)
    if device is None or not frequencies:
        raise ValueError('В native RPT отсутствуют ресурсы или fmax')
    memory_bits, cells = int(device[4]), int(device[5])
    fmax = min(float(x) for x in frequencies)

    output = ROOT / 'Build/SCSRC'
    plain(output)
    output.mkdir(parents=True, exist_ok=True)
    files = {}
    for origin, name in [(acx, 'SCROLL.ACX'), (ttf, 'SCROLL.TTF'),
                         (project / 'SCROLL.sof', 'SCROLL.SOF'),
                         (project / 'SCROLL.rpt', 'SCROLL.RPT')]:
        target = output / name
        plain(target)
        data = origin.read_bytes()
        # Предыдущий отдельный пакет SCAUTH31 и Build/scroll не затрагиваются.
        temporary = output / (name + '.' + run_id + '.tmp')
        plain(temporary)
        with temporary.open('xb') as stream:
            stream.write(data)
        os.replace(temporary, target)
        files[name] = {'bytes': len(data), 'sha256': digest(data)}
    summary = {
        'status': 'PASS_COMPILE_AND_OBSERVED_ISOLATION', 'run': str(run),
        'source': str(source), 'top': 'SCROLL', 'LC': cells,
        'memory_bits': memory_bits, 'limiting_fmax_MHz': fmax,
        'files': files, 'inputs': json.loads((run / 'logs/prepare.json').read_bytes())['inputs'],
        'scope': 'Native compile/fit and observed isolation; not board or functional simulation acceptance.',
    }
    manifest = output / 'BUILD.JSN'
    plain(manifest)
    temporary = output / ('BUILD.JSN.' + run_id + '.tmp')
    plain(temporary)
    with temporary.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    os.replace(temporary, manifest)
    print(f'LC: {cells}; RAM: {memory_bits} бит; fmax: {fmax:.2f} MHz', flush=True)
    print(f'BUILD OK: {output / "SCROLL.ACX"}', flush=True)
    print(f'Протокол: {manifest}', flush=True)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f'BUILD FAILED: {exc}', file=sys.stderr, flush=True)
        raise SystemExit(1)
