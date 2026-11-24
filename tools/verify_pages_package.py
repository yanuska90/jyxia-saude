"""Local simulation of GitHub Pages staging package from frontend/public/ and strict isolation verification."""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

WORK = Path(__file__).resolve().parent.parent
PAGES_YML = WORK / '.github' / 'workflows' / 'pages.yml'


def extract_staging_python(yml_text: str) -> str:
    m = re.search(r"python3 - <<'PY'\r?\n(.*?)\r?\n\s*PY", yml_text, re.DOTALL)
    if not m:
        raise RuntimeError('Could not find Python staging block in pages.yml')
    raw = m.group(1)
    lines = raw.splitlines()
    indent = min((len(ln) - len(ln.lstrip(' ')) for ln in lines if ln.strip()), default=0)
    return '\n'.join(ln[indent:] if len(ln) >= indent else ln for ln in lines)


def main():
    yml_text = PAGES_YML.read_text(encoding='utf-8')
    py_script = extract_staging_python(yml_text)

    with tempfile.TemporaryDirectory(prefix='jyxia-pages-pkg-') as tmp:
        tmp_path = Path(tmp)
        tmp_repo = tmp_path / 'repo'
        shutil.copytree(
            WORK,
            tmp_repo,
            ignore=shutil.ignore_patterns('.git', '__pycache__', '.pytest_cache', '.hypothesis'),
        )
        res = subprocess.run(
            ['python', '-c', py_script],
            cwd=str(tmp_repo),
            capture_output=True,
            text=True,
            encoding='utf-8',
        )
        print('STAGING_EXIT:', res.returncode)
        print('STAGING_STDOUT:', res.stdout.strip())
        if res.stderr.strip():
            print('STAGING_STDERR:', res.stderr.strip())
        if res.returncode != 0:
            raise SystemExit(res.returncode)

        site_dir = tmp_repo / '_site'
        staged_files = sorted(p.relative_to(site_dir).as_posix() for p in site_dir.rglob('*') if p.is_file())
        print('STAGED_COUNT:', len(staged_files))

        forbidden_prefixes = ('backend/', 'docs/', 'legacy/', 'tests/', 'tools/', 'lab/', 'benchmark/')
        forbidden_names = {
            'app.py',
            'integration.py',
            'demo-v2.html',
            'serve_documental.py',
            'serve_lab.py',
            'check_publication.py',
            'lab-local.html',
            'lab-local.mjs',
            'lab-extractor.mjs',
            'README.md',
            'CHANGELOG.md',
            '.env.example',
            'compose.institutional.yaml',
        }
        leaks = [f for f in staged_files if f.startswith(forbidden_prefixes) or Path(f).name in forbidden_names]
        assert not leaks, f'Forbidden or experimental files found in staged package: {leaks}'
        print(f'FORBIDDEN_CHECK_PASSED: 0 leaks ({len(staged_files)} public files validated)')

        e2e = subprocess.run(
            [
                'node',
                str(WORK / 'tests' / 'e2e' / 'test_documental_e2e.mjs'),
                '--static-dir',
                str(site_dir),
                '--subpath',
                'jyxia-saude',
                '--http-port',
                '8025',
                '--cdp-port',
                '9235',
            ],
            cwd=str(WORK),
            capture_output=True,
            text=True,
            encoding='utf-8',
        )
        print('PACKAGE_E2E_EXIT:', e2e.returncode)
        print('PACKAGE_E2E_OUT:\n' + e2e.stdout)
        if e2e.stderr.strip():
            print('PACKAGE_E2E_ERR:\n' + e2e.stderr)
        if e2e.returncode != 0:
            raise SystemExit(e2e.returncode)


if __name__ == '__main__':
    main()
