"""Limited repository hygiene check. Does not replace a dedicated secret scanner."""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
try:
    paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT, stderr=subprocess.DEVNULL).decode().split('\0')
except (FileNotFoundError, subprocess.CalledProcessError):
    paths = [str(p.relative_to(ROOT)) for p in ROOT.rglob('*') if p.is_file() and '__pycache__' not in p.parts]

issues = []
patterns = [
    re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}'),
    re.compile(rb'github_pat_[A-Za-z0-9_]{40,}'),
    re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(rb'postgresql(?:\+psycopg)?://[^:\s]+:[^@\s]+@(?!127\.0\.0\.1|localhost|postgres)[^\s]+'),
]
forbidden_parts = {'secrets', 'private-data', 'patient-data', 'JYXIA_LOCAL_WORK'}
forbidden_suffixes = {'.pem', '.key', '.p12', '.pfx', '.har', '.db', '.sqlite', '.sqlite3'}

for name in paths:
    if not name:
        continue
    path = ROOT / name
    if not path.is_file():
        continue
    if (
        (path.name.startswith('.env') and path.name != '.env.example')
        or path.suffix.lower() in forbidden_suffixes
        or any(x in path.parts for x in forbidden_parts)
    ):
        issues.append(name + ': arquivo privado ou banco local não permitido no Git')
    raw = path.read_bytes()
    if any(pattern.search(raw) for pattern in patterns):
        issues.append(name + ': possível segredo; conteúdo omitido')

if issues:
    print('\n'.join(issues))
    sys.exit(1)
print('Higiene básica aprovada: nomes privados e padrões limitados de segredos. Não é auditoria completa de segredos ou histórico.')
