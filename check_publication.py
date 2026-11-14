"""Limited repository hygiene check. Does not replace a dedicated secret scanner."""
import re,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parent
try:
    paths=subprocess.check_output(['git','ls-files','-z'],cwd=root,stderr=subprocess.DEVNULL).decode().split('\0')
except (FileNotFoundError,subprocess.CalledProcessError):
    paths=[str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts]
issues=[]
patterns=[re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}'),re.compile(rb'github_pat_[A-Za-z0-9_]{40,}'),re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')]
for name in paths:
    if not name:continue
    path=root/name
    if not path.is_file():continue
    if path.name.startswith('.env') and path.name!='.env.example' or path.suffix.lower() in {'.pem','.key','.p12','.pfx','.har'} or any(x in path.parts for x in ['secrets','private-data','patient-data']):issues.append(name+': arquivo privado não permitido')
    if any(pattern.search(path.read_bytes()) for pattern in patterns):issues.append(name+': possível segredo; conteúdo omitido')
if issues:
    print('\n'.join(issues));sys.exit(1)
print('Higiene básica aprovada: nomes privados e padrões limitados de segredos. Não é auditoria completa de segredos ou histórico.')
