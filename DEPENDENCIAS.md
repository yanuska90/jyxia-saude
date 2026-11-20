# Dependências da demo documental (`3.2.0`)

PDF.js (`pdfjs-dist`) `6.5.438`, pacote oficial do registro npm:
`https://registry.npmjs.org/pdfjs-dist/-/pdfjs-dist-6.5.438.tgz`

Integridade SHA512 do pacote conferida na preparação:
`vg8Pw1x+AFKy4AMDvhuWl5cOYV8d698UoEANoFFhc79hqXDnZQqnOXoxw3HG907WHOg1JYOvLhP756boddFxpA==`

Arquivos usados: `build/pdf.min.mjs`, `build/pdf.worker.min.mjs` e `LICENSE`. Distribuídos localmente em `vendor/` (Apache 2.0) e utilizados tanto pela Modalidade A (`demo.html`) quanto pelo laboratório experimental local (`lab-local.html`) e pelo benchmark (`benchmark/`). Nenhuma dependência é carregada por CDN em execução.

Os testes JavaScript usam Node.js 22 ou superior sem `npm install` externo em runtime. Python 3 executa os servidores locais (`serve_documental.py` e `serve_lab.py`), higiene (`check_publication.py`), simulação Pages (`test_pages_package_local.py`) e testes do normalizador histórico (`test_integration.py`). O Docker documental (`Dockerfile.documental`) usa a imagem Python já fixada por digest no projeto. Fixar versão e integridade não elimina vulnerabilidades; revisar dependências antes de operação institucional.
