# Dependências da demo documental

PDF.js (pdfjs-dist) 6.5.438, pacote oficial do registro npm:
https://registry.npmjs.org/pdfjs-dist/-/pdfjs-dist-6.5.438.tgz

Integridade SHA512 do pacote conferida na preparação:
vg8Pw1x+AFKy4AMDvhuWl5cOYV8d698UoEANoFFhc79hqXDnZQqnOXoxw3HG907WHOg1JYOvLhP756boddFxpA==

Arquivos usados: build/pdf.min.mjs, build/pdf.worker.min.mjs e LICENSE. Distribuídos localmente em vendor/. Licença Apache 2.0 preservada. Fonte do projeto: https://github.com/mozilla/pdf.js . Nenhuma dependência é carregada por CDN na demo.

Os testes JavaScript usam Node.js 22 ou superior, sem npm install. Python 3 executa o servidor estático e testes do normalizador histórico. O Docker documental usa a imagem Python já fixada por digest no projeto. Fixar versão e integridade não elimina vulnerabilidades; revisar avisos e dependências antes de operação institucional.
