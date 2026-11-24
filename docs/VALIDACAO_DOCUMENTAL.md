# Validação Técnica e Documental da JYXIA (`v3.2.0` + Backend `0.2.0`)

## 1. Execução técnica e verificação em repositório (`24/11/2026`, `jyxia-develop`)

- **Frontend v3.2.0, PDF.js real, Laboratório, Benchmark e Regressão v2.x (`55` testes Node — `55/55` pass, `0` fail, `0` skipped + `11/11` Python legado):**
  - `28` testes unitários em [`tests/frontend/test_documental.mjs`](../tests/frontend/test_documental.mjs);
  - `6` testes reais com `frontend/public/vendor/pdf.min.mjs` em [`tests/frontend/test_documental_pdfjs.mjs`](../tests/frontend/test_documental_pdfjs.mjs);
  - `3` testes do laboratório localhost e benchmark sintético (`8/8` casos artificiais) em [`tests/frontend/test_lab_and_benchmark.mjs`](../tests/frontend/test_lab_and_benchmark.mjs);
  - `18` testes JS + `11` Python preservados isoladamente em `tests/legacy/`.
- **E2E em navegador real (`Microsoft Edge` / CDP) e pacote GitHub Pages:**
  - `node tests/e2e/test_documental_e2e.mjs` (`E2E_ALL_PASSED`): abertura de `index.html` e `demo.html` com `?v=3.2.0`, seções `#problema`/`#versao-atual`/`#demonstracao`/`#validacao`/`#acessibilidade`/`#materiais`, link externo `docs/VALIDACAO_DOCUMENTAL.md`, guia `<details class="demo-guide">`, `<noscript>`, `#document-name[tabindex="-1"]`, orientação `Motivo:`/`Próximo passo:` e botão `Abrir documento` com foco em `#document-name`, avaliação dos `4` eixos e exportação CSV, `0` erros de console/exceções/requisições/CSP fora do proxy esperado, e zero overflow horizontal com alvos `>= 44 px` em `320`, `390`, `768`, `1024` e `1280 px`;
  - `python tools/verify_pages_package.py`: `31/31` arquivos públicos válidos em `_site`, `0` vazamentos e E2E estático completo aprovado (`E2E_ALL_PASSED`).
- **Qualidade estática, higiene e esquema:** `tools/check_publication.py` aprovado, `tools/sync_backend_deps.py --check` aprovado, `ruff check` (`0` erros) e `alembic -c backend/alembic.ini heads` = `20261122_0009 (head)`.
- **Backend Institucional `0.2.0` (`tests/backend/` — `76` testes coletados no total):**
  - **Execução local (`24/11/2026`):** `73 passed, 3 skipped, 5 warnings` (SQLite/FastAPI locais aprovados; os `3` skips correspondem exclusivamente a `test_db_roles_and_rls.py` [2 casos PG 16 `jyxia_app`/`jyxia_worker`] e `test_keycloak_integration.py` [1 caso Keycloak `26.8.2` + TOTP]);
  - **Execução completa em CI ([`.github/workflows/security.yml`](../.github/workflows/security.yml)):** todos os `76` casos executados contra **`postgres:16-alpine`** e **`quay.io/keycloak/keycloak:26.8.2`** reais com falha automática caso haja qualquer `SKIPPED`.

## 2. Registro histórico da entrega pública `3.1.0` (`22/11/2026` em `main`)

- Execução dos `13` testes unitários então existentes para o núcleo documental `3.0`/`3.1.0`, verificação de sintaxe e higiene básica de publicação (`tools/check_publication.py`);
- Inspeção em navegador de `index.html` e `demo.html` com catálogo fechado, motivo/próximo passo/documento das pendências, atalho `Abrir documento` com foco no título, destaque visual da emissão na página e quarentena sem formulário para identidade divergente;
- Emulação de larguras `320 px`, `390 px` e `1280 px` sem rolagem horizontal (emulação de tela, **não** certificação WCAG nem teste exaustivo em dispositivos físicos).
- **Atualização da `3.2.0` e do backend `0.2.0`:** os cenários de divergência de procedimento e lateralidade — então apontados como candidatos futuros na `3.1.0` — passaram a contar com avaliação determinística na `v3.2.0` (`frontend/public/`) e no motor `3.3.4`/`3.3.4.1` (`backend/`), preservando as melhorias de acessibilidade, roteiro e orientação da `3.1.0` após a integração de `24/11/2026`. Isso **não** constitui evidência de desempenho clínico ou operacional em ambiente hospitalar.

## 3. Plano qualitativo e de avaliação empírica (revisão de `19/11/2026` — em planejamento)

As atividades abaixo são **propostas ainda não executadas** (`0` entrevistas realizadas, `0` testes com usuários finais, `0` pilotos hospitalares):

1. **Entrevistas iniciais em campo (`3–5` profissionais):** observar tarefas reais, pontos de retrabalho e ferramentas usadas em conferência documental e preparação de pedidos para convênios, comparando as duas hipóteses sem assumir previamente qual gera maior valor; escolher o setor piloto com base em acesso à equipe, frequência e custo observado do problema.
2. **Conjunto exploratório independente (~`30` casos sintéticos adicionais):** separar inteiramente os exemplos usados no desenvolvimento desse conjunto reservado, criando gabarito revisado por duas pessoas com registro explícito de divergências.
3. **Métricas e comparação com processo manual:** medir exatidão por campo, significado do dado, localização da evidência na página, recusas corretas, falsos vínculos, alertas indevidos, taxa de correção humana e tempo ponta a ponta frente ao fluxo manual equivalente (relatando denominadores, amostra e incerteza, sem converter amostra sem erro observado em garantia de risco zero).
4. **Acessibilidade e atendimento assistido:** testar o fluxo por teclado, celular e com pessoas com diferentes necessidades de acesso, considerando alternativa de atendimento assistido quando o envio digital não for viável.
5. **Requisitos operacionais e regulatórios pendentes antes de dados reais:** UI autenticada conectada ao BFF, fluxo completo de revisão humana institucional (Etapa `3.3.5+`), OCR auditado para scans, object storage com KMS, auditoria externa WORM, antivírus/CDR, recuperação de backup demonstrada, contratos LGPD (Controlador/Operadora, DPA, RIPD), enquadramento regulatório (ANVISA/CFM) e pentest independente autorizado.

> **Importante:** os `9` cenários da demonstração pública e os `8` casos do benchmark local são artefatos sintéticos construídos pelo desenvolvimento; **não** representam amostragem hospitalar nem validação clínica ou comercial.
