# Arquitetura JYXIA — Demonstração v3.2.0 e Fundação Institucional 0.1.0

Consulte também:
- [`ESTRUTURA_DO_PROJETO.md`](ESTRUTURA_DO_PROJETO.md) — mapa definitivo de pastas do repositório e política para `legacy/v2/`.
- [`ARQUITETURA_INSTITUCIONAL.md`](ARQUITETURA_INSTITUCIONAL.md) — detalhamento completo do `backend/` institucional (`0.1.0`).

## 1. Modalidade A — Demonstração pública seletiva (`31` arquivos em `.github/workflows/pages.yml`)

Fluxo estático estritamente client-side entregue por lista explícita a partir de [`frontend/public/`](../frontend/public/) -> interface responsiva (`index.html`, `demo.html`, `documental.css`) -> controlador DOM e integração PDF.js (`documental-ui.mjs`) -> núcleo determinístico (`documental-core.mjs`). O Mozilla PDF.js `6.5.438` e seu worker rodam localmente a partir de `frontend/public/vendor/`.

- **Catálogo SHA-256 fechado:** `allowedFixture()` valida tamanho (`1 B` a `512 KB`), MIME (`application/pdf`, `image/png`, `text/csv`, `application/json`) e hash SHA-256 contra os `18` fixtures de `frontend/public/documental-manifest.json` antes de qualquer leitura de PDF (`caseId` inicia sempre `null`).
- **Leitura textual e coordenadas dinâmicas:** `extractPdfLines(doc, pdfjs.Util.transform, 5)` transforma texto com a matriz da página e projeta caixas normalizadas `[minX, minY, w, h]` em páginas únicas, múltiplas (`<= 5`) ou rotacionadas (`90°`).
- **Extração determinística (`extractFields()`):** extrai `type`, `subfamily`, `patient`, `birthDate`, `identifier`, `issueDate`, `procedure`, `procedureCode`, `procedureCodeSystem` (`Sistema:`, `SistemaCodigo:`, `TabelaCodigo:` ou prefixo explícito reconhecido), `procedureCodeSource`, `laterality` (`normalizeLaterality()`), `origin` e `syntheticMarkerCue` (busca textual literal `'MARCA FICTICIA'`, `authenticatesSignature: false`). Imagens PNG e PDFs sem texto recebem `readable = false`, `identity = 'unreadable'` e `detectionKind = 'none_no_text_layer'` (jamais afirmando assinatura ausente por análise visual).
- **Motor dos quatro eixos (`consistencyAxes()`):** utiliza taxonomia explícita de 6 estados (`ok`, `conflito`, `abstencao`, `nao_avaliado`, `nao_aplicavel`, `pendente`). `evaluateProcedureAxis()` distingue correspondência exata, normalização superficial, correspondência por código com sistema identificado, código sem sistema identificado (`"Código encontrado, sistema de codificação não identificado."`), divergência textual/código e ambiguidade. `evaluateLateralityAxis()` nunca converte campo ausente em `nao_aplicavel`. `_temporalityReport()` explicita regra ilustrativa aplicada somente a `laudo` e classifica `atualizado`, `antigo`, `fora_janela`, `prazo_desconhecido`, `data_invalida`, `data_futura` e `validade_nao_definida`.
- **Cinco estados gerais (`readinessState()`):** `pendente`, `bloqueado`, `abstencao`, `conferida_com_escopo_limitado`, `conferida`, sempre com `administrativeOnly: true` e `clinicalApproval: false`. `review()` registra `humanVisualObservation` (`unknown`/`observed`/`not_observed`) de modo separado do marcador textual.
- **Rastreabilidade em cinco níveis e exportações:** `export()` (`schema: 'jyxia.documental-session.v2'`) usa `structuredClone()` e separa histórico em memória, cadeia SHA-256 local em sessão (`verifyEventsReport()`), exportações JSON/CSV (`19` colunas com `csvSafeCell()`), persistência institucional em desenvolvimento no `backend/` e auditoria conectada por OIDC ainda pendente.

## 2. Modalidade B — Laboratório experimental local isolado (fora do GitHub Pages)

Os arquivos [`frontend/lab/lab-local.html`](../frontend/lab/lab-local.html), [`frontend/lab/lab-local.mjs`](../frontend/lab/lab-local.mjs), [`frontend/lab/lab-extractor.mjs`](../frontend/lab/lab-extractor.mjs) e [`tools/serve_lab.py`](../tools/serve_lab.py) operam exclusivamente em loopback (`127.0.0.1` / `localhost`), retornando HTTP `404` em [`tools/serve_documental.py`](../tools/serve_documental.py) e ausentes da allowlist pública do GitHub Pages:

- `assertLocalhostEnvironment()` bloqueia execução fora de `localhost`;
- `hasPdfMagicBytes()` verifica `%PDF-` binário até `512 KB` e `10` páginas; `extractLabPdfLines()` agrupa colunas e corridas espaciais usando vetor geométrico invariante à rotação (`0°/90°/180°/270°`);
- `extractWithExplicitAliases()` utiliza tabela fechada de aliases em `FIELD_ALIASES`, abstém-se em ambiguidade ou ausência de rótulo e lista rótulos desconhecidos em `unrecognizedLabels[]`, sem gravação em disco ou logs de conteúdo.

## 3. Benchmark sintético separado e arquivo histórico `legacy/v2/`

- **Benchmark (`tests/benchmark/`):** gerador determinístico e executor (`run_benchmark.mjs`) sobre `8` PDFs sintéticos em `development`, `regression` e `reserved_evaluation`. Excluído do Pages.
- **Legado isolado (`legacy/v2/` + `tests/legacy/`):** artefatos `v2.x` (`demo-v2.html`, `app.py`, `integration.py` e suítes `18` JS + `11` Python) preservados apenas para regressão histórica, sem conexão com `frontend/public/` nem reutilização em `backend/`.

## 4. Modalidade C — Fundação institucional (`backend/` `0.1.0`) e próximos passos

Na Etapa 3.0 foi implementada a fundação inicial em [`backend/`](../backend/) (detalhes em [`ARQUITETURA_INSTITUCIONAL.md`](ARQUITETURA_INSTITUCIONAL.md)): servidor FastAPI com `/api/v1/health/live` e `/api/v1/health/ready`, `11` modelos relacionais multi-tenant com FKs compostas por organização, primeira migração Alembic pronta para PostgreSQL, trilha `AuditEvent` append-only em banco, armazenamento sintético controlado (`LocalControlledSyntheticStorage`) e contratos preparatórios de OIDC/MFA/RBAC e pipeline.

Permanecem **não implementados** e condicionados à descoberta em campo e pareceres regulatórios: autenticação OIDC/MFA ativa, rotas HTTP autenticadas de upload/revisão, OCR auditado para scans, armazenamento S3 cifrado e conectores hospitalares/FHIR ativos.
