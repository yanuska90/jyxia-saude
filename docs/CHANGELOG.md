# Registro de decisões e versões

## 3.2.0 — 20 de novembro de 2026 (Etapa 2.3 — Precisão semântica, motor conservador, separação de modalidades e acessibilidade)

Evolução técnica na branch `jyxia-develop` preservando integralmente DE-01 a DE-05 (sem OCR, LLM/VLM, decisão clínica, persistência em servidor ou invenção de dicionários médicos):

- **Marcador sintético vs. assinatura (Problema 1):** substituído `signatureCue` por `syntheticMarkerCue` (`literal_synthetic_text_marker`, `authenticatesSignature: false`), separando detecção textual literal de `'MARCA FICTICIA'` da ação humana `humanVisualObservation` (`unknown`/`observed`/`not_observed`) e removendo expressões que indicavam análise visual ou autenticação em PNGs, JSON (`jyxia.documental-session.v2`) e CSV (`19` colunas com `marcador_textual_sintetico` e `observacao_visual_humana`).
- **Estados explícitos dos eixos e readiness (Problema 2):** taxonomia de `6` estados nos quatro eixos (`ok`, `conflito`, `abstencao`, `nao_avaliado`, `nao_aplicavel`, `pendente`) — impedindo conversão automática de campo ausente em `nao_aplicavel` — e `5` estados gerais (`pendente`, `bloqueado`, `abstencao`, `conferida_com_escopo_limitado`, `conferida`). **Cenário 1** histórico agora conclui em `abstencao` (e não falso `conferida`), e adicionado **Cenário 9 (`quatro_eixos`)** com `4` novos PDFs sintéticos (`solicitacao-completa.pdf`, `laudo-completo.pdf`, `avaliacao-completa.pdf`, `termo-completo.pdf`, elevando `documental-manifest.json` e `fixtures-jyxia.zip` para `18` fixtures e `.github/workflows/pages.yml` para `31` arquivos públicos).
- **Comparação conservadora de procedimentos e sistemas de código (Problema 3):** diferencia correspondência exata, normalização superficial, correspondência por código com sistema identificado (`procedureCodeSystem` e `procedureCodeSource`), código sem sistema (`"Código encontrado, sistema de codificação não identificado."`), divergência textual/código e múltiplos candidatos — nunca equiparando sinônimos clínicos não validados (`"Cirurgia de catarata"` × `"Facoemulsificação"`).
- **Modalidade A × Modalidade B × Benchmark separado (Problemas 4, 5 e 10):** mantida Modalidade A estritamente na whitelist SHA-256 pública; implementado laboratório localhost isolado (`serve_lab.py`, `lab-local.html`, `lab-local.mjs`, `lab-extractor.mjs`, HTTP `404` na demo pública e excluído do GitHub Pages) com aliases explícitos normalizados invariantes à rotação (`0°/90°/180°/270°`); criado benchmark sintético separado (`benchmark/`, `8` casos em `development`, `regression` e `reserved_evaluation` com métricas por campo e cenário, sem alegar holdout real).
- **Temporalidade, rastreabilidade, quarentena e acessibilidade (Problemas 6–9, 11–12):** regra temporal caracterizada como ilustrativa apenas para `laudo`, classificação explícita (`antigo`, `atualizado`, `fora_janela`, `prazo_desconhecido`, `data_invalida`, `data_futura`, `validade_nao_definida`), bloqueio explícito de `resolve()` em texto livre sobre conflitos de procedimento/lateralidade, verificação de remoção/reordenação em `verifyEventsReport()`, diferenciação de `5` níveis em `traceabilityLevels` (`export()`), `aria-invalid` + `role="alert"` em erros de formulário, e alvos interativos `>= 44×44 px` validados nos viewports `320px`, `390px`, `768px`, `1024px` e `1280px` (`37` testes v3/lab/benchmark + `29` v2 legados + E2E real + Pages local `31/31`).

## 3.1.0 (Sincronização Documental) — 20 de novembro de 2026

Auditoria estratégica integral (`JYXIA_DOCUMENTACAO_REVISAO_2026_11_20`) e sincronização dos documentos do repositório mantendo o código executável inalterado em relação à referência `f1ae841c5dc10941a6c915ac57ddb50187f695a5`.

## 3.1.0 — 19 de novembro de 2026 (Etapas 2 e 2.1)

Evolução na branch `jyxia-develop`: quatro eixos determinísticos em `consistencyAxes()`, `normalizeLaterality()` sem falso positivo de `"ao"`, delta UTC, CSV hardening, cenário `8 · Lateralidade divergente`, `14` fixtures, `27` arquivos Pages e `32` testes v3 + `29` v2.x.

## 3.0.0 — 14 de novembro de 2026

Decisão por Clinical Document Intelligence administrativo em procedimentos eletivos, preservando `demo-v2.html` e testes históricos sem migração destrutiva (`Projeto_JYXIA_Inteligencia_Documental_v3.docx`).
