# Registro de decisões e versões

## 3.1.0 (Sincronização Documental) — 20 de novembro de 2026

Auditoria estratégica integral (`JYXIA_DOCUMENTACAO_REVISAO_2026_11_20`) e sincronização dos documentos do repositório mantendo o código executável inalterado em relação à referência `f1ae841c5dc10941a6c915ac57ddb50187f695a5`:

- **Restauração e correção documental:** restaurados e atualizados `README.md`, `ARQUITETURA.md`, `VALIDACAO_DOCUMENTAL.md` e `CHANGELOG.md` (encontrados com `0 bytes` na inspeção de `f1ae841` após falha acidental de script CRLF na commit final da Etapa 2.1), bem como `SEGURANCA.md`, `DADOS_FICTICIOS.md`, `INTEGRACOES.md`, `Submissao_e_video_JYXIA.txt` e `Projeto_JYXIA_Inteligencia_Documental_v3.docx`.
- **Reconciliação técnica fiel ao código:** documentação passa a refletir extração real por PDF.js com coordenadas calculadas dinamicamente, `10` campos prefixados (`incl. Codigo:`) + marca literal `MARCA FICTICIA`, `4` eixos determinísticos, `8` cenários, `14` fixtures e `32` testes v3 (`26` unitários + `6` PDF.js reais) + `29` regressão v2.x + E2E browser (`320–1280 px`).
- **Correções regulatórias e de mercado com fontes verificadas (`20/11/2026`):** atualização de referência Tasy para **Bionexo**; separação dos denominadores da TIC Saúde 2024 (`4%` estabelecimentos de saúde em geral vs `16%` internação >50 leitos); separação entre prazos de resposta conclusiva (RN ANS nº 623/2024) e atendimento (RN ANS nº 566/2022); detalhamento das taxas INPI com condição (`R$ 440` pré-aprovada c/ desconto vs `R$ 860` livre preenchimento); ajuste preciso sobre Lei nº 14.063/2020 (arts. 13 e 14), Res. CD/ANPD nº 15/2024, RDC ANVISA nº 657/2022 (art. 1º, § 2º, III), Res. CFM nº 2.454/2026 e retenção temporária vs não treinamento em fornecedores de OCR em lote.
- **Direção estratégica aberta:** registro isento das **Propostas A (Conferência Documental)** e **B (Preparação para Autorização)** e manutenção de todas as mudanças estratégicas ainda não deliberadas em campo como hipóteses/propostas pendentes de entrevistas e decisão humana.

## 3.1.0 — 19 de novembro de 2026 (Etapas 2 e 2.1)

Evolução e homologação na branch `jyxia-develop` alinhada às diretrizes DE-01 a DE-05 (sem OCR, LLM, decisão clínica ou persistência em servidor):

- Motor determinístico dos 4 eixos de consistência (`Identidade`, `Procedimento informado`, `Lateralidade` e `Temporalidade/Versões`) com abstenção explícita e bloqueio automático em conflitos e abstenções bloqueantes.
- Extração de `subfamily`, `procedure`, `procedureCode` (`Codigo:`), `laterality` (com prevenção de falso positivo da preposição portuguesa `"ao"` em `'Nao aplicavel ao procedimento'`) e `signatureCue` literal não autenticante, preservando `candidates[]` e trava de substituição entre subfamílias distintas.
- Cálculo temporal puro em UTC (`diffDaysISO`) com tarefa `:window-unknown:`, reavaliação de documentos não revisados em `loadSyntheticCase()`, cenário `8 · Lateralidade divergente (OD × OE)` (`14` fixtures no manifesto), alvo de toque `>= 44 px` em `<summary>` validado até `320 px`, BOM UTF-8 no download CSV e proteção reforçada contra formula injection em `csvSafeCell()`.
- Suíte expandida para `32` testes v3 (`26` em `test_documental.mjs` + `6` em `test_documental_pdfjs.mjs`), `29` testes legados v2.x, E2E real e pacote seletivo GitHub Pages com `27` arquivos.

## 3.0.0 — 14 de novembro de 2026

Decisão de Yanuska de adotar o foco de Clinical Document Intelligence com primeiro módulo de conferência documental para procedimentos eletivos, preservando `demo-v2.html` e testes históricos sem migração destrutiva. O nome canônico em Word é `Projeto_JYXIA_Inteligencia_Documental_v3.docx`.
