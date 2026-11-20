# JYXIA Inteligência Documental em Saúde

Versão **3.2.0** · Documentação sincronizada em 20 de novembro de 2026 · Yanuska e João.

A JYXIA é uma camada administrativa de conferência e organização de documentos externos em saúde, complementar ao prontuário eletrônico (PEP), com vinculação visual à página original e revisão humana obrigatória. O primeiro recorte em investigação é a **conferência documental para procedimentos eletivos**; a eventual combinação com preparação documental para solicitação de autorização prévia está em avaliação comparativa junto a equipes e decisores, sem validação comercial concluída até esta data.

- [Site HTTPS](https://yanuska90.github.io/jyxia-saude/)
- [Demo documental HTTPS](https://yanuska90.github.io/jyxia-saude/demo.html)
- [Projeto completo em DOCX](Projeto_JYXIA_Inteligencia_Documental_v3.docx)
- [18 exemplos fictícios para baixar](fixtures-jyxia.zip)

## Modalidade A (Demonstração pública) vs. Modalidade B (Laboratório local) vs. Modalidade C (Futura)

1. **Modalidade A — Demonstração pública (`index.html`, `demo.html`):** restrita ao catálogo sintético fechado de **`18` fixtures** validados por SHA-256 em [`documental-manifest.json`](documental-manifest.json) (e [`fixtures-jyxia.zip`](fixtures-jyxia.zip)), executando localmente em memória do navegador com **`9` cenários** (incluindo o novo **Cenário 9 · Quatro eixos avaliados** vs. o **Cenário 1 histórico**, que entra honestamente em `abstencao` por omitir procedimento e lateralidade). Nenhum arquivo desconhecido ou dado real é aceito.
2. **Modalidade B — Laboratório experimental local (`lab-local.html`, `lab-extractor.mjs`, `serve_lab.py`):** ambiente estritamente isolado em `localhost` (**não incluído no GitHub Pages e bloqueado com HTTP 404 em `serve_documental.py`**) para testar PDFs sintéticos externos com variações de diagramação, fontes (`Helvetica`, `Courier`, `Times-Roman`), rotações (`90°`, `180°`, `270°`), múltiplas páginas e aliases explícitos cadastrados de rótulos (sem fuzzy matching agressivo, sem OCR e sem persistência/logs de conteúdo).
3. **Modalidade C — Processamento institucional futuro (planejada, não implementada):** backend autenticado, persistência privada, OCR auditado e integrações hospitalares, condicionados à conclusão das entrevistas e testes em conjunto reservado antes da evolução para produção.

## O que funciona na versão `3.2.0`

1. **Extração real via PDF.js e coordenadas dinâmicas:** o Mozilla PDF.js `6.5.438` lê texto de PDFs sintéticos localmente no navegador (`extractPdfLines`) e calcula dinamicamente as caixas `[x, y, w, h]` (inclusive em páginas rotacionadas), extraindo até **`11` chaves prefixadas** (`Tipo`, `Subfamília`, `Paciente`, `Nascimento`, `Identificador`, `Emissão`, `Procedimento`, `Código documental`, `Sistema do código`, `Origem do sistema` derivada e `Lateralidade`, além de `Origem`).
2. **Marcador textual sintético separado da observação humana:** a detecção da expressão literal `'MARCA FICTICIA'` (`syntheticMarkerCue`) sinaliza exclusivamente presença textual na camada PDF (**não executa reconhecimento visual nem autentica assinatura, signatário, CRM ou validade jurídica**). A observação visual humana na página (`humanVisualObservation`: `unknown` / `observed` / `not_observed`) é ação separada em termos. Documentos PNG sem texto nunca são apresentados como analisados quanto à assinatura.
3. **Seis estados explícitos por eixo e cinco estados gerais (`readinessState`):**
   - **Estados por eixo (`consistencyAxes`):** `ok`, `conflito`, `abstencao`, `nao_avaliado`, `nao_aplicavel` (apenas por declaração explícita — campo ausente nunca vira `nao_aplicavel`) e `pendente`.
   - **Estados gerais:** `pendente`, `bloqueado` (quarentena, conflito ou abstenção bloqueante), `abstencao` (informação insuficiente em eixo obrigatório), `conferida_com_escopo_limitado` (eixo explicitamente declarado não aplicável) e `conferida` (quatro eixos avaliados e compatíveis nas regras do exemplo). **Nenhum estado aprova ou libera procedimento clínico.**
4. **Comparação conservadora de procedimentos e códigos:** diferencia correspondência textual exata, correspondência após normalização superficial, correspondência por código com sistema identificado (`procedureCodeSystem` declarado por `Sistema:` ou prefixo explícito `TUSS:`/`SIGTAP:`/`CBHPM:`/`SUS:`), divergência textual, divergência de códigos e ambiguidade de múltiplos candidatos. Sem dicionários clínicos inventados — nunca equipara `"Cirurgia de catarata"` e `"Facoemulsificação"` automaticamente. Quando um código não declara sistema, emite explicitamente: `"Código encontrado, sistema de codificação não identificado."`
5. **Temporalidade explícita e versões:** regra configurável em dias UTC (`diffDaysISO`) caracterizada como **ilustrativa/configurável do exemplo** (`14/11/2026` referência, `30/11/2026` procedimento, janela inicial de `30` dias aplicada somente à categoria `Laudo`), diferenciando `atualizado`, `antigo`, `fora_janela`, `prazo_desconhecido`, `data_invalida`, `data_futura` e `validade_nao_definida`. Datas mais recentes nunca substituem versões anteriores sem `replace()` explícito do mesmo tipo e subfamília sem ciclos.
6. **Rastreabilidade local e exportações:** histórico em memória, cadeia local SHA-256 (`events[]` com `actorAuthenticated: false`, preservando `originalValue`, `revisedValue`, referência documental/espacial e `policyVersion`), resumo administrativo copiável e exportações **JSON** (`schema: 'jyxia.documental-session.v2'`, diferenciando os 5 níveis de rastreabilidade, extração vs. revisão e limitações) e **CSV** (`19` colunas com BOM UTF-8 no download e `csvSafeCell()` neutralizando fórmulas iniciadas por tabulação ou espaços/NBSP + `=`, `+`, `-`, `@`). **Cadeia local em memória não é auditoria institucional imutável.**

## Estado real, lacunas e limites

- **Sem OCR nem IA:** imagens PNG (`imagem-ilegivel.png`) e PDFs sem texto selecionável (`readable = false`) entram em quarentena/abstenção imediata.
- **Sem persistência, login ou integração ativa:** execução integralmente volátil na aba do navegador; sem backend PostgreSQL, S3, OIDC/MFA ou integração hospitalar (MV, Tasy/Bionexo, RNDS ou operadoras). **Não insira dados reais de pacientes em nenhum arquivo ou campo.**
- **Validação de campo e regulatória pendentes:** `0` entrevistas em campo executadas até esta data, `0` testes em hospitais reais, `0` contratos, marca pretendida **JYXIA** ainda não protocolada no INPI e pareceres LGPD/DPA/ANVISA pendentes antes de piloto com dados reais. Resultados do benchmark sintético interno (`benchmark/`) medem apenas robustez determinística em casos artificiais criados pela equipe.

## Como executar e testar

```sh
# 1. Demonstração pública (Modalidade A — localhost)
python serve_documental.py --bind 127.0.0.1 --port 8000

# 2. Laboratório experimental local (Modalidade B — localhost exclusivo)
python serve_lab.py --bind 127.0.0.1 --port 8099

# 3. Suítes automatizadas completas (Núcleo, PDF.js, Lab/Benchmark, Regressão v2, Higiene, E2E e Pages local)
node --test test_documental.mjs test_documental_pdfjs.mjs test_lab_and_benchmark.mjs test_security.cjs test_synthetic_import.cjs
python -m unittest test_integration.py -v
python check_publication.py
node test_documental_e2e.mjs
python test_pages_package_local.py
```

*(O workflow `.github/workflows/pages.yml` publica estritamente `31` arquivos estáticos da Modalidade A, mantendo laboratório experimental, benchmark e suítes de teste fora do pacote público.)*

## Origem, equipe e dependências

A ideia surgiu quando Yanuska vivenciou um câncer há cerca de seis anos e enfrentou fragmentação de exames e recebimento de medicamento ao qual tinha alergia; junto com João, construiu este protótipo administrativo para investigar evidências antes de escalar. Dependência runtime única: Mozilla PDF.js `6.5.438` em `vendor/` (Apache 2.0; ver [DEPENDENCIAS.md](DEPENDENCIAS.md)). Demais arquivos estratégicos detalhados em [ARQUITETURA.md](ARQUITETURA.md), [VALIDACAO_DOCUMENTAL.md](VALIDACAO_DOCUMENTAL.md), [DADOS_FICTICIOS.md](DADOS_FICTICIOS.md), [SEGURANCA.md](SEGURANCA.md), [INTEGRACOES.md](INTEGRACOES.md) e [CHANGELOG.md](CHANGELOG.md).
