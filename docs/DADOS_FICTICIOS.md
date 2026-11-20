# Dados fictícios da demo documental (`3.2.0`)

Baixe [`fixtures-jyxia.zip`](fixtures-jyxia.zip) ou use “Adicionar cenário” na demonstração pública (Modalidade A). Todos os nomes, identificadores (`SYN-P01`), instituições, códigos, procedimentos e marcadores textuais (`MARCA FICTICIA`) são **100% sintéticos e criados exclusivamente para demonstração**. Não correspondem a pessoas reais e não consultam CPF real.

| Cenário | Arquivos envolvidos | Comportamento esperado na v3.2.0 |
| --- | --- | --- |
| 1 · Conjunto parcial histórico | `solicitacao.pdf`, `laudo.pdf`, `avaliacao.pdf`, `termo.pdf` | Quatro classes sem campos de procedimento e lateralidade; após revisão humana conclui em **`abstencao`** (não gera falso estado conferido integral) |
| 2 · Arquivo duplicado | `laudo.pdf`, `laudo.pdf` | O segundo arquivo idêntico por SHA-256 é recusado sem criar segundo registro |
| 3 · Documento atualizado | `laudo.pdf`, `laudo-atualizado.pdf` | Dois laudos distintos preservados; versão mais nova não substitui a antiga automaticamente (exige `replace()` explícito na mesma subfamília) |
| 4 · Identidade divergente | `identidade-divergente.pdf` | Quarentena cadastral e `caseId` nulo; bloqueio programático impede vínculo ao caso (`bloqueado`) |
| 5 · Identificador ausente | `sem-identificador.pdf` | Nome e nascimento compatíveis com `CASO-SYN-001`; exige confirmação manual humana |
| 6 · Imagem sem texto extraível | `imagem-ilegivel.png` | Sem OCR nesta versão (`readable = false`); permanece em quarentena para inspeção visual manual ou reenvio, sem análise de assinatura |
| 7 · Data e marca a conferir | `solicitacao.pdf`, `laudo-antigo.pdf`, `avaliacao.pdf`, `termo-sem-marca.pdf` | Regra temporal ilustrativa em UTC (`laudo-antigo.pdf`) e falta de observação visual humana em termo geram pendências formais (`pendente`) |
| 8 · Lateralidade divergente (`OD × OE`) | `solicitacao-od.pdf`, `termo-oe.pdf` | Solicitação indica `Olho Direito (OD)` e termo indica `Olho Esquerdo (OE)`; conflito bloqueia conclusão (`bloqueado`) até retirada/substituição |
| 9 · Conjunto completo (4 eixos avaliados) | `solicitacao-completa.pdf`, `laudo-completo.pdf`, `avaliacao-completa.pdf`, `termo-completo.pdf` | Quatro classes com procedimento, sistema (`SIGTAP-FICTICIO`), código (`04.05.05.011-9`), lateralidade (`OD`) e marcador literal no termo; após revisão e observação visual humana conclui em **`conferida`** nas regras do exemplo |

## Separação entre catálogo público e benchmark sintético

- **Catálogo público (`documental-manifest.json`):** `18` arquivos estritamente bloqueados por SHA-256 e tamanho (`<= 512 KB`) na Modalidade A.
- **Benchmark sintético separado (`benchmark/benchmark-manifest.json`):** `8` PDFs sintéticos em `development` (`1`), `regression` (`3`) e `reserved_evaluation` (`4`) usados localmente com a Modalidade B (`lab-extractor.mjs`) para testar layouts tabulares, múltiplas fontes, rotações (`90°/180°/270°`), múltiplas páginas (até `5`), aliases explícitos, duplicidades, dados ausentes/conflitantes, espaços e acentos. **Não é publicado no GitHub Pages e não constitui holdout independente nem evidência com documentos reais.**
