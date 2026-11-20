# Dados fictícios da demo documental (`3.1.0`)

Baixe `fixtures-jyxia.zip` ou use “Adicionar cenário” na demonstração. Todos os nomes, identificadores (`SYN-P01`), instituições, documentos e marcas (`MARCA FICTICIA`) são sintéticos e criados exclusivamente para demonstração pública. Não correspondem a pessoas reais e não consultam CPF real.

| Cenário | Arquivos envolvidos | Comportamento esperado |
| --- | --- | --- |
| 1 · Conjunto completo | `solicitacao.pdf`, `laudo.pdf`, `avaliacao.pdf`, `termo.pdf` | Quatro classes; conferência de cada documento e marca do termo para concluir as regras administrativas do exemplo |
| 2 · Arquivo duplicado | `laudo.pdf`, `laudo.pdf` | O segundo arquivo idêntico por SHA-256 é recusado sem criar segundo registro |
| 3 · Documento atualizado | `laudo.pdf`, `laudo-atualizado.pdf` | Dois laudos distintos; sem substituição automática; exige revisão de ambos e confirmação explícita dentro da mesma subfamília |
| 4 · Identidade divergente | `identidade-divergente.pdf` | Quarentena obrigatória e `caseId` nulo; bloqueio programático impede vínculo ao caso |
| 5 · Identificador ausente | `sem-identificador.pdf` | Nome e nascimento compatíveis com `CASO-SYN-001`; exige confirmação manual humana |
| 6 · Imagem sem texto extraível | `imagem-ilegivel.png` | Sem OCR nesta versão (`readable = false`); permanece em quarentena para conferência visual ou reenvio |
| 7 · Data e marca a conferir | `solicitacao.pdf`, `laudo-antigo.pdf`, `avaliacao.pdf`, `termo-sem-marca.pdf` | Janela administrativa de 30 dias em UTC (`laudo-antigo.pdf`) e área de assinatura sem marca (`termo-sem-marca.pdf`) geram pendências formais |
| 8 · Lateralidade divergente (`OD × OE`) | `solicitacao-od.pdf`, `termo-oe.pdf` | Solicitação indica `Olho Direito (OD)` e termo indica `Olho Esquerdo (OE)`; conflito bloqueia conclusão e exige retirada/substituição |

Os PDFs contêm texto sintético em camada pesquisável, não resultados clínicos reais. A importação aceita somente bytes exatos dos **`14` arquivos** listados em `documental-manifest.json`; arquivos reais ou modificados são recusados antes da leitura por política da demonstração pública (não substitui varredura antivírus/CDR de produção). `casos-ficticios.csv` e `casos-ficticios.json` validam exclusivamente o único caso sintético fornecido (`CASO-SYN-001`).

Para avaliações técnicas futuras (conjuntos de validação e *holdout* cegos), será necessário produzir lote separado e independente dos `14` arquivos do desenvolvimento, com dupla anotação de gabarito, incluindo verificação semântica de que a evidência destacada corresponde ao significado do campo. Estes `8` cenários demonstram comportamento determinístico conhecido; não medem desempenho de OCR, IA ou impacto clínico.
