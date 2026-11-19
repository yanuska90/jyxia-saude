# Validação da versão 3.1.0

## Engenharia executada

21 testes unitários em `test_documental.mjs` e 6 testes de integração real com PDF.js em `test_documental_pdfjs.mjs` (total de 27 testes da v3) cobrem hashes dos 14 exemplos sintéticos e rejeição de bytes alterados, evidência com página/caixa, ambiguidade, revisão completa, duplicidade, versões explícitas com verificação de subfamília, identidade divergente, identificador ausente, imagem sem OCR, normalização e conflito de lateralidade (`OD × OE`), divergência de procedimento, abstenção sem inferência clínica, correção com justificativa, atribuição/prazo, invalidação de resoluções, resumo administrativo de pendências, exportação JSON/CSV segura contra injeção de fórmula e detecção de alteração na cadeia de hashes. O conjunto de regressão histórico v2.x contém 18 testes JavaScript e 11 Python.

Conferência E2E automatizada em navegador Chromium/Edge (`test_documental_e2e.mjs`): upload manual de PDF e PNG via seletor `#files` e recusa fora do catálogo, extração real dos PDFs fornecidos, destaque visual de emissão e lateralidade na página original, oito cenários completos incluindo divergência `OD × OE` nos quatro eixos de consistência, fechamento administrativo (`"Documentação conferida (regras do exemplo)"`), bloqueio de identidade divergente com orientação de quarentena, preservação de rascunho durante atribuição/regra, exportação JSON e CSV, resumo de pendências, reset limpo, layout desktop/celular de 390 px sem overflow horizontal e foco por teclado. As verificações de interface não demonstram auditoria completa WCAG.

## O que falta validar

Não foi realizado ensaio com usuários, estudo clínico, pentest independente, avaliação de OCR, benchmark de modelo ou teste de múltiplas instituições. Os exemplos são conhecidos do desenvolvimento. Não divulgar percentuais de acurácia nem redução de cancelamentos a partir destes testes.

Próxima avaliação proposta: pelo menos 30 casos sintéticos adicionais, reservados e revisados por duas pessoas, medindo exatidão por campo, localização da evidência, recusa correta, falsos vínculos, falsos alertas, tempo de conferência e correções. Medir denominador e intervalo de incerteza; separar extração, regra e revisão final.

Para avançar: nenhuma associação final incorreta no conjunto de aceite, nenhum acesso entre instituições nos testes de servidor, fonte em 100% dos campos aceitos e recuperação de backup demonstrada. São critérios propostos, não desempenho obtido nem garantia de erro zero em produção. Comparar tempo/erros com processo manual equivalente antes de alegar impacto.
