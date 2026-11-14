# Validação da versão 3.0.0

## Engenharia executada

13 testes do núcleo documental cobrem hashes dos exemplos e rejeição de bytes alterados, evidência com página/caixa, ambiguidade, revisão completa, duplicidade, versões explícitas, identidade divergente, identificador ausente, imagem, correção com justificativa, atribuição/prazo, invalidação de resoluções após nova revisão/regra, exportação e detecção de alteração na cadeia. O conjunto de regressão anterior contém 18 testes JavaScript e 11 Python.

Conferência em navegador: extração real dos PDFs fornecidos, destaque visual da emissão na página original, revisão de quatro classes, fechamento das pendências do conjunto completo, bloqueio de identidade divergente, duplicados, imagem sem OCR, confirmação manual de documento sem identificador e layout desktop/celular de 390 px. As verificações de interface não demonstram acessibilidade integral WCAG.

## O que falta validar

Não foi realizado ensaio com usuários, estudo clínico, pentest independente, avaliação de OCR, benchmark de modelo ou teste de múltiplas instituições. Os exemplos são conhecidos do desenvolvimento. Não divulgar percentuais de acurácia nem redução de cancelamentos a partir destes testes.

Próxima avaliação proposta: pelo menos 30 casos sintéticos adicionais, reservados e revisados por duas pessoas, medindo exatidão por campo, localização da evidência, recusa correta, falsos vínculos, falsos alertas, tempo de conferência e correções. Medir denominador e intervalo de incerteza; separar extração, regra e revisão final.

Para avançar: nenhuma associação final incorreta no conjunto de aceite, nenhum acesso entre instituições nos testes de servidor, fonte em 100% dos campos aceitos e recuperação de backup demonstrada. São critérios propostos, não desempenho obtido nem garantia de erro zero em produção. Comparar tempo/erros com processo manual equivalente antes de alegar impacto.
