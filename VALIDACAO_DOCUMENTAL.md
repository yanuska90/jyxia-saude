# Validação documental — versão 3.1.0

## Engenharia executada na versão 3.0.0 — registro histórico

13 testes do núcleo documental cobrem hashes dos exemplos e rejeição de bytes alterados, evidência com página/caixa, ambiguidade, revisão completa, duplicidade, versões explícitas, identidade divergente, identificador ausente, imagem, correção com justificativa, atribuição/prazo, invalidação de resoluções após nova revisão/regra, exportação e detecção de alteração na cadeia. O conjunto de regressão anterior contém 18 testes JavaScript e 11 Python.

Conferência em navegador: extração real dos PDFs fornecidos, destaque visual da emissão na página original, revisão de quatro classes, fechamento das pendências do conjunto completo, bloqueio de identidade divergente, duplicados, imagem sem OCR, confirmação manual de documento sem identificador e layout desktop/celular de 390 px. As verificações de interface não demonstram acessibilidade integral WCAG.

## O que falta validar

Não foi realizado ensaio com usuários, estudo clínico, pentest independente, avaliação de OCR, benchmark de modelo ou teste de múltiplas instituições. Os exemplos são conhecidos do desenvolvimento. Não divulgar percentuais de acurácia nem redução de cancelamentos a partir destes testes.

Próxima avaliação proposta: pelo menos 30 casos sintéticos adicionais, reservados e revisados por duas pessoas, medindo exatidão por campo, localização da evidência, recusa correta, falsos vínculos, falsos alertas, tempo de conferência e correções. Medir denominador e intervalo de incerteza; separar extração, regra e revisão final.

Para avançar: nenhuma associação final incorreta no conjunto de aceite, nenhum acesso entre instituições nos testes de servidor, fonte em 100% dos campos aceitos e recuperação de backup demonstrada. São critérios propostos, não desempenho obtido nem garantia de erro zero em produção. Comparar tempo/erros com processo manual equivalente antes de alegar impacto.

## Plano de validação após a revisão de 19/11/2026

- Iniciar entrevistas com 3–5 profissionais em paralelo ao desenvolvimento. Investigar conferência documental e preparação de solicitações a convênios, sem assumir previamente qual proposta tem maior utilidade.
- Escolher o primeiro setor conforme acesso a uma equipe disposta a testar, frequência e custo observado do problema.
- Separar exemplos de desenvolvimento de cerca de 30 casos sintéticos exploratórios de avaliação. Criar referência revisada por duas pessoas, registrando divergências de avaliação.
- Medir acerto por campo, significado do dado, localização da evidência, falsos vínculos, alertas indevidos, recusas e correções. Relatar denominadores, amostra e incerteza; não transformar ausência de erros observados em garantia.
- Comparar tempo total e erros com processo manual em casos equivalentes, considerando ordem e aprendizado. Tempo de extração isolado não mede ganho operacional.
- Incluir divergência de procedimento/lateralidade como cenário futuro. Esses campos não são extraídos pela demo atual.
- Verificar fluxo com teclado, celular e pessoas com diferentes necessidades; a revisão visual não equivale a certificação WCAG.

Estas atividades são propostas, não entrevistas, resultados ou evidências já obtidas.

## Verificações executadas em 22/11/2026 — versão 3.1.0

- Os 13 testes existentes do núcleo documental passaram, incluindo recusa de arquivos alterados, identidade divergente, necessidade de revisão, correção justificada, duplicidade e histórico.
- Verificação de sintaxe da interface e higiene básica da publicação aprovadas. O scanner continua limitado a nomes e alguns padrões de segredos.
- No navegador: carregamento do conjunto completo, motivo/próximo passo/documento das pendências, atalho para laudo com foco no título, destaque da fonte da emissão, recusa de revisão sem confirmação e revisão válida com recálculo.
- O caso divergente permaneceu em quarentena, sem formulário de confirmação; seu atalho abriu o documento correto.
- Site e demo sem rolagem horizontal nas larguras de 320 e 390 pixels; apresentação desktop conferida em 1280 pixels. É emulação de tela, não certificação de acessibilidade nem teste em todos os dispositivos.
- Nenhuma alegação de OCR, modelo de IA, eficácia clínica, ganho operacional ou integração institucional decorre dessas verificações.
