# Segurança e privacidade da JYXIA 3.0.0

## Fronteira desta demonstração

Demo pública exclusivamente sintética, sem login e sem transmissão de arquivos selecionados. O catálogo de hashes recusa documentos desconhecidos antes da extração. Não há isolamento institucional ou autenticação clínica a alegar. Observações são texto livre, portanto a interface orienta não inserir dados reais; o JSON exportado inclui essas observações. Atualizar ou fechar a aba elimina o estado documental em memória.

Sem scripts de CDN, análise de audiência ou chamadas a IA. PDF.js local com avaliação dinâmica desativada; CSP limita scripts, worker e conexões à mesma origem, bloqueia objetos e envio de formulários. Tipos/tamanho/páginas são limitados. Valores extraídos e observações entram na interface por textContent, não HTML. O histórico encadeado é verificável, mas pode ser refeito pelo controlador da sessão.

O GitHub Pages não fornece os controles de um servidor clínico. A CSP em meta não aplica frame-ancestors. A execução Docker de desenvolvimento acrescenta cabeçalhos, desativa cache e serve apenas uma lista de arquivos públicos. Nenhuma dessas medidas substitui pentest independente ou revisão de dependências.

## Controles antes de dados reais

Definir controlador/operador, finalidade/base legal, minimização, retenção, direitos do titular, contratos, transferências e resposta a incidentes. Avaliar relatório de impacto e enquadramento regulatório segundo finalidade e riscos. Não alegar LGPD integralmente atendida por conter consentimento ou criptografia.

Implementar OIDC, MFA privilegiado, autorização em cada objeto, isolamento por instituição/caso, recuperação de conta com tokens curtos e de uso único, revogação de sessões, limite de tentativas, armazenamento privado, gestão de chaves, backups restauráveis, antivírus e processamento isolado de documentos. Testar IDOR, acesso entre instituições, XSS, arquivos malformados, exfiltração por documento e abuso de recursos. Sem garantias de inviolabilidade.

Nunca colocar credenciais, arquivos .env, cookies, documentos reais ou dumps em GitHub. Não acessar Drives pessoais, portais de laboratório ou senhas. GitHub e site devem conter somente conteúdo autorizado e fictício. Contatos com instituições não constituem parceria ou autorização de integração.

## Versão histórica

O cofre criptografado local da versão 2.3 permanece em demo-v2.html para preservar registros existentes. Não é o armazenamento da demo 3.0. Suas limitações e recuperação continuam nos documentos históricos; nenhuma senha pessoal foi lida ou recuperada nesta atualização.

Referências: LGPD, texto atualizado em https://www2.camara.leg.br/legin/fed/lei/2018/lei-13709-14-agosto-2018-787077-normaatualizada-pl.html ; Anvisa, finalidade e enquadramento de software: https://www.gov.br/anvisa/pt-br/centraisdeconteudo/publicacoes/produtos-para-a-saude/manuais/software-como-dispositivo-medico-perguntas-e-respostas . Consultadas em 14/11/2026.
