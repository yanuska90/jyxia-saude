> Versão 3.0.0 — documento histórico. O produto atual é a conferência documental descrita no README. As funções abaixo pertencem à demo 2.3, preservada em demo-v2.html; não são capacidades da demo documental. Acesso a portais de laboratório permanece desativado.

# Revisão de segurança e prática de desenvolvimento

Revisão de 14/11/2026, incluindo componentes anteriores e a versão 2.3. Escopo: código do site, cadastro/anexos, CPF demonstrativo, ingestão sintética, API Docker, configuração de publicação e novos fluxos. Testes com dados fictícios nos ambientes próprios. Não houve pentest dos portais Delboni, Rede D’Or ou Daily, nem coleta de credenciais da titular.

## Achados e tratamento

| Prioridade no uso real | Achado | Tratamento e limite |
|---|---|---|
| Alta | Registros anteriores ficavam em texto legível no navegador. | Cofre criptográfico e bloqueio adicionados. Migração depende de a titular criar seu acesso; cópias anteriores não são protegidas retroativamente. |
| Crítica | API usa chave compartilhada e paciente fixo. | Continua exclusivamente em desenvolvimento e loopback, sem dados reais. Identidade individual, MFA e autorização por paciente são bloqueadores do piloto clínico. |
| Alta | Respostas assíncronas poderiam reaparecer depois de sair da sessão. | Conferência de geração da sessão, remoção do conteúdo e descarte de resultados após bloqueio. |
| Alta | Formulário de senha poderia ser confundido com integração do laboratório. | Acesso real suspenso por decisão da titular, incluindo teste individual; atalhos retirados e nenhum coletor implementado. Decisão em ACESSO_ASSISTIDO.md. |
| Média | Ingestão aceitava identificadores ambíguos e valor de exame com tipo incompatível. | Identificadores limitados ao formato adotado; quantidade incompatível rejeitada. Avisos são calculados antes da gravação, evitando persistência seguida de erro nessa etapa. |
| Alta | URLs de videochamada poderiam carregar credenciais ou apontar a qualquer domínio. | Validação HTTPS e subdomínio Daily, sem credenciais, query ou fragmento. Isso não comprova privacidade de uma sala externa. |
| Média | Dependências e imagens podiam variar entre construções. | Versões Python resolvidas e imagens Python/Mongo fixadas. Atualizações exigem nova revisão, não congelamento permanente. |
| Alta | Anexos validam formato inicial, mas não têm quarentena/antimalware. | Restrição a dados fictícios mantida. Inspeção, limite global de upload, quotas e recuperação de falhas são requisitos antes de produção. |
| Alta | Mongo usa conta administrativa no ambiente de desenvolvimento. | Banco não expõe porta no host. Usuário de aplicação com menor privilégio e gestão de chaves ainda são necessários no ambiente real. |
| Alta | Hospedagem pública e criptografia no cliente não oferecem isolamento clínico completo. | Origem privada isolada, servidor com autorização, cabeçalhos de segurança, recuperação e auditoria independente são bloqueadores para dados reais. |

## Evidências obtidas

- 11 testes de criptografia e validação de URLs passaram: credenciais incorretas, alteração de ciphertext/anexo, troca de contexto, IVs diferentes, ausência de anexo e rejeição de links com tokens/credenciais.
- 11 testes de ingestão passaram, incluindo os testes anteriores de paciente divergente, duplicação, conflito de versão e preservação da origem, e os dois casos de entrada malformada acrescentados.
- 23 verificações HTTP no ambiente Docker passaram: ausência de credencial, chave incorreta, arquivos privados inacessíveis pela API, criação de teleconsulta sintética, cache desativado, vínculo de anexo ao registro, download protegido, tentativa de substituir paciente, edição concorrente e arquivo mal rotulado. A limpeza removeu apenas o registro criado por esse teste.
- Verificação de bibliotecas Python com pip-audit em contêiner descartável retornou “No known vulnerabilities found” na consulta realizada. Isso não comprova ausência de vulnerabilidades desconhecidas, nem cobre o sistema operacional das imagens, o MongoDB, a hospedagem ou a lógica clínica.
- Verificação no navegador: cadastro, senha incorreta, bloqueio, reabertura e preservação de teleconsulta sintética; migração de registro legado com anexo para ciphertext, mantendo o conteúdo recuperável com a senha de teste.
- Layout conferido em larguras de 320 e 390 pixels, sem rolagem horizontal no formulário. É emulação de tamanho, não teste físico em todos os aparelhos, Safari ou leitores de tela.

## Controles contínuos incluídos

AGENTS.md registra a orientação da titular para futuras mudanças. O workflow executa testes sintéticos e verificação básica de arquivos privados e alguns padrões de segredos. Não é scanner completo de segredos, não inspeciona todo o histórico e não substitui pentest. A publicação usa lista explícita de arquivos, excluindo o ambiente de teste e seus dados.

O job de verificação, sozinho, não garante bloqueio do deploy do GitHub Pages: proteção de branch e dependência entre verificação e publicação precisam ser configuradas conforme as permissões e o fluxo do repositório. Não foi declarado que esses controles administrativos estão ativos.

## Próximas etapas para o piloto privado

1. Definir ameaça e responsabilidade por paciente, profissional, instituição, operador de suporte e fornecedor.
2. Implementar identidade individual/MFA, autorização por registro e anexo, recuperação e revogação; testar acesso indevido por troca de IDs.
3. Aplicar menor privilégio no banco, cofre de segredos, rede privada, TLS, criptografia e gestão de chaves, auditoria, backup e restauração.
4. Implementar limite total de requisição, controles de abuso, quarentena/inspeção de anexos e tratamento de falhas entre registro e arquivo.
5. Revisar dependências/imagens com SBOM e análise de vulnerabilidades, configurar proteção de branch e verificação obrigatória antes do deploy.
6. Validar privacidade, contratos, retenção, continuidade assistencial e requisitos regulatórios; realizar pentest independente com escopo autorizado e corrigir os achados antes de dados reais.

Os riscos abertos impedem classificar o protótipo como ferramenta clínica pronta. O trabalho reduziu riscos concretos, mas não fornece garantia de inviolabilidade.

## Importação fictícia — revisão 2.3

O acesso individual a portais reais foi suspenso por decisão da titular. O novo campo recebe somente o pacote sintético aprovado, limitado a 256 KB, e devolve uma cópia do catálogo confiável após comparação do conteúdo. Arquivos rejeitados não alimentam a interface nem a persistência. Não existe mecanismo de anonimização de arquivos reais.

Validação: 7 testes específicos de importação passaram, além dos 11 testes existentes de criptografia/links e dos 11 de ingestão. Foram cobertos pacote completo, identidade divergente, conteúdo extra, arquivo inválido ou excessivo, isolamento da cópia e fontes incompletas. No navegador, botão e seleção do arquivo resultaram em 7 registros de 2 fontes, reimportação sem duplicação e limpeza do cenário ao recarregar. O formulário foi conferido em largura de celular, sem rolagem horizontal. Esses testes não equivalem a um pentest independente.

## Revisão documental 3.1.0 — 22/11/2026

Escopo: apresentação, acessibilidade visual e navegação das pendências. A fronteira permanece a aba pública com dados sintéticos. Textos de motivo e próximo passo são definidos pela aplicação; dados do documento e observações são inseridos como texto. O atalho usa o identificador interno da pendência, sem URLs ou acesso externo. Nenhuma permissão, credencial ou dependência foi adicionada. Não houve pentest independente. As verificações específicas desta entrega ficam registradas em VALIDACAO_DOCUMENTAL.md.
