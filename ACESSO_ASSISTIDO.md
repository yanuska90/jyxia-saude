# JYXIA — acesso real suspenso nesta etapa

Decisão atualizada em 14/11/2026, por orientação de Yanuska: nesta etapa do projeto não haverá acesso a contas de laboratórios ou hospitais, inclusive à própria conta da titular. A proposta anterior de teste individual fica suspensa. A demonstração utiliza exclusivamente dados inteiramente fictícios.

## O que está disponível

- Um paciente fictício, identificado por SYN-P01, com sete registros de um laboratório e um hospital inventados.
- Botão para carregar o exemplo completo e campo para importar o pacote `paciente-ficticio-01.json` fornecido pelo projeto.
- Cadastro manual de registros fictícios e anexos de teste, protegido pelo cofre local da demonstração.
- Instruções em [DADOS_FICTICIOS.md](DADOS_FICTICIOS.md).

Os atalhos para portais reais foram retirados da demo. Não existe campo de senha de laboratório, coleta de credenciais, leitura de resultados reais ou conexão ativa com Delboni, São Luiz, Nav Dasa ou outra instituição. O acesso ao cofre local é exclusivo da JYXIA e não autentica em nenhum laboratório.

## Limites do exemplo

O importador público aceita somente o pacote fictício fornecido, sem alterações no conteúdo. Não é um importador genérico de laudos nem um detector capaz de anonimizar dados pessoais. Os registros importados ficam na memória da página e desaparecem ao recarregar. Não são salvos no cofre local ou no MongoDB.

Não usar laudos reais, mesmo com o nome ocultado, CPF real, senha de portal, código de acesso, assinatura ou documento de um paciente. Para demonstrar anexos, usar `anexo-ficticio-01.txt`, criado inteiramente para teste.

## Integrações institucionais futuras

As integrações reais permanecem no roadmap, fora desta etapa. Uma nova fase exige documentação e autorização do parceiro, ambiente de testes, identidade e permissões por paciente, proteção dos anexos, auditoria e validação técnica e clínica. Não anunciar parceria ou API disponível sem comprovação.

Priorizar interfaces oficiais e autorização delegada quando o fornecedor oferecer esses mecanismos. Não coletar senhas para tentar contornar a falta de API, nem contornar segundo fator ou restrições de acesso. A abertura de uma página externa não comprova integração.

Esta decisão de escopo é da equipe. As exigências vigentes do evento devem ser conferidas no regulamento oficial antes da submissão; este documento não acrescenta regras ao Hack Brasil.
