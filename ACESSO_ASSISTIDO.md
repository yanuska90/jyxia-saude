# JYXIA — acesso assistido aos portais e transição para APIs

Atualizado em 14/11/2026. Decisão de produto: facilitar o acesso do próprio paciente aos resultados enquanto não há integração institucional automatizada. Este documento não declara conexão ativa, parceria, permissão do fornecedor ou transferência de exames realizada.

## Dois acessos diferentes

1. **Acesso à JYXIA:** usuário e senha exclusivos para abrir os registros locais da demonstração. Ver SEGURANCA.md. Não substitui autenticação e autorização de um produto clínico.
2. **Acesso à instituição:** login, senha, código temporário ou outro fator exigido pelo portal oficial. O paciente realiza essa autenticação diretamente no portal. Esses campos pertencem ao serviço de origem; não são replicados na demo pública JYXIA.

A solicitação de um futuro formulário de credenciais foi registrada como requisito condicional. Um formulário sozinho não obtém acesso autorizado aos exames e não cria integração. Antes de automatizar esse fluxo, confirmar documentalmente o mecanismo permitido por cada instituição, seus termos, limites e consentimentos necessários. Priorizar autorização delegada com escopos e revogação quando o fornecedor oferecer esse recurso. Não foi verificada a disponibilidade de OAuth ou API aberta de pacientes nesses serviços.

## Portais consultados

| Instituição | Evidência pública consultada | O que está confirmado |
|---|---|---|
| Delboni | [Site oficial](https://delboniauriemo.com.br/) | A seção de resultados direciona o paciente ao Nav Dasa. Não confirma API autorizada para a JYXIA. |
| São Luiz / Rede D’Or | [Área do paciente](https://www.rededorsaoluiz.com.br/paciente/paciente/home/) | Informa acesso por CPF com validação por SMS, e-mail ou biometria; também descreve alternativa por número de atendimento. Não confirma conexão de terceiros mediante senha. |

Os links da demonstração abrem esses sites em nova aba, sem fornecer CPF, senha, token ou código à JYXIA e sem enviar a referência da página. A disponibilidade de exames pode variar por unidade e período. Não anunciar cobertura de todos os hospitais, laboratórios ou prontuários.

## Teste individual assistido

O primeiro teste real proposto será com a própria conta da titular que o solicitou, mediante sua atuação no portal oficial. A autorização para testar a conta não equivale a autorizar publicação dos exames.

1. Abrir o portal a partir do link oficial; conferir o domínio antes de digitar qualquer credencial.
2. A titular digita o acesso e conclui o segundo fator diretamente no serviço. Não enviar senhas, códigos, cookies ou tokens pelo chat, pelo GitHub ou em arquivos do projeto.
3. Consultar quais resultados estão disponíveis, com a titular escolhendo o documento. Não fazer coleta geral de todo o histórico.
4. Se houver download ou compartilhamento oficial, confirmar documento e destino privado antes de copiar. Neste estágio, a demo do Hack Brasil não é destino para laudos reais.
5. Encerrar a sessão do portal ao terminar. Evitar dispositivos compartilhados, gravação de tela, capturas com dados ou documentos em pastas sincronizadas/publicadas por engano.

Status: fluxo documentado; nenhum login de laboratório foi executado nem exame real transferido por esta implementação.

## Importação assistida em ambiente privado — próxima fase

Após disponibilizar ambiente privado HTTPS com identidade verificada, permissões por paciente e revisão de segurança, permitir que o paciente selecione e envie o arquivo exportado pelo próprio portal. Registrar instituição e unidade, paciente interno, data do exame quando conhecida, data de importação, documento original, hash, origem “enviado pelo paciente” e estado “pendente de conferência”. A origem declarada pelo usuário não comprova a autenticidade de um laudo.

Antes de vincular ao histórico: conferir identidade; impedir associação por CPF isolado; validar formato e tamanho; colocar anexos em quarentena para inspeção; restringir leitura/download; preservar correções e versões; rejeitar duplicatas sem apagar o original. OCR, quando houver, gera transcrição a conferir, nunca diagnóstico ou confirmação de identidade automática. Downloads permanecem sujeitos aos cuidados de segurança do dispositivo do paciente.

## Quando um conector por credenciais poderia ser considerado

Somente depois de confirmar que o fornecedor autoriza esse método e que o ambiente privado atende aos controles necessários. O uso da senha do paciente não dispensa essa verificação. Não contornar CAPTCHA, segundo fator, limitação de acesso ou medidas contra automação.

Se o fornecedor exigir credenciais reutilizáveis, a solução exige avaliação específica: campo somente em HTTPS privado; uso restrito à tarefa autorizada; não persistência por padrão; se retenção for indispensável e autorizada, cofre de segredos com chaves gerenciadas e acesso mínimo, separado dos prontuários; expiração/revogação; nenhuma credencial em logs, telemetria, URLs, arquivos estáticos ou repositório; resposta a incidentes e teste de exclusão. Hash de senha não permite autenticar em um serviço externo e não resolve esse requisito. Isso não está implementado nem aprovado para Delboni ou São Luiz.

Preferir API oficialmente habilitada com credenciais do aplicativo ou autorização delegada, conforme documentação do parceiro. Credenciais institucionais não devem ficar no navegador ou no JavaScript público. Integrações em segundo plano ficam desativadas até confirmação do contrato e dos escopos permitidos.

## Critérios para liberação

- Demo pública: somente dados sintéticos; nenhuma senha de laboratório recebida.
- Piloto privado: acesso negado sem sessão e fora do paciente autorizado; MFA; revogação; sessão curta; teste contra acesso a registros/anexos de outro usuário; logs sem conteúdo clínico ou segredos; backup e restauração verificados; retenção e responsabilidades definidas.
- Conector real: autorização do fornecedor, documentação, limites, identidade validada, fonte e versão preservadas, idempotência, revisão de erros, desconexão e exclusão verificadas.
- Comunicação: usar “acesso ao portal oficial” ou “importação assistida” até existir integração comprovada. Não exibir “conectado” por abrir um link ou por preencher um formulário.

## Referência do evento

O [regulamento do Hack Brasil, item 6.9](https://hackbrasil.com/regulamento) exige dados sintéticos em projetos de saúde. Por isso, o ambiente de demonstração do evento permanece separado de qualquer teste individual real. A documentação técnica e o código podem ser públicos; dados pessoais, laudos, senhas e segredos não podem ser incluídos no repositório.
