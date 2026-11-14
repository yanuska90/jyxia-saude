> Versão 3.0.0 — documento histórico. O produto atual é a conferência documental descrita no README. As funções abaixo pertencem à demo 2.3, preservada em demo-v2.html; não são capacidades da demo documental. Acesso a portais de laboratório permanece desativado.

# Teleconsulta JYXIA

## Entrega atual

O cadastro protegido contém tipo Teleconsulta, data, horário de Brasília, profissional/clínica, especialidade, observações, anexos e campo opcional para o link de uma sala Daily de teste. O registro é manual e não agenda atendimento, notifica o profissional, gera receita ou cria sala de vídeo.

Quando o usuário salva um endereço válido de sala, “Abrir sala informada” abre o serviço de vídeo em nova aba com `noopener noreferrer`. A demo aceita apenas HTTPS em um subdomínio direto de daily.co, um identificador de sala e nenhum usuário/senha, query string ou fragmento. Esse filtro reduz o risco de links arbitrários e de armazenamento acidental de tokens; não comprova que a sala seja privada ou pertença a um profissional habilitado. A URL é criptografada junto com o registro local.

Nenhuma conta Daily foi criada, nenhuma sala real foi provisionada e nenhuma videochamada clínica foi testada nesta entrega. Sem link fornecido por um responsável autorizado, aparece “Aguardando link do profissional”. Não há endereço real predefinido ou sala pública compartilhada entre pacientes.

## Ferramenta proposta

**Daily Prebuilt, serviço da Daily**, é o componente de videochamada candidato para o produto. A documentação descreve incorporação ao site ou abertura de uma URL de sala, além de APIs para salas privadas e tokens de reunião. A escolha técnica é uma proposta; contratação, plano, condições de saúde, tratamento de dados, subprocessadores, regiões, suporte e custos ainda devem ser confirmados. Não equivale a parceria, certificação LGPD ou garantia clínica.

Referências: [Daily Prebuilt](https://docs.daily.co/docs/prebuilt), [criar sala](https://docs.daily.co/reference/rest-api/rooms/create-room), [token de reunião](https://docs.daily.co/reference/rest-api/meeting-tokens/create-meeting-token). A oferta de recursos HIPAA indicada pelo fornecedor requer configuração/plano próprios e não substitui requisitos brasileiros.

## Funcionamento planejado no ambiente privado

1. Paciente autenticado solicita consulta; a clínica confirma profissional, data e disponibilidade. Identificar modalidade, consentimentos e orientações assistenciais. Não usar o canal para emergência.
2. Servidor verifica se paciente e profissional pertencem à consulta e se o horário permite entrada; CPF e ID de consulta recebidos do navegador não concedem autorização.
3. Servidor cria sala com identificador aleatório sem nome/CPF/diagnóstico na URL, privacidade `private`, janela de validade e limite de participantes adequados ao atendimento. Prever acompanhante/intérprete somente quando autorizado. Ativar sala de espera conforme o fluxo validado.
4. O servidor guarda a chave Daily no gerenciador de segredos; nunca no GitHub, HTML, JavaScript público, URL ou armazenamento do navegador. Emite token individual associado àquela sala, usuário e expiração, com privilégio mínimo. Token de paciente não é de administrador.
5. O botão Entrar na consulta abre a experiência de vídeo; o token temporário é entregue em memória para o SDK, sem query string ou persistência local. O navegador pede câmera/microfone. Exibir prévia, opção de áudio e informações do profissional. Biblioteca deve ter versão fixada e revisão de dependências, sem CDN flutuante.
6. Na saída, destruir a instância de vídeo, encerrar mídia e sessão conforme a política. Expiração de entrada não deve ser confundida com expulsão automática de quem já entrou: configurar e testar a política de encerramento do fornecedor.
7. Registrar presença e eventos operacionais mínimos, sem senha/token e sem gravar áudio/vídeo/transcrição por padrão. Retenção, gravação eventualmente necessária, permissões e finalidade precisam de decisão específica. O profissional registra o atendimento no prontuário autorizado.

## Testes antes de liberar pacientes reais

- Sem sessão, outra consulta ou outro paciente: negar entrada e criação de token.
- Sala privada: ingresso anônimo bloqueado; limite de participantes e permissões verificados.
- Token de sala A não abre B; token expirado ou fora da janela é rejeitado; encerramento e revogação testados.
- Paciente não consegue virar administrador ou abrir consulta de outra pessoa alterando parâmetros.
- Logs, repositório e URLs não contêm tokens, chaves ou identificadores clínicos.
- Câmera/microfone param ao sair; queda de rede permite recuperação controlada sem duplicar consulta.
- Dispositivos móveis, teclado, leitor de tela, baixa conexão e acompanhante/intérprete validados com usuários.
- Avaliação de segurança, requisitos assistenciais, contratos e privacidade concluídos antes do piloto.

O provedor de vídeo transporta a comunicação; a JYXIA continua responsável por implementar e validar seu controle de acesso e o fluxo de atendimento. Não prometer criptografia ponta a ponta, localização exclusiva no Brasil ou gravação desativada em uma sala externa sem verificar a configuração concreta.
