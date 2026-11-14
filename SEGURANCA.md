# Proteção de acesso e limites da JYXIA

Versão 2.3 — 14/11/2026. Protótipo com dados sintéticos. Não constitui prontuário clínico, certificação ou garantia de inviolabilidade.

## Implementado no site público HTTPS

- Usuário e senha exclusivos para o armazenamento local, com um único acesso por perfil de navegador. O CPF não serve como senha. Não há cadastro de identidade real ou sincronização de contas.
- Registros e anexos fechados por padrão, inclusive se JavaScript falhar. A leitura acontece após desbloqueio; retirar um elemento visual de bloqueio não descriptografa o banco.
- AES-GCM de 256 bits com IV aleatório por operação. Metadados clínicos, nomes de anexos e conteúdo são criptografados. Identificadores aleatórios, quantidade e tamanhos aproximados podem ser observáveis no armazenamento.
- Chave não exportável derivada da senha com PBKDF2-HMAC-SHA-256, 600.000 iterações e salt aleatório de 16 bytes. A senha não é persistida pelo código; a chave só fica disponível na sessão aberta. Usuário também fica dentro da prova criptografada. A persistência pelo gerenciador de senhas é uma escolha do próprio usuário.
- Contexto autenticado vincula ciphertext ao cofre, ao registro e ao anexo; alteração do conteúdo protegido é rejeitada.
- Botão “Bloquear registros agora”, bloqueio ao ocultar/sair da aba, ao navegar e após 5 minutos sem atividade. Remove registros exibidos e limpa formulários. Abas compatíveis são notificadas do bloqueio. Não há promessa de apagamento forense da memória do navegador.
- Mensagem genérica de acesso inválido e pausa de um minuto depois de cinco falhas na mesma instância da página. Essa pausa é apenas proteção de interface, pode ser contornada fora dela e não equivale a limitação de tentativas em servidor. A resistência a tentativa offline depende especialmente da senha e da derivação da chave.
- Sem botão para recuperar ou redefinir a senha preservando os dados: não existe chave mestra. Senha esquecida ou exclusão dos dados do navegador pode causar perda permanente. A demo não é backup.
- Código sem serviços de analytics, scripts externos ou envio de registros a IA. Política de conteúdo restringe scripts e conexões ao próprio site; links externos usam isolamento de aba e não enviam referência. A hospedagem ainda pode registrar acesso técnico às páginas.

## Dados anteriores à proteção

Nas versões anteriores, os registros locais não tinham criptografia. Ao criar o acesso, o usuário deve confirmar que está no próprio dispositivo e que os registros anteriores lhe pertencem. O aplicativo cifra os dados e só então substitui o armazenamento em uma transação junto com a configuração do cofre. Se ocorrer falha, preserva os dados anteriores e não afirma que estão protegidos. Fechar outras abas antigas pode ser necessário para atualizar o banco.

Não há como comprovar a titularidade dos registros antigos por software: a primeira criação deve ser feita pela pessoa responsável em seu dispositivo pessoal. A proteção não é retroativa a cópias anteriores, backups do navegador ou arquivos já baixados. Nenhum assistente deve definir a senha do cofre da titular ou abrir seus registros como parte do teste da interface.

## O que essa proteção não cobre

- Não é autenticação clínica no servidor, cadastro nacional, autorização entre pacientes/profissionais ou autorização do laboratório.
- Não protege contra dispositivo comprometido, extensões maliciosas, captura de tela, pessoa que conhece a senha, leitura durante uma sessão aberta ou alteração maliciosa do código entregue pela hospedagem.
- GitHub Pages é uma hospedagem estática pública. Outros projetos na mesma origem, permissões da conta de hospedagem e cadeia de publicação precisam ser considerados. Para dados reais, usar domínio/origem privada isolada e arquitetura com controles de servidor revisados.
- Arquivos baixados saem do cofre e dependem da proteção do dispositivo. A demo não sincroniza, compartilha ou recupera dados.
- A API Docker continua separada e restrita a SYN-P01, com chave compartilhada de desenvolvimento. Este cofre não adiciona autorização individual à API. O banco MongoDB não está publicado em produção. Não expor o ambiente Docker com dados reais.

## Senhas e segredos fora do GitHub

O repositório contém apenas código e exemplos sintéticos. Não guardar senhas, tokens, CPF real, laudos, cookies, gravações de rede, exportações de banco ou arquivos de sessão. `.gitignore` cobre arquivos de ambiente, chaves e pastas de segredos/dados privados; isso não remove segredos já publicados e não é uma inspeção de todo o histórico. A publicação desta versão usa uma lista explícita de arquivos revisados, sem enviar o ambiente de teste.

Na futura operação, segredos de infraestrutura e de integração ficam em gerenciador de segredos, com mínimo privilégio, rotação, acessos auditados e nunca incorporados ao JavaScript. Senhas da própria JYXIA devem ser tratadas por provedor de identidade confiável ou hash de senha apropriado no servidor. Não reaproveitar a senha do laboratório.

## Antes de dados reais

Implementar autenticação de servidor com MFA, recuperação segura e sessão revogável; cookies HttpOnly, Secure e SameSite quando aplicável; proteção contra CSRF e abuso; autorização por paciente e instituição em cada endpoint; criptografia em trânsito e repouso com gestão de chaves; anexos privados e verificados; trilha de auditoria sem segredos; backup e restauração; isolamento de ambientes; retenção e exclusão; revisão jurídica e clínica; teste independente de segurança. A decisão de implantação depende da evidência desses controles, não apenas deste documento.

## Referências de projeto

- [OWASP — armazenamento de senhas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): referência para derivação resistente; não certifica esta implementação.
- [MDN — Web Crypto encrypt](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt): API criptográfica e contexto seguro.
- [Acesso real suspenso](ACESSO_ASSISTIDO.md): decisão da etapa atual e requisitos para uma fase futura.

## Recuperação de acesso
A limitação atual e os critérios obrigatórios da futura recuperação estão em RECUPERACAO_DE_ACESSO.md. Não liberar dados reais sem demonstrar recuperação de identidade e de acesso aos dados sem perda ou exposição.


## Etapa atual: somente fontes fictícias
O acesso a laboratórios reais foi retirado do escopo atual. O importador 2.3 aceita somente o pacote sintético fornecido, com limite de 256 KB e comparação integral com o catálogo aprovado; retorna registros desse catálogo, nunca campos de um arquivo rejeitado. Não envia o arquivo ao servidor. Isso não transforma arquivos arbitrários em dados fictícios e não é uma ferramenta de anonimização.
