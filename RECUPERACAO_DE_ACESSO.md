> Versão 3.0.0 — documento histórico. O produto atual é a conferência documental descrita no README. As funções abaixo pertencem à demo 2.3, preservada em demo-v2.html; não são capacidades da demo documental. Acesso a portais de laboratório permanece desativado.

# Recuperação de acesso

## Situação atual da demonstração

Não há recuperação de usuário/senha, chave mestra, e-mail de recuperação ou redefinição do cofre local. A senha é necessária para derivar a chave dos registros e anexos. Alterar um campo de senha sem a chave anterior não recupera os dados. Esquecer a senha ou limpar o armazenamento pode causar perda permanente. Não apagar o navegador como tentativa de recuperação.

A titular deve guardar o usuário e uma senha exclusiva em seu gerenciador de senhas. Isso não transforma a demonstração em produto clínico. Nenhum colaborador ou assistente deve escolher a senha em nome do paciente ou alegar capacidade de recuperá-la. Dados reais permanecem fora do escopo da demo pública.

## Requisito obrigatório do produto com pacientes reais

Recuperação de identidade, recuperação de sessão e recuperação da chave dos dados precisam ser projetadas juntas. E-mail de redefinição, sozinho, não resolve a criptografia local atual. A migração do cofre para outro modelo deve ser feita enquanto o usuário ainda consegue desbloqueá-lo e com consentimento, integridade e backup verificados.

Fluxo proposto, ainda não implementado:

1. Conta com endereço verificado e segundo fator configurado. A tela Esqueci minha senha retorna a mesma resposta para contas existentes e inexistentes, com tempo de resposta controlado.
2. Limitar tentativas por conta e origem e controlar abuso; nunca bloquear definitivamente a conta apenas porque terceiros solicitaram redefinição.
3. Enviar link HTTPS para o contato previamente verificado, com token aleatório forte, uso único e prazo curto. Hipótese inicial: 15 minutos, sujeita à avaliação. Guardar somente a representação protegida do token no servidor e consumi-lo atomicamente. Não colocar token em logs, analytics ou repositório.
4. Exigir verificação adicional adequada ao risco. Não usar CPF, data de nascimento ou perguntas pessoais como segredo. A recuperação do segundo fator precisa de fluxo separado e controles contra engenharia social.
5. Após redefinição válida, invalidar tokens de recuperação e sessões anteriores, notificar o titular sem incluir dados clínicos, registrar o evento com acesso restrito e exigir novo login. Não iniciar automaticamente uma sessão privilegiada.
6. Suporte humano tem processo de identidade, mínimo acesso, registros e revisão. Não enviar senha existente por e-mail nem conceder acesso ao prontuário por uma conversa de suporte sem comprovação.

## Proteção dos dados durante a recuperação

Uma opção para o ambiente clínico é criptografia de envelope: chaves de dados separadas da senha de login, protegidas por serviço de gestão de chaves e acessíveis somente ao serviço autorizado. Redefinir a senha, após comprovação de identidade, não recriptografa nem apaga o prontuário. Esse modelo permite acesso controlado pelo serviço e precisa de governança e auditoria; não deve ser anunciado como criptografia ponta a ponta inacessível ao operador.

Se o produto adotar modelo em que apenas o paciente tem as chaves, é necessário um mecanismo de recuperação correspondente, como código de recuperação de alta entropia, protegido e entregue ao titular. Sem senha ou mecanismo previamente configurado, não se deve prometer restauração. Essa alternativa também não foi implementada nesta versão.

## Critérios de liberação

- Token expirado, reutilizado, adulterado ou de outra conta é rejeitado.
- Um terceiro não descobre se determinado e-mail possui conta nem redefine acesso com CPF apenas.
- As sessões antigas deixam de funcionar depois da redefinição confirmada.
- Usuário recupera os próprios registros e anexos, com integridade preservada, sem acesso aos de outra pessoa.
- Recuperação funciona com troca/perda de aparelho e respeita revogação, backup, retenção e auditoria.
- Segredos não aparecem em logs, URL de retorno, navegação de terceiros, código público ou histórico do Git.
- Revisão de segurança e teste independente aprovam o fluxo antes de uso com dados reais.

Para Delboni/Nav Dasa e São Luiz/Rede D’Or, a recuperação de acesso pertence ao portal oficial. A JYXIA não redefine nem armazena essas senhas.

Referência de desenho: [OWASP — Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html). A especificação acima contém decisões propostas, não afirmações de implementação ou certificação.
