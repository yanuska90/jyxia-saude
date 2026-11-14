# Diretriz de desenvolvimento JYXIA

A titular solicitou segurança em camadas e revisão com perspectiva de pentest/DevSecOps em todas as criações, incluindo código anterior.

- Antes de modificar uma função, considerar dados tratados, fronteiras de confiança, permissões, exposição pública e formas de abuso.
- Implementar controles no ponto que protege o dado; esconder um botão não é autorização. Em ambiente clínico, autorizar cada operação no servidor por paciente/instituição.
- Nunca colocar dados clínicos reais, senhas, tokens, cookies, arquivos de sessão ou segredos no repositório, código público, logs ou URLs. Usar credenciais exclusivas e mecanismos seguros de configuração.
- Usar somente dados sintéticos na demo do evento e nos testes. Não abrir ou alterar registros pessoais da titular para testar a interface.
- Validar entradas, anexos e URLs; negar por padrão; usar menor privilégio; preservar dados existentes e evitar migração destrutiva.
- Fazer testes negativos relevantes a cada alteração de segurança: acesso indevido, adulteração, identidade divergente, concorrência e falhas. Rodar verificações existentes quando afetadas.
- Revisar dependências e configurações, registrar riscos residuais e distinguir teste executado de controle apenas planejado. Não chamar esta revisão de pentest independente nem prometer inviolabilidade.
- Restringir testes ofensivos aos componentes próprios e ambientes explicitamente autorizados. Nunca testar ataques nos portais de laboratórios ou em serviços de vídeo de terceiros.
- Manter SEGURANCA.md, DEVSECOPS.md e documentação funcional coerentes com a versão realmente publicada.
