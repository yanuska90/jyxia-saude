# Integrações na versão documental 3.0.0

A entrada atual é um catálogo sintético de PDF, PNG, CSV e JSON. Não há conexão real com Delboni, Hospital São Luiz, RNDS, gov.br ou sistemas hospitalares. Não se solicita login ou senha de laboratório; a alternativa de acesso por credenciais do paciente está retirada do escopo ativo por decisão de Yanuska.

O protótipo histórico de normalização FHIR/JSON permanece testado em integration.py, sem caracterizar conector real. Para a próxima fase, escolher uma instituição e obter documentação pública/fornecida, autorização, contrato, responsável e ambiente de testes fictício. Não usar Drive pessoal, dados reais, cookies ou senhas para explorar integrações.

Validar contrato e perfis FHIR/HL7, identificadores por emissor, consentimento/base legal, autorização, versões, idempotência, proveniência, erros e reconciliação. Manter documentos sem vínculo quando houver dúvida de identidade. Planejar retorno manual e fila de exceções. Importação de arquivo pode anteceder API autorizada, mas não deve simular acesso nacional por CPF.
