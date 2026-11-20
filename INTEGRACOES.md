# Integrações na versão documental 3.1.0

A entrada da demonstração pública `3.1.0` é um catálogo sintético fechado de PDF, PNG, CSV e JSON validado por SHA-256 no navegador. **Não existe nenhuma conexão automatizada real com hospitais, laboratórios, operadoras de saúde, RNDS, gov.br ou sistemas como MV, Tasy (atualmente no portfólio Bionexo) ou Epic.** Alternativas de acesso usando credenciais pessoais de paciente em portais externos foram retiradas do escopo ativo.

Os módulos históricos em Python (`integration.py` / `test_integration.py` — `11` testes legados preservados) exercitam apenas normalização sintética local em JSON/FHIR conceitual e **não caracterizam conector hospitalar ativo**.

Qualquer integração futura com terceiros (ou recebimento de cadastros/documentos em produção) dependerá de: validação em campo da necessidade antes da engenharia, contrato e autorização formal da instituição controladora, documentação técnica da versão/perfil adotado pelo parceiro (ex.: HL7 FHIR R4, HL7 v2 ou especificações TISS/TUSS vigentes na ANS), testes com dados exclusivamente sintéticos ou homologados, idempotência, controle de versões e quarentena sem vínculo automático quando houver divergência cadastral.
