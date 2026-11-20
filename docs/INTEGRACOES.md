# Integrações na versão documental 3.2.0

A entrada da demonstração pública (Modalidade A, `3.2.0`) é um catálogo sintético fechado de PDF, PNG, CSV e JSON (`18` fixtures) validado por SHA-256 no navegador. A Modalidade B (`lab-local.html`, restrita a localhost e ausente do GitHub Pages) aceita apenas PDFs sintéticos locais sem upload nem comunicação externa. **Não existe nenhuma conexão automatizada real com hospitais, laboratórios, operadoras de saúde, RNDS, gov.br ou sistemas como MV, Tasy (portfólio Bionexo) ou Epic.** Alternativas usando credenciais pessoais de paciente em portais externos foram retiradas do escopo ativo.

Os módulos históricos em Python (`integration.py` / `test_integration.py` — `11` testes legados preservados) exercitam apenas normalização sintética local em JSON/FHIR conceitual e **não caracterizam conector hospitalar ativo**.

Qualquer integração futura (Modalidade C) dependerá de: validação em campo antes da engenharia, contrato e autorização formal da instituição controladora, especificação vigente (HL7 FHIR R4, HL7 v2 ou padrões TISS/TUSS da ANS sem tabelas médicas inventadas), testes exclusivamente sintéticos ou homologados, idempotência, controle de versões e quarentena anti-homônimo sem vínculo automático.
