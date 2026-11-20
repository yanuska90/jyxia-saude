# Integrações na JYXIA (`v3.2.0` + Fundação `0.1.0`)

A entrada da demonstração pública (Modalidade A em [`frontend/public/`](../frontend/public/)) é um catálogo sintético fechado de PDF, PNG, CSV e JSON (`18` fixtures) validado por SHA-256 no navegador. A Modalidade B ([`frontend/lab/lab-local.html`](../frontend/lab/lab-local.html), restrita a `localhost` e ausente do GitHub Pages) aceita apenas PDFs sintéticos locais sem upload nem comunicação externa.

O novo `backend/` institucional (`0.1.0`) inclui exclusivamente API de saúde (`/api/v1/health/live` e `/api/v1/health/ready`), persistência relacional multi-tenant em PostgreSQL e storage sintético controlado. **Não existe nenhuma conexão automatizada real com hospitais, laboratórios, operadoras de saúde, RNDS, gov.br ou sistemas como MV, Tasy ou Epic.** Alternativas usando credenciais pessoais de paciente em portais externos foram retiradas do escopo ativo.

Os módulos históricos em Python ([`legacy/v2/integration.py`](../legacy/v2/integration.py) / [`tests/legacy/test_integration.py`](../tests/legacy/test_integration.py) — `11` testes legados preservados) exercitam apenas normalização sintética local isolada e **não são importados pelo `backend/` nem caracterizam conector hospitalar ativo**.

Qualquer integração futura dependerá de validação em campo, contrato formal da instituição controladora, especificação vigente (HL7 FHIR R4, HL7 v2 ou padrões TISS/TUSS da ANS sem dicionários médicos inventados), testes homologados e quarentena anti-homônimo sem vínculo automático.
