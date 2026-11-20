# Integrações na JYXIA (`v3.2.0` + Backend `0.2.0`)

A entrada da demonstração pública (Modalidade A em [`frontend/public/`](../frontend/public/)) é um catálogo sintético fechado de PDF, PNG, CSV e JSON (`18` fixtures) validado por SHA-256 no navegador. A Modalidade B ([`frontend/lab/lab-local.html`](../frontend/lab/lab-local.html), restrita a `localhost` e ausente do GitHub Pages) aceita apenas PDFs sintéticos locais sem upload nem comunicação externa.

O `backend/` institucional (`0.2.0`) integra-se exclusivamente a:
- PostgreSQL 16 (ou SQLite local apenas para testes unitários/isolados), com separação de privilégios (`migration_owner` vs. `jyxia_app`) e Row-Level Security (`RLS`);
- Provedores OpenID Connect padrão (`Authorization Code + PKCE S256`, discovery + JWKS, MFA obrigatório), exercitado com **Keycloak `26.8.2`** em desenvolvimento (`compose.institutional.yaml`) e integração real em CI, por meio do adaptador agnóstico [`app/core/oidc.py`](../backend/app/core/oidc.py).

**Não existe nenhuma conexão automatizada real com hospitais, laboratórios, operadoras de saúde, RNDS, gov.br ou sistemas como MV, Tasy ou Epic.** Alternativas usando credenciais pessoais de paciente em portais externos foram retiradas do escopo ativo.

Os módulos históricos em Python ([`legacy/v2/integration.py`](../legacy/v2/integration.py) / [`tests/legacy/test_integration.py`](../tests/legacy/test_integration.py) — `11` testes legados preservados) exercitam apenas normalização sintética local isolada e **não são importados pelo `backend/` nem caracterizam conector hospitalar ativo**.

Qualquer integração futura dependerá de validação em campo, contrato formal da instituição controladora, especificação vigente (HL7 FHIR R4, HL7 v2 ou padrões TISS/TUSS da ANS sem dicionários médicos inventados), testes homologados e quarentena anti-homônimo sem vínculo automático.
