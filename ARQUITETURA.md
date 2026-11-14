# Arquitetura JYXIA 3.0.0

## Implementação atual

GitHub Pages HTTPS → interface HTML/CSS responsiva → `documental-ui.mjs` → `documental-core.mjs`. PDF.js e seu worker são distribuídos em `vendor/`. Originais autorizados pelo catálogo sintético são lidos no navegador. O SHA256 é calculado antes do parsing; são aceitos somente os 12 arquivos exatos de `documental-manifest.json`, nos tipos previstos. Limites: 512 KB por arquivo, cinco páginas, 12 arquivos por seleção e 20 documentos por sessão.

O motor separa campos extraídos, fonte (página e caixa normalizada), revisão humana, versão da regra e eventos. `caseId` começa nulo e só é atribuído após confirmação humana compatível com nome e nascimento do caso; divergências não admitem confirmação. Duplicidade é igualdade de hash; substituição exige ação explícita e revisão dos dois documentos do mesmo tipo. Correção não modifica o valor original.

O estado é volátil. Não há autenticação, API documental ou persistência nesta demo pública. CSV/JSON de cadastro são exemplos fixos reconhecidos por hash, não importação genérica. Responsáveis A/B são personagens fictícios. Os eventos têm sequência e hash anterior; o controlador do navegador pode reconstruir a cadeia. Não chamar isso de trilha imutável.

## Produto institucional proposto

Interface → API FastAPI/Pydantic com autorização por instituição e caso → fila → processamento isolado → banco PostgreSQL (metadados e JSON) e armazenamento privado compatível com S3 (originais). Docker isola componentes de desenvolvimento. OCR e extração assistida por modelo deverão produzir evidências, abstenção e versões; texto do documento nunca autoriza execução de instruções.

Modelo: instituições, usuários/papéis, casos, identidade, documento/família/versão, execução de extração, campos/evidências, revisões, regras, tarefas e eventos. Metadados devem guardar motor, versão, timestamp, origem informada e identificador de execução. Preservar original e separar correções. Checkpoints protegidos, separação de privilégios e retenção dependerão da implantação.

MongoDB/GridFS permanecem apenas na API histórica de demonstração. Não há migração executada. PostgreSQL é uma proposta a avaliar; MySQL e múltiplos bancos simultâneos não são necessários para o escopo atual. Nenhuma versão de banco proposta equivale a conformidade.

## Interoperabilidade futura

FHIR R4: Patient/Encounter para contexto; DocumentReference/Binary para documentos; DiagnosticReport/Observation para resultados estruturados; ServiceRequest para solicitação; Provenance/AuditEvent para proveniência e eventos, conforme perfis do parceiro. HL7 v2 pode requerer adaptadores para ADT/ORU. Mapear conceitos não comprova conformidade: validar perfis, terminologias, identidades e erros em ambiente autorizado. CPF é identificador potencial, nunca senha ou autorização.

Fonte primária: https://hl7.org/fhir/R4/servicerequest.html. Não existe conexão automatizada com laboratório, hospital, gov.br ou RNDS nesta entrega.
