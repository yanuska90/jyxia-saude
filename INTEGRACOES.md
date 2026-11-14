# Integrações JYXIA — ambiente sintético

Esta versão implementa um núcleo de ingestão de um subconjunto FHIR R4, com dois emissores fictícios. Não é servidor FHIR completo, não é certificado e não conecta instituições reais. Os registros manuais continuam separados dos importados.

## O que funciona nesta versão

- Busca na interface pelo identificador deliberadamente inválido `000.000.000-00`, retornando somente SYN-P01. Não é autenticação e não consulta CPF real.
- Importação visual de sete registros de laboratório e hospital fictícios na mesma jornada; reimportação sem duplicação durante a sessão. Esses exemplos somem ao recarregar.
- Normalização de Bundle `collection` com Observation, DiagnosticReport, AllergyIntolerance, Condition, Procedure, Encounter e MedicationStatement, limitada aos campos implementados em `integration.py`.
- Correspondência explícita dos identificadores externos Patient/LAB-P01 e Patient/HOSP-P01 com SYN-P01. Nenhuma associação aproximada, por nome ou CPF.
- Preservação do recurso original, emissor, identificador, versão e hash do conteúdo; preservação de unidade, referência e método de resultados. Não converte unidades nem interpreta valores.
- Rejeição de paciente não mapeado, fonte não autorizada, tipo não suportado, laudo com referência não resolvida e mudança de conteúdo sem mudança de versão.
- Nova versão fica junto da anterior. Avisos são pendências de revisão, não conclusões clínicas nem escolha automática da versão mais recente.
- API Docker: gravação atômica por paciente sintético em um documento MongoDB com revisão otimista e histórico limitado de importações. Limites: 1 MB por lote, 100 recursos por lote, 1.000 versões por paciente e 100 eventos recentes de auditoria. Não representa auditoria clínica imutável.

## Como verificar o núcleo sem dependências externas

Na pasta do projeto, com Python 3.13:

```sh
python -m unittest test_integration.py -v
python integration.py
```

Os testes cobrem duas fontes no mesmo paciente, bloqueio de identidade divergente, origem desconhecida, repetição idempotente, colisão de conteúdo, preservação de versões e do original e referências/tipos não suportados. Não substituem testes de integração com MongoDB e validação de perfis FHIR.

## API de desenvolvimento

Com o ambiente Docker iniciado conforme README, envie `lab-demo.json` como corpo JSON para `POST /api/integrations/lab-demo`, e `hospital-demo.json` para `POST /api/integrations/hospital-demo`, usando o cabeçalho `Authorization: Bearer <chave definida no ambiente local>`. Não coloque chaves no GitHub. `GET /api/integrations` retorna os registros sintéticos e o histórico. Reenvio idêntico retorna duplicatas sem multiplicar registros. Colisão de versão retorna 409; entrada inválida ou identidade não mapeada retorna 422.

A interface pública usa fixtures normalizadas e não chama essa API. O cadastro manual na API continua limitado a SYN-P01. A chave compartilhada é exclusivamente de desenvolvimento; não há identidade individual, consentimento operacional ou autorização clínica. Não exponha essa API com dados reais.

## Próxima integração institucional

Yanuska indicou contatos no Delboni e no Hospital São Luiz. Não há parceria, credenciamento, acesso, documentação ou conexão confirmados. Confirmar unidade e pessoa responsável antes de atribuir qualquer integração a essas instituições.

Solicitar ao responsável técnico, sem dados de pacientes:

1. Nome e versão do sistema de laboratório/prontuário e fornecedor responsável pela interface.
2. Documentação oficial de APIs ou mensagens, versão FHIR/HL7, perfis, terminologias e exemplos sintéticos.
3. Ambiente de homologação, autenticação prevista, escopos e processo de liberação de acesso por canal seguro.
4. Identificadores de paciente, exame e atendimento; regras para correção, cancelamento, versão e duplicidade.
5. Mecanismo de atualização, paginação, limites de uso, confirmação de recebimento e recuperação após falha.
6. Responsabilidades sobre os dados, base legal aplicável, contratos, retenção, atendimento a titulares e resposta a incidentes.

## Etapas que ainda precisam ser implementadas e validadas

Conector específico autorizado; HL7 v2 (ainda não há parser ou transporte); consulta incremental e filas com retentativa; gestão de identidades e permissões por paciente/instituição; reconciliação clínica assinada; terminologias e perfis brasileiros; auditoria protegida e retenção; backup e recuperação; gestão de segredos; proteção contra abuso; testes de invasão; OCR com conferência; integração pública eventualmente elegível; avaliação de IA e governança clínica. Não há diagnóstico automático, prescrição, agendamento ou decisão terapêutica.

Antes do piloto real, exigir: zero mistura de pacientes no conjunto de validação; original e fonte rastreáveis em todos os registros; reenvio sem duplicação; correção sem apagar história; acesso negado fora do escopo; trilha de acesso verificável; recuperação de falhas demonstrada; aprovação institucional, jurídica, de segurança e clínica. Definir metas de prazo e disponibilidade com o parceiro, sem inventar SLA.

## Referências técnicas

- [HL7 FHIR R4 — Bundle](https://hl7.org/fhir/R4/bundle.html)
- [HL7 FHIR R4 — Observation](https://hl7.org/fhir/R4/observation.html)
- [HL7 FHIR R4 — DiagnosticReport](https://hl7.org/fhir/R4/diagnosticreport.html)

FHIR R4 foi escolhido como base do protótipo; a versão, os perfis e as terminologias de cada integração serão confirmados com o parceiro. Preservar recursos não equivale a validar conformidade completa.

## Verificação em 14/11/2026
Nove testes do núcleo passaram. Ambiente Docker com MongoDB executado: autenticação, ingestão das duas fontes, reenvio idempotente, rejeição de paciente divergente, colisão de conteúdo, nova versão e consulta do histórico passaram. Após reiniciar aplicação e banco, as oito versões sintéticas e quatro eventos de importação permaneceram disponíveis. Nenhum sistema institucional foi acessado. O ambiente de teste foi parado após a verificação.


## Revisão de segurança 2.2
Foram acrescentados rejeição de identificador ambíguo, validação do tipo de valueQuantity e cálculo de avisos antes da gravação. O núcleo agora possui 11 testes. O fluxo assistido sem API institucional está descrito em ACESSO_ASSISTIDO.md, sem coleta de senha de laboratórios na demo.
