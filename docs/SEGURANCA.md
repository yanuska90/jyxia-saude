# Segurança e privacidade da JYXIA 3.2.0

## 1. Fronteira entre Modalidade A (Pública) e Modalidade B (Laboratório Local)

- **Modalidade A — Demo pública (`index.html`, `demo.html`):** estritamente sintética, sem login, sem servidor documental e sem envio de arquivos pela rede. O catálogo de hashes (`documental-manifest.json`, `18` arquivos) recusa qualquer arquivo fora da whitelist SHA-256 antes da leitura textual. Tudo roda apenas na memória da aba e é perdido ao recarregar.
- **Modalidade B — Laboratório experimental local (`lab-local.html`, `lab-local.mjs`, `serve_lab.py`):** estritamente isolado em `localhost` (`serve_lab.py` rejeita bind não-loopback e `assertLocalhostEnvironment()` bloqueia origens externas). **Não compõe o pacote publicado no GitHub Pages e retorna HTTP `404` em `serve_documental.py`**. Aceita apenas PDFs sintéticos (`%PDF-`, até `512 KB` e `10` páginas) sem upload remoto, sem gravação em disco ou armazenamento local (`localStorage`/`IndexedDB`) e sem registrar conteúdo documental em logs. **Proibido utilizar documentos reais de pacientes mesmo em localhost.**

**Controles implementados na entrega atual:**
- Mozilla PDF.js `6.5.438` em `vendor/` com `isEvalSupported: false`; CSP estrita (`default-src 'self'`, `object-src 'none'`, `form-action 'none'`); cabeçalhos HTTP `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` e `frame-ancestors 'none'` nos servidores locais Python;
- Inserção segura via `textContent` (sem HTML dinâmico de texto extraído);
- Neutralização `csvSafeCell()` em exportações CSV contra gatilhos comuns de fórmulas (`=`, `+`, `-`, `@` com espaços/NBSP ou tabulação, sanitização de quebras `\r\n` e remoção de byte nulo `U+0000`) — **observação honesta: ajuda contra interpretações comuns de planilhas, mas não promete proteção universal contra todo software cliente**;
- Cadeia local SHA-256 (`events[]`) verifica integridade da sequência em memória com ator fictício não autenticado (`actorAuthenticated: false`); **não constitui trilha imutável, assinatura digital ou prova criptográfica de autoria**;
- Pacote GitHub Pages (`.github/workflows/pages.yml`) estritamente restrito a `31` arquivos da Modalidade A, verificado por teste automatizado com zero vazamentos do laboratório ou benchmark.

Nenhuma dessas proteções substitui auditoria independente de segurança ou pentest antes da Modalidade C em produção.

## 2. Requisitos antes de tratar dados reais em futuras fases (Modalidade C — não implementada)

- **Governança LGPD e contratos (Lei nº 13.709/2018):** definir formalmente Controlador (instituição de saúde), Operadora (art. 39), bases legais aplicáveis (arts. 7º e 11), minimização, prazos curtos de retenção operacional (guarda legal de 20 anos permanece sob responsabilidade do PEP/instituição contratante sob Lei nº 13.787/2018), direitos dos titulares, Acordo de Processamento de Dados (DPA), Relatório de Impacto (RIPD) e cláusulas para eventuais Suboperadores de nuvem/OCR (transferência internacional arts. 33–36 e distinção entre **ausência de treinamento de modelos** e **armazenamento temporário operacional**). Controles técnicos isolados não comprovam conformidade integral com a LGPD.
- **Comunicação de incidentes (Res. CD/ANPD nº 15/2024):** plano contratual Operadora -> Controlador para suportar análise de **risco ou dano relevante** e eventual comunicação em até 3 dias úteis do conhecimento pelo Controlador.
- **Regulação sanitária, IA e assinaturas:** obter parecer formal perante a **RDC ANVISA nº 657/2022** (art. 1º, § 2º, III), alinhar governança à **Resolução CFM nº 2.454/2026** e respeitar **Lei nº 14.063/2020** (arts. 13 e 14) sobre assinaturas eletrônicas qualificada ICP-Brasil e avançada (lembrando que esta versão faz apenas detecção textual literal sintética, zero validação de assinatura).
- **Segurança aplicacional e upload (OWASP File Upload Cheat Sheet):** autenticação individual com OIDC/MFA, autorização RBAC/ABAC no servidor, armazenamento privado cifrado fora da webroot, sanitização/antivírus/CDR e proteção anti-ZIP bomb quando existir backend institucional.

## 3. Versão histórica preservada

O cofre criptografado de navegador da v2.3 permanece isolado em `demo-v2.html` apenas para regressão histórica (`29` testes legados preservados), sem conexão com a versão `3.2.0`.
