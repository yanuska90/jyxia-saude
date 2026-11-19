# Registro de decisões e versões

## 3.1.0 — 19 de novembro de 2026 (Etapa 2)

Evolução controlada na branch `jyxia-develop` alinhada às diretrizes DE-01 a DE-05 (sem OCR, LLM, decisão clínica ou persistência em servidor):

- Motor determinístico dos 4 eixos de consistência documental (`Identidade`, `Procedimento informado`, `Lateralidade` e `Temporalidade/Versões`) com abstenção explícita e bloqueio de conclusão automática em conflitos.
- Extração estendida dos atributos documentais DE-04 (`subfamily`, `procedure`, `laterality`, `signatureCue` visual não autenticante) com preservação da evidência em página e coordenadas, e trava de substituição entre subfamílias distintas.
- Novo cenário sintético `8 · Lateralidade divergente (OD × OE)` com fixtures `solicitacao-od.pdf` e `termo-oe.pdf` (`14` fixtures no catálogo).
- UX e acessibilidade: preservação de rascunho em ações secundárias (`#assign`, `#rule`, `#verify`), orientação explícita em quarentena/abstenção, prefixo textual em erros (não dependente apenas de cor), `aria-label` dinâmico no canvas PDF, resumo administrativo determinístico de pendências (`buildPendingNotice`) e exportação CSV segura contra injeção de fórmulas (`exportCsv`).
- Suíte expandida para 27 testes automatizados v3 (`test_documental.mjs` + `test_documental_pdfjs.mjs`), E2E real com upload manual e cenário 8 (`test_documental_e2e.mjs`), mantendo integralmente os 29 testes históricos v2.x e o deploy seletivo no GitHub Pages (`27` arquivos permitidos).

## 3.0.0 — 14 de novembro de 2026

Decisão de Yanuska: adotar os quatro arquivos de estratégia documental como base. Identidade JYXIA preservada. Primeiro módulo: conferência documental para procedimentos eletivos. Acessibilidade permanece requisito; teleconsulta e plataforma ampla saem do núcleo inicial.

Implementados: página institucional, demo documental, extração de PDFs com texto, evidência visual, catálogo sintético por hash, sete cenários, revisão/correção, pendências com responsáveis, versões explícitas e exportação. Incluídos testes, execução Docker estática e materiais alinhados. Não implementados: OCR, LLM, backend institucional, conector real e validação clínica/comercial.

Correções de estratégia: rastreabilidade não é exclusiva; cadeia de hashes não é imutabilidade; assinatura visual não é autenticidade; finalidade administrativa não elimina análise regulatória; mapeamento FHIR não é conformidade. Fontes, orçamento hipotético, critérios e referências estão no documento principal.

Preservação: demo anterior em demo-v2.html, códigos e testes históricos mantidos, sem apagar registros locais ou reescrever histórico Git. Nomes antigos de DOCX recebem a versão atual para manter links existentes; o nome canônico é Projeto_JYXIA_Inteligencia_Documental_v3.docx.
