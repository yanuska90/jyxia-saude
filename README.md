# JYXIA Inteligência Documental em Saúde

Versão 3.1.0 · Documentação sincronizada em 20 de novembro de 2026 · Yanuska e João.

A JYXIA é uma camada administrativa de conferência e organização de documentos externos em saúde, complementar ao prontuário eletrônico (PEP), com vinculação visual à página original e revisão humana obrigatória. O primeiro recorte em investigação é a **conferência documental para procedimentos eletivos**; a eventual combinação com preparação documental para solicitação de autorização prévia está em avaliação comparativa junto a equipes e decisores, sem validação comercial concluída até esta data.

- [Site HTTPS](https://yanuska90.github.io/jyxia-saude/)
- [Demo documental HTTPS](https://yanuska90.github.io/jyxia-saude/demo.html)
- [Projeto completo em DOCX](Projeto_JYXIA_Inteligencia_Documental_v3.docx)
- [Exemplos fictícios para baixar](fixtures-jyxia.zip)

## O que funciona nesta versão (`3.1.0`)

1. Adicione um dos **`8` cenários** ou anexe arquivos do catálogo fechado (`14` fixtures em [`fixtures-jyxia.zip`](fixtures-jyxia.zip) listados em [`documental-manifest.json`](documental-manifest.json)). Arquivos fora do catálogo têm entrada recusada por SHA-256 antes do parsing por política da demonstração pública.
2. Para PDFs sintéticos com camada de texto, o **Mozilla PDF.js `6.5.438`** lê o conteúdo localmente e calcula dinamicamente as coordenadas `[x, y, w, h]` na página (`extractPdfLines`), enquanto regras determinísticas por prefixo extraem até **`10` campos textuais** (`Tipo`, `Subfamília`, `Paciente`, `Nascimento`, `Identificador`, `Emissão`, `Procedimento`, `Código documental` quando presente, `Lateralidade` e `Origem`) mais a detecção literal de marca visual (`MARCA FICTICIA`). “Ver fonte” destaca o trecho na página original.
3. Os **quatro eixos determinísticos de consistência** (**Identidade cadastral**, **Procedimento informado**, **Lateralidade** e **Temporalidade e versões**) apontam divergências bloqueantes (como `OD × OE` no cenário 8 ou troca de cadastro em documento revisado), contradições no mesmo arquivo ou abstenção explícita por evidência ausente/incompleta, sem inferência clínica.
4. Confira identidade, data de emissão (correções exigem justificativa de 5 a 500 caracteres preservando o valor original), lateralidade e área de assinatura. **Uma marca gráfica aparente não autentica assinatura nem valida certificado digital.**
5. Acompanhe pendências com responsável fictício (`Revisor A` / `Revisor B`), prazo e justificativa, confirme substituições explícitas dentro da mesma subfamília documental sem ciclos, retire documentos com histórico preservado e gere o resumo administrativo padronizado para retorno ao emissor.
6. Exporte a sessão em **JSON** desacoplado ou **CSV** (com BOM UTF-8 no download e neutralização contra injeção de fórmulas em células iniciadas por tabulação ou espaços/NBSP seguidos de `=`, `+`, `-`, `@`), além de conferir localmente o encadeamento SHA-256 dos eventos em memória. Não se trata de auditoria institucional imutável.

As regras são administrativas e versionadas (`policy.version`). A referência do exemplo é `14/11/2026`, com procedimento fictício previsto em `30/11/2026` e janela inicial de `30` dias calculada em UTC (`diffDaysISO`) para a data do laudo. “Documentação conferida (regras do exemplo)” não libera cirurgia nem substitui decisão clínica ou de operadora.

## Estado real, lacunas e limites

- **Sem OCR nem IA nesta versão:** arquivos de imagem (`imagem-ilegivel.png`) ou PDFs sem camada de texto selecionável recebem `readable = false` e ficam em quarentena/abstenção para reenvio ou conferência manual.
- **Execução estritamente local e volátil:** o protótipo funciona na memória da aba, sem backend persistente, banco PostgreSQL, armazenamento S3, autenticação OIDC/MFA ou integração ativa com MV, Tasy (Bionexo), RNDS ou operadoras. Importar `casos-ficticios.csv`/`.json` valida apenas o cadastro sintético permitido por hash. **Não insira dados reais de pacientes em nenhum campo ou observação.**
- **Validação de mercado e regulatória pendentes:** ainda não foram executadas entrevistas com usuários/compradores (`0`), testes em hospitais (`0`), contratos comerciais (`0`), busca/registro oficial da marca pretendida **JYXIA** no INPI, nem parecer jurídico LGPD/DPA ou parecer técnico-regulatório ANVISA (RDC nº 657/2022). As métricas automatizadas atuais validam apenas o comportamento determinístico sobre os exemplos conhecidos de desenvolvimento. Veja [arquitetura](ARQUITETURA.md), [segurança](SEGURANCA.md), [dados fictícios](DADOS_FICTICIOS.md) e [validação](VALIDACAO_DOCUMENTAL.md).

## Como executar e testar

Para desenvolvimento local, sirva por HTTP com Python 3 (abrir `demo.html` diretamente via `file://` bloqueia módulos ES e worker PDF.js):

```sh
python serve_documental.py --bind 127.0.0.1 --port 8000
node --test test_documental.mjs test_documental_pdfjs.mjs
python check_publication.py
node test_documental_e2e.mjs
```

*(Observação: `node test_documental_e2e.mjs` requer Chromium/Edge instalado localmente ou caminho via `JYXIA_BROWSER_BIN`. O workflow `.github/workflows/pages.yml` publica uma lista explícita de `27` arquivos estáticos em `main`/`workflow_dispatch`, excluindo servidor local, testes e arquivos v2.x.)*

Testes históricos preservados da versão anterior v2.x (executados isoladamente para regressão):

```sh
node --test test_security.cjs test_synthetic_import.cjs
python -m unittest test_integration.py -v
```

Alternativa Docker para a demo documental estática (usuário sem privilégios, somente leitura, porta vinculada a `127.0.0.1`, sem banco):

```sh
docker compose -f compose.documental.yaml up --build
```

## Origem e equipe

A ideia surgiu quando eu, Yanuska, vivenciei um câncer há cerca de seis anos. Meus exames não estavam reunidos e eu precisava repetir minha história nos atendimentos. Também recebi um medicamento ao qual tinha alergia. Essa experiência mostrou a importância de informações acessíveis, organizadas e disponíveis para quem cuida do paciente.

Conheci o João durante a faculdade e compartilhei a ideia. Aprendemos muito juntos ao longo deste ano. Hoje dividimos a responsabilidade e o compromisso de investigar, validar em campo e construir a JYXIA com disciplina e evidências reais antes de escalar. *(Este relato registra a motivação humana fundadora, não substitui validação clínica ou comercial.)*

## Estratégia e histórico

- O núcleo atual prioriza conferência documental administrativa em procedimentos eletivos, mantendo acessibilidade como requisito contínuo. Teleconsulta, prescrições, prontuário único nacional e predição clínica ficam fora do escopo do produto.
- `demo-v2.html` e seus módulos/APIs históricos (`app.py`, `compose.yaml`) permanecem preservados para rastreabilidade e regressão, sem compor o fluxo documental `3.1.0`.
- Os materiais completos de revisão estratégica e descoberta permanecem em documentação interna de governança para evitar confundir hipóteses e análises em curso com entregas implementadas no repositório público.

## Hack Brasil

Trilha pretendida: Saúde & bem-estar. [Regulamento oficial](https://hackbrasil.com/regulamento) (prazo até `30/11/2026 às 23h59`; critérios com pesos iguais: execução técnica, implementação técnica, impacto e comunicação; exigência de dados sintéticos em saúde). Roteiro e checklist em [Submissao_e_video_JYXIA.txt](Submissao_e_video_JYXIA.txt). Vídeo, aceites e elegibilidade final do histórico Git dependem de conferência e ação da equipe.

## Dependência de terceiros e licenciamento

Mozilla PDF.js `6.5.438`, distribuído localmente em `vendor/` sob licença Apache 2.0 ([`vendor/PDFJS-LICENSE.txt`](vendor/PDFJS-LICENSE.txt)), com integridade descrita em [DEPENDENCIAS.md](DEPENDENCIAS.md). Nenhuma dependência externa ou API de IA recebe documentos nesta versão. A definição de licença própria para o código-fonte da JYXIA permanece pendente de decisão dos fundadores.
