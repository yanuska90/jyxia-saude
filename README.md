# JYXIA Inteligência Documental em Saúde

Versão 3.1.0 · 19 de novembro de 2026 · Yanuska e João.

A JYXIA organiza documentos, mostra a origem de informações e acompanha pendências com revisão humana. O primeiro módulo é a **conferência documental para procedimentos eletivos**. A hipótese de valor é reduzir procura, redigitação e retrabalho; ainda não há benefício operacional ou clínico validado.

- [Site HTTPS](https://yanuska90.github.io/jyxia-saude/)
- [Demo documental HTTPS](https://yanuska90.github.io/jyxia-saude/demo.html)
- [Projeto completo em DOCX](Projeto_JYXIA_Inteligencia_Documental_v3.docx)
- [Exemplos fictícios para baixar](fixtures-jyxia.zip)

## O que funciona

1. Adicione um dos oito cenários ou anexe os arquivos fornecidos (`14` fixtures em `fixtures-jyxia.zip`). O conteúdo deve corresponder ao catálogo sintético por SHA256; arquivos pessoais ou modificados são recusados.
2. A demo extrai texto de PDFs com PDF.js, localiza os atributos documentais suportados (`Tipo`, `Subfamília`, `Paciente`, `Nascimento`, `Identificação`, `Emissão`, `Procedimento`, `Lateralidade`, `Origem` e marca visual em termos). “Ver fonte” destaca o trecho na página original.
3. Os quatro eixos determinísticos de consistência (**Identidade**, **Procedimento**, **Lateralidade** e **Temporalidade/Versões**) apontam conflitos bloqueantes (ex.: `OD × OE` no cenário 8) ou abstenção por ausência de evidência, sem decidir clinicamente.
4. Confira identidade, data, lateralidade e área de assinatura. Correções de data exigem observação e preservam o valor extraído. Uma marca visual não autentica assinatura.
5. Trate pendências, atribua responsável fictício e prazo, e gere o resumo administrativo para retorno ao emissor. Conflitos ativos exigem retirada ou substituição explícita dentro da mesma subfamília documental.
6. Exporte a sessão em **JSON** ou **CSV** (com proteção contra injeção de fórmula) e verifique a sequência de hashes dos eventos. Não se trata de auditoria imutável ou autenticação de autoria.

As regras são administrativas e versionadas. A referência do exemplo é 14/11/2026, com procedimento fictício em 30/11/2026 e janela inicial de 30 dias para a data do laudo. “Sem pendências” não libera procedimento.

## Estado real e limites

O fluxo atual usa **extração determinística de PDFs com texto**, não IA generativa nem OCR de imagens. A imagem fictícia vai para revisão/reenvio. Há um caso sintético; a importação CSV/JSON confirma o cadastro fornecido. Não há busca por CPF real.

Arquivos e alterações permanecem na memória da aba e desaparecem ao recarregar. A demo não envia arquivos ao servidor, não possui login institucional, banco documental persistente, integração hospitalar, RNDS ou assinatura digital. Não inserir dados reais, mesmo nas observações. A hospedagem recebe requisições normais de acesso ao site.

OCR, extração assistida por IA, autenticação, autorização por instituição/caso, processamento isolado e armazenamento privado são próximas fases. Veja [arquitetura](ARQUITETURA.md), [segurança](SEGURANCA.md) e [validação](VALIDACAO_DOCUMENTAL.md).

## Como executar e testar

A banca pode usar diretamente a demo HTTPS, sem instalação. Para desenvolvimento, use um servidor estático local com Python 3 e abra a página servida; abrir o HTML como arquivo não carrega os módulos:

```sh
python serve_documental.py --bind 127.0.0.1 --port 8000
node --test test_documental.mjs test_documental_pdfjs.mjs
python check_publication.py
node test_documental_e2e.mjs
```

*(Observação: `node test_documental_e2e.mjs` requer Chromium/Edge instalado localmente ou caminho definido via `JYXIA_BROWSER_BIN`. A publicação no GitHub Pages usa `.github/workflows/pages.yml` com lista explícita de 27 arquivos públicos, excluindo servidor local, testes e legado v2.x.)*

Testes históricos da versão anterior v2.x (isolados):

```sh
node --test test_security.cjs test_synthetic_import.cjs
python -m unittest test_integration.py -v
```

Alternativa Docker para a demo documental, sem banco ou senha:

```sh
docker compose -f compose.documental.yaml up --build
```

O endereço local serve apenas para desenvolvimento; a entrega pública usa o HTTPS acima. O Docker documental executa um servidor estático restrito aos arquivos de publicação, como usuário sem privilégios, sistema de arquivos somente leitura e porta vinculada a 127.0.0.1. Isso não o torna um ambiente clínico.

## Origem e equipe

A ideia surgiu quando eu, Yanuska, vivenciei um câncer há cerca de seis anos. Meus exames não estavam reunidos e eu precisava repetir minha história nos atendimentos. Também recebi um medicamento ao qual tinha alergia. Essa experiência mostrou a importância de informações acessíveis, organizadas e disponíveis para quem cuida do paciente.

Conheci o João durante a faculdade e compartilhei a ideia. Aprendemos muito juntos ao longo deste ano. Hoje dividimos a responsabilidade e o sonho de fazer a JYXIA acontecer e contribuir para uma saúde mais ágil e acessível.

## Estratégia e histórico

O foco atual segue os quatro materiais enviados pela equipe sobre Clinical Document Intelligence. Acessibilidade continua como requisito transversal. Teleconsulta, prescrições, terapias, vacinas e integração ampla de prontuários ficam fora do primeiro produto e dependem de validação futura ou parceiros.

`demo-v2.html` preserva a demonstração anterior e seus registros locais; não é o produto documental atual. Os módulos antigos de cofre, teleconsulta e API MongoDB permanecem para referência e regressão. `compose.yaml` é o ambiente histórico; `compose.documental.yaml` é a execução recomendada desta versão. Nenhuma migração ou exclusão de registros do navegador foi feita.

## Hack Brasil

Trilha pretendida: Saúde & bem-estar. [Regulamento oficial](https://hackbrasil.com/regulamento), consultado em 14/11/2026: execução técnica, implementação técnica, impacto e comunicação. O roteiro e os campos estão em [Submissao_e_video_JYXIA.txt](Submissao_e_video_JYXIA.txt). Confirmar elegibilidade do histórico do código, prazo e condições no portal antes de enviar. Não houve submissão automática nem gravação do vídeo.

## Dependência de terceiros e licenciamento

PDF.js 6.5.438, distribuído localmente, licença Apache 2.0 em `vendor/PDFJS-LICENSE.txt`. A origem e a integridade do pacote constam em [DEPENDENCIAS.md](DEPENDENCIAS.md). Nenhum CDN ou serviço de IA recebe documentos nesta versão. A definição de licença própria para o código-fonte da JYXIA permanece pendente de deliberação da equipe.
