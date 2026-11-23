# JYXIA Inteligência Documental em Saúde

Versão 3.1.0 · 22 de novembro de 2026 · Yanuska e João.

A JYXIA organiza documentos, mostra a origem de informações e acompanha pendências com revisão humana. O primeiro módulo é a **conferência documental para procedimentos eletivos**. A hipótese de valor é reduzir procura, redigitação e retrabalho; ainda não há benefício operacional ou clínico validado.

- [Site HTTPS](https://yanuska90.github.io/jyxia-saude/)
- [Demo documental HTTPS](https://yanuska90.github.io/jyxia-saude/demo.html)
- [Plano base v3.0 de 14/11/2026 em DOCX](Projeto_JYXIA_Inteligencia_Documental_v3.docx)
- [Exemplos fictícios para baixar](fixtures-jyxia.zip)

## Atualização de 22/11/2026

Site e demo apresentam a versão 3.1.0. A atualização esclarece público, problema e estado real, acrescenta roteiro de uso e pendências com motivo/próximo passo/atalho para o documento, e aumenta legibilidade e áreas de toque. Os sete cenários e o mecanismo de extração permanecem os mesmos. Não foram acrescentados OCR, modelo de IA, autenticação ou integração clínica.

O plano base em DOCX preserva a edição de 14/11/2026; as mudanças desta versão estão neste README, no site e no CHANGELOG.

## O que funciona

1. Adicione um dos sete cenários ou anexe os arquivos fornecidos. O conteúdo deve corresponder ao catálogo sintético por SHA256; arquivos pessoais ou modificados são recusados.
2. A demo extrai texto de PDFs com PDF.js, localiza nome, nascimento, identificador, emissão, tipo e origem informada. “Ver fonte” destaca o trecho na página original.
3. Confira a identidade, a data e, em termos, a área de assinatura. Correções de data exigem observação e preservam o valor extraído. Uma marca visual não autentica assinatura.
4. Leia o motivo e o próximo passo de cada pendência, abra seu documento de origem e atribua responsável fictício e prazo. Exceções exigem justificativa. Documentos divergentes ficam em quarentena sem vínculo confirmado ao caso.
5. Confirme substituições entre documentos revisados do mesmo tipo; ambos ficam preservados. Arquivos idênticos não geram cópias adicionais.
6. Exporte a sessão em JSON e verifique a sequência de hashes dos eventos. Não se trata de auditoria imutável ou autenticação de autoria.

As regras são administrativas e versionadas. A referência do exemplo é 14/11/2026, com procedimento fictício em 30/11/2026 e janela inicial de 30 dias para a data do laudo. “Sem pendências” não libera procedimento.

## Estado real e limites

O fluxo atual usa **extração determinística de PDFs com texto**, não IA generativa nem OCR de imagens. A imagem fictícia vai para revisão/reenvio. Há um caso sintético; a importação CSV/JSON confirma o cadastro fornecido. Não há busca por CPF real.

Arquivos e alterações permanecem na memória da aba e desaparecem ao recarregar. A demo não envia arquivos ao servidor, não possui login institucional, banco documental persistente, integração hospitalar, RNDS ou assinatura digital. Não inserir dados reais, mesmo nas observações. A hospedagem recebe requisições normais de acesso ao site.

OCR, extração assistida por IA, autenticação, autorização por instituição/caso, processamento isolado e armazenamento privado são próximas fases. Veja [arquitetura](ARQUITETURA.md), [segurança](SEGURANCA.md) e [validação](VALIDACAO_DOCUMENTAL.md).

## Como executar e testar

A banca pode usar diretamente a demo HTTPS, sem instalação. Para desenvolvimento, use um servidor estático local com Python 3 e abra a página servida; abrir o HTML como arquivo não carrega os módulos:

```sh
python -m http.server 8000 --bind 127.0.0.1
node --test test_documental.mjs test_security.cjs test_synthetic_import.cjs
python -m unittest test_integration.py -v
python check_publication.py
```

Alternativa Docker para a demo documental, sem banco ou senha:

```sh
docker compose -f compose.documental.yaml up --build
```

O endereço local serve apenas para desenvolvimento; a entrega pública usa o HTTPS acima. O Docker documental executa um servidor estático restrito aos arquivos de publicação, como usuário sem privilégios, sistema de arquivos somente leitura e porta vinculada a 127.0.0.1. Isso não o torna um ambiente clínico.

## Origem e equipe

A ideia surgiu quando eu, Yanuska, vivenciei um câncer há cerca de seis anos. Meus exames não estavam reunidos e eu precisava repetir minha história nos atendimentos. Também recebi um medicamento ao qual tinha alergia. Essa experiência mostrou a importância de informações acessíveis, organizadas e disponíveis para quem cuida do paciente.

Conheci o João durante a faculdade e compartilhei a ideia. Aprendemos muito juntos ao longo deste ano. Hoje dividimos a responsabilidade e o sonho de fazer a JYXIA acontecer e contribuir para uma saúde mais ágil e acessível.

## Validação e escolhas ainda abertas

Propomos entrevistar inicialmente 3–5 profissionais e comparar a conferência documental com a preparação de pedidos para convênios. A necessidade de autorização de convênio, o segmento inicial e o modelo comercial dependem dessa pesquisa. Não há integração ou autorização automática.

Um conjunto exploratório de cerca de 30 casos sintéticos adicionais deve ficar separado dos exemplos de desenvolvimento. Avaliar valor e significado por campo, localização da fonte, recusas corretas, falsos alertas, tempo total e correções humanas. Comparar com trabalho manual em casos equivalentes. Amostra sem erros observados não comprova risco zero nem desempenho em todos os hospitais.

Procedimento e lateralidade divergentes são cenários candidatos para a próxima rodada; ainda não são campos extraídos pelos sete cenários atuais. Acessibilidade, linguagem clara e alternativa de atendimento assistido permanecem requisitos.

## Estratégia e histórico

O foco atual segue os quatro materiais enviados pela equipe sobre Clinical Document Intelligence. Acessibilidade continua como requisito transversal. Teleconsulta, prescrições, terapias, vacinas e integração ampla de prontuários ficam fora do primeiro produto e dependem de validação futura ou parceiros.

`demo-v2.html` preserva a demonstração anterior e seus registros locais; não é o produto documental atual. Os módulos antigos de cofre, teleconsulta e API MongoDB permanecem para referência e regressão. `compose.yaml` é o ambiente histórico; `compose.documental.yaml` é a execução recomendada desta versão. Nenhuma migração ou exclusão de registros do navegador foi feita.

## Hack Brasil

Trilha pretendida: Saúde & bem-estar. [Regulamento oficial](https://hackbrasil.com/regulamento), consultado em 14/11/2026: execução técnica, implementação técnica, impacto e comunicação. O roteiro e os campos estão em [Submissao_e_video_JYXIA.txt](Submissao_e_video_JYXIA.txt). Confirmar elegibilidade do histórico do código, prazo e condições no portal antes de enviar. Não houve submissão automática nem gravação do vídeo.

## Dependência de terceiros

PDF.js 6.5.438, distribuído localmente, licença Apache 2.0 em `vendor/PDFJS-LICENSE.txt`. A origem e a integridade do pacote constam em [DEPENDENCIAS.md](DEPENDENCIAS.md). Nenhum CDN ou serviço de IA recebe documentos nesta versão.
