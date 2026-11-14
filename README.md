# JYXIA

Plataforma proposta de acesso e continuidade do cuidado em saúde, com teleconsultas, histórico integrado, exames, avaliação de receitas, terapias e IA assistiva. Materiais preparados para apresentação ao Hack Brasil na trilha Saúde & bem-estar, conforme painel fornecido pelo time.

## Versão do projeto

Versão 2.1 — acesso, continuidade, cadastro de registros e anexos. Site e demonstração são publicados automaticamente pelo GitHub Pages a partir dos arquivos da versão principal deste repositório.

## Acessos públicos

- Site: https://yanuska90.github.io/jyxia-saude/
- Demo: https://yanuska90.github.io/jyxia-saude/demo.html
- Repositório: https://github.com/yanuska90/jyxia-saude

## Origem

A ideia do JYXIA surgiu quando eu, Yanuska, vivenciei um câncer há cerca de seis anos. Durante os atendimentos, meus exames não estavam reunidos e eu precisava repetir minha história e meus sintomas a cada novo médico. Também recebi um medicamento ao qual tinha alergia. Essa vivência me mostrou a importância de um histórico de saúde integrado e acessível à equipe que cuida do paciente.

Essa experiência deu origem ao desejo de tornar o cuidado mais integrado, ágil e acessível.

## Nossa parceria

Conheci o João durante a faculdade e compartilhei com ele a ideia do projeto. Ao longo deste ano, aprendemos muito juntos. Hoje, dividimos a responsabilidade e o sonho de fazer o JYXIA acontecer e contribuir para uma saúde mais ágil e acessível, que chegue a todos os cantos e às pessoas que precisam de cuidado.

## Problema e proposta

O JYXIA busca facilitar acesso a profissionais e continuidade entre consulta, exame e acompanhamento. O portal reúne histórico com fontes e datas, solicitações e próximas ações. Acessibilidade, baixa conectividade e uso por celular orientam o projeto. Benefícios de eficiência e segurança ainda precisam ser validados.

## Estado da implementação

Esta versão contém página e demonstração estática interativa com quatro fluxos de serviços simulados: teleconsulta, exame, avaliação de renovação de receita e terapia. Consulta quatro registros sintéticos, carrega um resumo pré-escrito e permite editar, aprovar, rejeitar e simular falha. O histórico existe apenas na aba e desaparece ao recarregar. A demo também permite cadastrar medicamento, dosagem informada, data, origem, observações e anexos. Os dados ficam no navegador neste site público. **Não há IA generativa, autenticação clínica, integração hospitalar, RNDS ou auditoria protegida implementadas.** Não usar para assistência ou inserir dados reais.

## Como executar

Abra `index.html` no navegador. Para servidor de desenvolvimento opcional, com Python 3 disponível:

```sh
python -m http.server 8080 --directory .
```

Essa opção é apenas para desenvolvimento. Para a submissão, utilizar a URL pública HTTPS publicada, nunca localhost.

## Exemplo e verificação

Abra a demo, consulte SYN-R01 a SYN-R04, carregue o resumo, confira as referências, edite e registre revisão simulada. Teste rejeição e indisponibilidade; as fontes devem continuar acessíveis. Reinicie para limpar o estado. Confira teclado e tela estreita.

## Roadmap

1. Portal acessível, histórico e acompanhamento sintéticos; validar tarefas com usuários.
2. Identidade, autorização, agenda, solicitações e importação FHIR em ambiente autorizado.
3. Operação de teleconsulta com profissionais, vídeo e documentos clínicos homologados.
4. Integração com laboratórios, centros de diagnóstico e rede de terapias; IA assistiva validada.
5. Possíveis integrações públicas conforme elegibilidade e acordos. CPF ajuda na identificação, nunca concede acesso sozinho.
6. Módulos hospitalares e cirúrgicos; pesquisa separada para imagem 3D, predição e monitoramento.

## CPF e serviços públicos

CPF é um possível identificador, não uma senha ou permissão de acesso. Integração de login gov.br, RNDS e operação com SUS são processos distintos e não estão ativos. O projeto é independente, sem vínculo ou parceria governamental confirmada.

## Materiais atualizados

O documento principal é `Projeto_JYXIA_Acesso_e_Continuidade.docx`. O arquivo com o nome anterior também contém a revisão consolidada para preservar os links já compartilhados. Hipóteses e estimativas não são resultados clínicos.

## Dados e segurança

Na demo pública, os anexos são guardados no navegador, sem envio a servidor. Não há analytics ou serviço de IA. A hospedagem pode manter logs técnicos. Dados fictícios são identificados como sintéticos. Autorização, criptografia, retenção e regulação clínica são requisitos do produto futuro.

## Materiais e direitos

Consultar o DOCX, o prompt mestre e o arquivo de submissão e vídeo na raiz deste repositório. Confirmar nomes e papéis da equipe antes da submissão. Nenhuma licença aberta é presumida; direitos de terceiros e licença final precisam ser revisados pelo time.

## Registros e anexos e ambiente Docker

Use a seção **Adicionar registros e anexos** na demo para cadastrar, editar e remover registros fictícios e baixar anexos. Use PDF, PNG, JPG ou TXT, até 5 arquivos por registro e 10 MB por arquivo. Registros persistem neste navegador mesmo ao reiniciar o cenário. O resumo de exemplo não incorpora os novos registros automaticamente.

A raiz inclui Dockerfile, compose.yaml, app.py, requirements.txt e .env.example. O ambiente Docker serve a interface com API FastAPI, MongoDB (NoSQL) e GridFS para anexos. Leia **ARQUITETURA.md** para execução, autenticação de teste, endpoints e limites. O banco e a API ainda não estão hospedados em produção. MySQL não é necessário para esta primeira implementação.
