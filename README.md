# JYXIA

Plataforma proposta de acesso e continuidade do cuidado em saúde, com teleconsultas, histórico integrado, exames, avaliação de receitas, terapias e IA assistiva. Materiais preparados para apresentação ao Hack Brasil na trilha Saúde & bem-estar, conforme painel fornecido pelo time.

## Versão do projeto

Versão 2.0 — acesso e continuidade do cuidado. Site e demonstração são publicados automaticamente pelo GitHub Pages a partir dos arquivos da versão principal deste repositório.

## Acessos públicos

- Site: https://yanuska90.github.io/jyxia-saude/
- Demo: https://yanuska90.github.io/jyxia-saude/demo.html
- Repositório: https://github.com/yanuska90/jyxia-saude

## Origem

A ideia nasceu da experiência pessoal de uma pessoa do time que teve câncer há cerca de seis anos. Ela relata exames dispersos, repetição de seu histórico em diferentes consultas e recebimento de medicamento ao qual tinha alergia. A divulgação de câncer e alergia foi autorizada sem identificação de médicos ou serviços. Essa experiência deu origem ao JYXIA e ao desejo de tornar o cuidado mais integrado, ágil e acessível.

## Nossa parceria

A parceria do JYXIA começou na faculdade, quando a ideia foi compartilhada com João. Ao longo deste ano, os dois aprenderam muito juntos. Hoje, compartilham a responsabilidade e o sonho de fazer o projeto acontecer e contribuir para uma saúde mais ágil e acessível, que chegue a todos os cantos e às pessoas que precisam de cuidado.

## Problema e proposta

O JYXIA busca facilitar acesso a profissionais e continuidade entre consulta, exame e acompanhamento. O portal reúne histórico com fontes e datas, solicitações e próximas ações. Acessibilidade, baixa conectividade e uso por celular orientam o projeto. Benefícios de eficiência e segurança ainda precisam ser validados.

## Estado da implementação

Esta versão contém página e demonstração estática interativa com quatro fluxos de serviços simulados: teleconsulta, exame, avaliação de renovação de receita e terapia. Consulta quatro registros sintéticos, carrega um resumo pré-escrito e permite editar, aprovar, rejeitar e simular falha. O histórico existe apenas na aba e desaparece ao recarregar. **Não há IA generativa, autenticação clínica, integração hospitalar, RNDS ou auditoria protegida implementadas.** Não usar para assistência ou inserir dados reais.

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

Nenhum upload, analytics ou serviço de IA é utilizado na demo. A hospedagem pode manter logs técnicos. Dados fictícios são identificados como sintéticos. Autorização, criptografia, retenção e regulação clínica são requisitos do produto futuro.

## Materiais e direitos

Consultar o DOCX, o prompt mestre e o arquivo de submissão e vídeo na raiz deste repositório. Confirmar nomes e papéis da equipe antes da submissão. Nenhuma licença aberta é presumida; direitos de terceiros e licença final precisam ser revisados pelo time.
