# JYXIA

Plataforma proposta de acesso e continuidade do cuidado em saúde, com teleconsultas, histórico integrado, exames, avaliação de receitas, terapias e IA assistiva. Materiais preparados para apresentação ao Hack Brasil na trilha Saúde & bem-estar, conforme painel fornecido pelo time.

## Versão do projeto

Versão 2.2 — acesso, continuidade, registros e anexos com cofre local e cadastro de teleconsulta. Site e demonstração são publicados automaticamente pelo GitHub Pages a partir dos arquivos da versão principal deste repositório.

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

Esta versão contém página e demonstração estática interativa com quatro fluxos de serviços simulados: teleconsulta, exame, avaliação de renovação de receita e terapia. Consulta quatro registros sintéticos, carrega um resumo pré-escrito e permite editar, aprovar, rejeitar e simular falha. O histórico existe apenas na aba e desaparece ao recarregar. A demo também permite cadastrar medicamento, dosagem informada, data, origem, observações e anexos. Os registros manuais e anexos ficam criptografados no navegador após criar o acesso local neste site público. Esse cofre não é autenticação clínica ou segregação de pacientes no servidor. **Não há IA generativa, autenticação clínica, integração hospitalar, RNDS ou auditoria protegida implementadas.** Não usar para assistência ou inserir dados reais.

## Como executar

Use a URL pública HTTPS. Para desenvolver e testar a criptografia em uma origem local segura, com Python 3 disponível:

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

Na demo pública, os anexos são guardados no navegador, sem envio a servidor. Não há analytics ou serviço de IA. A hospedagem pode manter logs técnicos. Dados fictícios são identificados como sintéticos. Autorização clínica, gestão de chaves no servidor, retenção e regulação são requisitos do produto futuro. A criptografia local desta versão e seus limites estão descritos em SEGURANCA.md.

## Materiais e direitos

Consultar o DOCX, o prompt mestre e o arquivo de submissão e vídeo na raiz deste repositório. Confirmar nomes e papéis da equipe antes da submissão. Nenhuma licença aberta é presumida; direitos de terceiros e licença final precisam ser revisados pelo time.

## Registros e anexos e ambiente Docker

Use a seção **Adicionar registros e anexos** na demo para cadastrar, editar e remover registros fictícios e baixar anexos. Use PDF, PNG, JPG ou TXT, até 5 arquivos por registro e 10 MB por arquivo. Registros persistem neste navegador mesmo ao reiniciar o cenário. O resumo de exemplo não incorpora os novos registros automaticamente.

A raiz inclui Dockerfile, compose.yaml, app.py, requirements.txt e .env.example. O ambiente Docker serve a interface com API FastAPI, MongoDB (NoSQL) e GridFS para anexos. Leia **ARQUITETURA.md** para execução, autenticação de teste, endpoints e limites. O banco e a API ainda não estão hospedados em produção. MySQL não é necessário para esta primeira implementação.


## Cadastro de alergias

Use o botão **Adicionar alergia** no cadastro ou **Cadastrar alergia** no cenário. Informe a substância ou medicamento, reação se conhecida, gravidade relatada (pode permanecer desconhecida), data, origem, observações e anexos. É possível editar ou remover depois. Dosagem não é exigida para alergia. Os registros são informados manualmente e sujeitos a avaliação profissional; não atualizam automaticamente o resumo pré-escrito do cenário. Na demo pública, ficam somente neste navegador.


## Doenças preexistentes e cirurgias anteriores

O cadastro inclui os tipos Doença preexistente e Cirurgia anterior e botões diretos para cada um. Nome, data do registro e fonte são obrigatórios. Data do diagnóstico ou cirurgia e instituição são opcionais, para evitar inventar informações desconhecidas. Doenças têm situação relatada. Todos permitem observações, anexos e edição. Dados são informados manualmente e não constituem diagnóstico ou validação clínica.


### Busca por CPF na demonstração
O formulário aceita exclusivamente o identificador fictício `000.000.000-00` para localizar o cenário SYN-P01. Outros valores não retornam paciente. O campo não envia requisições, não persiste a entrada e é limpo após a busca. Não consulta instituições nem implementa autenticação ou autorização. A demonstração tem um único paciente; não oferece segregação entre pacientes reais.

## Integração de fontes sintéticas
A demo reúne sete registros de duas instituições fictícias, com origem e versão preservadas. Veja INTEGRACOES.md para contrato, testes, API e limitações. Delboni e Hospital São Luiz são contatos indicados para possível piloto, sem conexão ou parceria confirmada.


## Acesso protegido, portais e teleconsulta

Na área de registros, crie um usuário local e uma senha exclusiva, sem reutilizar credenciais de laboratórios. Registros anteriores só passam a ser criptografados ao concluir essa configuração no próprio navegador. Use o botão de bloqueio ao terminar. Não há recuperação de senha ou sincronização; use somente dados fictícios. Leia [SEGURANCA.md](SEGURANCA.md).

O acesso provisório aos laboratórios está documentado em [ACESSO_ASSISTIDO.md](ACESSO_ASSISTIDO.md). Os links oficiais abrem o Delboni/Nav Dasa e a Rede D’Or, mas não conectam contas nem importam exames automaticamente. Senhas, códigos e laudos não devem entrar no GitHub.

O tipo **Teleconsulta** permite salvar data, horário de Brasília, profissional/clínica, especialidade, observações e endereço de uma sala Daily de teste. O link é guardado dentro do cofre; abrir a sala é uma navegação externa. Isso não cria nem confirma uma consulta. A criação de salas privadas e acessos temporários via servidor está especificada em [TELECONSULTA.md](TELECONSULTA.md).

Para verificar o núcleo criptográfico e a validação de links, com Node.js 22 ou superior: `node --test test_security.cjs`. Os testes usam exclusivamente valores fictícios e não abrem o armazenamento pessoal do usuário.
