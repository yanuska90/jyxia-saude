# Como importar dados fictícios na JYXIA

A etapa atual usa somente dados criados do zero para demonstração. Não há acesso aos laboratórios, login de paciente em serviços externos ou importação de laudos reais. Um exame real com nome oculto não é o exemplo sintético proposto aqui.

## Começar sem baixar arquivo

1. Abra a [demo HTTPS](https://yanuska90.github.io/jyxia-saude/demo.html#integracoes).
2. Localize **Importar dados fictícios**.
3. Clique em **Carregar exemplo completo**.
4. Confira o resultado: **7 registros · 2 fontes fictícias · paciente SYN-P01**.
5. Abra **Ver registro original sintético** em um cartão para visualizar o conteúdo de origem.

Não é necessário criar senha para este cenário público, que contém exclusivamente dados fictícios preparados pelo projeto. Também é possível usar os botões de laboratório e hospital separadamente: o laboratório adiciona 2 registros e o hospital adiciona 5.

## Importar o arquivo pronto

1. Na mesma seção, abra **Quero importar pelo arquivo de exemplo**.
2. Clique em **Baixar paciente-ficticio-01.json** e salve o arquivo no aparelho. JSON é o formato de arquivo que organiza os registros; não é necessário saber programar para usar o exemplo.
3. No campo **Arquivo fictício fornecido pela JYXIA**, selecione o arquivo baixado.
4. Clique em **Importar arquivo fictício**.
5. Confira os mesmos 7 registros e 2 fontes. Importar novamente não deve criar duplicatas.

Não altere o arquivo: este importador aceita exclusivamente o pacote fornecido, de até 256 KB. Outros arquivos, outros pacientes ou conteúdo modificado são rejeitados. Essa restrição é intencional para a demonstração desta etapa. Não é importador genérico de prontuários ou FHIR.

## Conteúdo do exemplo

| Origem inventada | Registro |
|---|---|
| Laboratório fictício A | Um resultado de exame com unidade, intervalo e método fictícios |
| Laboratório fictício A | Um laudo que referencia esse resultado |
| Hospital fictício B | Um atendimento |
| Hospital fictício B | Uma alergia relatada |
| Hospital fictício B | Uma condição preexistente |
| Hospital fictício B | Um procedimento anterior |
| Hospital fictício B | Um medicamento fictício informado |

Tudo pertence a **SYN-P01**. Não há nome, CPF válido, telefone, endereço ou identidade de uma pessoa real. A busca demonstrativa aceita apenas **000.000.000-00**, que não é CPF válido e não concede autorização.

As datas, valores, substâncias e instituições são fictícios e não têm significado clínico. Ausência de informação não significa ausência de alergia, normalidade ou liberação para atendimento. O resumo pré-escrito da demo não é atualizado automaticamente por esses registros.

## Criar registros fictícios próprios e testar anexos

Use **Adicionar registros e anexos**, crie seu usuário e uma senha exclusiva para a demonstração e escolha o tipo de registro. O cofre local não tem recuperação de senha; guarde seu acesso. Não reutilize senhas de serviços reais.

Exemplo para teste manual:

- Tipo: Exame ou laudo.
- Título: Exame fictício de demonstração.
- Data do registro: 14/11/2026.
- Origem: Laboratório fictício A — material de teste.
- Observações: Conteúdo inteiramente inventado, sem validade clínica.
- Anexo: anexo-ficticio-01.txt, fornecido pelo projeto.

O campo de anexos guarda o arquivo; não extrai nem interpreta resultados automaticamente. O JSON de importação usa o campo próprio de importação, não o campo de anexos do cadastro.

## Onde os dados ficam

| Uso | Armazenamento |
|---|---|
| Botões e arquivo de importação sintética | Somente memória desta aba. Desaparece ao recarregar; basta carregar novamente. |
| Cadastro manual e anexos | Cofre criptografado neste navegador depois de criar o acesso. Não sincroniza com outro dispositivo. |
| Ambiente Docker de desenvolvimento | Mecanismo separado, restrito a testes sintéticos; a demo pública não envia seus arquivos para esse banco. |

O importador não envia o conteúdo do arquivo selecionado para hospitais, laboratórios, GitHub ou IA. Ele consulta apenas o catálogo público do próprio site e compara o arquivo com o exemplo aprovado. Arquivos rejeitados não são exibidos nem persistidos.

## Limite atual e apresentação ao Hack Brasil

Esta versão demonstra **um paciente fictício**, com duas origens. Ainda não é cadastro de vários pacientes nem segregação clínica entre eles. Não use este pacote para criar pacientes reais ou afirmar que há integração ativa com instituições.

Texto para a apresentação: “Nesta demonstração, reunimos sete registros inteiramente fictícios de duas fontes simuladas no histórico do paciente SYN-P01. A origem de cada informação permanece visível e a reimportação não duplica registros. A integração com instituições reais é uma etapa futura.”

O pacote paciente-ficticio-01.json é um formato próprio da demonstração, baseado nos exemplos normalizados do projeto. Os arquivos lab-demo.json e hospital-demo.json continuam sendo os exemplos de Bundle do subconjunto FHIR usados no ambiente técnico; eles não são o arquivo aceito pelo novo campo público.
