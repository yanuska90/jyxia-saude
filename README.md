# JYXIA

Plataforma proposta de integração de prontuários e IA assistiva para o cuidado perioperatório. Materiais preparados para apresentação ao Hack Brasil na trilha Saúde & bem-estar, conforme painel fornecido pelo time.

## Origem

A ideia nasceu da experiência pessoal de uma pessoa do time que teve câncer há cerca de seis anos. Ela relata exames dispersos, repetição de seu histórico em diferentes consultas e recebimento de medicamento ao qual tinha alergia. A divulgação de câncer e alergia foi autorizada sem identificação de médicos ou serviços. Essa motivação não demonstra que uma IA teria antecipado o diagnóstico ou evitado o episódio.

## Problema e proposta

Informações relevantes ao preparo cirúrgico podem estar em fontes diferentes. O JYXIA propõe organizar origem, datas, conflitos e pendências em um painel com resumo assistido por IA e revisão profissional. Benefícios de eficiência e segurança ainda precisam ser validados.

## Estado da implementação

Esta versão contém página e demonstração estática interativa. Consulta quatro registros sintéticos, carrega um resumo pré-escrito e permite editar, aprovar, rejeitar e simular falha. O histórico existe apenas na aba e desaparece ao recarregar. **Não há IA generativa, autenticação clínica, integração hospitalar, RNDS ou auditoria protegida implementadas.** Não usar para assistência ou inserir dados reais.

## Como executar

Abra `index.html` no navegador. Para servidor de desenvolvimento opcional, com Python 3 disponível:

```sh
python -m http.server 8080 --directory .
```

Essa opção é apenas para desenvolvimento. Para a submissão, utilizar a URL pública HTTPS publicada, nunca localhost.

## Exemplo e verificação

Abra a demo, consulte SYN-R01 a SYN-R04, carregue o resumo, confira as referências, edite e registre revisão simulada. Teste rejeição e indisponibilidade; as fontes devem continuar acessíveis. Reinicie para limpar o estado. Confira teclado e tela estreita.

## Roadmap

1. Validar demonstração sintética e usabilidade.
2. Implementar identidade, isolamento institucional, importação FHIR R4 e auditoria real.
3. Avaliar IA com evidências e revisão clínica independente.
4. Integrar prontuário autorizado e executar piloto supervisionado após aprovações.
5. Teleconsulta, prescrições, vacinas e alertas com requisitos próprios.

## Dados e segurança

Nenhum upload, analytics ou serviço de IA é utilizado na demo. A hospedagem pode manter logs técnicos. Dados fictícios são identificados como sintéticos. Autorização, criptografia, retenção e regulação clínica são requisitos do produto futuro.

## Materiais e direitos

Consultar `docs/` para projeto e prompt quando incluídos. Confirmar nomes e papéis da equipe antes da submissão. Nenhuma licença aberta é presumida; direitos de terceiros e licença final precisam ser revisados pelo time. A configuração `.openai/hosting.json` identifica a hospedagem deste projeto e não deve ser reutilizada para um Site diferente.
