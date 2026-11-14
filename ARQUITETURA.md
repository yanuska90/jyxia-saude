# Estrutura de registros e anexos do JYXIA

## Duas formas de executar

**Site público no GitHub Pages:** formulário funcional com cofre criptográfico no IndexedDB, usuário/senha locais e bloqueio. A proteção é ativada ao criar o acesso; veja SEGURANCA.md. Medicamento ou título, dosagem transcrita, data, origem, observações e arquivos ficam no navegador e dispositivo utilizados. O usuário pode adicionar, editar, baixar anexos e remover o registro após confirmação. Isso não sincroniza dados entre dispositivos ou usuários. Dados do paciente fictício não são enviados ao GitHub.

**Ambiente Docker de desenvolvimento:** FastAPI serve a mesma interface e uma API protegida por chave de teste; MongoDB armazena registros e GridFS armazena arquivos. A interface muda automaticamente para o modo API e solicita a chave. O MongoDB não expõe porta no computador; somente a aplicação é vinculada a 127.0.0.1:8000. Este endereço é para desenvolvimento, não substitui o site público HTTPS.

## Por que MongoDB

MongoDB já é um banco NoSQL e atende ao modelo documental dos registros. GridFS mantém os anexos fora do documento principal, no mesmo banco. Adicionar MySQL agora duplicaria operação, credenciais e consistência sem um caso de uso definido. MySQL pode ser avaliado quando houver requisitos relacionais de agenda, faturamento ou contratos. Não se promete conformidade FHIR por escolher um banco específico.

## Execução com Docker

1. Inicie o Docker Desktop com engine Linux e confirme `docker version`.
2. Na raiz do repositório, copie `.env.example` para `.env`.
3. Preencha MONGO_PASSWORD com valor alfanumérico próprio e JYXIA_API_TOKEN com chave aleatória de pelo menos 32 caracteres. Não compartilhe ou envie `.env` ao GitHub.
4. Execute `docker compose up --build -d`.
5. Abra http://localhost:8000/demo.html e informe a chave de teste definida em JYXIA_API_TOKEN.
6. A API está documentada em http://localhost:8000/docs. Use o botão Authorize com a mesma chave de teste.
7. Para encerrar sem apagar os dados: `docker compose down`. O volume mongo_data é preservado. Não use `down -v` se quiser manter os registros.

O download de imagens e bibliotecas depende de internet. requirements.txt declara as dependências; requirements-lock.txt fixa as versões resolvidas desta revisão, aplicado no build. As imagens Python e MongoDB também têm digest fixado. Isso melhora a repetibilidade, mas exige atualização e nova análise de vulnerabilidades ao longo do tempo. Não há certificado ou hospedagem de produção incluídos no Compose.

## API

- GET /health: disponibilidade da aplicação e MongoDB.
- GET /api/records: lista até 100 registros do paciente sintético SYN-P01.
- POST /api/records: multipart com campo `record` em JSON e `files` opcionais.
- PUT /api/records/{id}: edição, preserva anexos existentes e exige cabeçalho If-Match com a versão atual.
- DELETE /api/records/{id}: remove registro e arquivos vinculados.
- GET /api/records/{id}/attachments/{file_id}: download autenticado, somente se o arquivo pertence ao registro.

Exemplo do campo `record`, para teste sem dados reais:

```json
{"kind":"medicamento","name":"Medicamento demonstrativo","dosage":"Transcrição do documento fictício","record_date":"2026-11-14","source":"Documento de teste","notes":"Cadastro sintético sem orientação de uso"}
```

## Regras da versão

- Até 100 registros na demonstração e até 5 anexos por registro.
- PDF, PNG, JPG/JPEG e TXT UTF-8; até 10 MB por arquivo.
- A API confere assinatura inicial dos formatos e texto UTF-8; isso não equivale a análise antimalware.
- Campos obrigatórios e limites são validados na interface e API. Dosagem é texto informado, sem cálculo ou recomendação.
- A edição no banco usa versão para rejeitar alteração concorrente.
- Textos são renderizados com textContent; anexos são baixados, sem execução inline.
- Arquivos e cadastro não entram no resumo pré-escrito do cenário. Não há interpretação automática dos anexos.
- O botão Reiniciar cenário limpa apenas a simulação; registros adicionados persistem. Para excluir, use Remover registro e confirme.

## Limites antes de dados reais

O token único é uma autenticação de desenvolvimento, não gestão de usuários ou autorização clínica. O ambiente tem um único paciente sintético e não deve receber dados reais. Antes de uso assistencial: identidade individual e MFA, autorização por instituição/paciente, auditoria protegida, TLS, criptografia e chaves, validação clínica, privacidade, retenção, backup com restauração, varredura de anexos, limite global de requisição, proteção contra abuso e análise regulatória.

O exemplo Mongo usa credencial administrativa somente na rede de desenvolvimento. Produção exige usuário de aplicação com menor privilégio. Escritas entre coleção e GridFS usam limpeza compensatória, sem transação distribuída; recuperação de falhas, arquivos órfãos e exclusão comprovável precisam de implementação e testes antes de produção. Limpar dados do navegador remove os registros locais; não há backup automático na demo pública.

## Referências técnicas

- https://fastapi.tiangolo.com/tutorial/request-files/
- https://www.mongodb.com/docs/languages/python/pymongo-driver/current/crud/gridfs/
- https://docs.docker.com/compose/how-tos/startup-order/


## Cadastro de alergias

Use o botão **Adicionar alergia** no cadastro ou **Cadastrar alergia** no cenário. Informe a substância ou medicamento, reação se conhecida, gravidade relatada (pode permanecer desconhecida), data, origem, observações e anexos. É possível editar ou remover depois. Dosagem não é exigida para alergia. Os registros são informados manualmente e sujeitos a avaliação profissional; não atualizam automaticamente o resumo pré-escrito do cenário. Na demo pública, ficam somente neste navegador.


## Doenças preexistentes e cirurgias anteriores

O cadastro inclui os tipos Doença preexistente e Cirurgia anterior e botões diretos para cada um. Nome, data do registro e fonte são obrigatórios. Data do diagnóstico ou cirurgia e instituição são opcionais, para evitar inventar informações desconhecidas. Doenças têm situação relatada. Todos permitem observações, anexos e edição. Dados são informados manualmente e não constituem diagnóstico ou validação clínica.

## Revisão 2.2
Cadastro de teleconsulta e validação do endereço da sala descritos em TELECONSULTA.md. A API continua com autenticação de teste. Controles implementados, testes e bloqueadores do ambiente real estão em DEVSECOPS.md.
