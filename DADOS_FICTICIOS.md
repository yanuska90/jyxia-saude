# Dados fictícios da demo documental

Baixe `fixtures-jyxia.zip` ou use “Adicionar cenário”. Todos os nomes, identificadores, instituições, documentos e marcas foram criados para demonstração. O caso SYN-P01 não corresponde a pessoa real; não é CPF.

| Cenário | Comportamento esperado |
| --- | --- |
| Conjunto completo | Quatro classes; revisão de cada documento e marca do termo para concluir as regras |
| Duplicado | O segundo arquivo idêntico não cria outro documento |
| Atualizado | Dois laudos distintos, sem substituição automática; revisar ambos e confirmar |
| Identidade divergente | Quarentena e caseId nulo, sem liberação manual do vínculo |
| Identificador ausente | Nome e nascimento compatíveis; confirmação humana obrigatória |
| Imagem sem texto | Sem OCR; quarentena e reenvio |
| Data e marca | Janela administrativa e área de assinatura exigem conferência |
| Lateralidade divergente (`OD × OE`) | Solicitação indica `Olho Direito (OD)` e termo indica `Olho Esquerdo (OE)`; conflito bloqueia conclusão e exige retirada/substituição |

Os PDFs contêm texto, não resultados clínicos. A importação aceita somente bytes exatos do catálogo sintético (`14` arquivos em `documental-manifest.json`); arquivos pessoais ou alterados são recusados por política da demonstração pública (o que não significa que o arquivo seja malicioso nem substitui quarentena técnica de segurança). Conferir e carregar cadastro CSV ou JSON lê e valida apenas o único caso sintético fornecido, sem acrescentar pacientes reais. É uma proteção do protótipo público, não um importador institucional.

Para uma avaliação futura, criar novo conjunto sintético reservado, com variações reais de layout e gabarito revisado, sem dados pessoais. Os oito cenários atuais são testes funcionais conhecidos; não medem acurácia de OCR, IA ou benefício clínico.
