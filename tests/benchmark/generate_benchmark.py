import hashlib
import json
import pathlib

BENCH_DIR = pathlib.Path(__file__).resolve().parent
FIX_DIR = BENCH_DIR / 'fixtures'
MANIFEST_PATH = BENCH_DIR / 'benchmark-manifest.json'
FIX_DIR.mkdir(parents=True, exist_ok=True)


def esc(text: str) -> str:
    return text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')


def to_winansi_bytes(text: str) -> bytes:
    return text.encode('cp1252', errors='replace')


def build_pdf(pages, font='Helvetica', rotate=0, layout='single'):
    """Build multi-layout %PDF-1.4 using specified base font, rotation, and label placements."""
    font_name = font if font in ('Helvetica', 'Courier', 'Times-Roman') else 'Helvetica'
    objects = [
        '<< /F1 2 0 R /F2 3 0 R >>',
        f'<< /BaseFont /{font_name} /Encoding /WinAnsiEncoding /Name /F1 /Subtype /Type1 /Type /Font >>',
        '<< /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding /Name /F2 /Subtype /Type1 /Type /Font >>',
        '',  # placeholder 4 Catalog
        '',  # placeholder 5 Pages
    ]
    page_ids = []
    for p_idx, page_spec in enumerate(pages):
        cmds = ['BT']
        y = 770
        for row in page_spec['rows']:
            kind = row.get('kind', 'line')
            if kind == 'split_cols':
                lbl = row['label']
                val = row['value']
                cmds.append(f'/F2 10 Tf 1 0 0 1 48 {y} Tm ({esc(lbl)}) Tj')
                cmds.append(f'/F1 10 Tf 1 0 0 1 220 {y} Tm ({esc(val)}) Tj')
            elif kind == 'right_col':
                cmds.append(f'/F1 10 Tf 1 0 0 1 300 {y} Tm ({esc(row["text"])}) Tj')
            else:
                cmds.append(f'/F1 10 Tf 1 0 0 1 48 {y} Tm ({esc(row["text"])}) Tj')
            y -= row.get('step', 22)
        cmds.append('ET')
        stream = to_winansi_bytes('\n'.join(cmds) + '\n')
        c_id = len(objects) + 1
        objects.append(b'<< /Length ' + str(len(stream)).encode('ascii') + b' >>\nstream\n' + stream + b'endstream')
        p_id = len(objects) + 1
        rot = page_spec.get('rotate', rotate)
        objects.append(
            f'<< /Contents {c_id} 0 R /MediaBox [ 0 0 595 842 ] /Parent 5 0 R /Resources << /Font 1 0 R >> /Rotate {rot} /Type /Page >>'
        )
        page_ids.append(p_id)

    objects[3] = '<< /Pages 5 0 R /Type /Catalog >>'
    objects[4] = f'<< /Count {len(page_ids)} /Kids [ {" ".join(f"{pid} 0 R" for pid in page_ids)} ] /Type /Pages >>'

    buf = bytearray(b'%PDF-1.4\n% JYXIA Synthetic Benchmark PDF\n')
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(buf))
        buf.extend(f'{i} 0 obj\n'.encode('ascii'))
        buf.extend(obj if isinstance(obj, bytes) else obj.encode('cp1252', errors='replace'))
        buf.extend(b'\nendobj\n')
    xref = len(buf)
    buf.extend(f'xref\n0 {len(objects) + 1}\n0000000000 65535 f \n'.encode('ascii'))
    for off in offsets[1:]:
        buf.extend(f'{off:010d} 00000 n \n'.encode('ascii'))
    buf.extend(f'trailer\n<< /Root 4 0 R /Size {len(objects) + 1} >>\nstartxref\n{xref}\n%%EOF\n'.encode('ascii'))
    return bytes(buf)


CASES = [
    # 1. DEVELOPMENT SPLIT (calibrated patterns)
    {
        'id': 'DEV-01',
        'split': 'development',
        'filename': 'dev-01-padrao-helvetica.pdf',
        'scenario': 'Padrao baseline Helvetica 1 pagina',
        'font': 'Helvetica',
        'rotate': 0,
        'pages': [{
            'rows': [
                {'text': 'Tipo: solicitacao'},
                {'text': 'Subfamilia: Solicitacao cirurgica'},
                {'text': 'Paciente: Pessoa Benchmarking Um'},
                {'text': 'Nascimento: 10/05/1982'},
                {'text': 'Identificador: BM-001'},
                {'text': 'Emissao: 12/11/2026'},
                {'text': 'Origem: Unidade Ficticia Sul'},
                {'text': 'Procedimento: Facoemulsificacao com implante de LIO'},
                {'text': 'Sistema: SIGTAP-FICTICIO'},
                {'text': 'Codigo: 04.05.05.011-9'},
                {'text': 'Lateralidade: Olho Direito (OD)'},
            ]
        }],
        'expected': {
            'patient': {'status': 'extraido', 'value': 'Pessoa Benchmarking Um', 'alias': 'Paciente', 'page': 1},
            'birthDate': {'status': 'extraido', 'value': '10/05/1982', 'alias': 'Nascimento', 'page': 1},
            'identifier': {'status': 'extraido', 'value': 'BM-001', 'alias': 'Identificador', 'page': 1},
            'issueDate': {'status': 'extraido', 'value': '12/11/2026', 'alias': 'Emissao', 'page': 1},
            'type': {'status': 'extraido', 'value': 'solicitacao', 'alias': 'Tipo', 'page': 1},
            'procedure': {'status': 'extraido', 'value': 'Facoemulsificacao com implante de LIO', 'alias': 'Procedimento', 'page': 1},
            'procedureCode': {'status': 'extraido', 'value': '04.05.05.011-9', 'alias': 'Codigo', 'page': 1},
            'procedureCodeSystem': {'status': 'extraido', 'value': 'SIGTAP-FICTICIO', 'alias': 'Sistema', 'page': 1},
            'laterality': {'status': 'extraido', 'normalized': 'direito', 'alias': 'Lateralidade', 'page': 1},
            'origin': {'status': 'extraido', 'value': 'Unidade Ficticia Sul', 'alias': 'Origem', 'page': 1},
        },
    },
    # 2. REGRESSION SPLIT (rotations, multi-page, blank, conflicts, invalid dates)
    {
        'id': 'REG-01',
        'split': 'regression',
        'filename': 'reg-01-rotacionado-90-multipagina.pdf',
        'scenario': 'Documento rotacionado 90 graus com campos em 2 paginas',
        'font': 'Helvetica',
        'rotate': 90,
        'pages': [
            {'rows': [
                {'text': 'Tipo documental: laudo'},
                {'text': 'Nome do paciente: Pessoa Rotacionada Alfa'},
                {'text': 'Data de nascimento: 29/02/2024'},
                {'text': 'ID: BM-REG-01'},
                {'text': 'Emitido em: 01/03/2026'},
            ]},
            {'rows': [
                {'text': 'Instituicao: Servico Ficticio Norte'},
                {'text': 'Procedimento solicitado: Artroscopia de joelho'},
                {'text': 'Regiao lateral: Lado esquerdo'},
            ]},
        ],
        'expected': {
            'patient': {'status': 'extraido', 'value': 'Pessoa Rotacionada Alfa', 'alias': 'Nome do paciente', 'page': 1},
            'birthDate': {'status': 'extraido', 'value': '29/02/2024', 'alias': 'Data de nascimento', 'page': 1},
            'identifier': {'status': 'extraido', 'value': 'BM-REG-01', 'alias': 'ID', 'page': 1},
            'issueDate': {'status': 'extraido', 'value': '01/03/2026', 'alias': 'Emitido em', 'page': 1},
            'type': {'status': 'extraido', 'value': 'laudo', 'alias': 'Tipo documental', 'page': 1},
            'procedure': {'status': 'extraido', 'value': 'Artroscopia de joelho', 'alias': 'Procedimento solicitado', 'page': 2},
            'laterality': {'status': 'extraido', 'normalized': 'esquerdo', 'alias': 'Regiao lateral', 'page': 2},
            'origin': {'status': 'extraido', 'value': 'ServicO'.replace('O', 'o') + ' Ficticio Norte' if False else 'Servico Ficticio Norte', 'alias': 'Instituicao', 'page': 2},
        },
    },
    {
        'id': 'REG-02',
        'split': 'regression',
        'filename': 'reg-02-duplicado-conflito-identidade.pdf',
        'scenario': 'Campos duplicados com divergencia critica de identidade e lateralidade',
        'font': 'Courier',
        'rotate': 180,
        'pages': [{
            'rows': [
                {'text': 'Tipo: termo'},
                {'text': 'Paciente: Pessoa Beta Um'},
                {'text': 'Nome completo: Pessoa Beta Dois'},
                {'text': 'Nascimento: 15/08/1990'},
                {'text': 'Identificador: BM-REG-02'},
                {'text': 'Emissao: 10/11/2026'},
                {'text': 'Procedimento: Colecistectomia videolaparoscopica'},
                {'text': 'Lado: Direito'},
                {'text': 'Lateralidade: Esquerdo'},
                {'text': 'Origem: Unidade Ficticia Centro'},
            ]
        }],
        'expected': {
            'patient': {'status': 'ambiguo'},
            'laterality': {'status': 'ambiguo'},
            'procedure': {'status': 'extraido', 'value': 'Colecistectomia videolaparoscopica', 'alias': 'Procedimento', 'page': 1},
        },
    },
    {
        'id': 'REG-03',
        'split': 'regression',
        'filename': 'reg-03-sem-camada-texto.pdf',
        'scenario': 'PDF sem texto extraivel (abstencao total sem OCR)',
        'font': 'Helvetica',
        'rotate': 0,
        'pages': [{'rows': []}],
        'expected': {
            'readable': False,
            'patient': {'status': 'abstencao'},
            'laterality': {'status': 'abstencao'},
            'procedure': {'status': 'abstencao'},
        },
    },
    # 3. RESERVED EVALUATION SPLIT (diverse synthetic templates, fonts, tabular col, spaces, accents, dates, unlabeled)
    {
        'id': 'EVAL-01',
        'split': 'reserved_evaluation',
        'filename': 'eval-01-tabular-times-acentos.pdf',
        'scenario': 'Layout tabular em duas colunas com Times-Roman e acentuacao',
        'font': 'Times-Roman',
        'rotate': 0,
        'pages': [{
            'rows': [
                {'kind': 'split_cols', 'label': 'Tipo documental:', 'value': 'avaliacao'},
                {'kind': 'split_cols', 'label': 'Nome completo:', 'value': 'Conceição de São João Fictícia'},
                {'kind': 'split_cols', 'label': 'Data de nascimento:', 'value': '03/01/1975'},
                {'kind': 'split_cols', 'label': 'Código do paciente:', 'value': 'BM-EV-01'},
                {'kind': 'split_cols', 'label': 'Data de emissão:', 'value': '11/11/2026'},
                {'kind': 'split_cols', 'label': 'Unidade:', 'value': 'Ambulatório Fictício Esperança'},
                {'kind': 'split_cols', 'label': 'Procedimento solicitado:', 'value': 'Hernioplastia inguinal unilateral sem prótese com descrição extensa demonstrativa'},
                {'kind': 'split_cols', 'label': 'Código do procedimento:', 'value': '04.07.04.010-2'},
                {'kind': 'split_cols', 'label': 'Tabela:', 'value': 'SIGTAP-FICTICIO'},
                {'kind': 'split_cols', 'label': 'Região lateral:', 'value': 'Lado direito'},
            ]
        }],
        'expected': {
            'patient': {'status': 'extraido', 'value': 'Conceição de São João Fictícia', 'alias': 'Nome completo', 'page': 1},
            'birthDate': {'status': 'extraido', 'value': '03/01/1975', 'alias': 'Data de nascimento', 'page': 1},
            'identifier': {'status': 'extraido', 'value': 'BM-EV-01', 'alias': 'Codigo do paciente', 'page': 1},
            'issueDate': {'status': 'extraido', 'value': '11/11/2026', 'alias': 'Emissao', 'alias_any': ['Data de emissao', 'Emissao'], 'page': 1},
            'procedure': {'status': 'extraido', 'value': 'Hernioplastia inguinal unilateral sem prótese com descrição extensa demonstrativa', 'alias': 'Procedimento solicitado', 'page': 1},
            'procedureCode': {'status': 'extraido', 'value': '04.07.04.010-2', 'alias': 'Codigo do procedimento', 'page': 1},
            'procedureCodeSystem': {'status': 'extraido', 'value': 'SIGTAP-FICTICIO', 'alias': 'Tabela', 'page': 1},
            'laterality': {'status': 'extraido', 'normalized': 'direito', 'alias': 'Regiao lateral', 'page': 1},
            'origin': {'status': 'extraido', 'value': 'Ambulatório Fictício Esperança', 'alias': 'Unidade', 'page': 1},
        },
    },
    {
        'id': 'EVAL-02',
        'split': 'reserved_evaluation',
        'filename': 'eval-02-courier-sem-rotulo-e-campos-ausentes.pdf',
        'scenario': 'Courier com rotulos ausentes, datas soltas sem rotulo e rotulo desconhecido',
        'font': 'Courier',
        'rotate': 270,
        'pages': [
            {'rows': [
                {'kind': 'right_col', 'text': 'Tipo: laudo'},
                {'kind': 'right_col', 'text': 'Nome do paciente:   Pessoa   Espacos  Ficticia  '},
                {'kind': 'right_col', 'text': 'Nascimento: 30/02/2026'},
                {'kind': 'right_col', 'text': '14/11/2026'},
                {'kind': 'right_col', 'text': '99988877'},
                {'kind': 'right_col', 'text': 'ConvenioNaoCadastrado: Plano Exemplo'},
                {'kind': 'right_col', 'text': 'Origem: Laboratorio Ficticio'},
            ]},
            {'rows': [
                {'text': 'Lado: Nao aplicavel ao procedimento'},
                {'text': 'Emissao: 11/11/2026'},
            ]},
        ],
        'expected': {
            'patient': {'status': 'extraido', 'value': 'Pessoa Espacos Ficticia', 'alias': 'Nome do paciente', 'page': 1},
            'birthDate': {'status': 'abstencao'},
            'identifier': {'status': 'abstencao'},
            'procedure': {'status': 'abstencao'},
            'laterality': {'status': 'extraido', 'normalized': 'nao_aplicavel', 'alias': 'Lado', 'page': 2},
            'issueDate': {'status': 'extraido', 'value': '11/11/2026', 'alias': 'Emissao', 'page': 2},
            'unrecognizedMin': 1,
            'unlabeledMin': 2,
        },
    },
    {
        'id': 'EVAL-03',
        'split': 'reserved_evaluation',
        'filename': 'eval-03-multipagina-3p-duplicidade-identica.pdf',
        'scenario': 'Multi-pagina 3 paginas com repeticao de identificador e espacos irregulares',
        'font': 'Helvetica',
        'rotate': 0,
        'pages': [
            {'rows': [
                {'text': 'Tipo: solicitacao'},
                {'text': 'Nome do paciente: Pessoa Tres Paginas'},
                {'text': 'Nascimento: 01/12/1988'},
                {'text': 'Identificador: BM-EV-03'},
            ]},
            {'rows': [
                {'text': 'Identificador: BM-EV-03'},
                {'text': 'Procedimento solicitado: Artroplastia total de quadril'},
                {'text': 'Codigo: 30724031'},
            ]},
            {'rows': [
                {'text': 'Lateralidade: Ambos os olhos (AO)'},
                {'text': 'Emissao: 14/11/2026'},
                {'text': 'MARCA FICTICIA'},
            ]},
        ],
        'expected': {
            'patient': {'status': 'extraido', 'value': 'Pessoa Tres Paginas', 'alias': 'Nome do paciente', 'page': 1},
            'identifier': {'status': 'ambiguo', 'duplicateIdentical': True},
            'procedure': {'status': 'extraido', 'value': 'Artroplastia total de quadril', 'alias': 'Procedimento solicitado', 'page': 2},
            'procedureCode': {'status': 'extraido', 'value': '30724031', 'alias': 'Codigo', 'page': 2},
            'laterality': {'status': 'extraido', 'normalized': 'bilateral', 'alias': 'Lateralidade', 'page': 3},
            'issueDate': {'status': 'extraido', 'value': '14/11/2026', 'alias': 'Emissao', 'page': 3},
        },
    },
    {
        'id': 'EVAL-04',
        'split': 'reserved_evaluation',
        'filename': 'eval-04-5-paginas-conflito-datas-e-virada-ano.pdf',
        'scenario': 'Documento de 5 paginas com virada de ano, datas conflitantes e marcador na pagina 5',
        'font': 'Times-Roman',
        'rotate': 0,
        'pages': [
            {'rows': [
                {'text': 'Tipo documental: termo'},
                {'text': 'Nome completo: Pessoa Cinco Paginas Acento Águia Conceição'},
                {'text': 'Nascimento: 31/12/1979'},
            ]},
            {'rows': [{'text': 'Identificador: BM-EV-04'}]},
            {'rows': [
                {'text': 'Data de emissao: 31/12/2025'},
                {'text': 'Emitido em: 01/01/2026'},
            ]},
            {'rows': [
                {'text': 'Procedimento solicitado: Colecistectomia aberta'},
                {'text': 'Codigo do procedimento: SIGTAP: 04.07.03.002-6'},
                {'text': 'Lateralidade: Nao aplicavel ao procedimento'},
            ]},
            {'rows': [
                {'text': 'Origem: Hospital Regional Fictício de Demonstração Prolongada'},
                {'text': 'MARCA FICTICIA'},
            ]},
        ],
        'expected': {
            'patient': {'status': 'extraido', 'value': 'Pessoa Cinco Paginas Acento Águia Conceição', 'alias': 'Nome completo', 'page': 1},
            'birthDate': {'status': 'extraido', 'value': '31/12/1979', 'alias': 'Nascimento', 'page': 1},
            'identifier': {'status': 'extraido', 'value': 'BM-EV-04', 'alias': 'Identificador', 'page': 2},
            'issueDate': {'status': 'ambiguo'},
            'procedure': {'status': 'extraido', 'value': 'Colecistectomia aberta', 'alias': 'Procedimento solicitado', 'page': 4},
            'laterality': {'status': 'extraido', 'normalized': 'nao_aplicavel', 'alias': 'Lateralidade', 'page': 4},
            'origin': {'status': 'extraido', 'value': 'Hospital Regional Fictício de Demonstração Prolongada', 'alias': 'Origem', 'page': 5},
        },
    },
]

manifest = {
    'schema': 'jyxia.synthetic-benchmark.v1',
    'version': '3.2.0',
    'synthetic': True,
    'independentRealHoldout': False,
    'isolatedFromPublicCatalog': True,
    'excludedFromGitHubPages': True,
    'methodologyNote': (
        'Conjunto sintético interno separado do catálogo público da demonstração. '
        'Inclui divisões development, regression e reserved_evaluation para medir aderência determinística e expor limitações. '
        'Por ser gerado pela equipe, não representa holdout independente nem prova de generalização em documentos hospitalares reais.'
    ),
    'cases': [],
}

for case in CASES:
    pdf_bytes = build_pdf(case['pages'], font=case['font'], rotate=case['rotate'])
    p = FIX_DIR / case['filename']
    p.write_bytes(pdf_bytes)
    manifest['cases'].append({
        'id': case['id'],
        'split': case['split'],
        'scenario': case['scenario'],
        'path': f'fixtures/{case["filename"]}',
        'sha256': hashlib.sha256(pdf_bytes).hexdigest(),
        'size': len(pdf_bytes),
        'pages': len(case['pages']),
        'rotate': case['rotate'],
        'font': case['font'],
        'expected': case['expected'],
    })
    print(f'Generated {case["id"]} ({case["split"]}): {p.name} ({len(pdf_bytes)} bytes)')

MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n', encoding='utf-8', newline='\n')
print(f'Wrote {MANIFEST_PATH} with {len(manifest["cases"])} synthetic benchmark documents.')
