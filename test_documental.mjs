import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  AXIS_STATES,
  DocumentarySession,
  READINESS_STATES,
  VERSION,
  addDaysISO,
  allowedFixture,
  brazilDate,
  csvSafeCell,
  diffDaysISO,
  extractFields,
  extractPdfLines,
  identity,
  isoToBrazil,
  normalizeLaterality,
  parseSyntheticCase,
  verifyEvents,
  verifyEventsReport,
} from './documental-core.mjs';

const manifest = JSON.parse(await readFile(new URL('./documental-manifest.json', import.meta.url)));
const fixture = name => manifest.files.find(x => x.name === name);

function lines(overrides = {}) {
  const values = {
    type: 'laudo',
    patient: 'Pessoa Sintetica Alfa',
    birthDate: '12/04/1986',
    identifier: 'SYN-P01',
    issueDate: '11/11/2026',
    origin: 'Instituicao Ficticia JYXIA',
    ...overrides,
  };
  const labels = {
    type: 'Tipo',
    patient: 'Paciente',
    birthDate: 'Nascimento',
    identifier: 'Identificador',
    issueDate: 'Emissao',
    origin: 'Origem',
  };
  return Object.entries(values)
    .filter(([, v]) => v !== null)
    .map(([k, v], i) => ({ text: labels[k] + ': ' + v, page: 1, box: [0.1, 0.2 + i * 0.03, 0.5, 0.02] }));
}

function fullAxisLines(type, extra = []) {
  const base = [
    ...lines({ type }),
    { text: 'Procedimento: Facoemulsificacao com implante de LIO', page: 1, box: [0.1, 0.5, 0.5, 0.02] },
    { text: 'Sistema: SIGTAP-FICTICIO', page: 1, box: [0.1, 0.53, 0.3, 0.02] },
    { text: 'Codigo: 04.05.05.011-9', page: 1, box: [0.1, 0.56, 0.3, 0.02] },
    { text: 'Lateralidade: Olho Direito (OD)', page: 1, box: [0.1, 0.59, 0.4, 0.02] },
    ...extra,
  ];
  if (type === 'termo') base.push({ text: 'MARCA FICTICIA', page: 1, box: [0.1, 0.7, 0.3, 0.02] });
  return base;
}

async function add(s, name, overrides = {}) {
  return (await s.ingest(fixture(name), lines(overrides))).document;
}

async function review(s, d, extra = {}) {
  return s.review(d.id, { identityChecked: true, issueDate: brazilDate(d.fields.issueDate.value), ...extra });
}

test('provided files are accepted by content hash, changed and unknown files are rejected', async () => {
  assert.equal(VERSION, '3.2.0');
  assert.equal(manifest.files.length, 18);
  for (const f of manifest.files) {
    const b = new Uint8Array(await readFile(new URL('./' + f.path, import.meta.url)));
    assert.equal((await allowedFixture(b, manifest, [f.mime])).sha256, f.sha256);
    const changed = b.slice();
    changed[0] ^= 1;
    await assert.rejects(allowedFixture(changed, manifest, [f.mime]));
  }
  await assert.rejects(allowedFixture(new Uint8Array(524289), manifest));
});

test('field evidence retains page and bounding box, ambiguous identity quarantined', () => {
  const extracted = extractFields(lines());
  assert.equal(extracted.fields.issueDate.source.page, 1);
  assert.equal(extracted.fields.issueDate.source.box.length, 4);
  assert.equal(identity(extracted, manifest.case), 'suggested');
  const ambiguous = extractFields([...lines(), { text: 'Identificador: SYN-P02', page: 1, box: [0, 0, 1, 1] }]);
  assert.equal(identity(ambiguous, manifest.case), 'conflict');
});

test('partial historical set reaches abstention (not false conferida) while full 4-axis set reaches conferida', async () => {
  // Scenario 1 historical files lack procedure and laterality -> MUST end in abstencao (Etapa 2.3 bugfix)
  const sPartial = new DocumentarySession(manifest);
  for (const [name, type] of [['solicitacao.pdf', 'solicitacao'], ['laudo.pdf', 'laudo'], ['avaliacao.pdf', 'avaliacao'], ['termo.pdf', 'termo']]) {
    const d = await add(sPartial, name, { type });
    assert.equal(d.caseId, null);
    await review(sPartial, d, { humanVisualObservation: type === 'termo' ? 'observed' : 'unknown' });
  }
  assert.equal(sPartial.summary().pending, 0);
  assert.equal(sPartial.summary().reviewed, 4);
  assert.equal(sPartial.readinessState().code, 'abstencao');
  assert(await verifyEvents(sPartial.events));

  // Scenario 9 complete 4-axis files -> reaches conferida
  const sFull = new DocumentarySession(manifest);
  for (const [name, type] of [
    ['solicitacao-completa.pdf', 'solicitacao'],
    ['laudo-completo.pdf', 'laudo'],
    ['avaliacao-completa.pdf', 'avaliacao'],
    ['termo-completo.pdf', 'termo'],
  ]) {
    const d = (await sFull.ingest(fixture(name), fullAxisLines(type))).document;
    await review(sFull, d, { humanVisualObservation: type === 'termo' ? 'observed' : 'unknown' });
  }
  assert.equal(sFull.readinessState().code, 'conferida');
  assert(sFull.consistencyAxes().every(a => a.status === 'ok'));
});

test('same bytes do not create a second document, different bytes do not auto-replace', async () => {
  const s = new DocumentarySession(manifest);
  await add(s, 'laudo.pdf');
  await add(s, 'laudo.pdf');
  const fresh = await add(s, 'laudo-atualizado.pdf', { issueDate: '14/11/2026' });
  assert.equal(s.documents.length, 2);
  assert.equal(s.duplicates, 1);
  assert.equal(fresh.replaces, null);
});

test('identity conflict cannot be linked even when confirmation is requested', async () => {
  const s = new DocumentarySession(manifest);
  const d = await add(s, 'identidade-divergente.pdf', { identifier: 'SYN-P02', patient: 'Pessoa Sintetica Beta', birthDate: '03/09/1990' });
  await assert.rejects(review(s, d));
  assert.equal(d.caseId, null);
  assert.equal(s.summary().quarantine, 1);
  assert.equal(s.readinessState().code, 'bloqueado');
});

test('missing identifier requires matching name and birthdate plus manual confirmation', async () => {
  const s = new DocumentarySession(manifest);
  const d = await add(s, 'sem-identificador.pdf', { identifier: null });
  assert.equal(d.identity, 'manual');
  await assert.rejects(s.review(d.id, { issueDate: '2026-11-11' }));
  await review(s, d);
  assert.equal(d.caseId, manifest.case.id);
  assert.equal(identity(extractFields(lines({ identifier: null, birthDate: null })), manifest.case), 'insufficient');
});

test('image remains in quarantine and cannot be made complete by a resolution', async () => {
  const s = new DocumentarySession(manifest);
  const d = (await s.ingest(fixture('imagem-ilegivel.png'), [])).document;
  assert.equal(d.identity, 'unreadable');
  await assert.rejects(review(s, d));
  const task = s.tasks().find(t => t.docId === d.id);
  await s.assign(task.id, 'Revisor A', '2026-11-16');
  await assert.rejects(s.resolve(task.id, 'Conferido'), /Resolução bloqueada/);
});

test('date correction preserves extraction and requires a reason', async () => {
  const s = new DocumentarySession(manifest);
  const d = await add(s, 'laudo-antigo.pdf', { issueDate: '16/10/2026' });
  await assert.rejects(review(s, d, { issueDate: '2026-11-11' }));
  await review(s, d, { issueDate: '2026-11-11', note: 'Correção fictícia para testar revisão.' });
  assert.equal(d.fields.issueDate.value, '16/10/2026');
  assert.equal(d.review.originalIssueDate, '2026-10-16');
  assert.equal(d.reviewHistory.length, 1);
});

test('administrative exceptions require review assignment deadline and justification', async () => {
  const s = new DocumentarySession(manifest);
  const d = await add(s, 'laudo-antigo.pdf', { issueDate: '16/10/2026' });
  await review(s, d);
  const t = s.tasks().find(x => x.id.includes(':window:'));
  await assert.rejects(s.resolve(t.id, 'Reenvio solicitado'));
  await assert.rejects(s.assign(t.id, 'Pessoa real', '2026-11-16'));
  await assert.rejects(s.assign(t.id, 'Revisor A', '2026-02-30'));
  await s.assign(t.id, 'Revisor A', '2026-11-16');
  await s.resolve(t.id, 'Exceção administrativa fictícia justificada.');
  assert(s.tasks().find(x => x.id === t.id).resolution);
  await review(s, d);
  assert.equal(s.tasks().find(x => x.id === t.id).resolution, null);
});

test('policy changes invalidate old task resolutions while preserving audit', async () => {
  const s = new DocumentarySession(manifest);
  const d = await add(s, 'laudo-antigo.pdf', { issueDate: '16/10/2026' });
  await review(s, d);
  const t = s.tasks().find(x => x.id.includes(':window:'));
  await s.assign(t.id, 'Revisor A', '2026-11-16');
  await s.resolve(t.id, 'Exceção fictícia documentada.');
  await s.configure(25);
  assert.equal(s.tasks().find(x => x.id.includes(':window:')).resolution, null);
  assert(s.events.some(e => e.action === 'pendencia_resolvida'));
  await assert.rejects(s.configure(0));
});

test('explicit replacement requires both reviews, keeps original and blocks cycles', async () => {
  const s = new DocumentarySession(manifest);
  const a = await add(s, 'laudo.pdf');
  const b = await add(s, 'laudo-atualizado.pdf', { issueDate: '14/11/2026' });
  await assert.rejects(s.replace(b.id, a.id));
  await review(s, a);
  await review(s, b);
  await s.replace(b.id, a.id);
  assert.equal(s.documents.length, 2);
  assert.equal(s.active().length, 1);
  assert.equal(a.supersededBy, b.id);
  await assert.rejects(s.replace(a.id, b.id));
});

test('export is detached from state and hash chain detects payload changes and order', async () => {
  const s = new DocumentarySession(manifest);
  const d = await add(s, 'laudo.pdf');
  await review(s, d);
  const exported = s.export();
  exported.documents[0].name = 'changed';
  assert.equal(s.documents[0].name, 'laudo.pdf');
  assert(await verifyEvents(exported.events));
  exported.events[0].data.identity = 'changed';
  assert.equal(await verifyEvents(exported.events), false);
  assert.equal(await verifyEvents([...s.events].reverse()), false);
});

test('date parser refuses rollover and future dates are flagged', async () => {
  assert.equal(brazilDate('30/02/2026'), '');
  const s = new DocumentarySession(manifest);
  const d = await add(s, 'laudo.pdf', { issueDate: '15/11/2026' });
  await review(s, d);
  assert(s.tasks().some(t => t.id.includes(':future:')));
});

test('date formatting helpers convert ISO dates and offset days safely', () => {
  assert.equal(isoToBrazil('1986-04-12'), '12/04/1986');
  assert.equal(isoToBrazil('2026-02-30'), '');
  assert.equal(addDaysISO('2026-11-14', 2), '2026-11-16');
  assert.equal(addDaysISO('2026-11-29', 2), '2026-12-01');
});

test('synthetic case CSV and JSON fixtures parse, update session case and reject malformed data', async () => {
  const csvText = await readFile(new URL('./fixtures/casos-ficticios.csv', import.meta.url), 'utf8');
  const jsonText = await readFile(new URL('./fixtures/casos-ficticios.json', import.meta.url), 'utf8');
  const parsedCsv = parseSyntheticCase(csvText, 'text/csv');
  const parsedJson = parseSyntheticCase(jsonText, 'application/json');
  assert.deepEqual(parsedCsv, parsedJson);
  assert.equal(parsedCsv.id, 'CASO-SYN-001');
  assert.throws(() => parseSyntheticCase('id,patient\nCASO,Nome', 'text/csv'));
  assert.throws(() => parseSyntheticCase('{"synthetic":false}', 'application/json'));
  const s = new DocumentarySession(manifest);
  const csvKnown = await allowedFixture(new TextEncoder().encode(csvText), manifest, ['text/csv']);
  const loaded = await s.loadSyntheticCase(csvKnown, csvText);
  assert.equal(loaded.identifier, 'SYN-P01');
  assert(s.events.some(e => e.action === 'cadastro_importado' && e.data.identifier === 'SYN-P01'));
});

test('discard preserves history, rejects short reason and blocks discarded review', async () => {
  const s = new DocumentarySession(manifest), d = await add(s, 'laudo.pdf');
  await assert.rejects(s.discard(d.id, 'abc'));
  await s.discard(d.id, 'Documento substituído manualmente no teste.');
  assert.equal(d.status, 'discarded');
  assert.equal(s.active().length, 0);
  await assert.rejects(review(s, d));
});

test('extractPdfLines enforces page limit via loadingTask.destroy when available', async () => {
  let destroyed = false;
  const mockDoc = { numPages: 6, loadingTask: { destroy: async () => { destroyed = true; } } };
  await assert.rejects(extractPdfLines(mockDoc, () => [1, 0, 0, 1, 0, 0], 5), /Limite de cinco páginas/);
  assert.equal(destroyed, true);
});

test('normalizeLaterality maps valid tokens deterministically and abstains on ambiguity', () => {
  assert.equal(normalizeLaterality('Olho Direito (OD)'), 'direito');
  assert.equal(normalizeLaterality('OE'), 'esquerdo');
  assert.equal(normalizeLaterality('Ambos os olhos (AO)'), 'bilateral');
  assert.equal(normalizeLaterality('Nao aplicavel'), 'nao_aplicavel');
  assert.equal(normalizeLaterality('Olho direito e olho esquerdo'), 'abstencao');
  assert.equal(normalizeLaterality('texto livre incerto'), 'abstencao');
  assert.equal(normalizeLaterality(''), '');
});

test('DE-04 consistency axes detect procedure/laterality conflicts and block automatic completion', async () => {
  const s = new DocumentarySession(manifest);
  const req = (await s.ingest(fixture('solicitacao-od.pdf'), [...lines({ type: 'solicitacao' }), { text: 'Subfamilia: Solicitacao cirurgica', page: 1, box: [0.1, 0.5, 0.4, 0.02] }, { text: 'Procedimento: Facoemulsificacao com LIO', page: 1, box: [0.1, 0.55, 0.5, 0.02] }, { text: 'Lateralidade: Olho Direito (OD)', page: 1, box: [0.1, 0.6, 0.4, 0.02] }])).document;
  const term = (await s.ingest(fixture('termo-oe.pdf'), [...lines({ type: 'termo' }), { text: 'Subfamilia: Termo de procedimento', page: 1, box: [0.1, 0.5, 0.4, 0.02] }, { text: 'Procedimento: Facoemulsificacao com LIO', page: 1, box: [0.1, 0.55, 0.5, 0.02] }, { text: 'Lateralidade: Olho Esquerdo (OE)', page: 1, box: [0.1, 0.6, 0.4, 0.02] }, { text: 'MARCA FICTICIA', page: 1, box: [0.1, 0.7, 0.3, 0.02] }])).document;
  assert.equal(term.fields.syntheticMarkerCue.source.page, 1);
  await review(s, req);
  await review(s, term, { humanVisualObservation: 'observed' });
  const axes = s.consistencyAxes();
  assert.equal(axes.find(a => a.id === 'procedure').status, 'ok');
  assert.equal(axes.find(a => a.id === 'laterality').status, 'conflito');
  assert.equal(axes.find(a => a.id === 'laterality').blocking, true);
  assert.equal(s.readinessState().code, 'bloqueado');
  const axisTask = s.tasks().find(t => t.id.startsWith('axis:laterality:'));
  assert(axisTask && !axisTask.manual);
  await assert.rejects(s.resolve(axisTask.id, 'Tentando forcar texto livre'), /Resolução bloqueada/);
  await s.discard(term.id, 'Lateralidade incorreta no termo anexado.');
  assert.equal(s.consistencyAxes().find(a => a.id === 'laterality').status, 'ok');
});

test('cross-subfamily replacement is rejected and abstention applies when procedure is absent', async () => {
  const s = new DocumentarySession(manifest);
  const a = (await s.ingest(fixture('laudo.pdf'), [...lines({ type: 'laudo' }), { text: 'Subfamilia: Hematologia', page: 1, box: [0.1, 0.5, 0.3, 0.02] }])).document;
  const b = (await s.ingest(fixture('laudo-atualizado.pdf'), [...lines({ type: 'laudo' }), { text: 'Subfamilia: Imagem', page: 1, box: [0.1, 0.5, 0.3, 0.02] }])).document;
  await review(s, a);
  await review(s, b);
  await assert.rejects(s.replace(b.id, a.id), /Subfamílias documentais distintas/);
  assert.equal(s.consistencyAxes().find(a => a.id === 'procedure').status, 'abstencao');
});

test('buildPendingNotice and exportCsv neutralize spreadsheet formula injection', async () => {
  assert.equal(csvSafeCell('=CMD("calc")'), '"\'=CMD(""calc"")"');
  assert.equal(csvSafeCell('+1+1'), '"\'+1+1"');
  assert.equal(csvSafeCell('@SUM(A1)'), '"\'@SUM(A1)"');
  const s = new DocumentarySession(manifest), d = await add(s, 'laudo.pdf');
  await review(s, d, { issueDate: '2026-11-12', note: '=IMPORTXML("http://example.invalid")' });
  const csv = s.exportCsv();
  assert(csv.includes('"\'=IMPORTXML(""http://example.invalid"")"'));
  assert(s.buildPendingNotice().includes('Aviso: uso exclusivamente administrativo'));
});

test('Etapa 2.1 identity re-evaluates unreviewed docs on case change and quarantines reviewed caseId mismatch', async () => {
  const s = new DocumentarySession(manifest);
  const unrev = await add(s, 'laudo.pdf', { patient: 'Outra Pessoa Sintetica', birthDate: '02/02/1980', identifier: 'SYN-P88' });
  assert.equal(unrev.identity, 'conflict');
  assert.equal(unrev.caseId, null);
  const docMatch = await add(s, 'solicitacao.pdf');
  await review(s, docMatch);
  assert.equal(docMatch.caseId, manifest.case.id);
  const jsonObj = JSON.parse(await readFile(new URL('./fixtures/casos-ficticios.json', import.meta.url), 'utf8'));
  const altPayload = JSON.stringify({ ...jsonObj, cases: [{ ...jsonObj.cases[0], id: 'CASO-SYN-OUTRO', identifier: 'SYN-P88', patient: 'Outra Pessoa Sintetica', birthDate: '1980-02-02' }] });
  await s.loadSyntheticCase(fixture('casos-ficticios.json'), altPayload);
  assert.equal(unrev.identity, 'suggested');
  assert.equal(s.consistencyAxes().find(a => a.id === 'identity').status, 'conflito');
  assert.equal(s.readinessState().code, 'bloqueado');
});

test('Etapa 2.1 laterality OD/OE/NA matrix, intra-doc contradiction and blocking abstention', async () => {
  assert.equal(normalizeLaterality('Nao aplicavel ao procedimento'), 'nao_aplicavel');
  const sIntra = new DocumentarySession(manifest);
  await sIntra.ingest(fixture('solicitacao.pdf'), [...lines({ type: 'solicitacao' }), { text: 'Lateralidade: Olho Direito (OD)', page: 1, box: [0.1, 0.6, 0.4, 0.02] }, { text: 'Lateralidade: Olho Esquerdo (OE)', page: 1, box: [0.1, 0.63, 0.4, 0.02] }]);
  const intraLat = sIntra.consistencyAxes().find(a => a.id === 'laterality');
  assert.equal(intraLat.status, 'conflito');
  assert.equal(intraLat.blocking, true);
  assert.equal(sIntra.readinessState().code, 'bloqueado');

  const sNa = new DocumentarySession(manifest);
  await sNa.ingest(fixture('solicitacao.pdf'), [...lines({ type: 'solicitacao' }), { text: 'Lateralidade: Olho Direito (OD)', page: 1, box: [0.1, 0.6, 0.4, 0.02] }]);
  await sNa.ingest(fixture('termo.pdf'), [...lines({ type: 'termo' }), { text: 'Lateralidade: Nao aplicavel', page: 1, box: [0.1, 0.6, 0.4, 0.02] }]);
  assert.equal(sNa.consistencyAxes().find(a => a.id === 'laterality').status, 'conflito');

  const sBlk = new DocumentarySession(manifest);
  for (const [name, type] of [['solicitacao.pdf', 'solicitacao'], ['laudo.pdf', 'laudo'], ['avaliacao.pdf', 'avaliacao'], ['termo.pdf', 'termo']]) {
    const extra = type === 'solicitacao' ? [{ text: 'Procedimento: Cirurgia Ficticia', page: 1, box: [0.1, 0.55, 0.4, 0.02] }, { text: 'Lateralidade: lado duvidoso xpto', page: 1, box: [0.1, 0.6, 0.4, 0.02] }] : [{ text: 'Procedimento: Cirurgia Ficticia', page: 1, box: [0.1, 0.55, 0.4, 0.02] }];
    const d = (await sBlk.ingest(fixture(name), [...lines({ type }), ...extra])).document;
    await review(sBlk, d, { humanVisualObservation: type === 'termo' ? 'observed' : 'unknown' });
  }
  const blkLat = sBlk.consistencyAxes().find(a => a.id === 'laterality');
  assert.equal(blkLat.status, 'abstencao');
  assert.equal(blkLat.blocking, true);
  assert.equal(sBlk.readinessState().code, 'bloqueado');
});

test('Etapa 2.3 P1 synthetic marker never claims signature visual recognition or authentication', async () => {
  // 1. MARCA FICTICIA -> textual marker
  const withMarker = extractFields([...lines({ type: 'termo' }), { text: 'MARCA FICTICIA', page: 1, box: [0.1, 0.7, 0.3, 0.02] }]);
  assert.equal(withMarker.fields.syntheticMarkerCue.present, true);
  assert.equal(withMarker.fields.syntheticMarkerCue.detectionKind, 'literal_synthetic_text_marker');
  assert.equal(withMarker.fields.syntheticMarkerCue.authenticatesSignature, false);
  assert(withMarker.fields.syntheticMarkerCue.value.includes('Marcador textual sintético'));
  assert(!('signatureCue' in withMarker.fields));

  // 2. Document without MARCA FICTICIA -> not marked as visual absence
  const withoutMarker = extractFields(lines({ type: 'termo' }));
  assert.equal(withoutMarker.fields.syntheticMarkerCue.present, false);
  assert.equal(withoutMarker.fields.syntheticMarkerCue.value, '');

  // 3. PNG / unreadable doc -> no text layer, zero signature analysis claim
  const pngEmpty = extractFields([]);
  assert.equal(pngEmpty.readable, false);
  assert.equal(pngEmpty.fields.syntheticMarkerCue.detectionKind, 'none_no_text_layer');

  // 4 & 5. Human visual observation separated in review, JSON & CSV honest
  const s = new DocumentarySession(manifest);
  const d = (await s.ingest(fixture('termo.pdf'), [...lines({ type: 'termo' }), { text: 'MARCA FICTICIA', page: 1, box: [0.1, 0.7, 0.3, 0.02] }])).document;
  await review(s, d, { humanVisualObservation: 'observed' });
  assert.equal(d.review.syntheticMarkerPresent, true);
  assert.equal(d.review.humanVisualObservation, 'observed');
  assert.equal(d.review.authenticatesSignature, false);
  assert(!('signature' in d.review));
  const jsonStr = JSON.stringify(s.export());
  const csvStr = s.exportCsv();
  assert(!/signatureCue|marca_visual|assinatura validada|identidade do signatário|autenticidade jurídica/i.test(jsonStr + csvStr));
  assert(csvStr.includes('"marcador_textual_sintetico","observacao_visual_humana"'));
});

test('Etapa 2.3 P2 readiness matrix covers all 5 states and prevents false positive completion', async () => {
  // Explicit nao_aplicavel -> conferida_com_escopo_limitado
  const sLim = new DocumentarySession(manifest);
  for (const [name, type] of [['solicitacao.pdf', 'solicitacao'], ['laudo.pdf', 'laudo'], ['avaliacao.pdf', 'avaliacao'], ['termo.pdf', 'termo']]) {
    const docLines = [...lines({ type }), { text: 'Procedimento: Apendicectomia ficticia', page: 1, box: [0.1, 0.5, 0.4, 0.02] }, { text: 'Lateralidade: Nao aplicavel', page: 1, box: [0.1, 0.55, 0.4, 0.02] }];
    if (type === 'termo') docLines.push({ text: 'MARCA FICTICIA', page: 1, box: [0.1, 0.7, 0.3, 0.02] });
    const d = (await sLim.ingest(fixture(name), docLines)).document;
    await review(sLim, d, { humanVisualObservation: type === 'termo' ? 'observed' : 'unknown' });
  }
  assert.equal(sLim.consistencyAxes().find(a => a.id === 'laterality').status, 'nao_aplicavel');
  assert.equal(sLim.readinessState().code, 'conferida_com_escopo_limitado');

  // Empty & all-discarded -> pendente, axes nao_avaliado
  const sDisc = new DocumentarySession(manifest);
  assert.equal(sDisc.readinessState().code, 'pendente');
  assert(sDisc.consistencyAxes().every(a => a.status === 'nao_avaliado'));
  const discDoc = await add(sDisc, 'laudo.pdf');
  await sDisc.discard(discDoc.id, 'Retirado neste teste.');
  assert.equal(sDisc.readinessState().code, 'pendente');
  assert.equal(sDisc.readinessState().discardedCount, 1);
  assert(AXIS_STATES.includes(sDisc.consistencyAxes()[0].status));
  assert(READINESS_STATES.includes(sDisc.readinessState().code));
});

test('Etapa 2.3 P3 conservative procedure and coding-system comparison rules', async () => {
  // 1. Exact vs superficial match
  const sExact = new DocumentarySession(manifest);
  await sExact.ingest(fixture('solicitacao.pdf'), [...lines({ type: 'solicitacao' }), { text: 'Procedimento: Facoemulsificacao', page: 1, box: [0.1, 0.5, 0.4, 0.02] }]);
  await sExact.ingest(fixture('laudo.pdf'), [...lines({ type: 'laudo' }), { text: 'Procedimento: Facoemulsificacao', page: 1, box: [0.1, 0.5, 0.4, 0.02] }]);
  assert.equal(sExact.consistencyAxes().find(a => a.id === 'procedure').comparisonType, 'correspondencia_textual_exata');

  const sSup = new DocumentarySession(manifest);
  await sSup.ingest(fixture('solicitacao.pdf'), [...lines({ type: 'solicitacao' }), { text: 'Procedimento: Facoemulsificação.', page: 1, box: [0.1, 0.5, 0.4, 0.02] }]);
  await sSup.ingest(fixture('laudo.pdf'), [...lines({ type: 'laudo' }), { text: 'Procedimento: Facoemulsificacao', page: 1, box: [0.1, 0.5, 0.4, 0.02] }]);
  assert.equal(sSup.consistencyAxes().find(a => a.id === 'procedure').comparisonType, 'correspondencia_normalizada_superficial');

  // 2. Non-invented clinical synonym ("Cirurgia de catarata" vs "Facoemulsificação") -> MUST conflict!
  const sSyn = new DocumentarySession(manifest);
  await sSyn.ingest(fixture('solicitacao.pdf'), [...lines({ type: 'solicitacao' }), { text: 'Procedimento: Cirurgia de catarata', page: 1, box: [0.1, 0.5, 0.4, 0.02] }]);
  await sSyn.ingest(fixture('laudo.pdf'), [...lines({ type: 'laudo' }), { text: 'Procedimento: Facoemulsificação com implante de lente intraocular', page: 1, box: [0.1, 0.5, 0.4, 0.02] }]);
  const synAxis = sSyn.consistencyAxes().find(a => a.id === 'procedure');
  assert.equal(synAxis.status, 'conflito');
  assert.equal(synAxis.comparisonType, 'divergencia_textual');

  // 3. Equal code + same declared system -> ok
  const sCodeSys = new DocumentarySession(manifest);
  await sCodeSys.ingest(fixture('solicitacao.pdf'), [...lines({ type: 'solicitacao' }), { text: 'Sistema: SIGTAP', page: 1, box: [0.1, 0.5, 0.3, 0.02] }, { text: 'Codigo: 04.05.05.011-9', page: 1, box: [0.1, 0.53, 0.3, 0.02] }]);
  await sCodeSys.ingest(fixture('laudo.pdf'), [...lines({ type: 'laudo' }), { text: 'Codigo: SIGTAP: 04.05.05.011-9', page: 1, box: [0.1, 0.53, 0.3, 0.02] }]);
  const codeSysAxis = sCodeSys.consistencyAxes().find(a => a.id === 'procedure');
  assert.equal(codeSysAxis.status, 'ok');
  assert.equal(codeSysAxis.comparisonType, 'correspondencia_por_codigo_sistema_identificado');

  // 4. Equal code WITHOUT coding system -> blocking abstention with explicit required message
  const sNoSys = new DocumentarySession(manifest);
  await sNoSys.ingest(fixture('solicitacao.pdf'), [...lines({ type: 'solicitacao' }), { text: 'Codigo: 30306027', page: 1, box: [0.1, 0.5, 0.3, 0.02] }]);
  const noSysAxis = sNoSys.consistencyAxes().find(a => a.id === 'procedure');
  assert.equal(noSysAxis.status, 'abstencao');
  assert.equal(noSysAxis.blocking, true);
  assert(noSysAxis.detail.includes('sistema de codificação não identificado'));

  // 5. Same code across DIFFERENT systems -> conflict
  const sDiffSys = new DocumentarySession(manifest);
  await sDiffSys.ingest(fixture('solicitacao.pdf'), [...lines({ type: 'solicitacao' }), { text: 'Procedimento: Teste A', page: 1, box: [0.1, 0.48, 0.3, 0.02] }, { text: 'Codigo: TUSS: 1234', page: 1, box: [0.1, 0.5, 0.3, 0.02] }]);
  await sDiffSys.ingest(fixture('laudo.pdf'), [...lines({ type: 'laudo' }), { text: 'Procedimento: Teste A', page: 1, box: [0.1, 0.48, 0.3, 0.02] }, { text: 'Codigo: SIGTAP: 1234', page: 1, box: [0.1, 0.5, 0.3, 0.02] }]);
  assert.equal(sDiffSys.consistencyAxes().find(a => a.id === 'procedure').status, 'conflito');

  // 6. Differing codes with same vs unknown system & incomplete proc mixed -> conservative
  const sDiffCode = new DocumentarySession(manifest);
  await sDiffCode.ingest(fixture('solicitacao.pdf'), [...lines({ type: 'solicitacao' }), { text: 'Sistema: SIGTAP', page: 1, box: [0.1, 0.48, 0.3, 0.02] }, { text: 'Codigo: 1111', page: 1, box: [0.1, 0.5, 0.3, 0.02] }]);
  await sDiffCode.ingest(fixture('laudo.pdf'), [...lines({ type: 'laudo' }), { text: 'Sistema: SIGTAP', page: 1, box: [0.1, 0.48, 0.3, 0.02] }, { text: 'Codigo: 2222', page: 1, box: [0.1, 0.5, 0.3, 0.02] }]);
  assert.equal(sDiffCode.consistencyAxes().find(a => a.id === 'procedure').comparisonType, 'divergencia_codigo_mesmo_sistema');

  const sInc = new DocumentarySession(manifest);
  await sInc.ingest(fixture('solicitacao.pdf'), [...lines({ type: 'solicitacao' }), { text: 'Procedimento: A definir.', page: 1, box: [0.1, 0.5, 0.4, 0.02] }]);
  assert.equal(sInc.consistencyAxes().find(a => a.id === 'procedure').status, 'abstencao');

  const sIntra = new DocumentarySession(manifest);
  await sIntra.ingest(fixture('solicitacao.pdf'), [...lines({ type: 'solicitacao' }), { text: 'Procedimento: Cirurgia A', page: 1, box: [0.1, 0.5, 0.4, 0.02] }, { text: 'Procedimento: Cirurgia B', page: 1, box: [0.1, 0.54, 0.4, 0.02] }]);
  assert.equal(sIntra.consistencyAxes().find(a => a.id === 'procedure').comparisonType, 'ambiguidade_multiplos_candidatos');
});

test('Etapa 2.3 P6 temporality dates, category distinctions, non-auto-replacement and UTC boundary checks', async () => {
  assert.equal(diffDaysISO('2024-02-28', '2024-03-01'), 2);
  assert.equal(brazilDate('29/02/2024'), '2024-02-29');
  assert.equal(brazilDate('29/02/2025'), '');
  assert.equal(brazilDate('31/04/2026'), '');
  assert.equal(addDaysISO('2026-12-31', 1), '2027-01-01');
  assert.equal(diffDaysISO('2026-12-31', '2027-01-01'), 1);

  const sMissingProcDate = new DocumentarySession({ ...manifest, case: { ...manifest.case, procedureDate: '' } });
  const dUnk = await add(sMissingProcDate, 'laudo.pdf', { issueDate: '01/09/2026' });
  await review(sMissingProcDate, dUnk);
  assert(sMissingProcDate.tasks().some(t => t.id.includes(':window-unknown:')));
  const tempAxis = sMissingProcDate.consistencyAxes().find(a => a.id === 'temporality');
  assert.equal(tempAxis.status, 'abstencao');
  assert.equal(tempAxis.rule.categoryApplied, 'laudo');
  assert.equal(tempAxis.rule.isIllustrative, true);

  // Newer laudo does not auto-supersede older laudo; categories classified clearly
  const sVer = new DocumentarySession(manifest);
  const oldL = await add(sVer, 'laudo.pdf', { issueDate: '10/11/2026' });
  const newL = await add(sVer, 'laudo-atualizado.pdf', { issueDate: '14/11/2026' });
  const sol = await add(sVer, 'solicitacao.pdf', { type: 'solicitacao', issueDate: '10/10/2026' });
  assert.equal(oldL.supersededBy, null);
  const exp = sVer.export();
  assert.equal(exp.documents.find(x => x.id === oldL.id).temporalityStatus.category, 'antigo');
  assert.equal(exp.documents.find(x => x.id === newL.id).temporalityStatus.category, 'atualizado');
  assert.equal(exp.documents.find(x => x.id === sol.id).temporalityStatus.category, 'validade_nao_definida');

  // 3-document replacement chain preserved
  const sChain = new DocumentarySession(manifest);
  const a = await add(sChain, 'laudo.pdf', { issueDate: '11/11/2026' });
  const b = await add(sChain, 'laudo-atualizado.pdf', { issueDate: '12/11/2026' });
  const c = await add(sChain, 'laudo-antigo.pdf', { issueDate: '13/11/2026' });
  await review(sChain, a);
  await review(sChain, b);
  await review(sChain, c);
  await sChain.replace(b.id, a.id);
  await sChain.replace(c.id, b.id);
  assert.equal(sChain.active()[0].id, c.id);
  await assert.rejects(sChain.replace(a.id, c.id), /ciclo/);
});

test('Etapa 2.3 P7 & P11 traceability integrity, event removal/reorder detection and CSV/JSON honesty', async () => {
  const s = new DocumentarySession(manifest);
  const d = await add(s, 'laudo.pdf', { issueDate: '10/11/2026' });
  await review(s, d, { issueDate: '2026-11-12', note: 'Ajuste de texto; =SUM(1,2)\tlinha' });
  assert.equal((await verifyEventsReport(s.events)).valid, true);

  // Removal, reorder, revisedValue tamper
  const removed = structuredClone(s.events).slice(1);
  assert.equal((await verifyEventsReport(removed)).valid, false);
  const reordered = [structuredClone(s.events[1]), structuredClone(s.events[0])];
  assert.equal((await verifyEventsReport(reordered)).valid, false);
  const modified = structuredClone(s.events);
  modified[1].data.revisedValue = '2026-11-13';
  assert.equal((await verifyEventsReport(modified)).valid, false);

  const exp = s.export();
  assert.equal(exp.traceabilityLevels.localHashChain.immutableServerAudit, false);
  assert.equal(exp.traceabilityLevels.serverPersistence.implemented, false);
  assert.equal(exp.events[1].actorAuthenticated, false);
  assert.equal(exp.events[1].data.originalValue, '2026-11-10');
  assert.equal(exp.events[1].data.revisedValue, '2026-11-12');
  assert(exp.events[1].data.evidenceRef.page === 1);

  assert.equal(csvSafeCell('  =CMD()'), '"\'  =CMD()"');
  assert.equal(csvSafeCell('\u00A0+1+1'), '"\'\u00A0+1+1"');
  assert.equal(csvSafeCell('\t=HYPERLINK("x")'), '"\'\t=HYPERLINK(""x"")"');
  assert.equal(csvSafeCell('-10+5'), '"\'-10+5"');
  assert.equal(csvSafeCell('linha1\r\nlinha2\u0000ação'), '"linha1 linha2ação"');
  const csv = s.exportCsv();
  assert(csv.includes('Ajuste de texto; =SUM(1,2)\tlinha'));
  exp.consistencyAxes[0].status = 'mutated';
  exp.readiness.code = 'mutated';
  assert.notEqual(s.consistencyAxes()[0].status, 'mutated');
  assert.notEqual(s.readinessState().code, 'mutated');
});
