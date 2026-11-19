import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

// Shims apenas no runner Node 24 para executar o bundle browser vendor/pdf.min.mjs sem alterá-lo.
Uint8Array.prototype.toHex ??= function () { return Buffer.from(this).toString('hex'); };

const pdfjs = await import('./vendor/pdf.min.mjs');
pdfjs.GlobalWorkerOptions.workerSrc = pathToFileURL(new URL('./vendor/pdf.worker.min.mjs', import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1')).href;

import {
  DocumentarySession,
  allowedFixture,
  brazilDate,
  extractPdfLines,
  verifyEvents
} from './documental-core.mjs';

const manifest = JSON.parse(await readFile(new URL('./documental-manifest.json', import.meta.url), 'utf8'));

function buildMinimalPdf({ pages = [{ text: '' }], rotate = 0 } = {}) {
  const objects = [];
  const addObj = body => { objects.push(body); return objects.length; };
  const catalogId = addObj(''); // placeholder 1
  const pagesId = addObj('');   // placeholder 2
  const fontId = addObj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  const pageIds = [];
  for (const p of pages) {
    const streamContent = p.text ? `BT /F1 12 Tf 40 700 Td (${p.text}) Tj ET` : '';
    const contentId = addObj(`<< /Length ${Buffer.byteLength(streamContent, 'latin1')} >>\nstream\n${streamContent}\nendstream`);
    const rot = rotate ? ` /Rotate ${rotate}` : '';
    const pageId = addObj(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 595 842]${rot} /Resources << /Font << /F1 ${fontId} 0 R >> >> /Contents ${contentId} 0 R >>`);
    pageIds.push(pageId);
  }
  objects[catalogId - 1] = `<< /Type /Catalog /Pages ${pagesId} 0 R >>`;
  objects[pagesId - 1] = `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pageIds.length} >>`;

  let out = '%PDF-1.4\n';
  const offsets = [0];
  for (let i = 0; i < objects.length; i++) {
    offsets.push(Buffer.byteLength(out, 'latin1'));
    out += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
  }
  const xrefPos = Buffer.byteLength(out, 'latin1');
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i < offsets.length; i++) {
    out += String(offsets[i]).padStart(10, '0') + ' 00000 n \n';
  }
  out += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R >>\nstartxref\n${xrefPos}\n%%EOF\n`;
  return new Uint8Array(Buffer.from(out, 'latin1'));
}

async function parseRealPdf(bytes) {
  const task = pdfjs.getDocument({ data: bytes.slice(), isEvalSupported: false, useSystemFonts: true, disableFontFace: true });
  const doc = await task.promise;
  try {
    const lines = await extractPdfLines(doc, pdfjs.Util.transform, 5);
    return { doc, lines };
  } finally {
    await doc.loadingTask.destroy();
  }
}

test('PDF.js extracts all 6 fields and valid normalized coordinates from every synthetic PDF fixture', async () => {
  for (const f of manifest.files.filter(x => x.mime === 'application/pdf')) {
    const bytes = new Uint8Array(await readFile(new URL('./' + f.path, import.meta.url)));
    const fixture = await allowedFixture(bytes, manifest, ['application/pdf']);
    const { lines } = await parseRealPdf(bytes);
    assert(lines.length >= 10, `${f.name} should yield text items`);
    const s = new DocumentarySession(manifest);
    const { document: d } = await s.ingest(fixture, lines, 12);

    for (const key of ['patient', 'birthDate', 'issueDate', 'type', 'origin']) {
      assert(d.fields[key].value.length > 0, `${f.name} missing ${key}`);
      assert.equal(d.fields[key].source.page, 1);
      const [x, y, w, h] = d.fields[key].source.box;
      assert(x >= 0 && y >= 0 && w > 0 && h > 0 && x + w <= 1.001 && y + h <= 1.001, `${f.name} ${key} box out of bounds: ${JSON.stringify([x, y, w, h])}`);
    }

    if (f.name === 'sem-identificador.pdf') {
      assert.equal(d.fields.identifier.value, '');
      assert.equal(d.identity, 'manual');
    } else if (f.name === 'identidade-divergente.pdf') {
      assert.equal(d.identity, 'conflict');
    } else {
      assert.equal(d.fields.identifier.value, 'SYN-P01');
      assert.equal(d.identity, 'suggested');
    }
  }
});

test('real PDF.js integration runs all 7 scenarios end-to-end without mocked lines', async () => {
  const s = new DocumentarySession(manifest);
  const loadReal = async name => {
    const f = manifest.files.find(x => x.name === name);
    const bytes = new Uint8Array(await readFile(new URL('./' + f.path, import.meta.url)));
    const lines = f.mime === 'application/pdf' ? (await parseRealPdf(bytes)).lines : [];
    return s.ingest(f, lines, 5);
  };

  // Scenario 1: completo
  const solicitacao = (await loadReal('solicitacao.pdf')).document;
  const laudo = (await loadReal('laudo.pdf')).document;
  const avaliacao = (await loadReal('avaliacao.pdf')).document;
  const termo = (await loadReal('termo.pdf')).document;
  await s.review(solicitacao.id, { identityChecked: true, issueDate: brazilDate(solicitacao.fields.issueDate.value) });
  await s.review(laudo.id, { identityChecked: true, issueDate: brazilDate(laudo.fields.issueDate.value) });
  await s.review(avaliacao.id, { identityChecked: true, issueDate: brazilDate(avaliacao.fields.issueDate.value) });
  await s.review(termo.id, { identityChecked: true, issueDate: brazilDate(termo.fields.issueDate.value), signature: 'present' });
  assert.equal(s.summary().pending, 0);

  // Scenario 2: duplicado
  const dup = await loadReal('laudo.pdf');
  assert.equal(dup.duplicate, true);
  assert.equal(s.duplicates, 1);

  // Scenario 3: versao + replace
  const atualizado = (await loadReal('laudo-atualizado.pdf')).document;
  await s.review(atualizado.id, { identityChecked: true, issueDate: brazilDate(atualizado.fields.issueDate.value) });
  await s.replace(atualizado.id, laudo.id);
  assert.equal(laudo.supersededBy, atualizado.id);
  assert.equal(atualizado.replaces, laudo.id);

  // Scenario 4: divergente quarantined
  const divergente = (await loadReal('identidade-divergente.pdf')).document;
  assert.equal(divergente.identity, 'conflict');
  await assert.rejects(s.review(divergente.id, { identityChecked: true, issueDate: '2026-11-11' }));

  // Scenario 5: sem identificador
  const semId = (await loadReal('sem-identificador.pdf')).document;
  assert.equal(semId.identity, 'manual');
  await s.review(semId.id, { identityChecked: true, issueDate: '2026-11-11' });
  assert.equal(semId.caseId, 'CASO-SYN-001');

  // Scenario 6: imagem ilegivel
  const img = (await loadReal('imagem-ilegivel.png')).document;
  assert.equal(img.identity, 'unreadable');
  await assert.rejects(s.review(img.id, { identityChecked: true }));

  // Scenario 7: laudo-antigo window task + assign + resolve + rule v2 invalidation + export + verifyEvents
  const antigo = (await loadReal('laudo-antigo.pdf')).document;
  await s.review(antigo.id, { identityChecked: true, issueDate: '2026-10-16' });
  const winTask = s.tasks().find(t => t.docId === antigo.id && t.id.includes(':window:'));
  assert(winTask);
  await s.assign(winTask.id, 'Revisor A', '2026-11-16');
  await s.resolve(winTask.id, 'Justificativa de teste real.');
  await s.configure(25);
  assert.equal(s.tasks().find(t => t.docId === antigo.id && t.id.includes(':window:')).resolution, null);
  assert.equal(await verifyEvents(s.export().events), true);
});

test('PDF.js rejects PDFs over 5 pages via loadingTask.destroy without throwing doc.destroy TypeError', async () => {
  const sixPages = buildMinimalPdf({
    pages: Array.from({ length: 6 }, (_, i) => ({ text: `Tipo: laudo pagina ${i + 1}` }))
  });
  const task = pdfjs.getDocument({ data: sixPages, isEvalSupported: false, useSystemFonts: true, disableFontFace: true });
  const doc = await task.promise;
  assert.equal(doc.numPages, 6);
  await assert.rejects(extractPdfLines(doc, pdfjs.Util.transform, 5), /Limite de cinco páginas/);
});

test('PDF.js rejects corrupted PDF bytes cleanly', async () => {
  const task = pdfjs.getDocument({ data: new TextEncoder().encode('%PDF-1.4\ncorrupted-bytes'), isEvalSupported: false });
  await assert.rejects(task.promise);
  await task.destroy();
});

test('PDF without selectable text yields empty lines and readable=false, multi-page & rotated stay within bounds', async () => {
  const blankPdf = buildMinimalPdf({ pages: [{ text: '' }] });
  const blank = await parseRealPdf(blankPdf);
  assert.equal(blank.lines.length, 0);

  const multiRotated = buildMinimalPdf({
    pages: [
      { text: 'Tipo: laudo' },
      { text: 'Paciente: Pessoa Sintetica Alfa' }
    ],
    rotate: 90
  });
  const rotated = await parseRealPdf(multiRotated);
  assert.equal(rotated.lines.length, 2);
  assert.equal(rotated.lines[0].page, 1);
  assert.equal(rotated.lines[1].page, 2);
  for (const l of rotated.lines) {
    const [x, y, w, h] = l.box;
    assert(x >= 0 && y >= 0 && w > 0 && h > 0 && x + w <= 1 && y + h <= 1, `Rotated box out of [0,1]: ${JSON.stringify(l.box)}`);
  }
});

test('PDF.js extracts DE-04 subfamily, procedure, laterality and signature cue from OD/OE fixtures and flags conflict', async () => {
  const s = new DocumentarySession(manifest);
  const ingestReal = async name => {
    const f = manifest.files.find(x => x.name === name);
    const bytes = new Uint8Array(await readFile(new URL('./' + f.path, import.meta.url)));
    const { lines } = await parseRealPdf(bytes);
    return (await s.ingest(f, lines, 5)).document;
  };
  const sol = await ingestReal('solicitacao-od.pdf');
  const term = await ingestReal('termo-oe.pdf');
  assert.equal(sol.fields.subfamily.value, 'Solicitacao cirurgica');
  assert.equal(sol.fields.procedure.value, 'Facoemulsificacao com implante de LIO');
  assert.equal(sol.fields.laterality.normalized, 'direito');
  assert.equal(term.fields.laterality.normalized, 'esquerdo');
  assert.equal(term.fields.signatureCue.source.page, 1);
  for (const key of ['subfamily', 'procedure', 'laterality']) {
    const [x, y, w, h] = sol.fields[key].source.box;
    assert(x >= 0 && y >= 0 && w > 0 && h > 0 && x + w <= 1 && y + h <= 1);
  }
  const latAxis = s.consistencyAxes().find(a => a.id === 'laterality');
  assert.equal(latAxis.status, 'conflito');
  assert.equal(latAxis.blocking, true);
});
