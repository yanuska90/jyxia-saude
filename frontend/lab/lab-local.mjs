import * as pdfjs from '../public/vendor/pdf.min.mjs';
import {
  LAB_LIMITS,
  assertLocalhostEnvironment,
  extractLabPdfLines,
  extractWithExplicitAliases,
  hasPdfMagicBytes,
} from './lab-extractor.mjs';

pdfjs.GlobalWorkerOptions.workerSrc = new URL('../public/vendor/pdf.worker.min.mjs', import.meta.url).href;
assertLocalhostEnvironment(window.location.hostname);

const $ = id => document.getElementById(id);
let activeDoc = null;
let renderSeq = 0;

function el(tag, text, cls) {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (cls) n.className = cls;
  return n;
}
function showMsg(text, isError = false) {
  const m = $('lab-message');
  m.setAttribute('role', isError ? 'alert' : 'status');
  m.textContent = isError && !String(text).startsWith('Erro:') ? 'Erro: ' + text : text;
  m.classList.toggle('error', isError);
}
async function renderSource(pageNum = 1, box = null, captionText = '') {
  if (!activeDoc) return;
  const ticket = ++renderSeq;
  const page = await activeDoc.getPage(pageNum);
  const vp = page.getViewport({ scale: 1.35 });
  const off = document.createElement('canvas');
  off.width = Math.ceil(vp.width);
  off.height = Math.ceil(vp.height);
  await page.render({ canvasContext: off.getContext('2d'), viewport: vp }).promise;
  if (ticket !== renderSeq) return;
  const target = $('lab-canvas');
  target.width = off.width;
  target.height = off.height;
  target.setAttribute('aria-label', 'Página ' + pageNum + ' do PDF no laboratório');
  target.getContext('2d').drawImage(off, 0, 0);
  $('lab-page-label').textContent = 'Página ' + pageNum;
  const hl = $('lab-highlight');
  if (box) {
    hl.style.left = box[0] * 100 + '%';
    hl.style.top = box[1] * 100 + '%';
    hl.style.width = box[2] * 100 + '%';
    hl.style.height = box[3] * 100 + '%';
    hl.hidden = false;
    $('lab-caption').textContent = captionText;
  } else {
    hl.hidden = true;
    $('lab-caption').textContent = 'Clique em “Ver fonte” ao lado de um campo reconhecido.';
  }
}

$('lab-file').addEventListener('change', async () => {
  const file = $('lab-file').files[0];
  $('lab-file').value = '';
  if (!file) return;
  if (file.size === 0 || file.size > LAB_LIMITS.maxBytes) {
    showMsg(`Arquivo fora do limite do laboratório (1 B a ${Math.round(LAB_LIMITS.maxBytes / 1024)} KB).`, true);
    return;
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (!hasPdfMagicBytes(bytes)) {
    showMsg('Somente PDFs sintéticos com cabeçalho binário %PDF- são aceitos no laboratório.', true);
    return;
  }
  try {
    if (activeDoc?.loadingTask?.destroy) await activeDoc.loadingTask.destroy();
    activeDoc = null;
    const task = pdfjs.getDocument({ data: bytes.slice(), isEvalSupported: false, useSystemFonts: true, disableFontFace: true });
    activeDoc = await task.promise;
    const extracted = await extractLabPdfLines(activeDoc, pdfjs.Util.transform, LAB_LIMITS.maxPages);
    const report = extractWithExplicitAliases(extracted.lines, extracted);

    $('lab-workspace').hidden = false;
    $('lab-meta').replaceChildren();
    for (const [val, label] of [
      [String(report.pagesCount), 'Páginas lidas'],
      [String(report.recognizedCount), 'Campos reconhecidos'],
      [String(report.ambiguities.length), 'Ambiguidades'],
      [String(report.abstentions.length), 'Abstenções'],
      [String(report.unrecognizedLabels.length), 'Rótulos desconhecidos'],
    ]) {
      const m = el('div', undefined, 'metric');
      m.append(el('strong', val), el('span', label));
      $('lab-meta').append(m);
    }

    $('lab-fields').replaceChildren();
    for (const [k, f] of Object.entries(report.fields)) {
      const row = el('div', undefined, 'field'), top = el('div', undefined, 'field-top');
      top.append(el('small', `${k}${f.matchedAlias ? ' · alias: ' + f.matchedAlias : ''} [${f.status}]`));
      if (f.source) {
        const b = el('button', 'Ver fonte');
        b.type = 'button';
        b.setAttribute('aria-label', 'Ver fonte de ' + k);
        b.addEventListener('click', () => renderSource(f.source.page, f.source.box, `Pág. ${f.source.page}: ${f.source.text}`));
        top.append(b);
      }
      const desc = f.uncertain ? f.reason : (f.value || f.reason || 'Não localizado');
      row.append(top, el('strong', desc));
      $('lab-fields').append(row);
    }

    $('lab-unrecognized').replaceChildren();
    if (!report.unrecognizedLabels.length && !report.unlabeledItems.length) {
      $('lab-unrecognized').append(el('p', 'Nenhum rótulo desconhecido ou valor solto detectado.', 'fine'));
    } else {
      for (const u of report.unrecognizedLabels) {
        const p = el('p', `[Rótulo não reconhecido] "${u.label}" (pág. ${u.page})`, 'fine');
        $('lab-unrecognized').append(p);
      }
      for (const s of report.unlabeledItems) {
        const p = el('p', `[Sem rótulo · abstenção] "${s.text}" (pág. ${s.page})`, 'fine');
        $('lab-unrecognized').append(p);
      }
    }

    await renderSource(1, null);
    showMsg(`Arquivo processado localmente em memória (${report.pagesCount} pág., ${report.recognizedCount} campos reconhecidos, ${report.ambiguities.length} ambiguidade(s)).`);
  } catch (err) {
    showMsg(err.message || 'Falha ao processar PDF no laboratório.', true);
  }
});
