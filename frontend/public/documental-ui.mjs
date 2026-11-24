import * as pdfjs from './vendor/pdf.min.mjs';
import {
  DocumentarySession,
  KINDS,
  SCENARIOS,
  addDaysISO,
  allowedFixture,
  brazilDate,
  extractPdfLines,
  isoToBrazil,
  verifyEventsReport,
} from './documental-core.mjs?v=3.2.0';

pdfjs.GlobalWorkerOptions.workerSrc = new URL('./vendor/pdf.worker.min.mjs', import.meta.url).href;
const $ = id => document.getElementById(id);
const manifest = await fetch('./documental-manifest.json', { cache: 'no-store' }).then(r => {
  if (!r.ok) throw Error('Não foi possível carregar os exemplos.');
  return r.json();
});
let session = new DocumentarySession(manifest);
let selected = null;
let busy = false;
let renderTicket = 0;
let renderedDocKey = '';
const sources = new Map();

const labels = {
  patient: 'Nome',
  birthDate: 'Nascimento',
  identifier: 'Identificação',
  issueDate: 'Data de emissão',
  type: 'Tipo',
  subfamily: 'Subfamília',
  procedure: 'Procedimento informado',
  procedureCodeSystem: 'Sistema do código (quando declarado)',
  procedureCode: 'Código documental',
  procedureCodeSource: 'Origem do sistema do código',
  laterality: 'Lateralidade informada',
  origin: 'Origem informada',
  syntheticMarkerCue: 'Marcador textual sintético (não autentica assinatura)',
};
const identityLabels = {
  suggested: 'Identidade sugerida · conferir',
  manual: 'Sem identificador · conferir manualmente',
  conflict: 'Identidade divergente · quarentena',
  insufficient: 'Identidade insuficiente · quarentena',
  unreadable: 'Sem extração · quarentena',
};
const actionLabels = {
  documento_recebido: 'Documento recebido',
  duplicado_recusado: 'Arquivo idêntico recusado',
  revisao_humana: 'Revisão humana registrada',
  documento_descartado: 'Documento retirado do fluxo',
  substituicao_confirmada: 'Substituição confirmada',
  regra_administrativa_alterada: 'Regra administrativa alterada',
  pendencia_atribuida: 'Responsável e prazo atribuídos',
  pendencia_resolvida: 'Resolução justificada',
  cadastro_importado: 'Cadastro fictício importado',
};
const axisBadges = {
  ok: 'OK · Compatível',
  conflito: 'BLOQUEIO · Conflito',
  abstencao: 'ABSTENÇÃO · Insuficiente',
  nao_avaliado: 'NÃO AVALIADO',
  nao_aplicavel: 'NÃO APLICÁVEL (Explícito)',
  pendente: 'PENDENTE · Conferência',
};

function el(tag, text, cls) {
  const n = document.createElement(tag);
  if (['button', 'input', 'select', 'textarea'].includes(tag)) n.disabled = busy;
  if (text !== undefined) n.textContent = text;
  if (cls) n.className = cls;
  return n;
}
function option(value, text) {
  const n = el('option', text);
  n.value = value;
  return n;
}
function clearFieldInvalidity() {
  for (const field of document.querySelectorAll('[aria-invalid="true"]')) field.removeAttribute('aria-invalid');
}
function markInvalidTarget(text) {
  const msg = String(text || '').toLowerCase();
  if (msg.includes('confirme a conferência de identidade')) $('identity-confirm')?.setAttribute('aria-invalid', 'true');
  else if (msg.includes('correção bloqueada sem justificativa') || msg.includes('observação deve ter')) $('review-note')?.setAttribute('aria-invalid', 'true');
  else if (msg.includes('motivo da retirada')) $('discard-note')?.setAttribute('aria-invalid', 'true');
  else if (msg.includes('data de emissão inválida')) $('issue-date')?.setAttribute('aria-invalid', 'true');
  else if (msg.includes('observação visual humana')) $('human-visual-observation')?.setAttribute('aria-invalid', 'true');
  else if (msg.includes('substitui')) $('previous-document')?.setAttribute('aria-invalid', 'true');
  else if (msg.includes('janela')) $('window')?.setAttribute('aria-invalid', 'true');
}
function message(text, error = false) {
  const m = $('message');
  clearFieldInvalidity();
  m.setAttribute('role', error ? 'alert' : 'status');
  m.textContent = error && !String(text).startsWith('Erro:') ? 'Erro: ' + text : text;
  m.classList.toggle('error', error);
  if (error) markInvalidTarget(text);
}
function syncDocumentActions(d) {
  const state = d ? session.documentActionState(d) : null;
  const prev = d ? session.active().filter(p => p.id !== d.id && p.kind === d.kind && p.review && p.caseId === d.caseId && (!d.subfamily || !p.subfamily || d.subfamily.toLowerCase() === p.subfamily.toLowerCase())) : [];
  const canReplace = Boolean(state?.canReplace && prev.length);
  const canDiscard = Boolean(state?.canDiscard);
  $('previous-document').disabled = busy || !canReplace;
  $('replace').disabled = busy || !canReplace;
  $('discard-note').disabled = busy || !canDiscard;
  $('discard').disabled = busy || !canDiscard;
  const hintEl = $('action-blocked-hint');
  if (hintEl) {
    if (!d) hintEl.textContent = '';
    else if (d.status === 'discarded') hintEl.textContent = 'Retirado do fluxo: substituição e descarte desabilitados; histórico preservado.';
    else if (d.supersededBy) hintEl.textContent = `Versão substituída por ${d.supersededBy}: mantida somente para histórico.`;
    else if (!d.review) hintEl.textContent = 'Para substituir uma versão anterior, registre antes a revisão humana deste documento. Retirar do fluxo é permitido com motivo (5+ caracteres).';
    else if (!prev.length) hintEl.textContent = 'Substituição indisponível: não há outro documento ativo revisado da mesma classe e subfamília no mesmo caso.';
    else hintEl.textContent = 'Substituição disponível entre versões revisadas da mesma classe e subfamília; ambas permanecem no histórico.';
  }
}
async function run(fn, rerender = true) {
  if (busy) return;
  busy = true;
  document.body.setAttribute('aria-busy', 'true');
  for (const b of document.querySelectorAll('button,input,select,textarea')) b.disabled = true;
  try {
    await fn();
    if (rerender) await refresh();
  } catch (e) {
    if (rerender === 'always') await refresh();
    message(e.message || 'Não foi possível concluir. Tente novamente.', true);
  } finally {
    busy = false;
    document.body.removeAttribute('aria-busy');
    for (const b of document.querySelectorAll('button,input,select,textarea')) b.disabled = false;
    syncDocumentActions(selected ? session.doc(selected) : null);
  }
}
async function destroyPdf(doc) {
  try {
    if (doc?.loadingTask?.destroy) await doc.loadingTask.destroy();
    else if (doc?.destroy) await doc.destroy();
    else if (doc?.cleanup) await doc.cleanup();
  } catch {}
}
async function parsePdf(bytes) {
  const task = pdfjs.getDocument({ data: bytes.slice(), isEvalSupported: false, useSystemFonts: true, disableFontFace: true });
  let doc;
  try { doc = await task.promise; } catch {
    try { await task.destroy?.(); } catch {}
    throw Error('Não foi possível ler este PDF.');
  }
  try {
    const lines = await extractPdfLines(doc, pdfjs.Util.transform, 5);
    return { doc, lines };
  } catch (e) {
    await destroyPdf(doc);
    throw e;
  }
}
async function ingestBytes(bytes) {
  const start = performance.now();
  const f = await allowedFixture(bytes, manifest);
  if (session.documents.some(d => d.hash === f.sha256)) return session.ingest(f, [], performance.now() - start);
  const source = { bytes: bytes.slice(), mime: f.mime };
  let lines = [];
  if (f.mime === 'application/pdf') {
    const parsed = await parsePdf(bytes);
    source.doc = parsed.doc;
    lines = parsed.lines;
  } else {
    source.url = URL.createObjectURL(new Blob([bytes], { type: f.mime }));
  }
  try {
    const result = await session.ingest(f, lines, performance.now() - start);
    sources.set(result.document.id, source);
    selected = result.document.id;
    return result;
  } catch (e) {
    if (source.doc) await destroyPdf(source.doc);
    if (source.url) URL.revokeObjectURL(source.url);
    throw e;
  }
}
async function loadScenario() {
  const s = SCENARIOS[$('scenario').value];
  let duplicates = 0;
  for (const name of s.files) {
    const f = manifest.files.find(x => x.name === name);
    const r = await fetch(f.path);
    if (!r.ok) throw Error('Exemplo indisponível: ' + name);
    const result = await ingestBytes(new Uint8Array(await r.arrayBuffer()));
    if (result.duplicate) duplicates++;
  }
  message(s.label + ' adicionado. ' + (duplicates ? 'Duplicados recusados: ' + duplicates + '.' : 'Selecione um documento e confira os campos.'));
}
async function showSource(d, field) {
  const ticket = ++renderTicket;
  const source = sources.get(d.id);
  $('source-highlight').hidden = true;
  if (!source) return;
  const page = field?.source?.page || 1;
  $('page-label').textContent = 'Página ' + page;
  if (source.doc) {
    $('source-image').hidden = true;
    $('pdf-canvas').hidden = false;
    $('pdf-canvas').setAttribute('aria-label', 'Página ' + page + ' de ' + d.name);
    const p = await source.doc.getPage(page);
    const viewport = p.getViewport({ scale: 1.4 });
    const canvas = document.createElement('canvas');
    canvas.width = Math.ceil(viewport.width);
    canvas.height = Math.ceil(viewport.height);
    await p.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
    if (ticket !== renderTicket) return;
    const target = $('pdf-canvas');
    target.width = canvas.width;
    target.height = canvas.height;
    target.getContext('2d').drawImage(canvas, 0, 0);
  } else {
    $('pdf-canvas').hidden = true;
    $('source-image').hidden = false;
    $('source-image').src = source.url;
  }
  if (field?.source) {
    const [x, y, w, h] = field.source.box;
    const mark = $('source-highlight');
    mark.style.left = x * 100 + '%';
    mark.style.top = y * 100 + '%';
    mark.style.width = w * 100 + '%';
    mark.style.height = h * 100 + '%';
    mark.hidden = false;
    $('source-caption').textContent = 'Fonte, página ' + page + ': ' + field.source.text;
  } else {
    $('source-caption').textContent = source.doc
      ? 'Clique em “Ver fonte” ao lado de um campo.'
      : 'Sem OCR nesta versão. A imagem permanece visível apenas para inspeção manual; nenhuma assinatura ou texto foi analisado.';
  }
}
function renderList() {
  $('document-list').replaceChildren();
  if (!session.documents.length) {
    $('document-list').append(el('p', 'Adicione um cenário para começar.'));
    return;
  }
  for (const d of session.documents) {
    const b = el('button', d.name, 'doc-button' + (d.id === selected ? ' selected' : ''));
    b.type = 'button';
    b.setAttribute('aria-pressed', String(d.id === selected));
    b.append(el('span', d.supersededBy ? 'Versão anterior preservada' : d.status === 'discarded' ? 'Retirado do fluxo' : d.review ? 'Revisado · ' + KINDS[d.kind] : identityLabels[d.identity]));
    b.addEventListener('click', () => run(async () => { selected = d.id; }));
    $('document-list').append(b);
  }
}
function syncPreviousOptions(d) {
  const prevList = d ? session.active().filter(p => p.id !== d.id && p.kind === d.kind && p.review && p.caseId === d.caseId && (!d.subfamily || !p.subfamily || d.subfamily.toLowerCase() === p.subfamily.toLowerCase())) : [];
  const sel = $('previous-document'), currentVal = sel.value;
  sel.replaceChildren(option('', prevList.length ? 'Escolha a versão anterior' : 'Nenhuma versão anterior revisada disponível'));
  for (const previous of prevList) sel.append(option(previous.id, previous.name + ' · ' + previous.id));
  if (prevList.some(p => p.id === currentVal)) sel.value = currentVal;
}
function quarantineGuidance(d) {
  if (!d) return '';
  if (d.supersededBy) return `Substituição preservada: versão anterior substituída explicitamente por ${d.supersededBy} e mantida fora do conjunto ativo.`;
  if (d.status === 'discarded') return 'Retirada do fluxo: documento descartado por ação humana, preservado apenas no histórico.';
  if (d.identity === 'unreadable') return 'Abstenção obrigatória (sem OCR nesta versão): imagem ou PDF sem camada textual não recebe extração nem análise de assinatura; reenvie PDF com texto ou retire do fluxo.';
  if (d.identity === 'conflict') return `Bloqueio por quarentena cadastral: os dados divergem do caso ativo (${session.case.patient}) ou têm duplicidade; vínculo automático proibido.`;
  if (d.identity === 'insufficient') return 'Bloqueio por informação insuficiente: nome ou data de nascimento ausentes para conferência cadastral.';
  if (d.kind === 'desconhecido') return 'Abstenção por classe desconhecida: tipo documental fora das quatro classes previstas.';
  return '';
}
async function renderReview() {
  const d = selected ? session.doc(selected) : null;
  const docKey = d ? [d.id, d.status, d.supersededBy || '', d.reviewHistory.length, d.caseId || ''].join('|') : 'none';
  $('review-area').hidden = !d;
  $('empty-review').hidden = !!d;
  if (!d) {
    renderedDocKey = docKey;
    syncDocumentActions(null);
    return;
  }
  syncPreviousOptions(d);
  syncDocumentActions(d);
  if (docKey === renderedDocKey) return;
  renderedDocKey = docKey;
  $('document-name').textContent = d.name;
  $('document-status').textContent = d.supersededBy ? 'Substituído por ' + d.supersededBy : d.status === 'discarded' ? 'Retirado do fluxo' : d.review ? 'Revisão registrada' : identityLabels[d.identity];
  $('document-status').classList.toggle('warn', !d.review);
  $('fields').replaceChildren();

  if (!d.readable) {
    const noticeRow = el('div', undefined, 'field');
    noticeRow.append(el('small', 'Extração textual (PDF.js)'), el('strong', 'Sem camada de texto extraível (sem OCR nesta versão). Nenhuma análise de campos ou assinatura foi realizada.'));
    $('fields').append(noticeRow);
  } else {
    for (const [key, label] of Object.entries(labels)) {
      const f = d.fields[key] || { value: '', source: null, uncertain: false };
      if (key === 'syntheticMarkerCue' && d.kind !== 'termo' && !f.present && !f.uncertain) continue;
      if (['procedureCode', 'procedureCodeSystem', 'procedureCodeSource'].includes(key) && !d.fields.procedureCode?.value && !d.fields.procedureCode?.uncertain && !f.value && !f.uncertain) continue;
      const row = el('div', undefined, 'field'), top = el('div', undefined, 'field-top');
      top.append(el('small', label));
      if (f.source) {
        const b = el('button', 'Ver fonte');
        b.type = 'button';
        b.setAttribute('aria-label', 'Ver fonte de ' + label);
        b.addEventListener('click', () => run(async () => {
          await showSource(d, f);
          message('Trecho de ' + label + ' destacado na página original.');
        }, false));
        top.append(b);
      }
      const emptyText = ['subfamily', 'procedure', 'procedureCode', 'procedureCodeSystem', 'laterality'].includes(key)
        ? 'Não informado neste documento'
        : key === 'syntheticMarkerCue'
          ? 'Marcador textual "MARCA FICTICIA" ausente na camada de texto (não analisa imagem nem autentica assinatura)'
          : 'Não localizado';
      const valText = f.uncertain
        ? `Ambíguo · múltiplos valores no documento${f.candidates?.length ? ' (' + f.candidates.join(' × ') + ')' : ''}`
        : (f.value || emptyText);
      row.append(top, el('strong', valText));
      $('fields').append(row);
    }
  }
  const guidance = quarantineGuidance(d), guideEl = $('quarantine-guidance');
  guideEl.textContent = guidance;
  guideEl.hidden = !guidance;
  $('identity-confirm').checked = !!d.review;
  $('issue-date').value = d.review?.issueDate ?? brazilDate(d.fields.issueDate.value);
  $('human-visual-observation').value = d.review?.humanVisualObservation || 'unknown';
  $('review-note').value = d.review?.note || '';
  $('visual-observation-group').hidden = d.kind !== 'termo';
  $('review-form').hidden = Boolean(guidance);
  $('discard-note').value = '';
  await showSource(d);
}
function renderAxes() {
  const wrap = $('consistency-axes');
  if (!wrap) return;
  wrap.replaceChildren();
  for (const a of session.consistencyAxes()) {
    const card = el('article', undefined, 'axis-card axis-' + a.status);
    card.setAttribute('aria-label', `${a.label}: ${axisBadges[a.status] || a.status}`);
    const head = el('div', undefined, 'axis-head');
    head.append(el('strong', a.label), el('span', axisBadges[a.status] || a.status, 'axis-badge'));
    card.append(head, el('p', a.detail));
    wrap.append(card);
  }
  const noticeEl = $('pending-notice');
  if (noticeEl) noticeEl.textContent = session.buildPendingNotice();
}
function taskGuidance(t) {
  const parts = String(t.id || '').split(':');
  const prefix = parts[0];
  const code = parts[1];
  if (prefix === 'missing') {
    return {
      reason: 'Nenhum documento ativo revisado desta classe foi vinculado ao caso.',
      next: 'Adicione ou localize o exemplo correspondente, confira a identidade e os campos e registre a revisão humana.',
    };
  }
  if (prefix === 'axis') {
    if (code === 'procedure') {
      return {
        reason: 'Os documentos ativos apresentam divergência, ambiguidade ou código sem sistema de codificação identificado no eixo de procedimento.',
        next: 'Confira o procedimento, o código e o sistema nos documentos do caso e retire ou substitua o arquivo conflitante (bloqueado para texto livre).',
      };
    }
    if (code === 'laterality') {
      return {
        reason: 'Há divergência ou ambiguidade de lateralidade entre os documentos ativos do caso (ex.: OD × OE).',
        next: 'Compare os trechos originais de lateralidade e retire ou substitua o documento divergente antes de concluir (bloqueado para texto livre).',
      };
    }
  }
  const guidance = {
    unreadable: {
      reason: 'Esta versão pública não extrai texto de imagens nem realiza OCR ou análise visual de assinatura.',
      next: 'Use “Abrir documento” para inspeção visual e solicite um PDF com camada textual ou retire o arquivo do fluxo.',
    },
    identity: {
      reason: 'Os dados de identidade divergem do cadastro ativo ou são insuficientes para confirmar o vínculo.',
      next: 'Use “Abrir documento” para comparar os campos originais em quarentena e solicite o documento correto; o vínculo automático permanece bloqueado.',
    },
    unknown: {
      reason: 'O tipo documental não foi reconhecido pelas regras determinísticas desta demonstração.',
      next: 'Use “Abrir documento” para conferir o original, solicite um exemplo das classes previstas ou retire este arquivo do fluxo.',
    },
    review: {
      reason: 'Os campos foram extraídos, mas ainda precisam de conferência e confirmação humana.',
      next: 'Use “Abrir documento”, confira a fonte de cada campo, valide a identidade e registre a revisão humana.',
    },
    'date-missing': {
      reason: 'A data de emissão não foi localizada ou não possui formato válido.',
      next: 'Use “Abrir documento” para conferir a data no original. Se corrigir o campo, registre o motivo (5 a 500 caracteres) ou solicite novo documento.',
    },
    future: {
      reason: `A data de emissão é posterior à data de referência do exemplo (${isoToBrazil(session.manifest.referenceDate) || session.manifest.referenceDate}).`,
      next: 'Use “Abrir documento” para conferir o trecho de emissão. Corrija com justificativa após revisão ou encaminhe a divergência.',
    },
    'window-unknown': {
      reason: 'A data do procedimento fictício está ausente ou inválida para avaliar a janela temporal ilustrativa.',
      next: 'Confira o cadastro sintético e a data do laudo; após revisão humana, registre o encaminhamento administrativo.',
    },
    window: {
      reason: `A data do laudo está fora da janela ilustrativa configurada (${session.policy.maxAgeDays} dias em UTC para este exemplo).`,
      next: 'Use “Abrir documento” para conferir a data e solicite versão atualizada se aplicável. Uma exceção exige revisão humana, responsável, prazo e justificativa.',
    },
    'visual-observation': {
      reason: 'A observação visual humana independente na página do termo ainda não foi registrada como observada.',
      next: 'Use “Abrir documento” e registre sua observação visual na página. Marca textual ou visual não autentica assinatura.',
    },
  };
  return guidance[code] || {
    reason: 'Há uma informação documental a conferir segundo as regras administrativas do exemplo.',
    next: 'Revise o documento ou os quatro eixos e registre o encaminhamento.',
  };
}
function taskDetail(label, value) {
  const p = el('p', undefined, 'task-detail');
  p.append(el('strong', label + ' '), document.createTextNode(value));
  return p;
}
function renderTasks() {
  $('tasks').replaceChildren();
  const tasks = session.tasks();
  const suggestedDue = addDaysISO(session.manifest.referenceDate, 2);
  const defaultDue = session.case.procedureDate && suggestedDue > session.case.procedureDate
    ? session.case.procedureDate
    : (suggestedDue || session.manifest.referenceDate);
  for (const t of tasks) {
    const row = el('article', undefined, 'task'), text = el('div');
    const guidance = taskGuidance(t);
    text.append(
      el('h3', t.title),
      taskDetail('Motivo:', guidance.reason),
      taskDetail('Próximo passo:', guidance.next),
    );
    if (t.docId) {
      const doc = session.doc(t.docId);
      if (doc) {
        text.append(taskDetail('Documento:', `${doc.name} · ${doc.id}`));
        const open = el('button', 'Abrir documento', 'task-source');
        open.type = 'button';
        open.setAttribute('aria-label', 'Abrir documento da pendência: ' + t.title);
        open.addEventListener('click', async () => {
          await run(async () => {
            if (!session.doc(t.docId)) throw Error('Documento não encontrado na sessão atual.');
            selected = t.docId;
            message('Documento aberto para conferir a pendência: ' + t.title);
          });
          const area = $('review-area');
          const heading = $('document-name');
          if (area && !area.hidden && heading) {
            heading.focus();
            area.scrollIntoView({ block: 'start' });
          }
        });
        text.append(open);
      }
    } else {
      text.append(taskDetail(
        'Fonte:',
        t.id.startsWith('axis:')
          ? 'Comparação cruzada dos quatro eixos nos documentos ativos do caso.'
          : 'Lista de classes exigidas pela regra administrativa do exemplo.',
      ));
    }
    if (t.resolution) {
      text.append(el('p', 'Resolução: ' + t.resolution.note), el('p', 'Responsável: ' + t.resolution.assignment.owner + ' · prazo ' + t.resolution.assignment.due));
      row.append(text, el('span', 'Justificativa registrada', 'pill'));
    } else {
      const controls = el('div', undefined, 'task-controls'), owner = el('select'), due = el('input');
      owner.setAttribute('aria-label', 'Responsável por ' + t.title);
      owner.append(option('Revisor A', 'Revisor A'), option('Revisor B', 'Revisor B'));
      owner.value = t.assignment?.owner || 'Revisor A';
      due.type = 'date';
      due.min = session.manifest.referenceDate;
      due.value = t.assignment?.due || defaultDue;
      due.setAttribute('aria-label', 'Prazo de ' + t.title);
      const ow = el('div'), dw = el('div');
      ow.append(el('label', 'Responsável fictício'), owner);
      dw.append(el('label', 'Prazo'), due);
      const assign = el('button', t.assignment ? 'Atualizar atribuição' : 'Atribuir');
      assign.type = 'button';
      assign.addEventListener('click', () => run(async () => {
        await session.assign(t.id, owner.value, due.value);
        message('Responsável e prazo registrados.');
      }));
      controls.append(ow, dw, assign);
      if (t.manual && session.doc(t.docId).review) {
        const group = el('div', undefined, 'task-note'), note = el('input'), resolve = el('button', 'Registrar resolução');
        note.maxLength = 500;
        note.placeholder = 'Justificativa da resolução (5 a 500 caracteres)';
        note.setAttribute('aria-label', 'Justificativa para ' + t.title);
        resolve.type = 'button';
        resolve.addEventListener('click', () => run(async () => {
          await session.resolve(t.id, note.value);
          message('Resolução registrada com justificativa.');
        }));
        group.append(note, resolve);
        controls.append(group);
      } else {
        const blockMsg = t.id.startsWith('axis:')
          ? 'Bloqueado para resolução em texto livre: retire ou substitua o documento conflitante.'
          : 'Requer revisão humana, envio legível ou retirada do documento.';
        controls.append(el('p', blockMsg));
      }
      row.append(text, controls);
    }
    $('tasks').append(row);
  }
  const r = session.readinessState();
  const rEl = $('readiness');
  rEl.textContent = r.label;
  rEl.classList.toggle('warn', ['pendente', 'abstencao'].includes(r.code));
  rEl.classList.toggle('limited', r.code === 'conferida_com_escopo_limitado');
  rEl.classList.toggle('danger', r.code === 'bloqueado');
  if (!tasks.length && r.code === 'conferida') {
    $('tasks').append(el('p', 'Quatro eixos avaliados e compatíveis nas regras administrativas do exemplo. A avaliação clínica permanece fora desta demonstração.'));
  } else if (!tasks.length && r.code === 'abstencao') {
    $('tasks').append(el('p', 'Sem pendências operacionais abertas, porém em ABSTENÇÃO porque algum eixo obrigatório (ex.: procedimento ou lateralidade) não possui dados extraídos suficientes.'));
  } else if (!tasks.length && r.code === 'conferida_com_escopo_limitado') {
    $('tasks').append(el('p', 'Conferida com escopo limitado: eixo(s) declarado(s) explicitamente como não aplicáveis nas regras administrativas, sem decisão clínica.'));
  }
}
function renderAudit() {
  $('audit').replaceChildren();
  for (const e of session.events.slice().reverse()) {
    const li = el('li');
    li.append(
      el('strong', '#' + e.seq + ' ' + (actionLabels[e.action] || e.action)),
      el('small', new Date(e.at).toLocaleString('pt-BR') + ' · ' + (e.data.document || e.data.taskId || 'sessão') + ' · ' + e.actor + ' · hash ' + e.hash.slice(0, 16) + '…')
    );
    $('audit').append(li);
  }
}
async function refresh() {
  $('case-name').textContent = session.case.patient;
  $('case-meta').textContent = 'Caso ' + session.case.id + ' · Identificação fictícia ' + session.case.identifier + ' · Nascimento ' + (isoToBrazil(session.case.birthDate) || session.case.birthDate);
  const ctx = $('rule-context');
  if (ctx) {
    ctx.textContent = `Referência do exemplo: ${isoToBrazil(session.manifest.referenceDate) || session.manifest.referenceDate}. Procedimento fictício: ${isoToBrazil(session.case.procedureDate) || session.case.procedureDate || 'Não informado'}. Regra ilustrativa/configurável (${session.policy.origin}), aplicada somente à categoria Laudo de exame; não define validade clínica.`;
  }
  $('rule-meta').textContent = 'Regra versão ' + session.policy.version + ' · janela de ' + session.policy.maxAgeDays + ' dias (ilustrativa para laudo)';
  $('window').value = session.policy.maxAgeDays;
  const s = session.summary();
  $('metrics').replaceChildren();
  for (const [key, label] of [['documents', 'Documentos recebidos'], ['reviewed', 'Ativos revisados'], ['pending', 'Pendências abertas'], ['duplicates', 'Duplicados recusados'], ['quarantine', 'Em quarentena']]) {
    const n = el('div', undefined, 'metric');
    n.append(el('strong', String(s[key])), el('span', label));
    $('metrics').append(n);
  }
  renderList();
  renderAxes();
  renderTasks();
  renderAudit();
  for (const b of document.querySelectorAll('button,input,select,textarea')) b.disabled = busy;
  await renderReview();
}

for (const [key, s] of Object.entries(SCENARIOS)) $('scenario').append(option(key, s.label));
$('load').addEventListener('click', () => run(loadScenario, 'always'));
$('files').addEventListener('change', () => run(async () => {
  const files = [...$('files').files];
  $('files').value = '';
  if (files.length > 12) throw Error('Selecione no máximo 12 arquivos por envio.');
  let accepted = 0;
  for (const file of files) {
    if (file.size > 524288) throw Error('Arquivo maior que 512 KB.');
    await ingestBytes(new Uint8Array(await file.arrayBuffer()));
    accepted++;
  }
  message(accepted + ' arquivo(s) fictício(s) processado(s).');
}, 'always'));
$('case-file').addEventListener('change', () => run(async () => {
  const f = $('case-file').files[0];
  $('case-file').value = '';
  if (!f) return;
  if (f.size > 524288) throw Error('Cadastro maior que o permitido.');
  const bytes = new Uint8Array(await f.arrayBuffer());
  const known = await allowedFixture(bytes, manifest, ['application/json', 'text/csv']);
  const loaded = await session.loadSyntheticCase(known, new TextDecoder().decode(bytes));
  message('Cadastro fictício conferido e carregado: ' + loaded.id + ' (' + loaded.identifier + ').');
}));
$('review-form').addEventListener('submit', e => {
  e.preventDefault();
  run(async () => {
    await session.review(selected, {
      identityChecked: $('identity-confirm').checked,
      issueDate: $('issue-date').value,
      humanVisualObservation: $('human-visual-observation').value,
      note: $('review-note').value,
    });
    message('Revisão humana registrada; eixos e pendências recalculados.');
  });
});
$('rule').addEventListener('click', () => run(async () => {
  await session.configure(Number($('window').value));
  message('Nova versão da regra aplicada. Justificativas anteriores foram invalidadas para nova conferência e preservadas no histórico.');
}));
$('replace').addEventListener('click', () => run(async () => {
  await session.replace(selected, $('previous-document').value);
  message('Substituição confirmada. As duas versões permanecem preservadas no histórico.');
}));
$('discard').addEventListener('click', () => run(async () => {
  await session.discard(selected, $('discard-note').value);
  message('Documento retirado do fluxo ativo e preservado no histórico.');
}));
$('verify').addEventListener('click', () => run(async () => {
  const rep = await verifyEventsReport(session.events);
  message(rep.valid ? `${rep.reason} Não autentica usuário nem substitui auditoria em servidor.` : rep.reason, !rep.valid);
}));
$('export').addEventListener('click', () => run(async () => {
  const url = URL.createObjectURL(new Blob([JSON.stringify(session.export(), null, 2)], { type: 'application/json' })), a = el('a');
  a.href = url;
  a.download = 'JYXIA-sessao-ficticia-v3.2.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  message('Exportação JSON gerada com distinção entre extração, revisão humana, limitações e cadeia local.');
}));
$('export-csv')?.addEventListener('click', () => run(async () => {
  const url = URL.createObjectURL(new Blob(['\uFEFF' + session.exportCsv()], { type: 'text/csv;charset=utf-8' })), a = el('a');
  a.href = url;
  a.download = 'JYXIA-conferencia-ficticia-v3.2.csv';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  message('Exportação CSV administrativa gerada para a sessão fictícia.');
}));
$('copy-notice')?.addEventListener('click', () => run(async () => {
  const text = session.buildPendingNotice();
  try {
    await navigator.clipboard?.writeText(text);
    message('Resumo administrativo copiado para a área de transferência.');
  } catch {
    message('Resumo administrativo pronto no painel abaixo para cópia manual.');
  }
}, false));
$('reset').addEventListener('click', () => run(async () => {
  if (!$('reset-confirm').checked) throw Error('Marque a confirmação antes de limpar a sessão fictícia.');
  for (const s of sources.values()) {
    if (s.doc) await destroyPdf(s.doc);
    if (s.url) URL.revokeObjectURL(s.url);
  }
  sources.clear();
  session = new DocumentarySession(manifest);
  selected = null;
  renderedDocKey = '';
  $('reset-confirm').checked = false;
  message('Sessão fictícia limpa.');
}));

await refresh();
message('Pronto (Modalidade A · versão 3.2.0). Escolha um cenário fictício ou anexe os exemplos fornecidos.');
