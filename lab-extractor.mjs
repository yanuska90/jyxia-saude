import { normalizeLaterality, brazilDate } from './documental-core.mjs';

export const LAB_LIMITS = Object.freeze({
  maxBytes: 524288,
  maxPages: 10,
  allowedHosts: Object.freeze(['127.0.0.1', 'localhost', '::1', '[::1]']),
});

export const FIELD_ALIASES = Object.freeze({
  patient: ['Paciente', 'Nome do paciente', 'Nome completo'],
  birthDate: ['Nascimento', 'Data de nascimento'],
  identifier: ['Identificador', 'ID', 'Codigo do paciente'],
  issueDate: ['Emissao', 'Data de emissao', 'Emitido em'],
  type: ['Tipo', 'Tipo documental'],
  subfamily: ['Subfamilia'],
  procedure: ['Procedimento', 'Procedimento solicitado'],
  procedureCode: ['Codigo', 'Codigo do procedimento'],
  procedureCodeSystem: ['Sistema', 'Sistema de codigo', 'SistemaCodigo', 'Tabela', 'TabelaCodigo'],
  laterality: ['Lateralidade', 'Lado', 'Regiao lateral'],
  origin: ['Origem', 'Instituicao', 'Unidade'],
});

const normalizeText = x => String(x ?? '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim().toLowerCase().replace(/\s+/g, ' ');

const ALIAS_LOOKUP = (() => {
  const entries = [];
  for (const [canonicalField, aliases] of Object.entries(FIELD_ALIASES)) {
    for (const alias of aliases) {
      entries.push({ canonicalField, alias, normAlias: normalizeText(alias) });
    }
  }
  // Longer aliases match first so "Nome do paciente" beats a shorter alias if any shares prefix
  return entries.sort((a, b) => b.normAlias.length - a.normAlias.length);
})();

export function hasPdfMagicBytes(bytes) {
  if (!bytes || bytes.byteLength < 5) return false;
  return bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46 && bytes[4] === 0x2d; // %PDF-
}

export function assertLocalhostEnvironment(hostname) {
  if (!LAB_LIMITS.allowedHosts.includes(String(hostname || '').toLowerCase())) {
    throw Error('Laboratório experimental restrito exclusivamente a localhost.');
  }
}

export async function extractLabPdfLines(doc, transformFn, maxPages = LAB_LIMITS.maxPages) {
  if (doc.numPages > maxPages) {
    if (doc.loadingTask?.destroy) await doc.loadingTask.destroy();
    else if (doc.destroy) await doc.destroy();
    throw Error(`Limite do laboratório: máximo de ${maxPages} páginas por PDF sintético.`);
  }
  const items = [];
  const pageRotations = [];
  for (let i = 1; i <= doc.numPages; i++) {
    const p = await doc.getPage(i);
    pageRotations.push({ page: i, rotate: p.rotate || 0 });
    const v = p.getViewport({ scale: 1 });
    const content = await p.getTextContent();
    const rowItems = [];
    for (const item of content.items) {
      if (!item.str?.trim()) continue;
      const t = transformFn(v.transform, item.transform);
      const rawH = Math.hypot(t[2], t[3]), height = Math.max(rawH, 8), scaleH = rawH > 0 ? height / rawH : 1;
      const hx = rawH > 0 ? t[2] * scaleH : 0, hy = rawH > 0 ? t[3] * scaleH : -height;
      const angle = Math.atan2(t[1], t[0]), wx = Math.cos(angle) * item.width, wy = Math.sin(angle) * item.width;
      const xs = [t[4], t[4] + wx, t[4] + hx, t[4] + wx + hx];
      const ys = [t[5], t[5] + wy, t[5] + hy, t[5] + wy + hy];
      const minX = Math.max(0, Math.min(...xs) / v.width), maxX = Math.min(1, Math.max(...xs) / v.width);
      const minY = Math.max(0, Math.min(...ys) / v.height), maxY = Math.min(1, Math.max(...ys) / v.height);
      rowItems.push({
        text: item.str.trim(),
        page: i,
        box: [minX, minY, Math.max(0, maxX - minX), Math.max(0, maxY - minY)],
        angle,
        height,
        u: Math.cos(angle) * t[4] + Math.sin(angle) * t[5],
        n: -Math.sin(angle) * t[4] + Math.cos(angle) * t[5],
        endU: Math.cos(angle) * (t[4] + wx) + Math.sin(angle) * (t[5] + wy),
      });
    }
    // Group visually collinear runs along the exact reading vector (rotation-invariant across 0/90/180/270)
    const groups = [];
    for (const it of rowItems) {
      const targetGroup = groups.find(g => {
        const last = g.items[g.items.length - 1];
        const sameAngle = Math.abs(Math.atan2(Math.sin(it.angle - g.angle), Math.cos(it.angle - g.angle))) < 0.08;
        const sameBaseline = Math.abs(it.n - g.n) < Math.max(g.height, it.height) * 0.45;
        if (!sameAngle || !sameBaseline) return false;
        const combinedSoFar = g.items.map(x => x.text).join(' ');
        const isSplitColumnLabel = /:\s*$/.test(combinedSoFar);
        const adjacentAlongLine = it.u >= last.u && (it.u - last.endU) < Math.max(g.height, it.height) * 6;
        return isSplitColumnLabel || adjacentAlongLine;
      });
      if (targetGroup) {
        targetGroup.items.push(it);
      } else {
        groups.push({ angle: it.angle, n: it.n, height: it.height, items: [it] });
      }
    }
    for (const g of groups) {
      if (g.items.length === 1) {
        items.push({ text: g.items[0].text, page: g.items[0].page, box: g.items[0].box });
      } else {
        const sorted = [...g.items].sort((a, b) => a.u - b.u);
        const minX = Math.min(...sorted.map(x => x.box[0]));
        const minY = Math.min(...sorted.map(x => x.box[1]));
        const maxX = Math.max(...sorted.map(x => x.box[0] + x.box[2]));
        const maxY = Math.max(...sorted.map(x => x.box[1] + x.box[3]));
        items.push({
          text: sorted.map(x => x.text).join(' ').replace(/\s+/g, ' ').trim(),
          page: i,
          box: [minX, minY, Math.max(0, maxX - minX), Math.max(0, maxY - minY)],
        });
      }
    }
  }
  return { lines: items, pagesCount: doc.numPages, pageRotations };
}

function matchRegisteredAlias(lineText) {
  const norm = normalizeText(lineText);
  for (const entry of ALIAS_LOOKUP) {
    // Require exact registered alias followed strictly by ':' (or ' - ' separator), never fuzzy substring inside sentences
    if (norm.startsWith(entry.normAlias + ':')) {
      const colonIdx = lineText.indexOf(':');
      return { canonicalField: entry.canonicalField, matchedAlias: entry.alias, value: lineText.slice(colonIdx + 1).trim() };
    }
    const dashPrefix = entry.normAlias + ' - ';
    if (norm.startsWith(dashPrefix)) {
      const dashIdx = lineText.indexOf(' - ');
      return { canonicalField: entry.canonicalField, matchedAlias: entry.alias, value: lineText.slice(dashIdx + 3).trim() };
    }
  }
  return null;
}

export function extractWithExplicitAliases(lines, { pagesCount = 1, pageRotations = [] } = {}) {
  const buckets = Object.fromEntries(Object.keys(FIELD_ALIASES).map(k => [k, []]));
  const unrecognizedLabels = [];
  const unlabeledItems = [];
  const markerMatches = [];

  for (const line of lines) {
    const raw = String(line.text ?? '').trim();
    if (!raw) continue;
    if (normalizeText(raw) === 'marca ficticia') {
      markerMatches.push(line);
      continue;
    }
    const matched = matchRegisteredAlias(raw);
    if (matched) {
      if (matched.value) {
        buckets[matched.canonicalField].push({
          value: matched.value,
          matchedAlias: matched.matchedAlias,
          page: line.page,
          box: [...line.box],
          text: raw,
        });
      }
      continue;
    }
    const colonPos = raw.indexOf(':');
    if (colonPos > 1 && colonPos <= 40 && !/^https?$/i.test(raw.slice(0, colonPos).trim())) {
      unrecognizedLabels.push({
        label: raw.slice(0, colonPos).trim(),
        value: raw.slice(colonPos + 1).trim(),
        page: line.page,
        box: [...line.box],
        text: raw,
        status: 'nao_reconhecido',
      });
    } else if (/^\d{2}\/\d{2}\/\d{4}$/.test(raw) || /^\d{4,}$/.test(raw)) {
      unlabeledItems.push({
        text: raw,
        page: line.page,
        box: [...line.box],
        reason: 'Informação numérica ou data sem rótulo explícito; não inferida automaticamente.',
      });
    }
  }

  const fields = {};
  const ambiguities = [];
  const abstentions = [];

  for (const field of Object.keys(FIELD_ALIASES)) {
    const hits = buckets[field];
    if (hits.length === 0) {
      fields[field] = {
        value: '',
        matchedAlias: null,
        source: null,
        uncertain: false,
        abstained: true,
        status: 'abstencao',
        reason: 'Rótulo explícito não localizado no PDF.',
      };
      abstentions.push({ field, reason: 'nao_localizado' });
    } else if (hits.length === 1) {
      const h = hits[0];
      const entry = {
        value: h.value,
        matchedAlias: h.matchedAlias,
        source: { page: h.page, box: [...h.box], text: h.text },
        uncertain: false,
        abstained: false,
        status: 'extraido',
      };
      if (field === 'laterality') {
        entry.normalized = normalizeLaterality(h.value);
        if (entry.normalized === 'abstencao') {
          entry.abstained = true;
          entry.status = 'abstencao';
          entry.reason = 'Valor de lateralidade não reconhecido de forma inequívoca.';
          abstentions.push({ field, reason: 'lateralidade_nao_reconhecida', value: h.value });
        }
      }
      if (field === 'birthDate' || field === 'issueDate') {
        entry.isoDate = brazilDate(h.value);
        if (!entry.isoDate) {
          entry.abstained = true;
          entry.status = 'abstencao';
          entry.reason = 'Data fora do formato DD/MM/AAAA válido ou calendário impossível.';
          abstentions.push({ field, reason: 'data_invalida', value: h.value });
        }
      }
      fields[field] = entry;
    } else {
      const uniqueNormVals = new Set(hits.map(h => normalizeText(h.value)));
      const duplicateIdentical = uniqueNormVals.size === 1;
      fields[field] = {
        value: '',
        matchedAlias: hits.map(h => h.matchedAlias).join(' | '),
        source: null,
        uncertain: true,
        abstained: true,
        duplicateIdentical,
        status: 'ambiguo',
        candidates: hits.map(h => ({ value: h.value, matchedAlias: h.matchedAlias, page: h.page, box: [...h.box], text: h.text })),
        reason: duplicateIdentical
          ? `Múltiplas ocorrências do mesmo valor (${hits.length}x) no documento; requer confirmação humana.`
          : `Múltiplos valores/rótulos conflitantes (${hits.map(h => `${h.matchedAlias}="${h.value}"`).join(' × ')}); abstenção obrigatória.`,
      };
      ambiguities.push({ field, duplicateIdentical, candidates: fields[field].candidates });
      abstentions.push({ field, reason: duplicateIdentical ? 'duplicado' : 'multiplos_candidatos' });
    }
  }

  fields.syntheticMarkerCue = markerMatches.length === 1
    ? {
        present: true,
        value: 'Marcador textual sintético detectado (MARCA FICTICIA). Não representa reconhecimento visual nem autenticação de assinatura.',
        source: { page: markerMatches[0].page, box: [...markerMatches[0].box], text: markerMatches[0].text },
        uncertain: false,
        status: 'extraido',
      }
    : {
        present: markerMatches.length > 1,
        value: '',
        source: null,
        uncertain: markerMatches.length > 1,
        candidates: markerMatches.length > 1 ? markerMatches.map(m => ({ page: m.page, box: [...m.box], text: m.text })) : undefined,
        status: markerMatches.length > 1 ? 'ambiguo' : 'ausente',
      };

  const readable = lines.some(x => String(x.text || '').trim().length > 4);
  return {
    mode: 'Modalidade B - Laboratório experimental local',
    nonProductionNotice: 'Extração experimental determinística por aliases explícitos (somente PDFs com camada textual). Não executa OCR nem valida dados reais.',
    readable,
    pagesCount,
    pageRotations,
    fields,
    unrecognizedLabels,
    unlabeledItems,
    ambiguities,
    abstentions,
    recognizedCount: Object.values(fields).filter(f => f.status === 'extraido').length,
  };
}
