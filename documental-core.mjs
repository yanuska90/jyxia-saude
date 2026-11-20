export const VERSION = '3.2.0';
export const KINDS = {
  solicitacao: 'Solicitação',
  laudo: 'Laudo de exame',
  avaliacao: 'Formulário de avaliação',
  termo: 'Termo documental',
  desconhecido: 'Não classificado',
};
export const AXIS_STATES = Object.freeze(['ok', 'conflito', 'abstencao', 'nao_avaliado', 'nao_aplicavel', 'pendente']);
export const READINESS_STATES = Object.freeze([
  'pendente',
  'bloqueado',
  'abstencao',
  'conferida_com_escopo_limitado',
  'conferida',
]);
export const SCENARIOS = {
  completo: {
    label: '1 · Conjunto parcial histórico (sem proced./lat.)',
    files: ['solicitacao.pdf', 'laudo.pdf', 'avaliacao.pdf', 'termo.pdf'],
  },
  duplicado: { label: '2 · Arquivo duplicado', files: ['laudo.pdf', 'laudo.pdf'] },
  versao: { label: '3 · Documento atualizado', files: ['laudo.pdf', 'laudo-atualizado.pdf'] },
  divergente: { label: '4 · Identidade divergente', files: ['identidade-divergente.pdf'] },
  identificador: { label: '5 · Identificador ausente', files: ['sem-identificador.pdf'] },
  ilegivel: { label: '6 · Imagem sem texto extraível', files: ['imagem-ilegivel.png'] },
  janela: {
    label: '7 · Data e marca a conferir',
    files: ['solicitacao.pdf', 'laudo-antigo.pdf', 'avaliacao.pdf', 'termo-sem-marca.pdf'],
  },
  lateralidade: {
    label: '8 · Lateralidade divergente (OD × OE)',
    files: ['solicitacao-od.pdf', 'termo-oe.pdf'],
  },
  quatro_eixos: {
    label: '9 · Conjunto completo (4 eixos avaliados)',
    files: ['solicitacao-completa.pdf', 'laudo-completo.pdf', 'avaliacao-completa.pdf', 'termo-completo.pdf'],
  },
};

const normalize = x => String(x ?? '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim().toLowerCase().replace(/\s+/g, ' ');
const normalizeComparable = x => normalize(x).replace(/[^a-z0-9]+/g, ' ').trim().replace(/\s+/g, ' ');
const INCOMPLETE_PROC = new Set(['', 'a definir', 'nao informado', 'indefinido', 'em avaliacao', 'pendente', 'outro', 'cirurgia', 'procedimento']);
const KNOWN_CODE_SYSTEMS = new Set(['TUSS', 'SIGTAP', 'CBHPM', 'SUS']);
const DEMO_ACTOR = 'Revisor de demonstração (ator fictício local, sem autenticação)';
const VISUAL_OBS_MAP = { unknown: 'unknown', not_verified: 'unknown', observed: 'observed', present: 'observed', not_observed: 'not_observed', absent: 'not_observed' };

export function validISO(s) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  return Number.isFinite(+d) && d.toISOString().slice(0, 10) === s;
}
export function brazilDate(s) {
  const m = String(s ?? '').match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (!m) return '';
  const v = `${m[3]}-${m[2]}-${m[1]}`;
  return validISO(v) ? v : '';
}
export function isoToBrazil(s) {
  if (!validISO(s)) return '';
  const [y, m, d] = s.split('-');
  return `${d}/${m}/${y}`;
}
export function addDaysISO(s, days) {
  if (!validISO(s) || !Number.isInteger(days)) return '';
  const d = new Date(s + 'T00:00:00Z');
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}
export function diffDaysISO(fromISO, toISO) {
  if (!validISO(fromISO) || !validISO(toISO)) return null;
  const [fy, fm, fd] = fromISO.split('-').map(Number);
  const [ty, tm, td] = toISO.split('-').map(Number);
  return Math.round((Date.UTC(ty, tm - 1, td) - Date.UTC(fy, fm - 1, fd)) / 86400000);
}
export function normalizeLaterality(text) {
  const n = normalize(text);
  if (!n) return '';
  const rawClean = String(text ?? '').normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  const hasRight = /\b(od|direit[oa]|olho direito|lado direito)\b/.test(n);
  const hasLeft = /\b(oe|esquerd[oa]|olho esquerdo|lado esquerdo)\b/.test(n);
  const hasBoth = /\b(bilateral(mente)?|ambos(\s+os\s+olhos)?|ambas)\b/.test(n) || n === 'ao' || /(?:^|[\s(/])(AO|A\.O\.)(?:$|[\s)./,;])/.test(rawClean);
  if ((hasRight && hasLeft) || (hasBoth && (hasRight || hasLeft))) return 'abstencao';
  if (hasBoth) return 'bilateral';
  if (hasRight) return 'direito';
  if (hasLeft) return 'esquerdo';
  if (n === 'na' || /\b(nao aplicavel|nao se aplica|sem lateralidade aplicavel|n\/a)\b/.test(n)) return 'nao_aplicavel';
  return 'abstencao';
}
export function parseSyntheticCase(text, mime) {
  if (typeof text !== 'string' || !text.trim()) throw Error('Cadastro sintético vazio.');
  const clean = text.replace(/^\uFEFF/, '').trim();
  let item;
  if (mime === 'application/json') {
    let parsed;
    try { parsed = JSON.parse(clean); } catch { throw Error('JSON de cadastro sintético inválido.'); }
    if (!parsed?.synthetic || !Array.isArray(parsed.cases) || !parsed.cases.length) throw Error('Estrutura de cadastro sintético inválida.');
    item = parsed.cases[0];
  } else if (mime === 'text/csv') {
    const rows = clean.split(/\r?\n/).map(r => r.trim()).filter(Boolean);
    if (rows.length < 2) throw Error('CSV de cadastro sintético incompleto.');
    const headers = rows[0].split(',').map(x => x.trim()), values = rows[1].split(',').map(x => x.trim());
    if (headers.length !== values.length) throw Error('Colunas incompatíveis no CSV sintético.');
    item = Object.fromEntries(headers.map((h, i) => [h, values[i]]));
  } else throw Error('Formato de cadastro não suportado.');
  const required = ['id', 'patient', 'birthDate', 'identifier', 'procedureDate'];
  for (const k of required) if (typeof item?.[k] !== 'string' || !item[k].trim()) throw Error('Campo obrigatório ausente no cadastro: ' + k);
  if (!validISO(item.birthDate) || !validISO(item.procedureDate)) throw Error('Datas inválidas no cadastro sintético.');
  return { id: item.id.trim(), patient: item.patient.trim(), birthDate: item.birthDate.trim(), identifier: item.identifier.trim(), procedureDate: item.procedureDate.trim() };
}
export async function extractPdfLines(doc, transformFn, maxPages = 5) {
  if (doc.numPages > maxPages) {
    if (doc.loadingTask?.destroy) await doc.loadingTask.destroy();
    else if (doc.destroy) await doc.destroy();
    throw Error(`Limite de ${maxPages === 5 ? 'cinco' : maxPages} páginas por documento.`);
  }
  const lines = [];
  for (let i = 1; i <= doc.numPages; i++) {
    const p = await doc.getPage(i), v = p.getViewport({ scale: 1 }), content = await p.getTextContent();
    for (const item of content.items) {
      if (!item.str?.trim()) continue;
      const t = transformFn(v.transform, item.transform), rawH = Math.hypot(t[2], t[3]), height = Math.max(rawH, 8), scaleH = rawH > 0 ? height / rawH : 1;
      const hx = rawH > 0 ? t[2] * scaleH : 0, hy = rawH > 0 ? t[3] * scaleH : -height, angle = Math.atan2(t[1], t[0]), wx = Math.cos(angle) * item.width, wy = Math.sin(angle) * item.width;
      const xs = [t[4], t[4] + wx, t[4] + hx, t[4] + wx + hx], ys = [t[5], t[5] + wy, t[5] + hy, t[5] + wy + hy];
      const minX = Math.max(0, Math.min(...xs) / v.width), maxX = Math.min(1, Math.max(...xs) / v.width), minY = Math.max(0, Math.min(...ys) / v.height), maxY = Math.min(1, Math.max(...ys) / v.height);
      lines.push({ text: item.str, page: i, box: [minX, minY, Math.max(0, maxX - minX), Math.max(0, maxY - minY)] });
    }
  }
  return lines;
}
export function stable(value) {
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + stable(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
export async function sha256(bytes) {
  const b = typeof bytes === 'string' ? new TextEncoder().encode(bytes) : bytes;
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', b)), v => v.toString(16).padStart(2, '0')).join('');
}
export async function allowedFixture(bytes, manifest, mimes = ['application/pdf', 'image/png']) {
  if (!bytes || bytes.byteLength === 0 || bytes.byteLength > 524288) throw Error('Use um dos arquivos fictícios fornecidos, com até 512 KB.');
  const hash = await sha256(bytes);
  const f = manifest.files.find(v => v.sha256 === hash && v.size === bytes.byteLength && mimes.includes(v.mime));
  if (!f) throw Error('Arquivo recusado. Esta demo pública aceita somente os exemplos fictícios fornecidos, sem alterações.');
  return { ...f };
}
export function csvSafeCell(value) {
  const raw = String(value ?? '').replace(/[\r\n]+/g, ' ').replace(/\u0000/g, '');
  const safe = /^[\t]/.test(raw) || /^[\s\u00A0]*[=+\-@]/.test(raw) ? "'" + raw : raw;
  return '"' + safe.replace(/"/g, '""') + '"';
}

function parseCodeInlineTag(rawCode) {
  const val = String(rawCode ?? '').trim();
  const bracketMatch = val.match(/^\[([A-Za-z0-9_-]{2,24})\]\s*(.+)$/);
  if (bracketMatch && KNOWN_CODE_SYSTEMS.has(bracketMatch[1].toUpperCase())) {
    return { code: bracketMatch[2].trim(), system: bracketMatch[1].toUpperCase(), inline: true };
  }
  const prefixMatch = val.match(/^([A-Za-z0-9_-]{2,24})\s*[:\- ]\s*([0-9A-Za-z.\-/]{3,})$/);
  if (prefixMatch && KNOWN_CODE_SYSTEMS.has(prefixMatch[1].toUpperCase())) {
    return { code: prefixMatch[2].trim(), system: prefixMatch[1].toUpperCase(), inline: true };
  }
  return { code: val, system: '', inline: false };
}

export function extractFields(lines) {
  const defs = {
    patient: ['Paciente:'],
    birthDate: ['Nascimento:'],
    identifier: ['Identificador:'],
    issueDate: ['Emissao:'],
    type: ['Tipo:'],
    origin: ['Origem:'],
    subfamily: ['Subfamilia:'],
    procedure: ['Procedimento:'],
    procedureCode: ['Codigo:'],
    procedureCodeSystem: ['Sistema:', 'SistemaCodigo:', 'TabelaCodigo:'],
    laterality: ['Lateralidade:'],
  };
  const fields = {};
  for (const [key, prefixes] of Object.entries(defs)) {
    const normPrefixes = prefixes.map(normalize);
    const matches = lines.filter(x => normPrefixes.some(p => normalize(x.text).startsWith(p)));
    if (matches.length > 1) {
      const candidates = matches.map(m => m.text.slice(m.text.indexOf(':') + 1).trim()).filter(Boolean);
      fields[key] = { value: '', source: null, uncertain: true, candidates };
      continue;
    }
    if (matches.length === 0) {
      fields[key] = { value: '', source: null, uncertain: false };
      continue;
    }
    const line = matches[0];
    const value = line.text.slice(line.text.indexOf(':') + 1).trim();
    fields[key] = { value, source: { page: line.page, box: [...line.box], text: line.text }, uncertain: false };
  }
  if (fields.laterality.value) fields.laterality.normalized = normalizeLaterality(fields.laterality.value);

  const inlineParsed = fields.procedureCode.value ? parseCodeInlineTag(fields.procedureCode.value) : { code: '', system: '', inline: false };
  if (inlineParsed.inline) fields.procedureCode.rawValue = fields.procedureCode.value;
  if (inlineParsed.code) fields.procedureCode.value = inlineParsed.code;
  const declaredSys = fields.procedureCodeSystem.value;
  const conflictingSys = Boolean(declaredSys && inlineParsed.system && normalize(declaredSys) !== normalize(inlineParsed.system));
  const resolvedSys = conflictingSys ? '' : (declaredSys || inlineParsed.system || '');
  const codeSourceDesc = conflictingSys
    ? `Sistemas conflitantes declarados (${declaredSys} × ${inlineParsed.system})`
    : declaredSys
      ? 'Campo explícito Sistema/Tabela no documento'
      : inlineParsed.inline
        ? 'Prefixo explícito no campo Codigo'
        : fields.procedureCode.value
          ? 'Sistema de codificação não identificado no documento'
          : '';
  if (conflictingSys) {
    fields.procedureCodeSystem = { value: '', source: fields.procedureCodeSystem.source, uncertain: true, candidates: [declaredSys, inlineParsed.system] };
  } else if (resolvedSys && !fields.procedureCodeSystem.value) {
    fields.procedureCodeSystem = { value: resolvedSys, source: fields.procedureCode.source, uncertain: false };
  }
  fields.procedureCode.system = resolvedSys;
  fields.procedureCode.codeSource = codeSourceDesc;
  fields.procedureCodeSource = {
    value: codeSourceDesc,
    source: fields.procedureCodeSystem.source || fields.procedureCode.source || null,
    uncertain: conflictingSys || fields.procedureCodeSystem.uncertain,
  };

  const readable = lines.some(x => x.text.trim().length > 4);
  const markerMatches = lines.filter(x => normalize(x.text) === 'marca ficticia');
  fields.syntheticMarkerCue = markerMatches.length === 1
    ? {
        present: true,
        value: 'Marcador textual sintético detectado (MARCA FICTICIA). Não representa reconhecimento visual nem autenticação de assinatura.',
        source: { page: markerMatches[0].page, box: [...markerMatches[0].box], text: markerMatches[0].text },
        uncertain: false,
        detectionKind: 'literal_synthetic_text_marker',
        authenticatesSignature: false,
      }
    : {
        present: markerMatches.length > 1,
        value: '',
        source: null,
        uncertain: markerMatches.length > 1,
        ...(markerMatches.length > 1 ? { candidates: markerMatches.map(m => m.text) } : {}),
        detectionKind: readable ? 'literal_synthetic_text_marker' : 'none_no_text_layer',
        authenticatesSignature: false,
      };
  const type = normalize(fields.type.value);
  return { fields, kind: Object.hasOwn(KINDS, type) && type !== 'desconhecido' ? type : 'desconhecido', readable };
}

export function identity(extraction, patient) {
  if (!extraction.readable) return 'unreadable';
  const f = extraction.fields, id = f.identifier.value, name = f.patient.value, dob = brazilDate(f.birthDate.value);
  if (f.identifier.uncertain || f.patient.uncertain || f.birthDate.uncertain) return 'conflict';
  if ((id && id !== patient.identifier) || (name && normalize(name) !== normalize(patient.patient)) || (dob && dob !== patient.birthDate)) return 'conflict';
  if (!name || !dob) return 'insufficient';
  return id ? 'suggested' : 'manual';
}

function classifyDocumentTemporality(d, { referenceDate, procedureDate, maxAgeDays, newerSiblingExists }) {
  const rawText = d.fields.issueDate?.value || '';
  const date = d.review ? d.review.issueDate : brazilDate(rawText);
  if (!d.readable) return { category: 'sem_camada_textual', detail: 'Imagem ou PDF sem camada textual; data não extraída.' };
  if (!date) {
    return rawText
      ? { category: 'data_invalida', detail: `Data de emissão inválida no documento ("${rawText}").` }
      : { category: 'data_invalida', detail: 'Data de emissão ausente.' };
  }
  if (date > referenceDate) return { category: 'data_futura', detail: `Data de emissão (${isoToBrazil(date)}) posterior à data de referência do exemplo (${isoToBrazil(referenceDate)}).` };
  if (d.kind !== 'laudo') return { category: 'validade_nao_definida', detail: `Regra temporal ilustrativa aplicada somente à categoria Laudo; classe ${KINDS[d.kind] || d.kind} sem janela temporal definida.` };
  const ageDays = diffDaysISO(date, procedureDate);
  if (ageDays === null) return { category: 'prazo_desconhecido', detail: 'Prazo desconhecido: data prevista do procedimento ausente ou inválida.' };
  if (ageDays > maxAgeDays) {
    return {
      category: 'fora_janela',
      olderVersionDetected: newerSiblingExists,
      detail: `${newerSiblingExists ? 'Documento antigo frente a outro laudo ativo e ' : ''}emissão (${ageDays} dias antes do procedimento) fora da janela ilustrativa configurada (${maxAgeDays} dias).`,
    };
  }
  if (newerSiblingExists) {
    return { category: 'antigo', olderVersionDetected: true, detail: 'Documento antigo dentro da janela frente a outra versão mais recente; não é substituído automaticamente sem confirmação humana.' };
  }
  return { category: 'atualizado', detail: `Emissão compatível com a janela administrativa ilustrativa (${ageDays} dias antes do procedimento; regra configurável de ${maxAgeDays} dias para laudo).` };
}

function evaluateProcedureAxis(active) {
  const readableDocs = active.filter(d => d.readable);
  if (!readableDocs.length) {
    return { id: 'procedure', label: '2. Procedimento informado', status: 'nao_avaliado', comparisonType: 'sem_documento_legivel', blocking: false, detail: 'Comparação de procedimento não executada: nenhum documento ativo com texto extraível.' };
  }
  const procDocs = readableDocs.filter(d => d.fields.procedure);
  const procUncertain = procDocs.filter(d => d.fields.procedure.uncertain || d.fields.procedureCode?.uncertain || d.fields.procedureCodeSystem?.uncertain);
  if (procUncertain.length) {
    return { id: 'procedure', label: '2. Procedimento informado', status: 'conflito', comparisonType: 'ambiguidade_multiplos_candidatos', blocking: true, detail: `Ambiguidade com múltiplos candidatos de procedimento, código ou sistema no mesmo documento (${procUncertain.map(d => d.name).join(', ')}). Requer revisão humana.` };
  }
  const procEntries = procDocs.filter(d => d.fields.procedure.value?.trim()).map(d => ({ doc: d.name, raw: d.fields.procedure.value.trim(), norm: normalizeComparable(d.fields.procedure.value) }));
  const incompleteProcs = procEntries.filter(x => x.norm.length < 3 || INCOMPLETE_PROC.has(x.norm));
  const validProcEntries = procEntries.filter(x => x.norm.length >= 3 && !INCOMPLETE_PROC.has(x.norm));
  const procUnique = [...new Map(validProcEntries.map(x => [x.norm, x])).values()];

  const codeEntries = procDocs.filter(d => d.fields.procedureCode?.value?.trim()).map(d => ({
    doc: d.name,
    raw: d.fields.procedureCode.value.trim(),
    norm: normalizeComparable(d.fields.procedureCode.value),
    system: normalize(d.fields.procedureCode.system || d.fields.procedureCodeSystem?.value || ''),
    systemRaw: (d.fields.procedureCode.system || d.fields.procedureCodeSystem?.value || '').trim(),
  }));
  const codeUnique = [...new Map(codeEntries.map(x => [x.norm, x])).values()];
  const knownSystems = [...new Set(codeEntries.map(x => x.system).filter(Boolean))];
  const someMissingSystem = codeEntries.some(x => !x.system);

  if (procUnique.length > 1) {
    return { id: 'procedure', label: '2. Procedimento informado', status: 'conflito', comparisonType: 'divergencia_textual', blocking: true, detail: `Divergência textual de procedimento entre documentos ativos: ${validProcEntries.map(e => `${e.doc} (${e.raw})`).join(' × ')}. Sem equivalência clínica automática; requer revisão humana.` };
  }
  if (codeUnique.length > 1) {
    const sameSystem = knownSystems.length === 1 && !someMissingSystem;
    return {
      id: 'procedure',
      label: '2. Procedimento informado',
      status: 'conflito',
      comparisonType: sameSystem ? 'divergencia_codigo_mesmo_sistema' : 'divergencia_codigo_sistema_desconhecido_ou_distinto',
      blocking: true,
      detail: sameSystem
        ? `Divergência de código no sistema ${codeEntries[0].systemRaw}: ${codeEntries.map(e => `${e.doc} (${e.raw})`).join(' × ')}. Requer revisão humana.`
        : `Divergência de códigos documentais entre documentos (${codeEntries.map(e => `${e.doc}: ${e.raw}${e.systemRaw ? ' [' + e.systemRaw + ']' : ' [sistema não identificado]'}`).join(' × ')}); sem equivalência automática, requer revisão humana.`,
    };
  }
  if (codeUnique.length === 1 && knownSystems.length > 1) {
    return {
      id: 'procedure',
      label: '2. Procedimento informado',
      status: 'conflito',
      comparisonType: 'divergencia_codigo_sistema_desconhecido_ou_distinto',
      blocking: true,
      detail: `Código "${codeUnique[0].raw}" aparece associado a sistemas distintos (${[...new Set(codeEntries.map(c => c.systemRaw).filter(Boolean))].join(' × ')}); comparação de equivalência bloqueada até revisão humana.`,
    };
  }
  if (incompleteProcs.length) {
    return { id: 'procedure', label: '2. Procedimento informado', status: 'abstencao', comparisonType: 'informacao_insuficiente', blocking: false, detail: `Descrição de procedimento incompleta ou genérica (${incompleteProcs.map(e => `${e.doc}: "${e.raw}"`).join(', ')}); abstenção sem inferência clínica.` };
  }
  if (procUnique.length === 1) {
    const exactMatch = validProcEntries.every(x => x.raw === validProcEntries[0].raw);
    const comparisonType = exactMatch ? 'correspondencia_textual_exata' : 'correspondencia_normalizada_superficial';
    const matchDesc = exactMatch ? 'Correspondência textual exata' : 'Correspondência após normalização superficial (acentuação/pontuação)';
    let codeDetail = '';
    if (codeUnique.length === 1) {
      codeDetail = someMissingSystem
        ? ` Código ${codeUnique[0].raw}: Código encontrado, sistema de codificação não identificado.`
        : ` Código ${codeUnique[0].raw} compatível no sistema ${codeEntries[0].systemRaw}.`;
    }
    return {
      id: 'procedure',
      label: '2. Procedimento informado',
      status: 'ok',
      comparisonType,
      codeSystemIdentified: codeUnique.length === 1 ? !someMissingSystem : null,
      blocking: false,
      detail: `${matchDesc}: "${procUnique[0].raw}" em ${validProcEntries.length} de ${readableDocs.length} documento(s) legível(is).${codeDetail} Sem inferência de sinonímia clínica.`,
    };
  }
  if (codeUnique.length === 1) {
    if (someMissingSystem) {
      return { id: 'procedure', label: '2. Procedimento informado', status: 'abstencao', comparisonType: 'codigo_sem_sistema_identificado', codeSystemIdentified: false, blocking: true, detail: `Código encontrado (${codeUnique[0].raw}), sistema de codificação não identificado. Sem descrição textual compatível; requer identificação do sistema e conferência humana.` };
    }
    return { id: 'procedure', label: '2. Procedimento informado', status: 'ok', comparisonType: 'correspondencia_por_codigo_sistema_identificado', codeSystemIdentified: true, blocking: false, detail: `Correspondência por código ${codeUnique[0].raw} no sistema identificado ${codeEntries[0].systemRaw}.` };
  }
  return { id: 'procedure', label: '2. Procedimento informado', status: 'abstencao', comparisonType: 'informacao_insuficiente', blocking: false, detail: 'Informação de procedimento não localizada nos campos extraídos; abstenção automática (sem inferência clínica).' };
}

function evaluateLateralityAxis(active) {
  const readableDocs = active.filter(d => d.readable);
  if (!readableDocs.length) {
    return { id: 'laterality', label: '3. Lateralidade (quando aplicável)', status: 'nao_avaliado', blocking: false, detail: 'Comparação de lateralidade não executada: nenhum documento ativo com texto extraível.' };
  }
  const latDocs = readableDocs.filter(d => d.fields.laterality);
  const latUncertain = latDocs.filter(d => d.fields.laterality.uncertain);
  const latUncertainConflict = latUncertain.filter(d => {
    const codes = (d.fields.laterality.candidates || []).map(normalizeLaterality).filter(Boolean);
    return new Set(codes).size > 1 || codes.includes('abstencao');
  });
  const latBadText = latDocs.filter(d => !d.fields.laterality.uncertain && d.fields.laterality.value?.trim() && normalizeLaterality(d.fields.laterality.value) === 'abstencao');
  const latEntries = latDocs.filter(d => d.fields.laterality.value?.trim()).map(d => ({ doc: d.name, raw: d.fields.laterality.value.trim(), code: normalizeLaterality(d.fields.laterality.value) }));
  const latDirs = latEntries.filter(x => ['direito', 'esquerdo', 'bilateral'].includes(x.code));
  const latDirCodes = [...new Set(latDirs.map(x => x.code))];
  const latNa = latEntries.filter(x => x.code === 'nao_aplicavel');

  if (latUncertainConflict.length) {
    return { id: 'laterality', label: '3. Lateralidade (quando aplicável)', status: 'conflito', blocking: true, detail: `Lateralidade contraditória ou ambígua no mesmo documento (${latUncertainConflict.map(d => `${d.name}: ${(d.fields.laterality.candidates || []).join(' × ')}`).join('; ')}). Requer revisão humana.` };
  }
  if (latUncertain.length || latBadText.length) {
    return { id: 'laterality', label: '3. Lateralidade (quando aplicável)', status: 'abstencao', blocking: true, detail: `Lateralidade ambígua ou não reconhecida em ${[...latUncertain, ...latBadText].map(d => d.name).join(', ')}. Abstenção bloqueante.` };
  }
  if (latDirCodes.length > 1 || (latDirs.length > 0 && latNa.length > 0)) {
    return { id: 'laterality', label: '3. Lateralidade (quando aplicável)', status: 'conflito', blocking: true, detail: `Divergência de lateralidade entre documentos ativos: ${latEntries.map(e => `${e.doc} (${e.raw})`).join(' × ')}. Abstenção automática; revisão humana obrigatória.` };
  }
  if (latDirCodes.length === 1) {
    return { id: 'laterality', label: '3. Lateralidade (quando aplicável)', status: 'ok', blocking: false, detail: `Lateralidade compatível nos documentos informados: ${latDirs[0].raw}.` };
  }
  if (latNa.length > 0) {
    return { id: 'laterality', label: '3. Lateralidade (quando aplicável)', status: 'nao_aplicavel', blocking: false, detail: 'Lateralidade declarada explicitamente como não aplicável nos documentos.' };
  }
  return { id: 'laterality', label: '3. Lateralidade (quando aplicável)', status: 'abstencao', blocking: false, detail: 'Lateralidade não informada nos campos extraídos; campo ausente não é convertido em não aplicável.' };
}

export class DocumentarySession {
  constructor(manifest) {
    this.manifest = structuredClone(manifest);
    this.case = structuredClone(manifest.case);
    this.documents = [];
    this.events = [];
    this.resolutions = {};
    this.assignments = {};
    this.duplicates = 0;
    this.policy = {
      version: 1,
      maxAgeDays: 30,
      categoryApplied: 'laudo',
      isIllustrative: true,
      origin: 'Configuração administrativa do exemplo sintético',
    };
    this.startedAt = new Date().toISOString();
  }
  async event(action, data = {}) {
    const payload = {
      seq: this.events.length + 1,
      previous: this.events.at(-1)?.hash || '0'.repeat(64),
      at: new Date().toISOString(),
      actor: DEMO_ACTOR,
      actorAuthenticated: false,
      action,
      data: structuredClone(data),
    };
    const hash = await sha256(stable(payload));
    this.events.push({ ...payload, hash });
  }
  doc(id) {
    const d = this.documents.find(x => x.id === id);
    if (!d) throw Error('Documento não encontrado.');
    return d;
  }
  async ingest(fixture, lines, elapsedMs = 0) {
    const known = this.manifest.files.find(x => x.sha256 === fixture.sha256 && ['application/pdf', 'image/png'].includes(x.mime));
    if (!known) throw Error('Documento fora do conjunto sintético.');
    const duplicate = this.documents.find(x => x.hash === fixture.sha256);
    if (duplicate) {
      this.duplicates++;
      await this.event('duplicado_recusado', { document: duplicate.id, documentRef: { id: duplicate.id, name: duplicate.name, hash: duplicate.hash }, hash: fixture.sha256 });
      return { duplicate: true, document: duplicate };
    }
    if (this.documents.length >= 20) throw Error('Limite de 20 documentos por sessão.');
    const extraction = extractFields(lines);
    const d = {
      id: 'DOC-' + String(this.documents.length + 1).padStart(3, '0'),
      caseId: null,
      name: known.name,
      mime: known.mime,
      hash: known.sha256,
      kind: extraction.kind,
      subfamily: extraction.fields.subfamily?.value || '',
      fields: extraction.fields,
      identity: identity(extraction, this.case),
      readable: extraction.readable,
      review: null,
      reviewHistory: [],
      status: 'received',
      replaces: null,
      supersededBy: null,
      elapsedMs: Math.round(elapsedMs),
      receivedAt: new Date().toISOString(),
    };
    d.extractionRun = {
      id: 'EXT-' + d.id,
      documentId: d.id,
      sourceHash: d.hash,
      engine: known.mime === 'application/pdf' ? 'PDF.js 6.5.438 + regras-documentais-2.0' : 'sem OCR (somente visual)',
      at: d.receivedAt,
      elapsedMs: d.elapsedMs,
    };
    this.documents.push(d);
    await this.event('documento_recebido', {
      document: d.id,
      documentRef: { id: d.id, name: d.name, hash: d.hash },
      hash: d.hash,
      identity: d.identity,
      engine: d.extractionRun.engine,
    });
    return { duplicate: false, document: d };
  }
  documentActionState(idOrDoc) {
    const d = typeof idOrDoc === 'string' ? this.doc(idOrDoc) : idOrDoc;
    if (!d) return null;
    const isDiscarded = d.status === 'discarded';
    const isSuperseded = Boolean(d.supersededBy);
    let stateCategory = 'revisao_necessaria';
    let reviewBlockedReason = '';
    if (isDiscarded) {
      stateCategory = 'retirada_do_fluxo';
      reviewBlockedReason = 'Ação bloqueada: documento retirado do fluxo ativo por descarte.';
    } else if (isSuperseded) {
      stateCategory = 'substituicao';
      reviewBlockedReason = `Ação bloqueada: versão anterior já substituída por ${d.supersededBy}.`;
    } else if (!d.readable) {
      stateCategory = 'abstencao';
      reviewBlockedReason = 'Ação bloqueada: documento sem camada textual extraível (sem OCR nesta versão); reenvie PDF legível ou retire do fluxo.';
    } else if (d.identity === 'conflict') {
      stateCategory = 'quarentena_conflito';
      reviewBlockedReason = 'Ação bloqueada: conflito cadastral (nome, nascimento ou identificador divergente ou ambíguo); vínculo automático proibido.';
    } else if (d.identity === 'insufficient') {
      stateCategory = 'informacao_insuficiente';
      reviewBlockedReason = 'Ação bloqueada: informação cadastral insuficiente (nome ou nascimento ausente); não pode ser vinculado automaticamente.';
    } else if (d.kind === 'desconhecido') {
      stateCategory = 'abstencao';
      reviewBlockedReason = 'Ação bloqueada: tipo documental fora das quatro classes previstas.';
    } else if (d.review) {
      stateCategory = 'correcao_permitida';
    }
    const canReview = !reviewBlockedReason;
    const canDiscard = !isDiscarded && !isSuperseded;
    const canReplace = Boolean(
      d.review && !isDiscarded && !isSuperseded && !d.replaces &&
      this.active().some(p => p.id !== d.id && p.kind === d.kind && p.review && p.caseId === d.caseId && (!d.subfamily || !p.subfamily || normalize(d.subfamily) === normalize(p.subfamily)))
    );
    return { stateCategory, canReview, reviewBlockedReason, canDiscard, canReplace };
  }
  async review(id, { identityChecked = false, issueDate = '', humanVisualObservation, signature, note = '' } = {}) {
    const d = this.doc(id);
    const state = this.documentActionState(d);
    if (!state.canReview) throw Error(state.reviewBlockedReason);
    if (!identityChecked) throw Error('Revisão incompleta: confirme a conferência de identidade.');
    if (issueDate && !validISO(issueDate)) throw Error('Data de emissão inválida.');
    const rawObs = humanVisualObservation ?? signature ?? 'unknown';
    const normalizedObs = VISUAL_OBS_MAP[rawObs];
    if (!normalizedObs) throw Error('Observação visual humana inválida.');
    if (typeof note !== 'string' || note.length > 500) throw Error('Observação deve ter até 500 caracteres.');
    const original = brazilDate(d.fields.issueDate.value);
    if (issueDate !== original && note.trim().length < 5) {
      throw Error('Correção bloqueada sem justificativa: explique a alteração da data de emissão com 5 a 500 caracteres.');
    }
    const review = {
      at: new Date().toISOString(),
      identityChecked: true,
      issueDate,
      originalIssueDate: original,
      syntheticMarkerPresent: Boolean(d.fields.syntheticMarkerCue?.present),
      humanVisualObservation: d.kind === 'termo' ? normalizedObs : 'unknown',
      visualObservationOnly: true,
      authenticatesSignature: false,
      note: note.trim(),
      policyVersion: this.policy.version,
    };
    for (const key of Object.keys(this.resolutions)) if (key.startsWith(id + ':')) delete this.resolutions[key];
    d.review = review;
    d.reviewHistory.push(structuredClone(review));
    d.caseId = this.case.id;
    d.status = 'reviewed';
    await this.event('revisao_humana', {
      document: id,
      documentRef: { id: d.id, name: d.name, hash: d.hash },
      evidenceRef: d.fields.issueDate?.source ? { field: 'issueDate', page: d.fields.issueDate.source.page, box: [...d.fields.issueDate.source.box] } : null,
      originalValue: original || d.fields.issueDate.value || '',
      revisedValue: issueDate,
      reason: review.note || null,
      policyVersion: this.policy.version,
      review,
    });
  }
  async discard(id, reason) {
    const d = this.doc(id);
    if (d.status === 'discarded') throw Error('Documento já retirado do fluxo.');
    if (d.supersededBy) throw Error('Ação bloqueada: versão anterior já substituída e preservada no histórico.');
    if (typeof reason !== 'string' || reason.trim().length < 5 || reason.length > 500) throw Error('Informe o motivo da retirada com 5 a 500 caracteres.');
    d.status = 'discarded';
    await this.event('documento_descartado', {
      document: id,
      documentRef: { id: d.id, name: d.name, hash: d.hash },
      reason: reason.trim(),
      policyVersion: this.policy.version,
    });
  }
  async replace(newId, oldId) {
    const newer = this.doc(newId), older = this.doc(oldId);
    if (newId === oldId) throw Error('Substituição bloqueada: selecione documentos distintos.');
    let cursor = older.replaces;
    while (cursor) {
      if (cursor === newId) throw Error('Substituição bloqueada: ciclo de substituições não permitido.');
      cursor = this.doc(cursor).replaces;
    }
    if (newer.status === 'discarded' || older.status === 'discarded') throw Error('Substituição bloqueada: não é possível vincular documento retirado do fluxo.');
    if (older.supersededBy || newer.supersededBy) throw Error('Substituição bloqueada: um dos documentos já foi substituído anteriormente.');
    if (newer.replaces) throw Error('Substituição bloqueada: este documento já substitui outra versão.');
    if (newer.kind === 'desconhecido' || older.kind === 'desconhecido' || newer.kind !== older.kind) {
      throw Error('Substituição bloqueada: os dois documentos precisam pertencer à mesma classe documental reconhecida.');
    }
    if (!newer.review || !older.review) throw Error('Substituição bloqueada: revise os dois documentos antes de confirmar a substituição.');
    if (newer.caseId !== older.caseId) throw Error('Substituição bloqueada: documentos vinculados a casos distintos.');
    if (newer.subfamily && older.subfamily && normalize(newer.subfamily) !== normalize(older.subfamily)) {
      throw Error('Subfamílias documentais distintas; confirme substituição apenas dentro da mesma subfamília.');
    }
    newer.replaces = oldId;
    older.supersededBy = newId;
    await this.event('substituicao_confirmada', {
      previous: oldId,
      current: newId,
      documentRef: { id: newer.id, name: newer.name, hash: newer.hash },
      replacedRef: { id: older.id, name: older.name, hash: older.hash },
      policyVersion: this.policy.version,
    });
  }
  async configure(days) {
    if (!Number.isInteger(days) || days < 1 || days > 365) throw Error('A janela deve ter de 1 a 365 dias.');
    this.policy = { ...this.policy, version: this.policy.version + 1, maxAgeDays: days };
    await this.event('regra_administrativa_alterada', { policy: structuredClone(this.policy) });
  }
  async loadSyntheticCase(known, text) {
    const file = this.manifest.files.find(x => x.sha256 === known?.sha256 && ['application/json', 'text/csv'].includes(x.mime));
    if (!file) throw Error('Cadastro fora do conjunto sintético autorizado.');
    const parsed = parseSyntheticCase(text, file.mime);
    this.case = parsed;
    for (const d of this.documents) if (!d.review && d.status !== 'discarded') d.identity = identity({ fields: d.fields, readable: d.readable }, this.case);
    await this.event('cadastro_importado', { name: file.name, hash: file.sha256, caseId: this.case.id, identifier: this.case.identifier, policyVersion: this.policy.version });
    return structuredClone(this.case);
  }
  active() {
    return this.documents.filter(d => d.status !== 'discarded' && !d.supersededBy);
  }
  _temporalityReport() {
    const active = this.active();
    const laudoDates = active.filter(d => d.kind === 'laudo').map(d => ({
      id: d.id,
      date: d.review ? d.review.issueDate : brazilDate(d.fields.issueDate.value),
    })).filter(x => Boolean(x.date));
    const maxLaudoDate = laudoDates.length ? laudoDates.map(x => x.date).sort().at(-1) : '';
    const byDocument = {};
    for (const d of active) {
      const date = d.review ? d.review.issueDate : brazilDate(d.fields.issueDate.value);
      const newerSiblingExists = d.kind === 'laudo' && Boolean(date && maxLaudoDate && date < maxLaudoDate);
      byDocument[d.id] = classifyDocumentTemporality(d, {
        referenceDate: this.manifest.referenceDate,
        procedureDate: this.case.procedureDate,
        maxAgeDays: this.policy.maxAgeDays,
        newerSiblingExists,
      });
    }
    return {
      rule: {
        name: 'Janela administrativa configurável em dias UTC',
        categoryApplied: this.policy.categoryApplied,
        maxAgeDays: this.policy.maxAgeDays,
        version: this.policy.version,
        referenceDate: this.manifest.referenceDate,
        procedureDate: this.case.procedureDate || '',
        origin: this.policy.origin,
        isIllustrative: true,
        clinicalValidityClaimed: false,
      },
      byDocument,
    };
  }
  _coreTasks() {
    const tasks = [];
    const active = this.active();
    const temp = this._temporalityReport();
    const push = (id, title, docId, manual = false, category = 'revisao_necessaria') => {
      const key = `${id}:v${this.policy.version}`;
      tasks.push({
        id: key,
        title,
        docId,
        manual,
        category,
        resolution: this.resolutions[key] || null,
        assignment: this.assignments[key] || null,
      });
    };
    for (const kind of ['solicitacao', 'laudo', 'avaliacao', 'termo']) {
      if (!active.some(d => d.kind === kind && d.review && (!d.caseId || d.caseId === this.case.id))) {
        push('missing:' + kind, 'Pendente: conferir ' + KINDS[kind].toLowerCase(), null, false, 'revisao_necessaria');
      }
    }
    for (const d of active) {
      if (!d.readable) { push(d.id + ':unreadable', 'Imagem ou PDF sem texto extraível (sem OCR); requer reenvio legível ou retirada do fluxo', d.id, false, 'abstencao'); continue; }
      if (['conflict', 'insufficient'].includes(d.identity) || (d.caseId && d.caseId !== this.case.id)) { push(d.id + ':identity', 'Identidade divergente ou insuficiente; documento em quarentena', d.id, false, d.identity === 'insufficient' ? 'informacao_insuficiente' : 'conflito'); continue; }
      if (d.kind === 'desconhecido') { push(d.id + ':unknown', 'Tipo de documento não reconhecido', d.id, false, 'abstencao'); continue; }
      if (!d.review) push(d.id + ':review', d.identity === 'manual' ? 'Conferir identificação manualmente e revisar campos' : 'Conferir identidade e campos extraídos', d.id, false, 'revisao_necessaria');
      const tc = temp.byDocument[d.id];
      if (tc?.category === 'data_invalida') push(d.id + ':date-missing', 'Data de emissão ausente ou inválida', d.id, true, 'informacao_insuficiente');
      else if (tc?.category === 'data_futura') push(d.id + ':future', 'Data de emissão posterior à data de referência do exemplo', d.id, true, 'revisao_necessaria');
      else if (tc?.category === 'prazo_desconhecido') push(d.id + ':window-unknown', 'Temporalidade indeterminada: data do procedimento ausente ou inválida', d.id, true, 'informacao_insuficiente');
      else if (tc?.category === 'fora_janela') push(d.id + ':window', `Emissão fora da janela ilustrativa configurada (${this.policy.maxAgeDays} dias para laudo)`, d.id, true, 'revisao_necessaria');
      if (d.kind === 'termo' && (!d.review || d.review.humanVisualObservation !== 'observed')) {
        push(d.id + ':visual-observation', 'Observação visual humana pendente na página do termo (não autentica assinatura)', d.id, true, 'revisao_necessaria');
      }
    }
    return tasks;
  }
  consistencyAxes() {
    const active = this.active();
    const baseTasks = this._coreTasks();
    if (!active.length) {
      const msg = this.documents.length
        ? 'Comparação não executada: todos os documentos recebidos foram retirados do fluxo.'
        : 'Comparação não executada: nenhum documento recebido nesta sessão.';
      return [
        { id: 'identity', label: '1. Identidade cadastral', status: 'nao_avaliado', blocking: false, detail: msg },
        { id: 'procedure', label: '2. Procedimento informado', status: 'nao_avaliado', comparisonType: 'nao_avaliado', blocking: false, detail: msg },
        { id: 'laterality', label: '3. Lateralidade (quando aplicável)', status: 'nao_avaliado', blocking: false, detail: msg },
        { id: 'temporality', label: '4. Temporalidade e versões', status: 'nao_avaliado', blocking: false, detail: msg },
      ];
    }

    const caseMismatch = active.filter(d => d.caseId && d.caseId !== this.case.id);
    const conflicts = active.filter(d => d.identity === 'conflict');
    const abstainsId = active.filter(d => d.identity === 'unreadable' || d.identity === 'insufficient');
    const unreviewedId = active.filter(d => ['suggested', 'manual'].includes(d.identity) && !d.review);
    let identityAxis;
    if (conflicts.length || caseMismatch.length) {
      identityAxis = { id: 'identity', label: '1. Identidade cadastral', status: 'conflito', blocking: true, detail: 'Divergência de identidade em quarentena (' + [...new Set([...conflicts, ...caseMismatch].map(d => d.name))].join(', ') + '). Vínculo automático bloqueado.' };
    } else if (abstainsId.length) {
      identityAxis = { id: 'identity', label: '1. Identidade cadastral', status: 'abstencao', blocking: true, detail: 'Abstenção obrigatória por ilegibidade ou dados insuficientes (' + abstainsId.map(d => d.name).join(', ') + ').' };
    } else if (unreviewedId.length) {
      identityAxis = { id: 'identity', label: '1. Identidade cadastral', status: 'pendente', blocking: false, detail: 'Aguardando confirmação humana em ' + unreviewedId.length + ' documento(s).' };
    } else {
      identityAxis = { id: 'identity', label: '1. Identidade cadastral', status: 'ok', blocking: false, detail: 'Nenhuma divergência cadastral identificada nos documentos revisados para ' + this.case.patient + '.' };
    }

    const procedureAxis = evaluateProcedureAxis(active);
    const lateralityAxis = evaluateLateralityAxis(active);

    const openTemp = baseTasks.filter(t => !t.resolution && (
      t.id.includes(':window:') || t.id.includes(':window-unknown:') || t.id.includes(':future:') ||
      t.id.includes(':date-missing:') || t.id.includes(':visual-observation:') || t.id.startsWith('missing:') || t.id.includes(':review:')
    ));
    const openUnknownTemp = openTemp.filter(t => t.id.includes(':window-unknown:') || t.id.includes(':date-missing:'));
    const replacedCount = this.documents.filter(d => d.supersededBy).length;
    const tempReport = this._temporalityReport();
    const readableCount = active.filter(d => d.readable).length;
    let temporalityAxis;
    if (!readableCount) {
      temporalityAxis = { id: 'temporality', label: '4. Temporalidade e versões', status: 'nao_avaliado', blocking: false, detail: 'Temporalidade não avaliada: nenhum documento ativo possui texto extraível.' };
    } else if (openUnknownTemp.length) {
      temporalityAxis = {
        id: 'temporality',
        label: '4. Temporalidade e versões',
        status: 'abstencao',
        blocking: false,
        rule: tempReport.rule,
        classifications: tempReport.byDocument,
        detail: `${openUnknownTemp.length} item(ns) com informação temporal ausente ou inválida (prazo desconhecido / data ausente); regra do exemplo (${this.policy.maxAgeDays} dias somente para laudo) não é validade universal.`,
      };
    } else if (openTemp.length) {
      temporalityAxis = {
        id: 'temporality',
        label: '4. Temporalidade e versões',
        status: 'pendente',
        blocking: false,
        rule: tempReport.rule,
        classifications: tempReport.byDocument,
        detail: `${openTemp.length} item(ns) documental(is) ou temporal(is) aguardando conferência/resolução (${replacedCount} substituição(ões) preservada(s); regra ilustrativa de ${this.policy.maxAgeDays} dias para laudo não define validade clínica).`,
      };
    } else {
      temporalityAxis = {
        id: 'temporality',
        label: '4. Temporalidade e versões',
        status: 'ok',
        blocking: false,
        rule: tempReport.rule,
        classifications: tempReport.byDocument,
        detail: `Datas, regra ilustrativa para laudo (${this.policy.maxAgeDays} dias sobre referência ${isoToBrazil(this.manifest.referenceDate)}) e ${replacedCount} substituição(ões) conferidas sem pendências abertas.`,
      };
    }

    return [identityAxis, procedureAxis, lateralityAxis, temporalityAxis];
  }
  tasks() {
    const tasks = this._coreTasks();
    const axes = this.consistencyAxes();
    const push = (id, title, category = 'conflito') => {
      const key = `${id}:v${this.policy.version}`;
      tasks.push({ id: key, title, docId: null, manual: false, category, resolution: this.resolutions[key] || null, assignment: this.assignments[key] || null });
    };
    const procAxis = axes.find(a => a.id === 'procedure');
    const latAxis = axes.find(a => a.id === 'laterality');
    if (procAxis?.blocking) push('axis:procedure', 'Conflito ou pendência bloqueante de procedimento — retirar ou substituir documento conflitante', 'conflito');
    if (latAxis?.blocking) push('axis:laterality', 'Conflito ou ambiguidade de lateralidade entre documentos ativos — retirar ou substituir antes de concluir', 'conflito');
    return tasks;
  }
  async assign(taskId, owner, due) {
    if (!this.tasks().some(x => x.id === taskId)) throw Error('Pendência não encontrada.');
    if (!['Revisor A', 'Revisor B'].includes(owner) || !validISO(due)) throw Error('Escolha responsável fictício e prazo válido.');
    this.assignments[taskId] = { owner, due };
    await this.event('pendencia_atribuida', { taskId, owner, due, policyVersion: this.policy.version });
  }
  async resolve(taskId, note) {
    const t = this.tasks().find(x => x.id === taskId);
    if (!t) throw Error('Pendência não encontrada.');
    if (taskId.startsWith('axis:laterality') || taskId.startsWith('axis:procedure')) {
      throw Error('Resolução bloqueada: divergência ou ambiguidade de procedimento/lateralidade não pode ser resolvida por justificativa em texto livre; retire ou substitua o documento conflitante.');
    }
    if (!t.manual) {
      throw Error('Resolução bloqueada: esta pendência exige conferência humana, revisão documental ou retirada do fluxo (documento em quarentena ou classe ausente).');
    }
    const targetDoc = this.doc(t.docId);
    if (!targetDoc.review) throw Error('Resolução bloqueada: registre a revisão humana do documento antes de justificar a exceção.');
    if (!this.assignments[taskId]) throw Error('Resolução bloqueada: atribua responsável fictício e prazo antes de registrar a justificativa.');
    if (typeof note !== 'string' || note.trim().length < 5 || note.length > 500) throw Error('Explique a resolução com 5 a 500 caracteres.');
    this.resolutions[taskId] = { note: note.trim(), at: new Date().toISOString(), assignment: structuredClone(this.assignments[taskId]) };
    await this.event('pendencia_resolvida', {
      taskId,
      document: targetDoc.id,
      documentRef: { id: targetDoc.id, name: targetDoc.name, hash: targetDoc.hash },
      reason: note.trim(),
      policyVersion: this.policy.version,
      resolution: this.resolutions[taskId],
    });
  }
  summary() {
    const tasks = this.tasks();
    const active = this.active();
    return {
      documents: this.documents.length,
      active: active.length,
      reviewed: active.filter(x => x.review).length,
      pending: tasks.filter(x => !x.resolution).length,
      duplicates: this.duplicates,
      quarantine: active.filter(x => !['suggested', 'manual'].includes(x.identity)).length,
      discarded: this.documents.filter(x => x.status === 'discarded').length,
      replaced: this.documents.filter(x => Boolean(x.supersededBy)).length,
    };
  }
  readinessState() {
    const active = this.active();
    const axes = this.consistencyAxes();
    const s = this.summary();
    const baseMetrics = {
      activeCount: active.length,
      reviewedCount: s.reviewed,
      quarantineCount: s.quarantine,
      discardedCount: s.discarded,
      replacedCount: s.replaced,
      pendingCount: s.pending,
      conflictsCount: axes.filter(a => a.status === 'conflito').length,
      blockingAbstentionsCount: axes.filter(a => a.status === 'abstencao' && a.blocking).length,
      evaluatedAxes: axes.filter(a => ['ok', 'conflito', 'nao_aplicavel'].includes(a.status)).map(a => a.id),
      notEvaluatedAxes: axes.filter(a => a.status === 'nao_avaliado').map(a => a.id),
      abstainedAxes: axes.filter(a => a.status === 'abstencao').map(a => a.id),
      notApplicableAxes: axes.filter(a => a.status === 'nao_aplicavel').map(a => a.id),
      administrativeOnly: true,
      clinicalApproval: false,
    };
    if (!this.documents.length || !active.length) {
      return {
        code: 'pendente',
        stage: this.documents.length ? 'sem_ativos' : 'aguardando',
        label: this.documents.length ? 'Pendente · documentos retirados do fluxo' : 'Aguardando documentos',
        ...baseMetrics,
      };
    }
    if (axes.some(a => a.status === 'conflito' || a.blocking) || s.quarantine > 0) {
      return {
        code: 'bloqueado',
        label: s.quarantine
          ? 'Bloqueado · documento em quarentena (revisão obrigatória; sem decisão clínica)'
          : 'Divergência bloqueante · revisão obrigatória (não conclui nem aprova clinicamente)',
        ...baseMetrics,
      };
    }
    const allFour = ['solicitacao', 'laudo', 'avaliacao', 'termo'].every(k => active.some(d => d.kind === k && d.review && (!d.caseId || d.caseId === this.case.id)));
    if (!allFour || active.some(d => !d.review) || s.pending > 0 || axes.some(a => a.status === 'pendente')) {
      return {
        code: 'pendente',
        label: `${s.pending} pendência(s) documental(is) · conferência em aberto`,
        ...baseMetrics,
      };
    }
    if (axes.some(a => a.status === 'abstencao' || a.status === 'nao_avaliado')) {
      return {
        code: 'abstencao',
        label: 'Abstenção documental · eixo obrigatório sem informação suficiente (não conclui nem aprova clinicamente)',
        ...baseMetrics,
      };
    }
    if (axes.some(a => a.status === 'nao_aplicavel')) {
      return {
        code: 'conferida_com_escopo_limitado',
        label: 'Conferida com escopo limitado (eixo declarado não aplicável; regras administrativas, sem decisão clínica)',
        ...baseMetrics,
      };
    }
    return {
      code: 'conferida',
      label: 'Documentação conferida (regras administrativas do exemplo; sem aprovação clínica)',
      ...baseMetrics,
    };
  }
  buildPendingNotice() {
    const axes = this.consistencyAxes(), tasks = this.tasks().filter(t => !t.resolution), r = this.readinessState();
    const lines = [
      'JYXIA · Resumo Administrativo de Conferência Documental (Dados Fictícios)',
      `Caso: ${this.case.id} · Paciente fictício: ${this.case.patient} (${this.case.identifier}) · Procedimento previsto: ${isoToBrazil(this.case.procedureDate) || this.case.procedureDate || 'Não informado'}`,
      `Regra temporal: até ${this.policy.maxAgeDays} dias UTC aplicável somente a laudos (ilustrativa/configurável; referência ${isoToBrazil(this.manifest.referenceDate)})`,
      `Estado administrativo: ${r.label}`,
      '',
      'Eixos de consistência:',
    ];
    for (const a of axes) lines.push(`- ${a.label} [${a.status.toUpperCase()}]: ${a.detail}`);
    if (tasks.length) {
      lines.push('', `Itens em aberto (${tasks.length}):`);
      for (const t of tasks) {
        const doc = t.docId ? this.doc(t.docId) : null;
        const prazo = t.assignment ? ` · Resp.: ${t.assignment.owner}, prazo ${isoToBrazil(t.assignment.due) || t.assignment.due}` : '';
        lines.push(`- ${t.title}${doc ? ' [' + doc.name + ']' : ''}${prazo}`);
      }
    } else if (r.code === 'abstencao') {
      lines.push('', 'Sem pendências operacionais abertas, porém com abstenção por ausência de informação em eixo obrigatório.');
    } else {
      lines.push('', 'Nenhuma divergência ou pendência aberta nas regras executadas.');
    }
    lines.push('', 'Aviso: uso exclusivamente administrativo sobre dados fictícios; não autentica assinaturas, não executa OCR e não aprova nem libera procedimento clínico.');
    return lines.join('\n');
  }
  exportCsv() {
    const headers = [
      'documento_id',
      'arquivo',
      'tipo_documental',
      'subfamilia',
      'identidade',
      'caso_vinculado',
      'procedimento_extraido',
      'codigo_procedimento',
      'sistema_codigo',
      'lateralidade_extraida',
      'marcador_textual_sintetico',
      'observacao_visual_humana',
      'emissao_extraida',
      'emissao_revisada',
      'status_temporalidade',
      'status',
      'substitui_id',
      'substituido_por',
      'observacao_revisao',
    ];
    const rows = [headers.map(csvSafeCell).join(',')];
    const temp = this._temporalityReport().byDocument;
    for (const d of this.documents) {
      const markerText = d.fields.syntheticMarkerCue?.present
        ? 'Marcador textual MARCA FICTICIA detectado (não autentica)'
        : (d.readable ? 'Marcador textual ausente (sem análise visual)' : 'Sem camada textual (sem OCR)');
      rows.push([
        d.id,
        d.name,
        KINDS[d.kind] || d.kind,
        d.subfamily || '',
        d.identity,
        d.caseId || '',
        d.fields.procedure?.value || '',
        d.fields.procedureCode?.value || '',
        d.fields.procedureCode?.system || d.fields.procedureCodeSystem?.value || '',
        d.fields.laterality?.value || '',
        markerText,
        d.review?.humanVisualObservation || 'unknown',
        d.fields.issueDate?.value || '',
        d.review?.issueDate || '',
        temp[d.id]?.category || (d.status === 'discarded' ? 'retirado_do_fluxo' : d.supersededBy ? 'substituido' : ''),
        d.status,
        d.replaces || '',
        d.supersededBy || '',
        d.review?.note || '',
      ].map(csvSafeCell).join(','));
    }
    return rows.join('\n');
  }
  export() {
    const axes = this.consistencyAxes();
    const temporality = this._temporalityReport();
    return {
      schema: 'jyxia.documental-session.v2',
      version: VERSION,
      synthetic: true,
      mode: 'Modalidade A - Demonstração pública restrita ao catálogo SHA-256 sintético',
      notice: 'Demonstração local em memória sobre dados fictícios. Não é prontuário, auditoria institucional imutável, autenticação de assinatura ou decisão clínica.',
      limitations: [
        'Sem OCR: imagens PNG e PDFs sem texto selecionável entram em abstenção.',
        'Detecção de MARCA FICTICIA é busca textual literal e não reconhece visualmente nem autentica assinaturas.',
        'Ator fictício sem autenticação nominal e cadeia SHA-256 em memória local do navegador.',
        'Comparação de procedimentos sem dicionário médico de sinonímia automática.',
        'Regra temporal de 30 dias aplicável somente a laudos é ilustrativa e configurável.',
      ],
      traceabilityLevels: {
        inMemoryHistory: { implemented: true, description: 'Histórico em memória da aba (perdido ao recarregar).' },
        localHashChain: { implemented: true, tamperEvidentInSessionOnly: true, immutableServerAudit: false, description: 'Cadeia SHA-256 encadeada localmente; pode ser recalculada por quem controla o navegador.' },
        exportArtifacts: { implemented: true, formats: ['json', 'csv'], detachedClone: true },
        serverPersistence: { implemented: false, plannedPhase: 'Modalidade C institucional futura' },
        institutionalAudit: { implemented: false, actorAuthenticated: false, description: 'Sem backend, autenticação OIDC/MFA ou retenção WORM em servidor.' },
      },
      temporalityPolicy: structuredClone(temporality.rule),
      case: structuredClone(this.case),
      policy: structuredClone(this.policy),
      referenceDate: this.manifest.referenceDate,
      readiness: this.readinessState(),
      consistencyAxes: structuredClone(axes),
      documents: structuredClone(this.documents.map(d => ({
        ...d,
        temporalityStatus: temporality.byDocument[d.id] || null,
      }))),
      tasks: structuredClone(this.tasks()),
      events: structuredClone(this.events),
      metrics: this.summary(),
      exportedAt: new Date().toISOString(),
    };
  }
}

export async function verifyEventsReport(events) {
  if (!Array.isArray(events)) return { valid: false, reason: 'Lista de eventos inválida.', index: -1 };
  let previous = '0'.repeat(64);
  for (let i = 0; i < events.length; i++) {
    const { hash, ...payload } = events[i] || {};
    if (payload.seq !== i + 1) return { valid: false, reason: `Sequência divergente no índice ${i}: esperado ${i + 1}, obtido ${payload.seq}.`, index: i };
    if (payload.previous !== previous) return { valid: false, reason: `Hash anterior divergente no evento #${payload.seq}.`, index: i };
    if (await sha256(stable(payload)) !== hash) return { valid: false, reason: `Hash SHA-256 do payload adulterado no evento #${payload.seq}.`, index: i };
    previous = hash;
  }
  return { valid: true, reason: `Sequência íntegra de ${events.length} evento(s) nesta sessão.`, index: -1 };
}

export async function verifyEvents(events) {
  return (await verifyEventsReport(events)).valid;
}
