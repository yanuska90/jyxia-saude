/**
 * JYXIA Institutional Review Core Logic (Etapa 3.3.5)
 * Pure deterministic helpers for dashboard metrics, case filtering, pipeline stage
 * derivation, 4-axis presentation, side-by-side documentary comparison, and
 * administrative human review state validation.
 */

export const INSTITUTIONAL_FIELD_DEFS = Object.freeze([
  { key: 'patient', label: 'Paciente', axis: 'identidade' },
  { key: 'birth_date', label: 'Data de nascimento', axis: 'identidade' },
  { key: 'identifier', label: 'Identificador (CPF/CNS)', axis: 'identidade' },
  { key: 'procedure', label: 'Procedimento', axis: 'procedimento_codigo' },
  { key: 'procedure_code_system', label: 'Tabela / Sistema de código', axis: 'procedimento_codigo' },
  { key: 'procedure_code', label: 'Código do procedimento', axis: 'procedimento_codigo' },
  { key: 'laterality', label: 'Lateralidade', axis: 'lateralidade' },
  { key: 'issue_date', label: 'Data de emissão', axis: 'temporalidade' },
  { key: 'document_type', label: 'Tipo documental extraído', axis: 'complementar' },
  { key: 'subfamily', label: 'Subfamília documental', axis: 'complementar' },
  { key: 'origin', label: 'Origem documental', axis: 'complementar' },
]);

export const FOUR_AXES_ORDER = Object.freeze([
  'identidade',
  'procedimento_codigo',
  'lateralidade',
  'temporalidade',
]);

export const AXIS_LABELS = Object.freeze({
  identidade: '1. Identidade',
  procedimento_codigo: '2. Procedimento / Código',
  lateralidade: '3. Lateralidade',
  temporalidade: '4. Temporalidade',
});

export const AXIS_STATUS_META = Object.freeze({
  ok: {
    code: 'ok',
    label: 'Consistente (OK)',
    badgeText: 'OK · CONSISTENTE',
    icon: '✓',
    tone: 'ok',
    summary: 'Evidências convergentes nos documentos ativos comparados.',
  },
  conflito: {
    code: 'conflito',
    label: 'Conflito documental',
    badgeText: '✕ CONFLITO',
    icon: '✕',
    tone: 'conflito',
    summary: 'Divergência determinística explícita entre documentos ou referência.',
  },
  abstencao: {
    code: 'abstencao',
    label: 'Abstenção explícita',
    badgeText: '⚠ ABSTENÇÃO',
    icon: '⚠',
    tone: 'abstencao',
    summary: 'Evidência ausente, ilegível, ambígua ou insuficiente para conclusão segura.',
  },
  nao_avaliado: {
    code: 'nao_avaliado',
    label: 'Não avaliado',
    badgeText: '∅ NÃO AVALIADO',
    icon: '∅',
    tone: 'nao_avaliado',
    summary: 'Eixo fora do escopo avaliado; nunca convertido em OK.',
  },
  nao_aplicavel: {
    code: 'nao_aplicavel',
    label: 'Não aplicável',
    badgeText: '— NÃO APLICÁVEL',
    icon: '—',
    tone: 'nao_aplicavel',
    summary: 'Eixo estruturalmente não aplicável ao procedimento/documento.',
  },
  pendente: {
    code: 'pendente',
    label: 'Pendente de processamento',
    badgeText: '… PENDENTE',
    icon: '…',
    tone: 'pendente',
    summary: 'Aguardando extração ou execução da comparação determinística.',
  },
});

export const CASE_READINESS_META = Object.freeze({
  pendente: {
    code: 'pendente',
    label: 'Pendente de conferência / revisão',
    badgeText: '… PENDENTE',
    tone: 'pendente',
  },
  em_revisao: {
    code: 'em_revisao',
    label: 'Em revisão administrativa',
    badgeText: '⟳ EM REVISÃO',
    tone: 'pendente',
  },
  conferida: {
    code: 'conferida',
    label: 'Documentação conferida (administrativa)',
    badgeText: '✓ CONFERIDA (ADM)',
    tone: 'ok',
  },
  conferida_com_escopo_limitado: {
    code: 'conferida_com_escopo_limitado',
    label: 'Conferida com escopo limitado (adm)',
    badgeText: '✓ CONFERIDA · ESCOPO LIMITADO',
    tone: 'ok',
  },
  abstencao: {
    code: 'abstencao',
    label: 'Abstenção documental',
    badgeText: '⚠ ABSTENÇÃO',
    tone: 'abstencao',
  },
  bloqueado: {
    code: 'bloqueado',
    label: 'Bloqueado por conflito ou quarentena',
    badgeText: '✕ BLOQUEADO',
    tone: 'conflito',
  },
});

export const FIELD_STATUS_META = Object.freeze({
  extracted: { code: 'extracted', label: 'Extraído', icon: '✓', tone: 'ok' },
  ambiguous: { code: 'ambiguous', label: 'Ambíguo (abstenção)', icon: '⚠', tone: 'abstencao' },
  abstained: { code: 'abstained', label: 'Abstenção explícita', icon: '⚠', tone: 'abstencao' },
  missing: { code: 'missing', label: 'Ausente no documento', icon: '∅', tone: 'abstencao' },
  absent: { code: 'absent', label: 'Ausente no documento', icon: '∅', tone: 'abstencao' },
  unreadable: { code: 'unreadable', label: 'Ilegível / Sem camada textual', icon: '✕', tone: 'conflito' },
});

export const CASE_FILTERS = Object.freeze([
  { id: 'all', label: 'Todos' },
  { id: 'awaiting_processing', label: 'Aguardando processamento' },
  { id: 'awaiting_review', label: 'Aguardando revisão humana' },
  { id: 'conflicts', label: 'Conflitos' },
  { id: 'abstentions', label: 'Abstenções' },
  { id: 'reviewed', label: 'Revisados' },
]);

export function getAxisStatusMeta(status) {
  let key = String(status || 'pendente').trim().toLowerCase();
  if (key === 'all_ok' || key === 'ok_with_limited_scope') {
    key = 'ok';
  } else if (key === 'conflict_detected') {
    key = 'conflito';
  } else if (key === 'abstention_required') {
    key = 'abstencao';
  } else if (key === 'pending_evaluation') {
    key = 'pendente';
  }
  return AXIS_STATUS_META[key] || {
    code: key,
    label: `Estado desconhecido (${key})`,
    badgeText: `? ${key.toUpperCase()}`,
    icon: '?',
    tone: 'pendente',
    summary: 'Estado retornado pelo backend fora do catálogo conhecido.',
  };
}

export function getReadinessMeta(state) {
  const key = String(state || 'pendente').trim().toLowerCase();
  return CASE_READINESS_META[key] || {
    code: key,
    label: key,
    badgeText: key.toUpperCase(),
    tone: 'pendente',
  };
}

export function getFieldStatusMeta(status, abstained = false) {
  const key = String(status || (abstained ? 'abstained' : 'missing')).trim().toLowerCase();
  if (abstained && key === 'extracted') {
    return FIELD_STATUS_META.abstained;
  }
  return FIELD_STATUS_META[key] || FIELD_STATUS_META.abstained;
}

/**
 * Compute institutional dashboard metrics strictly from backend case summaries.
 */
export function computeDashboardMetrics(cases) {
  const list = Array.isArray(cases) ? cases : [];
  let awaitingProcessing = 0;
  let awaitingHumanReview = 0;
  let withConflicts = 0;
  let withAbstentions = 0;
  let processingCompleted = 0;
  let withHumanReview = 0;

  for (const c of list) {
    const procStatus = String(c.processing_status || 'idle').toLowerCase();
    const activeVers = Number(c.active_versions_count || 0);
    const reviewedVers = Number(c.reviewed_active_versions_count || 0);
    const reviewCompleted = Boolean(c.human_review_completed);
    const hasConflict = Boolean(c.has_conflict) || c.readiness_state === 'bloqueado' || c.consistency_status === 'conflito';
    const hasAbstention = Boolean(c.has_abstention) || c.readiness_state === 'abstencao' || c.consistency_status === 'abstencao';

    if (procStatus === 'in_progress' || procStatus === 'idle' || c.consistency_status === 'not_evaluated' || c.consistency_status === 'pendente') {
      awaitingProcessing += 1;
    }
    if (procStatus === 'completed' || procStatus === 'abstained') {
      processingCompleted += 1;
    }
    if (activeVers > 0 && !reviewCompleted) {
      awaitingHumanReview += 1;
    }
    if (hasConflict) {
      withConflicts += 1;
    }
    if (hasAbstention) {
      withAbstentions += 1;
    }
    if (reviewedVers > 0 || reviewCompleted) {
      withHumanReview += 1;
    }
  }

  return {
    totalCases: list.length,
    awaitingProcessing,
    awaitingHumanReview,
    withConflicts,
    withAbstentions,
    processingCompleted,
    withHumanReview,
  };
}

/**
 * Filter cases according to institutional filter tabs and optional search text.
 */
export function filterInstitutionalCases(cases, { filterId = 'all', searchQuery = '' } = {}) {
  const list = Array.isArray(cases) ? cases : [];
  const normalizedFilter = String(filterId || 'all').trim().toLowerCase();
  const q = String(searchQuery || '').trim().toLowerCase();

  return list.filter((c) => {
    if (q) {
      const haystack = [
        c.case_code,
        c.case_id,
        c.external_reference,
        c.procedure_reference,
        c.readiness_state,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      if (!haystack.includes(q)) {
        return false;
      }
    }

    const procStatus = String(c.processing_status || 'idle').toLowerCase();
    const activeVers = Number(c.active_versions_count || 0);
    const reviewedVers = Number(c.reviewed_active_versions_count || 0);
    const reviewCompleted = Boolean(c.human_review_completed);
    const hasConflict = Boolean(c.has_conflict) || c.readiness_state === 'bloqueado' || c.consistency_status === 'conflito';
    const hasAbstention = Boolean(c.has_abstention) || c.readiness_state === 'abstencao' || c.consistency_status === 'abstencao';

    switch (normalizedFilter) {
      case 'awaiting_processing':
        return (
          procStatus === 'in_progress' ||
          procStatus === 'idle' ||
          c.consistency_status === 'not_evaluated' ||
          c.consistency_status === 'pendente'
        );
      case 'awaiting_review':
        return activeVers > 0 && !reviewCompleted;
      case 'conflicts':
        return hasConflict;
      case 'abstentions':
        return hasAbstention;
      case 'reviewed':
        return reviewedVers > 0 || reviewCompleted;
      case 'all':
      default:
        return true;
    }
  });
}

/**
 * Derive the 5 institutional processing pipeline stages for a case workspace.
 * Stage 2 (integrity verification) is explicitly marked as binary integrity only, never documentary approval.
 */
export function buildCasePipelineStages({
  activeDocuments = [],
  processingRuns = [],
  latestAssessment = null,
  caseReviews = null,
} = {}) {
  const docs = Array.isArray(activeDocuments) ? activeDocuments : [];
  const runs = Array.isArray(processingRuns) ? processingRuns : [];
  const activeVersionIds = new Set(
    docs
      .map((d) => d?.current_version?.version_id)
      .filter(Boolean)
  );

  // 1. Recebimento do documento
  const stage1State = activeVersionIds.size > 0 ? 'completed' : 'pending';
  const stage1Detail =
    activeVersionIds.size > 0
      ? `${activeVersionIds.size} documento(s) ativo(s) recebido(s) com versão corrente.`
      : 'Nenhum documento ativo vinculado ao caso.';

  // 2. Verificação de integridade (verify_object_integrity)
  const integrityRuns = runs.filter(
    (r) =>
      r.step_type === 'verify_object_integrity' &&
      (!activeVersionIds.size || activeVersionIds.has(r.document_version_id))
  );
  let stage2State = 'pending';
  let stage2Detail =
    'Aguardando verificação binária SHA-256 (integridade física não representa aprovação documental).';
  if (activeVersionIds.size > 0 && integrityRuns.length > 0) {
    if (integrityRuns.some((r) => ['queued', 'running', 'retry_wait'].includes(r.status))) {
      stage2State = 'in_progress';
      stage2Detail = 'Verificação de integridade binária SHA-256 em execução na fila.';
    } else if (integrityRuns.some((r) => r.status === 'failed')) {
      stage2State = 'failed';
      stage2Detail = 'Falha de integridade binária detectada (objeto divergente ou ausente).';
    } else {
      const verifiedVers = new Set(
        integrityRuns.filter((r) => r.status === 'succeeded').map((r) => r.document_version_id)
      );
      if (verifiedVers.size >= activeVersionIds.size) {
        stage2State = 'completed';
        stage2Detail =
          'Integridade binária SHA-256 verificada para todas as versões ativas (não equivale a aprovação documental).';
      } else {
        stage2State = 'partial';
        stage2Detail = `Integridade binária verificada em ${verifiedVers.size}/${activeVersionIds.size} versão(ões) ativa(s).`;
      }
    }
  }

  // 3. Extração textual (extract_pdf_text)
  const extractRuns = runs.filter(
    (r) =>
      r.step_type === 'extract_pdf_text' &&
      (!activeVersionIds.size || activeVersionIds.has(r.document_version_id))
  );
  let stage3State = 'pending';
  let stage3Detail = 'Aguardando execução da extração determinística de texto e coordenadas espaciais.';
  if (activeVersionIds.size > 0 && extractRuns.length > 0) {
    if (extractRuns.some((r) => ['queued', 'running', 'retry_wait'].includes(r.status))) {
      stage3State = 'in_progress';
      stage3Detail = 'Extração textual determinística na fila ou em processamento pelo worker.';
    } else if (extractRuns.some((r) => r.status === 'failed')) {
      stage3State = 'failed';
      stage3Detail = 'Extração textual encerrada com erro permanente ou documento sem camada textual legível.';
    } else {
      const doneVers = new Set(
        extractRuns
          .filter((r) => ['succeeded', 'abstained'].includes(r.status))
          .map((r) => r.document_version_id)
      );
      const anyAbstained = extractRuns.some((r) => r.status === 'abstained');
      if (doneVers.size >= activeVersionIds.size) {
        stage3State = anyAbstained ? 'abstained' : 'completed';
        stage3Detail = anyAbstained
          ? 'Extração concluída com abstenção explícita em um ou mais campos/documentos.'
          : 'Extração determinística de texto, campos e evidências concluída.';
      } else {
        stage3State = 'partial';
        stage3Detail = `Extração textual concluída em ${doneVers.size}/${activeVersionIds.size} versão(ões) ativa(s).`;
      }
    }
  }

  // 4. Comparação de consistência (compare_consistency)
  const compareRuns = runs.filter((r) => r.step_type === 'compare_consistency');
  const activeCompare = compareRuns.find((r) =>
    ['queued', 'running', 'retry_wait'].includes(r.status)
  );
  let stage4State = 'pending';
  let stage4Detail = 'Aguardando comparação determinística dos 4 eixos.';
  if (activeCompare) {
    stage4State = 'in_progress';
    stage4Detail = `Reavaliação dos 4 eixos enfileirada (${activeCompare.status}) aguardando worker.`;
  } else if (latestAssessment) {
    const outcome = String(latestAssessment.automated_axes_outcome || 'pendente').toLowerCase();
    stage4State = outcome === 'conflito' ? 'failed' : outcome === 'abstencao' ? 'abstained' : 'completed';
    stage4Detail = `Avaliação #${latestAssessment.assessment_sequence} concluída — desfecho dos eixos: ${outcome.toUpperCase()}.`;
  } else if (compareRuns.some((r) => r.status === 'failed')) {
    stage4State = 'failed';
    stage4Detail = 'Execução de comparação de consistência falhou.';
  }

  // 5. Revisão humana administrativa
  const totalActiveVers =
    caseReviews && typeof caseReviews.active_document_versions_count === 'number'
      ? caseReviews.active_document_versions_count
      : activeVersionIds.size;
  const reviewedActiveVers =
    caseReviews && typeof caseReviews.reviewed_active_versions_count === 'number'
      ? caseReviews.reviewed_active_versions_count
      : 0;
  const reviewCompleted = Boolean(caseReviews?.human_review_completed);
  let stage5State = 'pending';
  let stage5Detail = 'Aguardando registro de revisão administrativa nas versões documentais ativas.';
  if (totalActiveVers > 0) {
    if (reviewCompleted) {
      stage5State = activeCompare ? 'in_progress' : 'completed';
      stage5Detail = activeCompare
        ? `Revisão humana registrada (${reviewedActiveVers}/${totalActiveVers}); aguardando worker concluir reavaliação.`
        : `Revisão administrativa concluída (${reviewedActiveVers}/${totalActiveVers} versões ativas revisadas).`;
    } else if (reviewedActiveVers > 0) {
      stage5State = 'partial';
      stage5Detail = `Revisão administrativa parcial (${reviewedActiveVers}/${totalActiveVers} versões ativas revisadas).`;
    }
  }

  return [
    {
      stepNumber: 1,
      key: 'receipt',
      title: '1. Recebimento do documento',
      state: stage1State,
      detail: stage1Detail,
    },
    {
      stepNumber: 2,
      key: 'integrity',
      title: '2. Verificação de integridade binária',
      state: stage2State,
      detail: stage2Detail,
      disclaimer: 'Integridade SHA-256 valida apenas o arquivo físico; não aprova conteúdo documental.',
    },
    {
      stepNumber: 3,
      key: 'extraction',
      title: '3. Extração textual e evidências',
      state: stage3State,
      detail: stage3Detail,
    },
    {
      stepNumber: 4,
      key: 'consistency',
      title: '4. Comparação determinística dos 4 eixos',
      state: stage4State,
      detail: stage4Detail,
    },
    {
      stepNumber: 5,
      key: 'human_review',
      title: '5. Revisão humana administrativa',
      state: stage5State,
      detail: stage5Detail,
    },
  ];
}

/**
 * Determine whether an evidence reference has a valid spatial bounding box on the page.
 * Never invent coordinates when bbox is missing or zero-area.
 */
export function hasValidSpatialBbox(evidence) {
  if (!evidence) return false;
  const bbox = Array.isArray(evidence.bbox)
    ? evidence.bbox
    : [evidence.bbox_x, evidence.bbox_y, evidence.bbox_w, evidence.bbox_h];
  if (bbox.length !== 4 || bbox.some((v) => typeof v !== 'number' || Number.isNaN(v))) {
    return false;
  }
  const [x, y, w, h] = bbox;
  return x >= 0 && y >= 0 && w > 0.001 && h > 0.001 && x + w <= 1.001 && y + h <= 1.001;
}

/**
 * Build side-by-side field comparison rows between two active documents (Documento A | Documento B).
 * Preserves literal raw_value, normalized_value, extraction status, page, evidence, and divergence/abstention reason.
 */
export function buildSideBySideFieldComparison(docABundle, docBBundle, assessmentDetail = null) {
  const fieldsA = new Map();
  const fieldsB = new Map();
  for (const f of docABundle?.fields || []) {
    fieldsA.set(f.field_key, f);
  }
  for (const f of docBBundle?.fields || []) {
    fieldsB.set(f.field_key, f);
  }

  const axisByName = new Map();
  for (const ax of assessmentDetail?.axes || []) {
    axisByName.set(ax.axis || ax.axis_name, ax);
  }

  return INSTITUTIONAL_FIELD_DEFS.map((def) => {
    const fA = fieldsA.get(def.key) || null;
    const fB = fieldsB.get(def.key) || null;
    const evA = fA?.evidences?.[0] || null;
    const evB = fB?.evidences?.[0] || null;
    const normA = fA?.normalized_value ?? null;
    const normB = fB?.normalized_value ?? null;
    const statusA = fA ? fA.status : 'missing';
    const statusB = fB ? fB.status : 'missing';
    const abstainedA = fA ? Boolean(fA.abstained) : true;
    const abstainedB = fB ? Boolean(fB.abstained) : true;
    const metaA = fA?.metadata_json || fA?.metadata || {};
    const metaB = fB?.metadata_json || fB?.metadata || {};

    const axisInfo = axisByName.get(def.axis) || null;
    let comparisonOutcome = 'convergent';
    let comparisonNote = 'Valores normalizados equivalentes.';

    if (abstainedA || abstainedB || statusA !== 'extracted' || statusB !== 'extracted') {
      comparisonOutcome = 'abstention';
      const reasonA = metaA.reason_code || metaA.abstention_reason || statusA;
      const reasonB = metaB.reason_code || metaB.abstention_reason || statusB;
      comparisonNote = `Campo ausente ou com abstenção (Doc A: ${reasonA} | Doc B: ${reasonB}).`;
    } else if (normA !== normB) {
      if (axisInfo && axisInfo.status === 'ok' && def.axis === 'temporalidade') {
        comparisonOutcome = 'convergent_window';
        comparisonNote = axisInfo.justification || 'Datas distintas dentro da janela temporal permitida.';
      } else if (axisInfo && axisInfo.status === 'ok' && def.key === 'procedure') {
        comparisonOutcome = 'convergent';
        comparisonNote = axisInfo.justification || 'Descrições compatíveis segundo regra determinística.';
      } else {
        comparisonOutcome = 'conflict';
        comparisonNote = `Divergência detectada entre Documento A (${normA}) e Documento B (${normB}).`;
      }
    }

    return {
      fieldKey: def.key,
      label: def.label,
      axis: def.axis,
      comparisonOutcome,
      comparisonNote,
      axisRuleCode: axisInfo?.rule || axisInfo?.rule_code || null,
      axisStatus: axisInfo?.status || null,
      sideA: {
        present: Boolean(fA),
        rawValue: fA?.raw_value ?? null,
        normalizedValue: normA,
        status: statusA,
        abstained: abstainedA,
        reasonCode: metaA.reason_code || metaA.abstention_reason || null,
        pageNumber: evA?.page_number ?? null,
        evidenceId: evA?.evidence_reference_id ?? evA?.evidence_id ?? null,
        bbox: evA?.bbox ?? null,
        hasSpatialBbox: hasValidSpatialBbox(evA),
        quoteExcerpt: evA?.quote_excerpt ?? null,
      },
      sideB: {
        present: Boolean(fB),
        rawValue: fB?.raw_value ?? null,
        normalizedValue: normB,
        status: statusB,
        abstained: abstainedB,
        reasonCode: metaB.reason_code || metaB.abstention_reason || null,
        pageNumber: evB?.page_number ?? null,
        evidenceId: evB?.evidence_reference_id ?? evB?.evidence_id ?? null,
        bbox: evB?.bbox ?? null,
        hasSpatialBbox: hasValidSpatialBbox(evB),
        quoteExcerpt: evB?.quote_excerpt ?? null,
      },
    };
  });
}

/**
 * Format Four Consistency Axes strictly from the backend assessment detail.
 * Never overrides or recalculates axis statuses in the frontend.
 */
export function formatFourAxesFromBackend(assessmentDetail) {
  const axesMap = new Map();
  if (assessmentDetail && Array.isArray(assessmentDetail.axes)) {
    for (const ax of assessmentDetail.axes) {
      axesMap.set(ax.axis || ax.axis_name, ax);
    }
  }

  return FOUR_AXES_ORDER.map((axisName) => {
    const backendAxis = axesMap.get(axisName) || null;
    const rawStatus = backendAxis ? backendAxis.status : 'pendente';
    const meta = getAxisStatusMeta(rawStatus);
    return {
      axisName,
      title: AXIS_LABELS[axisName] || axisName,
      status: meta.code,
      statusLabel: meta.label,
      badgeText: meta.badgeText,
      icon: meta.icon,
      tone: meta.tone,
      ruleCode: backendAxis?.rule || backendAxis?.rule_code || 'AWAITING_CONSISTENCY_ASSESSMENT',
      justification:
        backendAxis?.justification ||
        'Aguardando execução ou conclusão da comparação determinística pelo worker.',
      fieldsUsed: Array.isArray(backendAxis?.fields_used) ? backendAxis.fields_used : [],
      comparedDocumentIds: Array.isArray(backendAxis?.compared_document_ids)
        ? backendAxis.compared_document_ids
        : [],
      comparedVersionIds: Array.isArray(backendAxis?.compared_version_ids)
        ? backendAxis.compared_version_ids
        : [],
      evidenceReferenceIds: Array.isArray(backendAxis?.evidence_reference_ids)
        ? backendAxis.evidence_reference_ids
        : [],
      comparisonItems: Array.isArray(backendAxis?.comparison) ? backendAxis.comparison : [],
      limitations: Array.isArray(backendAxis?.limitations) ? backendAxis.limitations : [],
      engineVersion: backendAxis?.engine_version || assessmentDetail?.engine_version || '—',
      administrativeOnly: true,
      clinicalApproval: false,
    };
  });
}

/**
 * Validate administrative human review submission inputs on the client before POSTing.
 * Ensures explicit confirmation checkbox and minimum justification length (>= 5 chars),
 * and produces a strict payload without forbidden override fields.
 */
export function validateAndBuildHumanReviewPayload({
  confirmed = false,
  actionType = 'observed',
  justification = '',
  fieldKey = null,
  evidenceReferenceId = null,
} = {}) {
  if (!confirmed) {
    return {
      valid: false,
      error: 'Confirme explicitamente a conferência administrativa antes de registrar a revisão.',
      payload: null,
    };
  }
  const trimmedJustification = String(justification || '').trim();
  if (trimmedJustification.length < 5) {
    return {
      valid: false,
      error: 'A observação / justificativa administrativa deve conter ao menos 5 caracteres.',
      payload: null,
    };
  }
  const payload = {
    action_type: String(actionType || 'observed').trim(),
    justification: trimmedJustification,
    enqueue_comparison: true,
  };
  if (fieldKey && String(fieldKey).trim()) {
    payload.field_key = String(fieldKey).trim();
  }
  if (evidenceReferenceId && String(evidenceReferenceId).trim()) {
    payload.evidence_reference_id = String(evidenceReferenceId).trim();
  }
  return {
    valid: true,
    error: null,
    payload,
  };
}
