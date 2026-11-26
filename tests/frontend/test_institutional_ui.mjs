import assert from 'node:assert/strict';
import test from 'node:test';

import {
  CASE_FILTERS,
  FOUR_AXES_ORDER,
  INSTITUTIONAL_FIELD_DEFS,
  buildCasePipelineStages,
  buildSideBySideFieldComparison,
  computeDashboardMetrics,
  createPdfLoadSequencer,
  filterInstitutionalCases,
  formatFourAxesFromBackend,
  getAxisStatusMeta,
  getFieldStatusMeta,
  getReadinessMeta,
  hasValidSpatialBbox,
  validateAndBuildHumanReviewPayload,
} from '../../frontend/institutional/institutional-core.mjs';

test('Etapa 3.3.5: computeDashboardMetrics and filterInstitutionalCases reflect real API state accurately', () => {
  const sampleCases = [
    {
      case_id: 'c1',
      case_code: 'CASO-001',
      readiness_state: 'pendente',
      processing_status: 'in_progress',
      consistency_status: 'not_evaluated',
      active_documents_count: 2,
      active_versions_count: 2,
      reviewed_active_versions_count: 0,
      human_review_completed: false,
      has_conflict: false,
      has_abstention: false,
    },
    {
      case_id: 'c2',
      case_code: 'CASO-002',
      readiness_state: 'pendente',
      processing_status: 'completed',
      consistency_status: 'ok',
      active_documents_count: 2,
      active_versions_count: 2,
      reviewed_active_versions_count: 1,
      human_review_completed: false,
      has_conflict: false,
      has_abstention: false,
    },
    {
      case_id: 'c3',
      case_code: 'CASO-003',
      readiness_state: 'bloqueado',
      processing_status: 'completed',
      consistency_status: 'conflito',
      active_documents_count: 2,
      active_versions_count: 2,
      reviewed_active_versions_count: 2,
      human_review_completed: true,
      has_conflict: true,
      has_abstention: false,
    },
    {
      case_id: 'c4',
      case_code: 'CASO-004',
      readiness_state: 'abstencao',
      processing_status: 'abstained',
      consistency_status: 'abstencao',
      active_documents_count: 1,
      active_versions_count: 1,
      reviewed_active_versions_count: 0,
      human_review_completed: false,
      has_conflict: false,
      has_abstention: true,
    },
    {
      case_id: 'c5',
      case_code: 'CASO-005',
      readiness_state: 'conferida',
      processing_status: 'completed',
      consistency_status: 'ok',
      active_documents_count: 2,
      active_versions_count: 2,
      reviewed_active_versions_count: 2,
      human_review_completed: true,
      has_conflict: false,
      has_abstention: false,
    },
  ];

  const metrics = computeDashboardMetrics(sampleCases);
  assert.equal(metrics.totalCases, 5);
  assert.equal(metrics.awaitingProcessing, 1);
  assert.equal(metrics.awaitingHumanReview, 3); // c1, c2, c4
  assert.equal(metrics.withConflicts, 1); // c3
  assert.equal(metrics.withAbstentions, 1); // c4
  assert.equal(metrics.processingCompleted, 4); // c2, c3, c4, c5
  assert.equal(metrics.withHumanReview, 3); // c2 (partial), c3, c5

  assert.equal(CASE_FILTERS.length, 6);
  assert.equal(filterInstitutionalCases(sampleCases, { filterId: 'all' }).length, 5);
  assert.deepEqual(
    filterInstitutionalCases(sampleCases, { filterId: 'awaiting_processing' }).map((c) => c.case_id),
    ['c1']
  );
  assert.deepEqual(
    filterInstitutionalCases(sampleCases, { filterId: 'awaiting_review' }).map((c) => c.case_id),
    ['c1', 'c2', 'c4']
  );
  assert.deepEqual(
    filterInstitutionalCases(sampleCases, { filterId: 'conflicts' }).map((c) => c.case_id),
    ['c3']
  );
  assert.deepEqual(
    filterInstitutionalCases(sampleCases, { filterId: 'abstentions' }).map((c) => c.case_id),
    ['c4']
  );
  assert.deepEqual(
    filterInstitutionalCases(sampleCases, { filterId: 'reviewed' }).map((c) => c.case_id),
    ['c2', 'c3', 'c5']
  );
  assert.deepEqual(
    filterInstitutionalCases(sampleCases, { filterId: 'all', searchQuery: 'CASO-005' }).map((c) => c.case_id),
    ['c5']
  );
});

test('Etapa 3.3.5: formatFourAxesFromBackend preserves all 6 axis states without client-side override', () => {
  const backendAssessment = {
    engine_version: '3.3.4.1',
    axes: [
      {
        axis_name: 'identidade',
        status: 'ok',
        rule_code: 'IDENTITY_CONSISTENT',
        justification: 'Identidade convergente.',
        fields_used: ['patient', 'birth_date', 'identifier'],
        compared_document_ids: ['d1', 'd2'],
        compared_version_ids: ['v1', 'v2'],
        evidence_reference_ids: ['e1', 'e2'],
        comparison: [],
        limitations: [],
      },
      {
        axis_name: 'procedimento_codigo',
        status: 'abstencao',
        rule_code: 'PROCEDURE_CODE_SYSTEM_MISSING',
        justification: 'Sistema de codificacao ausente.',
        fields_used: ['procedure', 'procedure_code'],
        compared_document_ids: ['d1', 'd2'],
        compared_version_ids: ['v1', 'v2'],
        evidence_reference_ids: ['e3'],
        comparison: [],
        limitations: ['CODE_WITHOUT_SYSTEM'],
      },
      {
        axis_name: 'lateralidade',
        status: 'conflito',
        rule_code: 'LATERALITY_CONFLICT_DETECTED',
        justification: 'Conflito OD vs OE.',
        fields_used: ['laterality'],
        compared_document_ids: ['d1', 'd2'],
        compared_version_ids: ['v1', 'v2'],
        evidence_reference_ids: ['e4', 'e5'],
        comparison: [],
        limitations: [],
      },
      {
        axis_name: 'temporalidade',
        status: 'nao_avaliado',
        rule_code: 'AXIS_OUT_OF_EXECUTION_SCOPE',
        justification: 'Eixo nao avaliado.',
        fields_used: ['issue_date'],
        compared_document_ids: [],
        compared_version_ids: [],
        evidence_reference_ids: [],
        comparison: [],
        limitations: ['AXIS_NOT_EVALUATED_CANNOT_BE_TREATED_AS_OK'],
      },
    ],
  };

  const formatted = formatFourAxesFromBackend(backendAssessment);
  assert.equal(formatted.length, 4);
  assert.deepEqual(
    formatted.map((a) => a.axisName),
    FOUR_AXES_ORDER
  );
  assert.equal(formatted[0].status, 'ok');
  assert.equal(formatted[1].status, 'abstencao');
  assert.equal(formatted[2].status, 'conflito');
  assert.equal(formatted[3].status, 'nao_avaliado');
  for (const ax of formatted) {
    assert.equal(ax.administrativeOnly, true);
    assert.equal(ax.clinicalApproval, false);
    assert.ok(ax.icon.length >= 1);
    assert.ok(ax.badgeText.length >= 2);
  }

  for (const code of ['ok', 'conflito', 'abstencao', 'nao_avaliado', 'nao_aplicavel', 'pendente']) {
    const meta = getAxisStatusMeta(code);
    assert.equal(meta.code, code);
    assert.ok(meta.icon);
  }

  for (const rState of ['pendente', 'em_revisao', 'conferida', 'conferida_com_escopo_limitado', 'abstencao', 'bloqueado']) {
    const rMeta = getReadinessMeta(rState);
    assert.equal(rMeta.code, rState);
  }
});

test('Etapa 3.3.5: buildSideBySideFieldComparison and hasValidSpatialBbox handle conflicts, abstentions, and missing bboxes', () => {
  assert.equal(INSTITUTIONAL_FIELD_DEFS.length, 11);
  assert.equal(hasValidSpatialBbox({ bbox: [0.1, 0.2, 0.3, 0.05] }), true);
  assert.equal(hasValidSpatialBbox({ bbox: [0, 0, 0, 0] }), false);
  assert.equal(hasValidSpatialBbox(null), false);

  const docA = {
    fields: [
      {
        field_key: 'patient',
        raw_value: 'Helena Sintetica Oliveira',
        normalized_value: 'HELENA SINTETICA OLIVEIRA',
        status: 'extracted',
        abstained: false,
        evidences: [{ evidence_id: 'ev-a1', page_number: 1, bbox: [0.1, 0.1, 0.5, 0.03], quote_excerpt: 'Paciente: Helena' }],
      },
      {
        field_key: 'laterality',
        raw_value: 'OD',
        normalized_value: 'OD',
        status: 'extracted',
        abstained: false,
        evidences: [{ evidence_id: 'ev-a2', page_number: 1, bbox: [0.1, 0.4, 0.2, 0.03], quote_excerpt: 'Lateralidade: OD' }],
      },
    ],
  };

  const docB = {
    fields: [
      {
        field_key: 'patient',
        raw_value: 'Helena Sintetica Oliveira',
        normalized_value: 'HELENA SINTETICA OLIVEIRA',
        status: 'extracted',
        abstained: false,
        evidences: [{ evidence_id: 'ev-b1', page_number: 1, bbox: [0, 0, 0, 0], quote_excerpt: 'Paciente: Helena' }],
      },
      {
        field_key: 'laterality',
        raw_value: 'OE',
        normalized_value: 'OE',
        status: 'extracted',
        abstained: false,
        evidences: [{ evidence_id: 'ev-b2', page_number: 1, bbox: [0.1, 0.4, 0.2, 0.03], quote_excerpt: 'Lateralidade: OE' }],
      },
    ],
  };

  const rows = buildSideBySideFieldComparison(docA, docB, null);
  assert.equal(rows.length, 11);

  const patientRow = rows.find((r) => r.fieldKey === 'patient');
  assert.equal(patientRow.comparisonOutcome, 'convergent');
  assert.equal(patientRow.sideA.hasSpatialBbox, true);
  assert.equal(patientRow.sideB.hasSpatialBbox, false);

  const latRow = rows.find((r) => r.fieldKey === 'laterality');
  assert.equal(latRow.comparisonOutcome, 'conflict');
  assert.equal(latRow.sideA.normalizedValue, 'OD');
  assert.equal(latRow.sideB.normalizedValue, 'OE');

  const missingRow = rows.find((r) => r.fieldKey === 'birth_date');
  assert.equal(missingRow.comparisonOutcome, 'abstention');
  assert.equal(getFieldStatusMeta(missingRow.sideA.status, missingRow.sideA.abstained).tone, 'abstencao');
});

test('Etapa 3.3.5: buildCasePipelineStages and validateAndBuildHumanReviewPayload enforce institutional rules', () => {
  const stages = buildCasePipelineStages({
    activeDocuments: [{ current_version: { version_id: 'v1' } }],
    processingRuns: [
      { step_type: 'verify_object_integrity', document_version_id: 'v1', status: 'succeeded' },
      { step_type: 'extract_pdf_text', document_version_id: 'v1', status: 'succeeded' },
      { step_type: 'compare_consistency', document_version_id: 'v1', status: 'queued' },
    ],
    latestAssessment: null,
    caseReviews: {
      active_document_versions_count: 1,
      reviewed_active_versions_count: 1,
      human_review_completed: true,
    },
  });

  assert.equal(stages.length, 5);
  assert.equal(stages[0].state, 'completed');
  assert.equal(stages[1].state, 'completed');
  assert.ok(stages[1].disclaimer.includes('não aprova conteúdo documental'));
  assert.equal(stages[2].state, 'completed');
  assert.equal(stages[3].state, 'in_progress');
  assert.equal(stages[4].state, 'in_progress');

  // Unconfirmed checkbox must fail validation
  const unconfirmed = validateAndBuildHumanReviewPayload({
    confirmed: false,
    justification: 'Justificativa valida com mais de cinco caracteres.',
  });
  assert.equal(unconfirmed.valid, false);

  // Short justification (< 5 chars) must fail validation
  const shortJust = validateAndBuildHumanReviewPayload({
    confirmed: true,
    justification: 'abcd',
  });
  assert.equal(shortJust.valid, false);

  // Valid payload contains only allowed keys and never includes readiness_state or reviewer_user_id
  const validCheck = validateAndBuildHumanReviewPayload({
    confirmed: true,
    actionType: 'observed',
    justification: 'Conferencia administrativa integral realizada.',
  });
  assert.equal(validCheck.valid, true);
  assert.deepEqual(Object.keys(validCheck.payload).sort(), [
    'action_type',
    'enqueue_comparison',
    'justification',
  ]);
});

test('Etapa 3.3.5 (P2-02): createPdfLoadSequencer prevents slow stale PDF load from overwriting newer PDF selection', () => {
  const sequencer = createPdfLoadSequencer();
  const destroyed = [];

  // 1. User selects Version A (slow load starts)
  const tokenA = sequencer.beginLoad({
    organizationId: 'org-1',
    caseId: 'case-1',
    versionId: 'ver-slow-a',
  });
  const taskA = {
    id: 'task-a',
    destroy() {
      destroyed.push('task-a');
      return Promise.resolve();
    },
  };
  assert.equal(sequencer.registerLoadingTask(tokenA, taskA), true);

  // 2. Before Version A finishes, user selects Version B (fast load starts and cancels taskA)
  const tokenB = sequencer.beginLoad({
    organizationId: 'org-1',
    caseId: 'case-1',
    versionId: 'ver-fast-b',
  });
  assert.deepEqual(destroyed, ['task-a']);
  assert.equal(
    sequencer.isCurrent(tokenA, {
      organizationId: 'org-1',
      caseId: 'case-1',
      versionId: 'ver-fast-b',
    }),
    false
  );
  assert.equal(
    sequencer.isCurrent(tokenB, {
      organizationId: 'org-1',
      caseId: 'case-1',
      versionId: 'ver-fast-b',
    }),
    true
  );

  // 3. Version B finishes first and commits its pdfDoc
  const pdfDocB = {
    id: 'doc-b',
    destroy() {
      destroyed.push('doc-b');
      return Promise.resolve();
    },
  };
  assert.equal(sequencer.commitLoadedDocument(tokenB, pdfDocB), true);

  // 4. Slow Version A resolves late; commitLoadedDocument MUST reject it and destroy pdfDocA without touching pdfDocB
  const pdfDocA = {
    id: 'doc-a',
    destroy() {
      destroyed.push('doc-a');
      return Promise.resolve();
    },
  };
  assert.equal(sequencer.commitLoadedDocument(tokenA, pdfDocA), false);
  assert.deepEqual(destroyed, ['task-a', 'doc-a']);
  assert.equal(
    sequencer.isCurrent(tokenB, {
      organizationId: 'org-1',
      caseId: 'case-1',
      versionId: 'ver-fast-b',
    }),
    true
  );
});

