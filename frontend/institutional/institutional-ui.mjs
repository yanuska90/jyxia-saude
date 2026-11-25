/**
 * JYXIA Institutional Review UI Controller (Etapa 3.3.5)
 * Same-origin BFF session & CSRF controller, real API dashboard/cases/workspace,
 * local PDF.js spatial evidence renderer, and append-only administrative human review.
 */

import {
  CASE_FILTERS,
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
} from '/institutional/institutional-core.mjs';

const state = {
  authenticated: false,
  sessionStatus: null,
  userProfile: null,
  organizations: [],
  activeOrgId: null,
  activeMembership: null,
  csrfCookieName: 'jyxia_csrf',
  csrfHeaderName: 'X-CSRF-Token',

  cases: [],
  activeFilterId: 'all',
  searchQuery: '',

  selectedCaseId: null,
  selectedCaseSummary: null,
  caseDocuments: [],
  caseProcessingRuns: [],
  caseAssessments: [],
  selectedAssessmentId: null,
  selectedAssessmentDetail: null,
  caseReviews: null,
  workspaceLoadSeq: 0,

  // Map<version_id, { document, version, fields, latestExtractRun, reviews }>
  versionBundles: new Map(),

  selectedDocumentId: null,
  selectedVersionId: null,
  compareDocAId: null,
  compareDocBId: null,
  workspaceLoadInFlight: false,

  // PDF.js state
  pdfLib: null,
  pdfDoc: null,
  pdfLoadedVersionId: null,
  pdfLoadSequencer: createPdfLoadSequencer(),
  pdfActiveLoadToken: null,
  pdfPageNum: 1,
  pdfPageCount: 0,
  pdfScale: 1.2,
  activeHighlights: [], // Array<{ pageNumber, bbox, label }>
};

function readCookie(name) {
  const prefix = `${encodeURIComponent(name)}=`;
  const parts = (document.cookie || '').split(';');
  for (const raw of parts) {
    const trimmed = raw.trim();
    if (trimmed.startsWith(prefix)) {
      return decodeURIComponent(trimmed.slice(prefix.length));
    }
  }
  return '';
}

function getCsrfToken() {
  return readCookie(state.csrfCookieName || 'jyxia_csrf');
}

function formatDateTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString('pt-BR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function formatBytes(bytes) {
  const n = Number(bytes || 0);
  if (!n || Number.isNaN(n)) return '0 B';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function createEl(tag, { className = '', text = '', attrs = {} } = {}) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined && text !== null && text !== '') {
    el.textContent = String(text);
  }
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== undefined && v !== null) {
      el.setAttribute(k, String(v));
    }
  }
  return el;
}

function showAlert(message, tone = 'info') {
  const region = document.getElementById('global-alert-region');
  if (!region) return;
  region.replaceChildren();
  if (!message) return;

  const box = createEl('div', {
    className: `inst-alert inst-alert-${tone}`,
  });
  const span = createEl('span', { text: message });
  const closeBtn = createEl('button', {
    className: 'inst-btn inst-btn-sm inst-btn-secondary',
    text: 'Fechar',
    attrs: { type: 'button', 'aria-label': 'Fechar aviso' },
  });
  closeBtn.addEventListener('click', () => {
    region.replaceChildren();
  });
  box.append(span, closeBtn);
  region.appendChild(box);
}

async function apiFetch(path, { method = 'GET', body = null, headers = {}, isBinary = false } = {}) {
  const reqHeaders = { ...headers };
  const upperMethod = method.toUpperCase();
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(upperMethod)) {
    const csrf = getCsrfToken();
    if (csrf) {
      reqHeaders[state.csrfHeaderName || 'X-CSRF-Token'] = csrf;
    }
  }
  let payload = body;
  if (body && !(body instanceof FormData) && typeof body === 'object') {
    reqHeaders['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }

  const res = await fetch(path, {
    method: upperMethod,
    headers: reqHeaders,
    body: payload,
    credentials: 'same-origin',
    cache: 'no-store',
  });

  if (res.status === 401) {
    state.authenticated = false;
    renderAuthGate();
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || 'Sessão expirada ou não autenticada (401). Faça login via OIDC + MFA.');
  }

  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    const detail = errData.detail || `Erro HTTP ${res.status}`;
    const err = new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    err.status = res.status;
    throw err;
  }

  if (isBinary) {
    return res.arrayBuffer();
  }
  return res.json();
}

function hasPermission(perm) {
  const perms = state.activeMembership?.permissions || [];
  return perms.includes(perm);
}

function renderAuthGate() {
  const unauthGate = document.getElementById('unauth-gate');
  const authApp = document.getElementById('authenticated-app');
  const loginBtn = document.getElementById('btn-login-oidc');
  const logoutBtn = document.getElementById('btn-logout');
  const refreshBtn = document.getElementById('btn-refresh-all');
  const userBox = document.getElementById('user-summary-box');
  const orgWrap = document.getElementById('org-switcher-wrap');

  if (!state.authenticated) {
    unauthGate.hidden = false;
    authApp.hidden = true;
    loginBtn.hidden = false;
    logoutBtn.hidden = true;
    refreshBtn.hidden = true;
    userBox.hidden = true;
    orgWrap.hidden = true;
    return;
  }

  unauthGate.hidden = true;
  authApp.hidden = false;
  loginBtn.hidden = true;
  logoutBtn.hidden = false;
  refreshBtn.hidden = false;
  userBox.hidden = false;

  document.getElementById('user-display-name').textContent =
    state.userProfile?.display_name || state.userProfile?.email || state.userProfile?.user_id || 'Operador';
  document.getElementById('user-role-badge').textContent =
    state.activeMembership?.role || 'sem_papel';

  const orgSelect = document.getElementById('org-select');
  orgSelect.replaceChildren();
  for (const org of state.organizations) {
    const opt = createEl('option', {
      text: `${org.organization_name} (${org.role})`,
      attrs: { value: org.organization_id },
    });
    if (org.organization_id === state.activeOrgId) {
      opt.selected = true;
    }
    orgSelect.appendChild(opt);
  }
  orgWrap.hidden = state.organizations.length === 0;

  const activeOrg = state.organizations.find((o) => o.organization_id === state.activeOrgId);
  document.getElementById('active-org-caption').textContent = activeOrg
    ? `Organização ativa: ${activeOrg.organization_name} (${activeOrg.organization_slug}) · Papel: ${activeOrg.role}`
    : 'Nenhuma organização ativa selecionada.';

  const newCaseBtn = document.getElementById('btn-toggle-new-case');
  newCaseBtn.hidden = !hasPermission('case:write');
}

function renderFilterTabs() {
  const container = document.getElementById('case-filter-tabs');
  container.replaceChildren();
  for (const f of CASE_FILTERS) {
    const btn = createEl('button', {
      className: 'inst-filter-tab',
      text: f.label,
      attrs: {
        type: 'button',
        role: 'tab',
        'data-filter-id': f.id,
        'aria-selected': f.id === state.activeFilterId ? 'true' : 'false',
      },
    });
    btn.addEventListener('click', () => {
      state.activeFilterId = f.id;
      renderFilterTabs();
      renderCasesTable();
    });
    container.appendChild(btn);
  }
}

function renderDashboardAndCases() {
  const metrics = computeDashboardMetrics(state.cases);
  document.getElementById('metric-total-cases').textContent = String(metrics.totalCases);
  document.getElementById('metric-awaiting-processing').textContent = String(metrics.awaitingProcessing);
  document.getElementById('metric-awaiting-review').textContent = String(metrics.awaitingHumanReview);
  document.getElementById('metric-with-conflicts').textContent = String(metrics.withConflicts);
  document.getElementById('metric-with-abstentions').textContent = String(metrics.withAbstentions);
  document.getElementById('metric-processing-completed').textContent = String(metrics.processingCompleted);
  document.getElementById('metric-with-review').textContent = String(metrics.withHumanReview);

  renderFilterTabs();
  renderCasesTable();
}

function renderCasesTable() {
  const tbody = document.getElementById('cases-table-body');
  tbody.replaceChildren();

  const filtered = filterInstitutionalCases(state.cases, {
    filterId: state.activeFilterId,
    searchQuery: state.searchQuery,
  });

  if (filtered.length === 0) {
    const tr = createEl('tr');
    const td = createEl('td', {
      className: 'inst-empty-cell',
      text: 'Nenhum caso encontrado para o filtro selecionado.',
      attrs: { colspan: '9' },
    });
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (const c of filtered) {
    const tr = createEl('tr', {
      className: c.case_id === state.selectedCaseId ? 'inst-row-selected' : '',
      attrs: { 'data-case-id': c.case_id },
    });

    // 1. Case code
    const tdCode = createEl('td');
    const strongCode = createEl('strong', { text: c.case_code });
    tdCode.appendChild(strongCode);
    if (c.procedure_reference) {
      tdCode.appendChild(
        createEl('div', {
          className: 'inst-code-mono',
          text: `Ref: ${c.procedure_reference}`,
        })
      );
    }

    // 2. Created at
    const tdCreated = createEl('td', { text: formatDateTime(c.created_at) });

    // 3. Active docs count
    const tdDocs = createEl('td', {
      text: `${c.active_documents_count || 0} doc(s) / ${c.active_versions_count || 0} ver.`,
    });

    // 4. Processing status
    const procMap = {
      completed: { text: '✓ Concluído', tone: 'ok' },
      abstained: { text: '⚠ Com abstenção', tone: 'abstencao' },
      in_progress: { text: '⟳ Em fila / execução', tone: 'pendente' },
      failed: { text: '✕ Falha técnica', tone: 'conflito' },
      idle: { text: '… Aguardando', tone: 'pendente' },
    };
    const pMeta = procMap[c.processing_status] || procMap.idle;
    const tdProc = createEl('td');
    tdProc.appendChild(
      createEl('span', {
        className: `inst-status-badge inst-tone-${pMeta.tone}`,
        text: pMeta.text,
      })
    );

    // 5. Consistency status
    const tdCons = createEl('td');
    const cMeta = getAxisStatusMeta(
      c.consistency_status === 'not_evaluated' ? 'pendente' : c.consistency_status
    );
    tdCons.appendChild(
      createEl('span', {
        className: `inst-status-badge inst-tone-${cMeta.tone}`,
        text: c.consistency_status === 'not_evaluated' ? '… NÃO AVALIADO' : cMeta.badgeText,
      })
    );

    // 6. Human review state
    const tdRev = createEl('td');
    const revCountText = `${c.reviewed_active_versions_count || 0}/${c.active_versions_count || 0}`;
    const revTone = c.human_review_completed
      ? 'ok'
      : (c.reviewed_active_versions_count || 0) > 0
      ? 'abstencao'
      : 'pendente';
    const revLabel = c.human_review_completed
      ? `✓ Revisado (${revCountText})`
      : (c.active_versions_count || 0) === 0
      ? '… Sem versões'
      : `⏳ Aguardando (${revCountText})`;
    tdRev.appendChild(
      createEl('span', {
        className: `inst-status-badge inst-tone-${revTone}`,
        text: revLabel,
      })
    );

    // 7. Readiness state
    const rMeta = getReadinessMeta(c.readiness_state);
    const tdReady = createEl('td');
    tdReady.appendChild(
      createEl('span', {
        className: `inst-status-badge inst-tone-${rMeta.tone}`,
        text: rMeta.badgeText,
      })
    );

    // 8. Updated at
    const tdUpdated = createEl('td', { text: formatDateTime(c.updated_at || c.created_at) });

    // 9. Action
    const tdAction = createEl('td');
    const openBtn = createEl('button', {
      className: 'inst-btn inst-btn-sm inst-btn-primary',
      text: c.case_id === state.selectedCaseId ? 'Caso aberto' : 'Abrir revisão',
      attrs: {
        type: 'button',
        'data-open-case-id': c.case_id,
      },
    });
    openBtn.addEventListener('click', () => {
      openCaseWorkspace(c.case_id);
    });
    tdAction.appendChild(openBtn);

    tr.append(tdCode, tdCreated, tdDocs, tdProc, tdCons, tdRev, tdReady, tdUpdated, tdAction);
    tbody.appendChild(tr);
  }
}

async function loadOrganizationCases() {
  if (!state.activeOrgId) return;
  const data = await apiFetch(`/api/v1/organizations/${state.activeOrgId}/cases`);
  state.cases = Array.isArray(data.cases) ? data.cases : [];
  renderDashboardAndCases();
}

async function openCaseWorkspace(caseId) {
  if (!state.activeOrgId || !caseId) return;
  const loadSeq = ++state.workspaceLoadSeq;
  const isNewCase = state.selectedCaseId !== caseId;
  state.selectedCaseId = caseId;
  if (isNewCase) {
    state.selectedDocumentId = null;
    state.selectedVersionId = null;
    state.selectedAssessmentId = null;
    state.selectedAssessmentDetail = null;
  }
  state.workspaceLoadInFlight = true;
  renderCasesTable();

  const workspace = document.getElementById('case-workspace');
  workspace.hidden = false;

  document.getElementById('btn-toggle-upload-doc').hidden = !hasPermission('document:upload');
  document.getElementById('btn-trigger-compare').hidden = !hasPermission('case:write');

  try {
    const [caseSummary, docsResp, runsResp, assessmentsResp, reviewsResp] = await Promise.all([
      apiFetch(`/api/v1/organizations/${state.activeOrgId}/cases/${caseId}`),
      apiFetch(`/api/v1/organizations/${state.activeOrgId}/cases/${caseId}/documents?limit=100`),
      apiFetch(`/api/v1/organizations/${state.activeOrgId}/cases/${caseId}/processing-runs?limit=200`),
      apiFetch(`/api/v1/organizations/${state.activeOrgId}/cases/${caseId}/consistency-assessments?limit=50`),
      apiFetch(`/api/v1/organizations/${state.activeOrgId}/cases/${caseId}/human-reviews`),
    ]);
    if (loadSeq !== state.workspaceLoadSeq) return;

    state.selectedCaseSummary = caseSummary;
    state.caseDocuments = Array.isArray(docsResp.documents) ? docsResp.documents : [];
    state.caseProcessingRuns = Array.isArray(runsResp.processing_runs) ? runsResp.processing_runs : [];
    state.caseAssessments = Array.isArray(assessmentsResp.assessments) ? assessmentsResp.assessments : [];
    state.caseReviews = reviewsResp;

    // Update case in state.cases list so dashboard & table stay in sync
    const idx = state.cases.findIndex((c) => c.case_id === caseId);
    if (idx >= 0) {
      state.cases[idx] = caseSummary;
      renderDashboardAndCases();
    }

    // Load extracted fields & version reviews for each active document's current version
    const nextBundles = new Map();
    await Promise.all(
      state.caseDocuments.map(async (doc) => {
        const ver = doc.current_version;
        if (!ver) return;
        const [fieldsResp, verReviewsResp] = await Promise.all([
          apiFetch(
            `/api/v1/organizations/${state.activeOrgId}/documents/${doc.document_id}/versions/${ver.version_id}/extracted-fields?latest_only=true`
          ),
          apiFetch(
            `/api/v1/organizations/${state.activeOrgId}/documents/${doc.document_id}/versions/${ver.version_id}/human-reviews`
          ),
        ]);
        const rawFields = Array.isArray(fieldsResp.extracted_fields)
          ? fieldsResp.extracted_fields
          : Array.isArray(fieldsResp.fields)
          ? fieldsResp.fields
          : [];
        nextBundles.set(ver.version_id, {
          document: doc,
          version: ver,
          fields: rawFields,
          latestExtractRun:
            fieldsResp.latest_extract_processing_run ||
            (fieldsResp.latest_processing_run_id
              ? {
                  processing_run_id: fieldsResp.latest_processing_run_id,
                  status: fieldsResp.latest_outcome || 'succeeded',
                }
              : null),
          reviews: Array.isArray(verReviewsResp.reviews) ? verReviewsResp.reviews : [],
        });
      })
    );
    if (loadSeq !== state.workspaceLoadSeq) return;
    state.versionBundles = nextBundles;

    // Load latest assessment detail if available
    if (state.caseAssessments.length > 0) {
      const targetAssessmentId =
        state.selectedAssessmentId &&
        state.caseAssessments.some((a) => a.assessment_id === state.selectedAssessmentId)
          ? state.selectedAssessmentId
          : state.caseAssessments[0].assessment_id;
      state.selectedAssessmentId = targetAssessmentId;
      const assessDetail = await apiFetch(
        `/api/v1/organizations/${state.activeOrgId}/cases/${caseId}/consistency-assessments/${targetAssessmentId}`
      );
      if (loadSeq !== state.workspaceLoadSeq) return;
      state.selectedAssessmentDetail = assessDetail;
    } else {
      state.selectedAssessmentId = null;
      state.selectedAssessmentDetail = null;
    }

    const activeDocsWithVer = state.caseDocuments.filter((d) => d.current_version);
    const currentSelectedBundle = state.selectedVersionId
      ? state.versionBundles.get(state.selectedVersionId)
      : null;
    const unreviewedDoc = activeDocsWithVer.find((d) => {
      const b = state.versionBundles.get(d.current_version.version_id);
      return b && (!b.reviews || b.reviews.length === 0);
    });

    if (
      !state.selectedVersionId ||
      !currentSelectedBundle ||
      (currentSelectedBundle.reviews?.length > 0 && unreviewedDoc)
    ) {
      const targetDoc = unreviewedDoc || activeDocsWithVer[0];
      state.selectedDocumentId = targetDoc?.document_id || null;
      state.selectedVersionId = targetDoc?.current_version?.version_id || null;
    } else {
      const matchedDoc = activeDocsWithVer.find(
        (d) => d.current_version?.version_id === state.selectedVersionId
      );
      if (matchedDoc) {
        state.selectedDocumentId = matchedDoc.document_id;
      }
    }

    state.compareDocAId = activeDocsWithVer[0]?.document_id || null;
    state.compareDocBId = (activeDocsWithVer[1] || activeDocsWithVer[0])?.document_id || null;

    renderCaseWorkspace();
    if (state.selectedVersionId) {
      await selectDocumentVersionForInspection(state.selectedDocumentId, state.selectedVersionId);
    }
  } catch (err) {
    if (loadSeq === state.workspaceLoadSeq) {
      showAlert(`Falha ao carregar o caso: ${err.message}`, 'error');
    }
  } finally {
    if (loadSeq === state.workspaceLoadSeq) {
      state.workspaceLoadInFlight = false;
    }
  }
}

function renderCaseWorkspace() {
  const c = state.selectedCaseSummary;
  if (!c) return;

  // Section A
  document.getElementById('workspace-case-title').textContent = `Caso ${c.case_code}`;
  const subParts = [
    `Escopo: Administrativo (clinical_approval: false)`,
    c.procedure_reference ? `Ref. Procedimento: ${c.procedure_reference}` : null,
    c.external_reference ? `Ref. Externa: ${c.external_reference}` : null,
    c.declared_laterality ? `Lateralidade declarada: ${c.declared_laterality}` : null,
  ].filter(Boolean);
  document.getElementById('workspace-case-sub').textContent = subParts.join(' · ');

  const rMeta = getReadinessMeta(c.readiness_state);
  const badge = document.getElementById('workspace-readiness-badge');
  badge.className = `inst-status-badge inst-tone-${rMeta.tone}`;
  badge.textContent = rMeta.badgeText;

  document.getElementById('kv-case-id').textContent = c.case_id;
  document.getElementById('kv-case-readiness').textContent = `${rMeta.label} (${c.readiness_state})`;
  document.getElementById('kv-case-docs-count').textContent = `${c.active_documents_count} documento(s) ativo(s) / ${c.active_versions_count} versão(ões) ativa(s)`;

  const latestRun = state.caseProcessingRuns[state.caseProcessingRuns.length - 1] || null;
  document.getElementById('kv-case-last-run').textContent = latestRun
    ? `${latestRun.step_type} · ${latestRun.status.toUpperCase()} (${formatDateTime(latestRun.updated_at)})`
    : 'Nenhuma execução registrada';

  const latestAssess = state.caseAssessments[0] || null;
  document.getElementById('kv-case-last-assessment').textContent = latestAssess
    ? `#${latestAssess.assessment_sequence} · Eixos: ${latestAssess.automated_axes_outcome.toUpperCase()} · Prontidão: ${latestAssess.readiness_state}`
    : 'Nenhuma avaliação dos 4 eixos concluída';

  const revCompleted = Boolean(state.caseReviews?.human_review_completed);
  const revCount = `${state.caseReviews?.reviewed_active_versions_count || 0}/${state.caseReviews?.active_document_versions_count || 0}`;
  document.getElementById('kv-case-review-state').textContent = revCompleted
    ? `Concluída (${revCount} versões ativas revisadas)`
    : `Pendente (${revCount} versões ativas revisadas)`;

  // Section C: 5-Stage Pipeline
  renderPipelineStepper();

  // Section B: Documents table
  renderCaseDocumentsTable();

  // Part 6: Four Axes
  renderFourAxesPanel();

  // Part 5: Side-by-Side Comparison
  renderSideBySideComparison();

  // Part 7: Case Human Reviews Ledger
  renderCaseHumanReviewsLedger();
}

function renderPipelineStepper() {
  const listEl = document.getElementById('case-pipeline-stepper');
  listEl.replaceChildren();
  const stages = buildCasePipelineStages({
    activeDocuments: state.caseDocuments,
    processingRuns: state.caseProcessingRuns,
    latestAssessment: state.caseAssessments[0] || null,
    caseReviews: state.caseReviews,
  });

  for (const st of stages) {
    const li = createEl('li', {
      className: 'inst-pipeline-step',
      attrs: { 'data-state': st.state, 'data-step-key': st.key },
    });
    li.appendChild(createEl('div', { className: 'inst-pipeline-step-title', text: st.title }));
    li.appendChild(createEl('p', { className: 'inst-pipeline-step-detail', text: st.detail }));
    if (st.disclaimer) {
      li.appendChild(createEl('div', { className: 'inst-pipeline-disclaimer', text: st.disclaimer }));
    }
    listEl.appendChild(li);
  }
}

function renderCaseDocumentsTable() {
  const tbody = document.getElementById('case-documents-tbody');
  tbody.replaceChildren();

  if (state.caseDocuments.length === 0) {
    const tr = createEl('tr');
    tr.appendChild(
      createEl('td', {
        className: 'inst-empty-cell',
        text: 'Nenhum documento ativo neste caso. Utilize "+ Enviar documento PDF sintético" para adicionar.',
        attrs: { colspan: '10' },
      })
    );
    tbody.appendChild(tr);
    return;
  }

  for (const doc of state.caseDocuments) {
    const ver = doc.current_version;
    if (!ver) continue;
    const bundle = state.versionBundles.get(ver.version_id);
    const issueField = bundle?.fields?.find((f) => f.field_key === 'issue_date');
    const issueDateText = issueField?.normalized_value || issueField?.raw_value || 'Não extraída';

    const verRuns = state.caseProcessingRuns.filter((r) => r.document_version_id === ver.version_id);
    const integrityRun = verRuns.filter((r) => r.step_type === 'verify_object_integrity').pop();
    const extractRun = verRuns.filter((r) => r.step_type === 'extract_pdf_text').pop();
    const verReviews = bundle?.reviews || [];

    const tr = createEl('tr', {
      className: ver.version_id === state.selectedVersionId ? 'inst-row-selected' : '',
      attrs: { 'data-version-id': ver.version_id },
    });

    // 1. Filename / label
    const tdName = createEl('td');
    tdName.appendChild(createEl('strong', { text: ver.original_filename || doc.source_label }));
    tdName.appendChild(createEl('div', { text: doc.source_label }));

    // 2. Kind
    const tdKind = createEl('td', { className: 'inst-code-mono', text: doc.document_kind });

    // 3. Version
    const tdVer = createEl('td');
    tdVer.appendChild(
      createEl('span', {
        className: 'inst-status-badge inst-tone-ok',
        text: `v${ver.version_number} · Ativa`,
      })
    );

    // 4. Upload date
    const tdUpload = createEl('td', { text: formatDateTime(ver.created_at) });

    // 5. Extracted issue date
    const tdIssue = createEl('td', { className: 'inst-code-mono', text: issueDateText });

    // 6. Byte size & SHA-256
    const tdSha = createEl('td', {
      className: 'inst-code-mono',
      text: `${formatBytes(ver.byte_size)} · SHA256: ${ver.sha256_hex.slice(0, 12)}…`,
      attrs: { title: `SHA-256 completo: ${ver.sha256_hex}` },
    });

    // 7. Binary integrity
    const tdInt = createEl('td');
    const intStatus = integrityRun ? integrityRun.status : 'pending';
    const intTone = intStatus === 'succeeded' ? 'ok' : intStatus === 'failed' ? 'conflito' : 'pendente';
    tdInt.appendChild(
      createEl('span', {
        className: `inst-status-badge inst-tone-${intTone}`,
        text: intStatus === 'succeeded' ? '✓ Íntegro (SHA-256)' : intStatus.toUpperCase(),
      })
    );

    // 8. Text extraction
    const tdExt = createEl('td');
    const extStatus = extractRun ? extractRun.status : 'pending';
    const extTone =
      extStatus === 'succeeded'
        ? 'ok'
        : extStatus === 'abstained'
        ? 'abstencao'
        : extStatus === 'failed'
        ? 'conflito'
        : 'pendente';
    tdExt.appendChild(
      createEl('span', {
        className: `inst-status-badge inst-tone-${extTone}`,
        text:
          extStatus === 'succeeded'
            ? '✓ Extraído'
            : extStatus === 'abstained'
            ? '⚠ Com abstenção'
            : extStatus.toUpperCase(),
      })
    );

    // 9. Human Review state
    const tdRev = createEl('td');
    const hasRev = verReviews.length > 0;
    tdRev.appendChild(
      createEl('span', {
        className: `inst-status-badge inst-tone-${hasRev ? 'ok' : 'pendente'}`,
        text: hasRev ? `✓ Revisada (${verReviews.length})` : '⏳ Pendente',
      })
    );

    // 10. Actions
    const tdAct = createEl('td');
    const inspectBtn = createEl('button', {
      className: 'inst-btn inst-btn-sm inst-btn-primary',
      text: ver.version_id === state.selectedVersionId ? 'Selecionado' : 'Inspecionar & Revisar',
      attrs: {
        type: 'button',
        'data-inspect-version-id': ver.version_id,
        'data-inspect-document-id': doc.document_id,
        'data-version-reviewed': hasRev ? 'true' : 'false',
      },
    });
    inspectBtn.addEventListener('click', () => {
      selectDocumentVersionForInspection(doc.document_id, ver.version_id);
    });
    tdAct.appendChild(inspectBtn);

    if (!extractRun && hasPermission('document:upload')) {
      const enqueueExtBtn = createEl('button', {
        className: 'inst-btn inst-btn-sm inst-btn-secondary',
        text: 'Reprocessar versão',
        attrs: {
          type: 'button',
          'data-reprocess-version-id': ver.version_id,
        },
      });
      enqueueExtBtn.addEventListener('click', async () => {
        if (enqueueExtBtn.disabled) return;
        enqueueExtBtn.disabled = true;
        try {
          await apiFetch(
            `/api/v1/organizations/${state.activeOrgId}/documents/${doc.document_id}/versions/${ver.version_id}/reprocess`,
            { method: 'POST' }
          );
          showAlert('Reprocessamento da versão documental enfileirado com sucesso.', 'success');
          await openCaseWorkspace(state.selectedCaseId);
        } catch (err) {
          enqueueExtBtn.disabled = false;
          showAlert(`Não foi possível enfileirar reprocessamento: ${err.message}`, 'error');
        }
      });
      tdAct.appendChild(enqueueExtBtn);
    }

    tr.append(tdName, tdKind, tdVer, tdUpload, tdIssue, tdSha, tdInt, tdExt, tdRev, tdAct);
    tbody.appendChild(tr);
  }
}

function renderFourAxesPanel() {
  const selectEl = document.getElementById('assessment-history-select');
  selectEl.replaceChildren();

  if (state.caseAssessments.length === 0) {
    selectEl.appendChild(
      createEl('option', {
        text: 'Nenhuma avaliação concluída',
        attrs: { value: '' },
      })
    );
    selectEl.disabled = true;
  } else {
    selectEl.disabled = false;
    for (const a of state.caseAssessments) {
      const opt = createEl('option', {
        text: `Avaliação #${a.assessment_sequence} · ${a.automated_axes_outcome.toUpperCase()} · Prontidão: ${a.readiness_state} (${formatDateTime(a.assessed_at)})`,
        attrs: { value: a.assessment_id },
      });
      if (a.assessment_id === state.selectedAssessmentId) {
        opt.selected = true;
      }
      selectEl.appendChild(opt);
    }
  }

  const grid = document.getElementById('four-axes-grid');
  grid.replaceChildren();

  const formattedAxes = formatFourAxesFromBackend(state.selectedAssessmentDetail);
  for (const ax of formattedAxes) {
    const card = createEl('article', {
      className: `inst-axis-card inst-tone-${ax.tone}`,
      attrs: {
        'data-axis-name': ax.axisName,
        'data-axis-status': ax.status,
      },
    });

    const header = createEl('div', { className: 'inst-axis-header' });
    header.appendChild(createEl('h4', { className: 'inst-axis-title', text: ax.title }));
    header.appendChild(
      createEl('span', {
        className: `inst-status-badge inst-tone-${ax.tone}`,
        text: ax.badgeText,
      })
    );

    const ruleEl = createEl('div', {
      className: 'inst-axis-rule',
      text: `Regra: ${ax.ruleCode}`,
    });

    const justEl = createEl('p', {
      className: 'inst-axis-just',
      text: ax.justification,
    });

    const metaEl = createEl('div', { className: 'inst-axis-meta' });
    metaEl.appendChild(
      createEl('div', {
        text: `Campos avaliados: ${ax.fieldsUsed.length ? ax.fieldsUsed.join(', ') : '—'}`,
      })
    );
    metaEl.appendChild(
      createEl('div', {
        text: `Versões comparadas: ${ax.comparedVersionIds.length} · Evidências vinculadas: ${ax.evidenceReferenceIds.length}`,
      })
    );
    if (ax.limitations.length > 0) {
      metaEl.appendChild(
        createEl('div', {
          text: `Limitações / Avisos: ${ax.limitations.join(', ')}`,
        })
      );
    }

    card.append(header, ruleEl, justEl, metaEl);
    grid.appendChild(card);
  }
}

function renderSideBySideComparison() {
  const selA = document.getElementById('compare-doc-a-select');
  const selB = document.getElementById('compare-doc-b-select');
  selA.replaceChildren();
  selB.replaceChildren();

  const docsWithVer = state.caseDocuments.filter((d) => d.current_version);
  for (const doc of docsWithVer) {
    const label = `${doc.source_label} (${doc.current_version.original_filename || doc.document_kind})`;
    const optA = createEl('option', { text: label, attrs: { value: doc.document_id } });
    if (doc.document_id === state.compareDocAId) optA.selected = true;
    selA.appendChild(optA);

    const optB = createEl('option', { text: label, attrs: { value: doc.document_id } });
    if (doc.document_id === state.compareDocBId) optB.selected = true;
    selB.appendChild(optB);
  }

  const tbody = document.getElementById('side-by-side-tbody');
  tbody.replaceChildren();

  if (docsWithVer.length === 0) {
    const tr = createEl('tr');
    tr.appendChild(
      createEl('td', {
        className: 'inst-empty-cell',
        text: 'Envie documentos ao caso para visualizar a comparação lado a lado.',
        attrs: { colspan: '4' },
      })
    );
    tbody.appendChild(tr);
    return;
  }

  const docA = docsWithVer.find((d) => d.document_id === state.compareDocAId) || docsWithVer[0];
  const docB = docsWithVer.find((d) => d.document_id === state.compareDocBId) || docsWithVer[docsWithVer.length - 1];
  const bundleA = state.versionBundles.get(docA.current_version.version_id);
  const bundleB = state.versionBundles.get(docB.current_version.version_id);

  const rows = buildSideBySideFieldComparison(bundleA, bundleB, state.selectedAssessmentDetail);
  for (const row of rows) {
    const tr = createEl('tr', {
      attrs: {
        'data-compare-field': row.fieldKey,
        'data-compare-outcome': row.comparisonOutcome,
      },
    });

    const tdField = createEl('td');
    tdField.appendChild(createEl('strong', { text: row.label }));
    tdField.appendChild(createEl('div', { className: 'inst-code-mono', text: `${row.fieldKey} (${row.axis})` }));

    const renderSideCell = (side, docObj) => {
      const td = createEl('td');
      const stMeta = getFieldStatusMeta(side.status, side.abstained);
      td.appendChild(
        createEl('span', {
          className: `inst-status-badge inst-tone-${stMeta.tone}`,
          text: `${stMeta.icon} ${stMeta.label}`,
        })
      );
      td.appendChild(
        createEl('div', {
          text: `Bruto: ${side.rawValue !== null ? side.rawValue : '—'}`,
        })
      );
      td.appendChild(
        createEl('div', {
          className: 'inst-code-mono',
          text: `Normalizado: ${side.normalizedValue !== null ? side.normalizedValue : '—'}`,
        })
      );
      if (side.reasonCode) {
        td.appendChild(
          createEl('div', {
            className: 'inst-code-mono',
            text: `Motivo: ${side.reasonCode}`,
          })
        );
      }
      if (side.pageNumber) {
        const evBtn = createEl('button', {
          className: 'inst-btn inst-btn-sm inst-btn-secondary',
          text: side.hasSpatialBbox
            ? `📍 Ver Pág. ${side.pageNumber} (destacar BBox)`
            : `📄 Ver Pág. ${side.pageNumber} (sem BBox)`,
          attrs: { type: 'button' },
        });
        evBtn.addEventListener('click', () => {
          highlightFieldEvidenceOnPdf(docObj.document_id, docObj.current_version.version_id, {
            fieldLabel: row.label,
            pageNumber: side.pageNumber,
            bbox: side.bbox,
            hasSpatialBbox: side.hasSpatialBbox,
            quoteExcerpt: side.quoteExcerpt,
            evidenceId: side.evidenceId,
          });
        });
        td.appendChild(evBtn);
      }
      return td;
    };

    const tdA = renderSideCell(row.sideA, docA);
    const tdB = renderSideCell(row.sideB, docB);

    const tdDiag = createEl('td');
    const diagTone =
      row.comparisonOutcome === 'conflict'
        ? 'conflito'
        : row.comparisonOutcome === 'abstention'
        ? 'abstencao'
        : 'ok';
    const diagLabel =
      row.comparisonOutcome === 'conflict'
        ? '✕ CONFLITO'
        : row.comparisonOutcome === 'abstention'
        ? '⚠ ABSTENÇÃO / AUSENTE'
        : '✓ CONVERGENTE';
    tdDiag.appendChild(
      createEl('span', {
        className: `inst-status-badge inst-tone-${diagTone}`,
        text: diagLabel,
      })
    );
    tdDiag.appendChild(createEl('div', { text: row.comparisonNote }));

    tr.append(tdField, tdA, tdB, tdDiag);
    tbody.appendChild(tr);
  }
}

async function selectDocumentVersionForInspection(documentId, versionId) {
  state.selectedDocumentId = documentId;
  state.selectedVersionId = versionId;
  renderCaseDocumentsTable();

  const bundle = state.versionBundles.get(versionId);
  if (!bundle) return;

  renderVersionExtractedFields(bundle);
  renderVersionHumanReviewForm(bundle);
  await loadPdfIntoViewer(bundle.document, bundle.version);
}

function renderVersionExtractedFields(bundle) {
  const { document: doc, version: ver, fields, latestExtractRun } = bundle;
  document.getElementById('selected-doc-version-meta').textContent =
    `Documento: ${doc.source_label} (${ver.original_filename || doc.document_kind}) · Versão v${ver.version_number} (${ver.version_id}) · Extração: ${latestExtractRun ? latestExtractRun.status : 'pendente'}`;

  const tbody = document.getElementById('version-extracted-fields-tbody');
  tbody.replaceChildren();

  if (!fields || fields.length === 0) {
    const tr = createEl('tr');
    tr.appendChild(
      createEl('td', {
        className: 'inst-empty-cell',
        text: 'Nenhum campo extraído disponível para esta versão documental (aguardando worker ou documento sem camada textual).',
        attrs: { colspan: '6' },
      })
    );
    tbody.appendChild(tr);
    return;
  }

  const labelByKey = new Map(INSTITUTIONAL_FIELD_DEFS.map((d) => [d.key, d.label]));

  for (const f of fields) {
    const tr = createEl('tr', { attrs: { 'data-extracted-field-key': f.field_key } });
    const ev = Array.isArray(f.evidences) && f.evidences.length > 0 ? f.evidences[0] : null;
    const stMeta = getFieldStatusMeta(f.status, f.abstained);

    // 1. Field name
    const tdName = createEl('td');
    tdName.appendChild(createEl('strong', { text: labelByKey.get(f.field_key) || f.field_key }));
    tdName.appendChild(createEl('div', { className: 'inst-code-mono', text: f.field_key }));

    // 2. Raw value (literal)
    const tdRaw = createEl('td', {
      text: f.raw_value !== null && f.raw_value !== undefined ? f.raw_value : '— (ausente)',
    });

    // 3. Normalized value
    const tdNorm = createEl('td', {
      className: 'inst-code-mono',
      text: f.normalized_value !== null && f.normalized_value !== undefined ? f.normalized_value : '—',
    });

    // 4. Status / reason
    const tdStatus = createEl('td');
    tdStatus.appendChild(
      createEl('span', {
        className: `inst-status-badge inst-tone-${stMeta.tone}`,
        text: `${stMeta.icon} ${stMeta.label}`,
      })
    );
    const reason = f.metadata_json?.reason_code || f.metadata_json?.abstention_reason || f.metadata?.reason_code || f.metadata?.abstention_reason;
    if (reason) {
      tdStatus.appendChild(createEl('div', { className: 'inst-code-mono', text: `Motivo: ${reason}` }));
    }

    // 5. Page & BBox
    const tdBbox = createEl('td', { className: 'inst-code-mono' });
    if (ev) {
      const validBox = hasValidSpatialBbox(ev);
      const bboxText = validBox
        ? `Pág. ${ev.page_number} · [${ev.bbox.map((n) => Number(n).toFixed(3)).join(', ')}]`
        : `Pág. ${ev.page_number} · Sem BBox espacial`;
      tdBbox.textContent = bboxText;
    } else {
      tdBbox.textContent = 'Sem evidência espacial';
    }

    // 6. Highlight button
    const tdAct = createEl('td');
    if (ev) {
      const validBox = hasValidSpatialBbox(ev);
      const btn = createEl('button', {
        className: 'inst-btn inst-btn-sm inst-btn-secondary',
        text: validBox ? '📍 Destacar no PDF' : '📄 Ver trecho',
        attrs: {
          type: 'button',
          'data-highlight-field': f.field_key,
        },
      });
      btn.addEventListener('click', () => {
        highlightFieldEvidenceOnPdf(doc.document_id, ver.version_id, {
          fieldLabel: labelByKey.get(f.field_key) || f.field_key,
          pageNumber: ev.page_number,
          bbox: ev.bbox,
          hasSpatialBbox: validBox,
          quoteExcerpt: ev.quote_excerpt,
          evidenceId: ev.evidence_reference_id || ev.evidence_id,
        });
      });
      tdAct.appendChild(btn);
    } else {
      tdAct.textContent = '—';
    }

    tr.append(tdName, tdRaw, tdNorm, tdStatus, tdBbox, tdAct);
    tbody.appendChild(tr);
  }
}

function renderVersionHumanReviewForm(bundle) {
  const { document: doc, version: ver, reviews } = bundle;
  const targetBox = document.getElementById('review-version-target-box');
  const form = document.getElementById('human-review-form');
  const notice = document.getElementById('review-already-recorded-notice');

  targetBox.textContent =
    `Alvo da revisão: ${doc.source_label} (${ver.original_filename || doc.document_kind}) · Versão v${ver.version_number} · ID: ${ver.version_id}`;

  const generalReview = reviews.find((r) => !r.field_key);
  const canReview = hasPermission('field:review');

  if (generalReview) {
    form.hidden = true;
    notice.hidden = false;
    notice.textContent =
      `✓ Revisão administrativa já registrada para esta versão documental por ${generalReview.reviewer_display_name || generalReview.reviewer_email || generalReview.reviewer_user_id} (${generalReview.reviewer_role || 'revisor'}) em ${formatDateTime(generalReview.created_at)}. Ação: ${generalReview.action_type}. Justificativa: "${generalReview.justification}"`;
  } else if (!canReview) {
    form.hidden = true;
    notice.hidden = false;
    notice.textContent =
      `Seu papel atual (${state.activeMembership?.role || 'leitura'}) possui acesso somente leitura e não possui a permissão 'field:review' para registrar revisão humana.`;
  } else {
    form.hidden = false;
    notice.hidden = true;
    document.getElementById('review-confirm-checkbox').checked = false;
  }
}

function renderCaseHumanReviewsLedger() {
  const container = document.getElementById('case-human-reviews-list');
  container.replaceChildren();

  const reviews = state.caseReviews?.reviews || [];
  if (reviews.length === 0) {
    container.appendChild(
      createEl('p', {
        className: 'inst-empty-cell',
        text: 'Nenhuma revisão humana registrada neste caso até o momento.',
      })
    );
    return;
  }

  for (const r of reviews) {
    const item = createEl('div', {
      className: 'inst-review-item',
      attrs: { 'data-review-id': r.review_id },
    });
    const who = r.reviewer_display_name
      ? `${r.reviewer_display_name} (${r.reviewer_email || r.reviewer_user_id})`
      : r.reviewer_email || r.reviewer_user_id;
    item.appendChild(
      createEl('div', {
        text: `✓ Versão v${r.version_number || '?'} (${r.document_version_id}) · Ação: ${r.action_type} · Escopo: ${r.field_key || 'Versão completa'}`,
      })
    );
    item.appendChild(
      createEl('div', {
        text: `Revisor: ${who} [${r.reviewer_role || 'membro'}] · Data/Hora: ${formatDateTime(r.created_at)}`,
      })
    );
    item.appendChild(
      createEl('div', {
        text: `Justificativa: "${r.justification}"`,
      })
    );
    container.appendChild(item);
  }
}

async function ensurePdfJsLoaded() {
  if (state.pdfLib) return state.pdfLib;
  const pdfjs = await import('/institutional/vendor/pdf.min.mjs');
  pdfjs.GlobalWorkerOptions.workerSrc = '/institutional/vendor/pdf.worker.min.mjs';
  state.pdfLib = pdfjs;
  return pdfjs;
}

async function loadPdfIntoViewer(doc, ver) {
  const titleEl = document.getElementById('pdf-viewer-title');
  const emptyMsg = document.getElementById('pdf-empty-message');
  const canvasWrap = document.getElementById('pdf-canvas-wrapper');
  const downloadLink = document.getElementById('btn-pdf-download');

  const loadToken = state.pdfLoadSequencer.beginLoad({
    organizationId: state.activeOrgId,
    caseId: state.selectedCaseId,
    versionId: ver.version_id,
  });
  state.pdfActiveLoadToken = loadToken;

  const isCurrentLoad = () =>
    state.pdfLoadSequencer.isCurrent(loadToken, {
      organizationId: state.activeOrgId,
      caseId: state.selectedCaseId,
      versionId: state.selectedVersionId,
    });

  titleEl.textContent = `${doc.source_label} · ${ver.original_filename || doc.document_kind} (v${ver.version_number})`;
  const contentUrl = `/api/v1/organizations/${state.activeOrgId}/documents/${doc.document_id}/versions/${ver.version_id}/content`;
  downloadLink.href = contentUrl;
  downloadLink.hidden = false;

  if (ver.mime_type !== 'application/pdf') {
    state.pdfLoadSequencer.clearDocument(loadToken);
    state.pdfDoc = null;
    state.pdfLoadedVersionId = ver.version_id;
    canvasWrap.hidden = true;
    emptyMsg.hidden = false;
    emptyMsg.textContent = `Este documento possui formato ${ver.mime_type} (sem camada PDF renderizável via PDF.js).`;
    updatePdfControls();
    return;
  }

  try {
    emptyMsg.hidden = false;
    emptyMsg.textContent = 'Carregando PDF autenticado via BFF...';
    canvasWrap.hidden = true;

    const [pdfjs, buffer] = await Promise.all([
      ensurePdfJsLoaded(),
      apiFetch(contentUrl, { isBinary: true }),
    ]);
    if (!isCurrentLoad()) {
      return;
    }

    const loadingTask = pdfjs.getDocument({ data: new Uint8Array(buffer) });
    if (!state.pdfLoadSequencer.registerLoadingTask(loadToken, loadingTask)) {
      return;
    }
    const pdfDoc = await loadingTask.promise;
    if (!isCurrentLoad() || !state.pdfLoadSequencer.commitLoadedDocument(loadToken, pdfDoc)) {
      return;
    }

    state.pdfDoc = pdfDoc;
    state.pdfLoadedVersionId = ver.version_id;
    state.pdfPageCount = pdfDoc.numPages;
    state.pdfPageNum = 1;
    state.activeHighlights = [];
    document.getElementById('pdf-highlight-banner').hidden = true;
    document.getElementById('btn-pdf-clear-highlight').hidden = true;

    emptyMsg.hidden = true;
    canvasWrap.hidden = false;
    await renderCurrentPdfPage(loadToken);
  } catch (err) {
    if (!isCurrentLoad()) {
      return;
    }
    state.pdfLoadSequencer.clearDocument(loadToken);
    state.pdfDoc = null;
    canvasWrap.hidden = true;
    emptyMsg.hidden = false;
    emptyMsg.textContent = `Não foi possível renderizar o PDF: ${err.message}`;
    updatePdfControls();
  }
}

async function renderCurrentPdfPage(expectedToken = state.pdfActiveLoadToken) {
  if (!state.pdfDoc) {
    updatePdfControls();
    return;
  }
  const isCurrentToken = () =>
    !expectedToken ||
    state.pdfLoadSequencer.isCurrent(expectedToken, {
      organizationId: state.activeOrgId,
      caseId: state.selectedCaseId,
      versionId: state.selectedVersionId,
    });
  if (!isCurrentToken()) {
    return;
  }
  const targetDoc = state.pdfDoc;
  const targetPageNum = state.pdfPageNum;
  const page = await targetDoc.getPage(targetPageNum);
  if (!isCurrentToken() || state.pdfDoc !== targetDoc) {
    return;
  }
  const viewport = page.getViewport({ scale: state.pdfScale });
  const canvas = document.getElementById('pdf-render-canvas');
  const ctx = canvas.getContext('2d');
  canvas.width = Math.floor(viewport.width);
  canvas.height = Math.floor(viewport.height);

  await page.render({ canvasContext: ctx, viewport }).promise;
  if (!isCurrentToken() || state.pdfDoc !== targetDoc) {
    return;
  }
  renderPdfBboxOverlays(canvas.width, canvas.height);
  updatePdfControls();
}

function renderPdfBboxOverlays(widthPx, heightPx) {
  const layer = document.getElementById('pdf-bbox-overlay-layer');
  layer.replaceChildren();
  layer.style.width = `${widthPx}px`;
  layer.style.height = `${heightPx}px`;

  for (const hl of state.activeHighlights) {
    if (hl.pageNumber !== state.pdfPageNum || !Array.isArray(hl.bbox) || hl.bbox.length !== 4) {
      continue;
    }
    const [bx, by, bw, bh] = hl.bbox;
    const rect = createEl('div', {
      className: 'inst-bbox-rect',
      attrs: {
        title: hl.label || 'Evidência destacada',
      },
    });
    rect.style.left = `${Math.max(0, bx * widthPx - 2)}px`;
    rect.style.top = `${Math.max(0, by * heightPx - 2)}px`;
    rect.style.width = `${Math.max(12, bw * widthPx + 4)}px`;
    rect.style.height = `${Math.max(12, bh * heightPx + 4)}px`;
    layer.appendChild(rect);
  }
}

function updatePdfControls() {
  const hasDoc = Boolean(state.pdfDoc);
  document.getElementById('btn-pdf-prev').disabled = !hasDoc || state.pdfPageNum <= 1;
  document.getElementById('btn-pdf-next').disabled = !hasDoc || state.pdfPageNum >= state.pdfPageCount;
  document.getElementById('btn-pdf-zoom-out').disabled = !hasDoc || state.pdfScale <= 0.6;
  document.getElementById('btn-pdf-zoom-in').disabled = !hasDoc || state.pdfScale >= 2.4;
  document.getElementById('pdf-page-indicator').textContent = hasDoc
    ? `Pág. ${state.pdfPageNum} / ${state.pdfPageCount}`
    : 'Pág. 0 / 0';
  document.getElementById('pdf-zoom-indicator').textContent = `${Math.round(state.pdfScale * 100)}%`;
}

async function highlightFieldEvidenceOnPdf(documentId, versionId, evidenceInfo) {
  if (state.selectedVersionId !== versionId || state.pdfLoadedVersionId !== versionId) {
    await selectDocumentVersionForInspection(documentId, versionId);
  }

  const banner = document.getElementById('pdf-highlight-banner');
  const clearBtn = document.getElementById('btn-pdf-clear-highlight');
  banner.hidden = false;
  clearBtn.hidden = false;

  if (evidenceInfo.hasSpatialBbox) {
    state.activeHighlights = [
      {
        pageNumber: evidenceInfo.pageNumber,
        bbox: evidenceInfo.bbox,
        label: evidenceInfo.fieldLabel,
      },
    ];
    banner.textContent =
      `📍 Evidência espacial destacada: ${evidenceInfo.fieldLabel} · Página ${evidenceInfo.pageNumber} · BBox [${evidenceInfo.bbox.map((n) => Number(n).toFixed(3)).join(', ')}] · Trecho: "${evidenceInfo.quoteExcerpt || '—'}"`;
  } else {
    state.activeHighlights = [];
    banner.textContent =
      `📄 Evidência textual (sem destaque espacial disponível): ${evidenceInfo.fieldLabel} · Página ${evidenceInfo.pageNumber} · Trecho: "${evidenceInfo.quoteExcerpt || '—'}"`;
  }

  if (state.pdfDoc && evidenceInfo.pageNumber >= 1 && evidenceInfo.pageNumber <= state.pdfPageCount) {
    state.pdfPageNum = evidenceInfo.pageNumber;
    await renderCurrentPdfPage();
  }
}

async function bootstrapSession() {
  try {
    const sessionData = await apiFetch('/api/v1/auth/session');
    state.sessionStatus = sessionData;
    state.authenticated = Boolean(sessionData.authenticated);
    state.csrfCookieName = sessionData.csrf_cookie_name || 'jyxia_csrf';
    state.csrfHeaderName = sessionData.csrf_header_name || 'X-CSRF-Token';

    const [me, orgsResp] = await Promise.all([
      apiFetch('/api/v1/me'),
      apiFetch('/api/v1/me/organizations'),
    ]);
    state.userProfile = me;
    const orgList = Array.isArray(orgsResp)
      ? orgsResp
      : Array.isArray(orgsResp?.organizations)
      ? orgsResp.organizations
      : [];
    state.organizations = orgList;
    state.activeOrgId =
      me.active_organization_id ||
      orgsResp?.active_organization_id ||
      state.organizations[0]?.organization_id ||
      null;
    state.activeMembership =
      state.organizations.find((o) => o.organization_id === state.activeOrgId) || null;

    renderAuthGate();
    if (state.activeOrgId) {
      await loadOrganizationCases();
      if (state.cases.length > 0 && !state.selectedCaseId) {
        await openCaseWorkspace(state.cases[0].case_id);
      }
    }
  } catch (_err) {
    state.authenticated = false;
    renderAuthGate();
  }
}

function wireEventListeners() {
  // Refresh all
  document.getElementById('btn-refresh-all').addEventListener('click', async () => {
    await loadOrganizationCases();
    if (state.selectedCaseId) {
      await openCaseWorkspace(state.selectedCaseId);
    }
    showAlert('Dados atualizados a partir da API institucional.', 'info');
  });

  // Organization switcher
  document.getElementById('org-select').addEventListener('change', async (e) => {
    const newOrgId = e.target.value;
    if (!newOrgId || newOrgId === state.activeOrgId) return;
    try {
      await apiFetch('/api/v1/auth/select-organization', {
        method: 'POST',
        body: { organization_id: newOrgId },
      });
      state.selectedCaseId = null;
      document.getElementById('case-workspace').hidden = true;
      await bootstrapSession();
      showAlert('Contexto organizacional alterado com sucesso.', 'success');
    } catch (err) {
      showAlert(`Falha ao alternar organização: ${err.message}`, 'error');
    }
  });

  // Logout
  document.getElementById('btn-logout').addEventListener('click', async () => {
    try {
      await apiFetch('/api/v1/auth/logout', { method: 'POST' });
    } catch (_e) {
      // ignore
    }
    state.authenticated = false;
    state.selectedCaseId = null;
    renderAuthGate();
    showAlert('Sessão institucional encerrada.', 'info');
  });

  // Search box
  document.getElementById('case-search-input').addEventListener('input', (e) => {
    state.searchQuery = e.target.value;
    renderCasesTable();
  });

  // New Case drawer
  const newCaseForm = document.getElementById('new-case-form');
  document.getElementById('btn-toggle-new-case').addEventListener('click', () => {
    newCaseForm.hidden = !newCaseForm.hidden;
  });
  document.getElementById('btn-cancel-new-case').addEventListener('click', () => {
    newCaseForm.hidden = true;
  });
  newCaseForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const caseCode = document.getElementById('input-case-code').value.trim();
    const procRef = document.getElementById('input-proc-ref').value.trim() || null;
    const extRef = document.getElementById('input-ext-ref').value.trim() || null;
    const latRef = document.getElementById('input-laterality-ref').value.trim() || null;
    try {
      const created = await apiFetch(`/api/v1/organizations/${state.activeOrgId}/cases`, {
        method: 'POST',
        body: {
          case_code: caseCode,
          procedure_reference: procRef,
          external_reference: extRef,
          declared_laterality: latRef,
        },
      });
      newCaseForm.reset();
      newCaseForm.hidden = true;
      showAlert(`Caso ${created.case_code} criado com sucesso.`, 'success');
      await loadOrganizationCases();
      await openCaseWorkspace(created.case_id);
    } catch (err) {
      showAlert(`Falha ao criar caso: ${err.message}`, 'error');
    }
  });

  // Refresh case button
  document.getElementById('btn-refresh-case').addEventListener('click', async () => {
    if (state.selectedCaseId && !state.workspaceLoadInFlight) {
      await openCaseWorkspace(state.selectedCaseId);
    }
  });

  // Enqueue 4-axis comparison
  document.getElementById('btn-trigger-compare').addEventListener('click', async () => {
    if (!state.selectedCaseId) return;
    try {
      const run = await apiFetch(
        `/api/v1/organizations/${state.activeOrgId}/cases/${state.selectedCaseId}/consistency-assessments`,
        { method: 'POST' }
      );
      showAlert(
        `Comparação determinística dos 4 eixos enfileirada (run: ${run.processing_run_id}, status: ${run.status}).`,
        'success'
      );
      await openCaseWorkspace(state.selectedCaseId);
    } catch (err) {
      showAlert(`Não foi possível enfileirar comparação: ${err.message}`, 'error');
    }
  });

  // Upload document drawer
  const uploadForm = document.getElementById('upload-doc-form');
  document.getElementById('btn-toggle-upload-doc').addEventListener('click', () => {
    uploadForm.hidden = !uploadForm.hidden;
  });
  document.getElementById('btn-cancel-upload-doc').addEventListener('click', () => {
    uploadForm.hidden = true;
  });
  uploadForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!state.selectedCaseId) return;
    const fileInput = document.getElementById('upload-file-input');
    const file = fileInput.files?.[0];
    if (!file) {
      showAlert('Selecione um arquivo PDF ou PNG sintético.', 'warning');
      return;
    }
    const fd = new FormData();
    fd.append('document_kind', document.getElementById('upload-doc-kind').value);
    fd.append('source_label', document.getElementById('upload-source-label').value.trim());
    fd.append('file', file, file.name);

    try {
      const res = await apiFetch(
        `/api/v1/organizations/${state.activeOrgId}/cases/${state.selectedCaseId}/documents`,
        { method: 'POST', body: fd }
      );
      uploadForm.reset();
      uploadForm.hidden = true;
      const verInfo = res.current_version || res.version;
      showAlert(
        `Documento "${verInfo.original_filename}" recebido (SHA-256: ${verInfo.sha256_hex.slice(0, 12)}…) e verificação enfileirada.`,
        'success'
      );
      await openCaseWorkspace(state.selectedCaseId);
    } catch (err) {
      showAlert(`Falha no upload documental: ${err.message}`, 'error');
    }
  });

  // Historical assessment selector
  document.getElementById('assessment-history-select').addEventListener('change', async (e) => {
    const assessId = e.target.value;
    if (!assessId || !state.selectedCaseId) return;
    try {
      state.selectedAssessmentId = assessId;
      state.selectedAssessmentDetail = await apiFetch(
        `/api/v1/organizations/${state.activeOrgId}/cases/${state.selectedCaseId}/consistency-assessments/${assessId}`
      );
      renderFourAxesPanel();
      renderSideBySideComparison();
    } catch (err) {
      showAlert(`Falha ao carregar avaliação histórica: ${err.message}`, 'error');
    }
  });

  // Side-by-side selectors
  document.getElementById('compare-doc-a-select').addEventListener('change', (e) => {
    state.compareDocAId = e.target.value;
    renderSideBySideComparison();
  });
  document.getElementById('compare-doc-b-select').addEventListener('change', (e) => {
    state.compareDocBId = e.target.value;
    renderSideBySideComparison();
  });

  // PDF viewer controls
  document.getElementById('btn-pdf-prev').addEventListener('click', async () => {
    if (state.pdfDoc && state.pdfPageNum > 1) {
      state.pdfPageNum -= 1;
      await renderCurrentPdfPage();
    }
  });
  document.getElementById('btn-pdf-next').addEventListener('click', async () => {
    if (state.pdfDoc && state.pdfPageNum < state.pdfPageCount) {
      state.pdfPageNum += 1;
      await renderCurrentPdfPage();
    }
  });
  document.getElementById('btn-pdf-zoom-out').addEventListener('click', async () => {
    if (state.pdfDoc && state.pdfScale > 0.6) {
      state.pdfScale = Math.max(0.6, Number((state.pdfScale - 0.2).toFixed(2)));
      await renderCurrentPdfPage();
    }
  });
  document.getElementById('btn-pdf-zoom-in').addEventListener('click', async () => {
    if (state.pdfDoc && state.pdfScale < 2.4) {
      state.pdfScale = Math.min(2.4, Number((state.pdfScale + 0.2).toFixed(2)));
      await renderCurrentPdfPage();
    }
  });
  document.getElementById('btn-pdf-clear-highlight').addEventListener('click', async () => {
    state.activeHighlights = [];
    document.getElementById('pdf-highlight-banner').hidden = true;
    document.getElementById('btn-pdf-clear-highlight').hidden = true;
    if (state.pdfDoc) {
      await renderCurrentPdfPage();
    }
  });

  // Human Review submission
  document.getElementById('human-review-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!state.selectedDocumentId || !state.selectedVersionId) return;

    const actionType = document.getElementById('review-action-type').value;
    const fieldKey = document.getElementById('review-field-key').value || null;
    const justification = document.getElementById('review-justification').value;
    const confirmed = document.getElementById('review-confirm-checkbox').checked;

    const check = validateAndBuildHumanReviewPayload({
      confirmed,
      actionType,
      justification,
      fieldKey,
    });
    if (!check.valid) {
      showAlert(check.error, 'warning');
      return;
    }

    const submitBtn = document.getElementById('btn-submit-human-review');
    submitBtn.disabled = true;
    try {
      const recorded = await apiFetch(
        `/api/v1/organizations/${state.activeOrgId}/documents/${state.selectedDocumentId}/versions/${state.selectedVersionId}/human-reviews`,
        {
          method: 'POST',
          body: check.payload,
        }
      );
      document.getElementById('review-justification').value = '';
      document.getElementById('review-confirm-checkbox').checked = false;

      const compRunMsg = recorded.comparison_processing_run
        ? ` Reavaliação de consistência enfileirada (${recorded.comparison_processing_run.status}).`
        : '';
      showAlert(
        `Revisão administrativa registrada com sucesso (ID: ${recorded.review_id}).${compRunMsg}`,
        'success'
      );
      await openCaseWorkspace(state.selectedCaseId);
    } catch (err) {
      showAlert(`Falha ao registrar revisão administrativa: ${err.message}`, 'error');
    } finally {
      submitBtn.disabled = false;
    }
  });
}

document.addEventListener('DOMContentLoaded', () => {
  wireEventListeners();
  bootstrapSession();
});
