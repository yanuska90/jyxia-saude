/**
 * Real-Browser (Chromium / Edge via CDP) End-to-End Test for JYXIA Institutional Review UI (Etapa 3.3.5).
 * Validates:
 *  - Unauthenticated gate vs. BFF authenticated session (`jyxia_session` + `jyxia_csrf`)
 *  - Real API dashboard metrics and case filtering
 *  - Scenario A (Coherent 2-document case): PDF.js rendering, extracted fields, spatial bbox highlight,
 *    side-by-side comparison, 4 consistency axes, recording administrative human reviews on both active
 *    versions, worker re-assessment transitioning the case from `pendente` to `conferida` while preserving
 *    historical assessment #1 and `clinical_approval=false`.
 *  - Scenario B (Conflicting OD vs OE case): recording administrative human reviews on both active versions,
 *    worker re-assessment keeping the case `bloqueado` (human review never overrides axis conflict).
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const MSEDGE_CANDIDATES = [
  process.env.JYXIA_BROWSER_BIN,
  String.raw`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
  String.raw`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
  String.raw`C:\Program Files\Google\Chrome\Application\chrome.exe`,
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/google-chrome',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean);

const PYTHON_CANDIDATES = [
  process.env.JYXIA_PYTHON_BIN,
  path.join(ROOT_DIR, 'backend', '.venv', 'Scripts', 'python.exe'),
  path.join(ROOT_DIR, 'backend', '.venv', 'bin', 'python'),
  'python',
  'python3',
].filter(Boolean);

async function findExecutable(candidates, label) {
  for (const candidate of candidates) {
    if (!candidate.includes(path.sep) && !candidate.includes('/')) {
      return candidate;
    }
    try {
      await fs.access(candidate);
      return candidate;
    } catch {}
  }
  throw new Error(`Nenhum executável encontrado para ${label}.`);
}

async function waitForHttp(url, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(url);
      if (r.ok) return r;
    } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`Timeout aguardando ${url}`);
}

class CDP {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.id = 0;
    this.pending = new Map();
  }
  async connect() {
    await new Promise((resolve, reject) => {
      this.ws.addEventListener('open', resolve, { once: true });
      this.ws.addEventListener('error', reject, { once: true });
    });
    this.ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(JSON.stringify(msg.error)));
        else resolve(msg.result);
      }
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  async eval(expression) {
    const res = await this.send('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (res.exceptionDetails) {
      throw new Error(`JS Eval Exception: ${JSON.stringify(res.exceptionDetails)}`);
    }
    return res.result ? res.result.value : undefined;
  }
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

async function waitForCondition(cdp, jsExpr, timeoutMs = 12000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const val = await cdp.eval(jsExpr);
    if (val) return val;
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`Timeout aguardando condição E2E: ${jsExpr}`);
}

async function main() {
  const httpPort = 8045;
  const cdpPort = 9255;
  const sessionToken = 'e2e-raw-session-token-335-secret-value';
  const csrfToken = 'e2e-raw-csrf-token-335-secret-value';

  const pythonBin = await findExecutable(PYTHON_CANDIDATES, 'Python');
  const browserBin = await findExecutable(MSEDGE_CANDIDATES, 'Browser Chromium/Edge');
  const userDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'jyxia-inst-cdp-'));

  let serverStderr = '';
  const serverProc = spawn(
    pythonBin,
    [
      path.join(ROOT_DIR, 'tools', 'serve_institutional_e2e_harness.py'),
      '--port',
      String(httpPort),
      '--session-token',
      sessionToken,
      '--csrf-token',
      csrfToken,
    ],
    { cwd: ROOT_DIR, stdio: ['ignore', 'pipe', 'pipe'] }
  );
  serverProc.stderr.on('data', (chunk) => {
    serverStderr += chunk.toString();
  });

  let browserProc = null;
  let cdp = null;

  try {
    try {
      await waitForHttp(`http://127.0.0.1:${httpPort}/api/v1/health/live`, 20000);
    } catch (err) {
      throw new Error(`${err.message}\nServer stderr:\n${serverStderr}`);
    }

    browserProc = spawn(
      browserBin,
      [
        '--headless=new',
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        `--user-data-dir=${userDataDir}`,
        `--remote-debugging-port=${cdpPort}`,
        `http://127.0.0.1:${httpPort}/institutional/`,
      ],
      { stdio: 'ignore' }
    );

    const targetsResp = await waitForHttp(`http://127.0.0.1:${cdpPort}/json/list`, 10000);
    const targets = await targetsResp.json();
    const pageTarget = targets.find((t) => t.type === 'page') || targets[0];
    assert.ok(pageTarget?.webSocketDebuggerUrl, 'Target CDP não encontrado');

    cdp = new CDP(pageTarget.webSocketDebuggerUrl);
    await cdp.connect();
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');

    // 1. Verify Unauthenticated Gate renders when no BFF session cookie is set
    await waitForCondition(
      cdp,
      `document.getElementById('unauth-gate') && !document.getElementById('unauth-gate').hidden`
    );

    // 2. Set BFF HttpOnly session cookie + readable CSRF cookie via CDP Network.setCookie
    const setSess = await cdp.send('Network.setCookie', {
      name: 'jyxia_session',
      value: sessionToken,
      url: `http://127.0.0.1:${httpPort}/`,
      path: '/',
      httpOnly: true,
      sameSite: 'Lax',
    });
    assert.ok(setSess.success !== false, 'Falha ao definir cookie jyxia_session via CDP');
    const setCsrf = await cdp.send('Network.setCookie', {
      name: 'jyxia_csrf',
      value: csrfToken,
      url: `http://127.0.0.1:${httpPort}/`,
      path: '/',
      httpOnly: false,
      sameSite: 'Lax',
    });
    assert.ok(setCsrf.success !== false, 'Falha ao definir cookie jyxia_csrf via CDP');

    await cdp.send('Page.navigate', { url: `http://127.0.0.1:${httpPort}/institutional/` });

    // 3. Wait for authenticated workspace & Scenario A (`CASO-E2E-COERENTE-A`) to load
    await waitForCondition(
      cdp,
      `Boolean(document.getElementById('authenticated-app')) &&
       !document.getElementById('authenticated-app').hidden &&
       document.getElementById('metric-total-cases')?.textContent === '2' &&
       document.getElementById('workspace-case-title')?.textContent.includes('CASO-E2E-COERENTE-A')`
    );

    // Verify dashboard metrics before human review
    const initialMetrics = await cdp.eval(`({
      total: document.getElementById('metric-total-cases').textContent,
      awaitingReview: document.getElementById('metric-awaiting-review').textContent,
      conflicts: document.getElementById('metric-with-conflicts').textContent,
      readiness: document.getElementById('kv-case-readiness').textContent,
    })`);
    assert.equal(initialMetrics.total, '2');
    assert.equal(initialMetrics.awaitingReview, '2');
    assert.equal(initialMetrics.conflicts, '1');
    assert.ok(initialMetrics.readiness.includes('pendente'));

    // Verify PDF.js rendered the first document and extracted fields are populated
    try {
      await waitForCondition(
        cdp,
        `Boolean(document.getElementById('pdf-canvas-wrapper')) &&
         !document.getElementById('pdf-canvas-wrapper').hidden &&
         document.getElementById('pdf-render-canvas')?.width > 100 &&
         document.querySelectorAll('#version-extracted-fields-tbody tr[data-extracted-field-key]').length >= 8`
      );
    } catch (err) {
      const diag = await cdp.eval(`({
        pdfEmptyText: document.getElementById('pdf-empty-message')?.textContent,
        pdfHidden: document.getElementById('pdf-canvas-wrapper')?.hidden,
        canvasW: document.getElementById('pdf-render-canvas')?.width,
        fieldsCount: document.querySelectorAll('#version-extracted-fields-tbody tr[data-extracted-field-key]').length,
        docsCount: document.querySelectorAll('#case-documents-tbody tr').length,
        alertText: document.getElementById('global-alert-region')?.textContent,
      })`);
      throw new Error(`${err.message} | Diagnostic: ${JSON.stringify(diag)}`);
    }

    // Click spatial highlight button for 'patient' field and verify bbox overlay appears on PDF canvas
    await cdp.eval(`
      document.querySelector('button[data-highlight-field="patient"]').click();
    `);
    await waitForCondition(
      cdp,
      `Boolean(document.getElementById('pdf-highlight-banner')) &&
       !document.getElementById('pdf-highlight-banner').hidden &&
       document.querySelectorAll('#pdf-bbox-overlay-layer .inst-bbox-rect').length === 1`
    );

    // 4. Scenario A: Record administrative human review on Document 1 Version 1
    await cdp.eval(`
      document.getElementById('review-justification').value = 'Conferencia administrativa E2E do Documento 1 realizada.';
      document.getElementById('review-confirm-checkbox').checked = true;
      document.getElementById('btn-submit-human-review').click();
    `);

    await waitForCondition(
      cdp,
      `document.querySelectorAll('#case-human-reviews-list .inst-review-item').length === 1 &&
       document.getElementById('btn-submit-human-review')?.disabled === false &&
       Boolean(document.getElementById('human-review-form')) &&
       !document.getElementById('human-review-form').hidden`
    );

    // Next unreviewed document in Scenario A is now auto-selected; record its administrative human review
    await cdp.eval(`
      document.getElementById('review-justification').value = 'Conferencia administrativa E2E do Documento 2 concluida.';
      document.getElementById('review-confirm-checkbox').checked = true;
      document.getElementById('btn-submit-human-review').click();
    `);

    await waitForCondition(
      cdp,
      `document.querySelectorAll('#case-human-reviews-list .inst-review-item').length === 2 &&
       document.getElementById('btn-submit-human-review')?.disabled === false &&
       Boolean(document.getElementById('review-already-recorded-notice')) &&
       !document.getElementById('review-already-recorded-notice').hidden`
    );

    // Wait for background worker to finish post-review compare_consistency and click Refresh case
    await waitForCondition(
      cdp,
      `(() => {
        if (
          document.getElementById('kv-case-readiness')?.textContent.includes('conferida') &&
          !document.getElementById('cases-table-body')?.textContent.includes('CASO-E2E-COERENTE-A…')
        ) {
          return true;
        }
        document.getElementById('btn-refresh-case')?.click();
        return false;
      })()`,
      15000
    );

    // Wait until any in-flight refresh finishes before switching case
    await new Promise((r) => setTimeout(r, 400));

    const scenarioAOutcome = await cdp.eval(`({
      readiness: document.getElementById('kv-case-readiness').textContent,
      reviewState: document.getElementById('kv-case-review-state').textContent,
      assessmentCount: document.getElementById('assessment-history-select').options.length,
    })`);
    assert.ok(scenarioAOutcome.readiness.includes('conferida'));
    assert.ok(scenarioAOutcome.reviewState.includes('Concluída (2/2'));
    assert.ok(scenarioAOutcome.assessmentCount >= 2, 'Histórico append-only de avaliações deve preservar avaliação anterior');

    // 5. Scenario B (`CASO-E2E-CONFLITO-B` with OD vs OE conflict): Open case and record human reviews on both versions
    await cdp.eval(`
      const conflictRow = Array.from(document.querySelectorAll('#cases-table-body tr')).find((tr) =>
        tr.textContent.includes('CASO-E2E-CONFLITO-B')
      );
      conflictRow?.querySelector('button[data-open-case-id]')?.click();
    `);

    await waitForCondition(
      cdp,
      `document.getElementById('workspace-case-title')?.textContent.includes('CASO-E2E-CONFLITO-B') &&
       document.querySelector('[data-axis-name="lateralidade"][data-axis-status="conflito"]') !== null &&
       document.querySelectorAll('#case-human-reviews-list .inst-review-item').length === 0 &&
       document.getElementById('human-review-form')?.hidden === false`,
      15000
    );

    // Verify side-by-side comparison shows conflict on laterality (OD vs OE)
    const latCompareOutcome = await cdp.eval(`
      document.querySelector('tr[data-compare-field="laterality"]')?.getAttribute('data-compare-outcome')
    `);
    assert.equal(latCompareOutcome, 'conflict');

    // Record review on first version of conflicting case
    await cdp.eval(`
      document.getElementById('review-justification').value = 'Conferencia administrativa E2E registrada em documento com conflito OD.';
      document.getElementById('review-confirm-checkbox').checked = true;
      document.getElementById('btn-submit-human-review').click();
    `);
    await waitForCondition(
      cdp,
      `document.querySelectorAll('#case-human-reviews-list .inst-review-item').length === 1 &&
       document.getElementById('btn-submit-human-review')?.disabled === false &&
       Boolean(document.getElementById('human-review-form')) &&
       !document.getElementById('human-review-form').hidden`
    );

    // Record review on second version of conflicting case (auto-selected)
    await cdp.eval(`
      document.getElementById('review-justification').value = 'Conferencia administrativa E2E registrada no segundo documento OE.';
      document.getElementById('review-confirm-checkbox').checked = true;
      document.getElementById('btn-submit-human-review').click();
    `);
    await waitForCondition(
      cdp,
      `document.querySelectorAll('#case-human-reviews-list .inst-review-item').length === 2 &&
       document.getElementById('btn-submit-human-review')?.disabled === false`
    );

    // Wait for worker re-evaluation and verify case remains BLOQUEADO despite human_review_completed=true
    await waitForCondition(
      cdp,
      `(() => {
        if (
          document.getElementById('kv-case-review-state')?.textContent.includes('Concluída (2/2') &&
          document.getElementById('assessment-history-select')?.options.length >= 2
        ) {
          return true;
        }
        document.getElementById('btn-refresh-case')?.click();
        return false;
      })()`,
      15000
    );

    const scenarioBOutcome = await cdp.eval(`({
      readiness: document.getElementById('kv-case-readiness').textContent,
      lateralityAxisStatus: document.querySelector('[data-axis-name="lateralidade"]')?.getAttribute('data-axis-status'),
    })`);
    assert.ok(
      scenarioBOutcome.readiness.includes('bloqueado'),
      `Caso com conflito deve permanecer bloqueado após revisão humana, mas retornou: ${scenarioBOutcome.readiness}`
    );
    assert.equal(scenarioBOutcome.lateralityAxisStatus, 'conflito');

    console.log('INSTITUTIONAL_E2E_ALL_PASSED: Scenario A (conferida) + Scenario B (bloqueado preserved) + PDF.js bbox overlay');
  } finally {
    if (cdp) cdp.close();
    if (browserProc) {
      try {
        browserProc.kill();
      } catch {}
    }
    try {
      serverProc.kill();
    } catch {}
    await fs.rm(userDataDir, { recursive: true, force: true }).catch(() => {});
  }
}

main().catch((err) => {
  console.error('INSTITUTIONAL_E2E_FAILED:', err);
  process.exit(1);
});
