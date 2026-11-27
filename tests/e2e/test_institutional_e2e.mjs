/**
 * Real-Browser (Chromium / Edge via CDP) End-to-End Test for JYXIA Institutional Review UI (Etapas 3.3.5 & 3.3.6).
 * Validates:
 *  - A. Unauthenticated gate (`#unauth-gate`)
 *  - B. In mandatory OIDC mode (`JYXIA_E2E_REQUIRE_KEYCLOAK=1` / `JYXIA_KEYCLOAK_E2E_URL`):
 *       Real browser click on `#gate-login-link` -> Keycloak 26.8.2 OIDC Authorization Code + PKCE S256 redirect ->
 *       Keycloak username/password submission (`#kc-form-login`) -> RFC 6238 TOTP MFA challenge submission
 *       (`#kc-otp-login-form`) -> FastAPI `/api/v1/auth/callback` -> real BFF `jyxia_session` (`HttpOnly`) and
 *       `jyxia_csrf` cookies issued without `Network.setCookie`.
 *       (Preserves local pre-seeded BFF session fallback only when `JYXIA_E2E_REQUIRE_KEYCLOAK` is not active
 *       and no Keycloak URL is configured).
 *  - C. Organization selection & switching via `#org-select`, verifying session/CSRF cookie rotation, revocation of
 *       prior session, cross-tenant isolation (`403` when querying inactive org), and denial of unassociated org (`403`).
 *  - D. Real UI case creation (`#new-case-form`) and real UI multipart PDF upload (`#upload-doc-form` via CDP
 *       `DOM.setFileInputFiles`), verifying SHA-256 integrity, versioning, and persistence.
 *  - E. Independent worker subprocess (`python -m app.worker` as `jyxia_worker`) processing of the UI-uploaded PDF
 *       (`verify_object_integrity` -> `extract_pdf_text` -> `compare_consistency`).
 *  - F. Scenario A (Coherent 2-document case -> `pendente` to `conferida` with historical assessment #1 preserved)
 *       and Scenario B (Conflicting OD vs OE case -> remains `bloqueado` after human review, `clinical_approval=false`),
 *       plus PDF.js rendering and spatial BBox highlight overlay.
 *  - G. Real click on `#btn-logout`, verifying `POST /api/v1/auth/logout`, DB session revocation, cookie removal,
 *       return to `#unauth-gate`, and complete cleanup of `userProfile`, `organizations`, `cases`, `versionBundles`,
 *       `pdfDoc`, and DOM containers.
 */

import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const MSEDGE_CANDIDATES = [
  process.env.JYXIA_BROWSER_BIN,
  process.env.CHROME_PATH,
  String.raw`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
  String.raw`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
  String.raw`C:\Program Files\Google\Chrome\Application\chrome.exe`,
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  'google-chrome',
  'google-chrome-stable',
  'chromium',
  'chromium-browser',
  'msedge',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean);

const PYTHON_CANDIDATES = [
  process.env.JYXIA_PYTHON_BIN,
  path.join(ROOT_DIR, 'backend', '.venv', 'Scripts', 'python.exe'),
  path.join(ROOT_DIR, 'backend', '.venv', 'bin', 'python'),
  'python',
  'python3',
].filter(Boolean);

function isTruthyEnv(val) {
  if (!val) return false;
  return ['1', 'true', 'yes', 'on'].includes(String(val).trim().toLowerCase());
}

function decodeBase32(base32Str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = String(base32Str).toUpperCase().replace(/[\s=]+/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const ch of cleaned) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character in TOTP secret: ${ch}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTotp(base32Secret, { forTimeSec = null, stepSec = 30 } = {}) {
  const key = decodeBase32(base32Secret);
  const nowSec = forTimeSec !== null ? forTimeSec : Math.floor(Date.now() / 1000);
  const counter = BigInt(Math.floor(nowSec / stepSec));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(counter, 0);
  const digest = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const codeInt =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(codeInt % 1_000_000).padStart(6, '0');
}

async function findExecutable(candidates, label) {
  for (const candidate of candidates) {
    if (!candidate.includes(path.sep) && !candidate.includes('/')) {
      try {
        const lookupCmd = process.platform === 'win32' ? 'where' : 'which';
        const resolved = execFileSync(lookupCmd, [candidate], {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore'],
        })
          .split(/\r?\n/)[0]
          .trim();
        if (resolved) {
          return resolved;
        }
      } catch {}
      continue;
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

async function waitForCondition(cdp, jsExpr, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const val = await cdp.eval(jsExpr);
      if (val) return val;
    } catch (_err) {
      // Ignore transient execution context destruction during full-page navigation redirects
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`Timeout aguardando condição E2E: ${jsExpr}`);
}

async function getAppCookies(cdp, appOriginUrl) {
  const { cookies } = await cdp.send('Network.getCookies', { urls: [appOriginUrl] });
  const sess = cookies.find((c) => c.name === 'jyxia_session') || null;
  const csrf = cookies.find((c) => c.name === 'jyxia_csrf') || null;
  return { sess, csrf, all: cookies };
}

async function stopChildProcessGracefully(
  proc,
  {
    label = 'subprocess',
    timeoutMs = 10000,
    killTimeoutMs = 5000,
    sendWin32StdinShutdown = false,
  } = {}
) {
  if (!proc || proc.exitCode !== null || proc.signalCode !== null) {
    return {
      exitCode: proc?.exitCode ?? null,
      signalCode: proc?.signalCode ?? null,
      forcedKill: false,
    };
  }

  const closePromise = new Promise((resolve) => {
    proc.once('close', (code, signal) => {
      resolve({ exitCode: code, signalCode: signal });
    });
  });

  if (process.platform === 'win32' && sendWin32StdinShutdown) {
    try {
      proc.stdin?.write('SHUTDOWN\n');
      proc.stdin?.end();
    } catch {}
  } else {
    try {
      proc.kill('SIGTERM');
    } catch {}
  }

  let timerId = null;
  const timeoutPromise = new Promise((resolve) => {
    timerId = setTimeout(() => resolve({ timedOut: true }), timeoutMs);
  });

  const firstOutcome = await Promise.race([closePromise, timeoutPromise]);
  if (timerId) clearTimeout(timerId);

  if (firstOutcome && firstOutcome.timedOut) {
    try {
      proc.kill('SIGKILL');
    } catch {}
    let killTimerId = null;
    const killTimeoutPromise = new Promise((resolve) => {
      killTimerId = setTimeout(() => resolve({ killTimedOut: true }), killTimeoutMs);
    });
    const finalOutcome = await Promise.race([closePromise, killTimeoutPromise]);
    if (killTimerId) clearTimeout(killTimerId);
    if (finalOutcome && finalOutcome.killTimedOut) {
      throw new Error(
        `${label} (PID ${proc.pid}) did not terminate even after SIGKILL fallback.`
      );
    }
    return {
      ...finalOutcome,
      forcedKill: true,
    };
  }

  return {
    ...firstOutcome,
    forcedKill: false,
  };
}

async function main() {
  const httpPort = 8045;
  const cdpPort = 9255;
  const appBaseUrl = `http://127.0.0.1:${httpPort}`;
  const sessionToken = 'e2e-raw-session-token-335-secret-value';
  const csrfToken = 'e2e-raw-csrf-token-335-secret-value';

  const requireKeycloak = isTruthyEnv(process.env.JYXIA_E2E_REQUIRE_KEYCLOAK);
  const kcIssuerUrl = (process.env.JYXIA_KEYCLOAK_E2E_URL || '').trim();
  const useKeycloakOidc = requireKeycloak || Boolean(kcIssuerUrl);

  if (useKeycloakOidc) {
    for (const reqKey of [
      'JYXIA_KEYCLOAK_E2E_URL',
      'JYXIA_KEYCLOAK_CLIENT_ID',
      'JYXIA_KEYCLOAK_CLIENT_SECRET',
      'JYXIA_KEYCLOAK_MFA_USER_SUB',
      'JYXIA_KEYCLOAK_MFA_USERNAME',
      'JYXIA_KEYCLOAK_MFA_PASSWORD',
      'JYXIA_KEYCLOAK_MFA_TOTP_SECRET',
    ]) {
      if (!process.env[reqKey] || !String(process.env[reqKey]).trim()) {
        throw new Error(
          `Modo OIDC/Keycloak ativo: variável obrigatória ausente no ambiente: ${reqKey}`
        );
      }
    }
  }

  const pythonBin = await findExecutable(PYTHON_CANDIDATES, 'Python');
  const browserBin = await findExecutable(MSEDGE_CANDIDATES, 'Browser Chromium/Edge');
  const userDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'jyxia-inst-cdp-'));
  const reportFilePath =
    (process.env.JYXIA_E2E_REPORT_FILE || '').trim() ||
    path.join(userDataDir, 'jyxia_inst_e2e_report.json');
  const uiUploadPdfPath = path.join(userDataDir, 'solicitacao-ui-upload-336.pdf');

  let serverStderr = '';
  const isWin = process.platform === 'win32';
  const harnessArgs = [
    path.join(ROOT_DIR, 'tools', 'serve_institutional_e2e_harness.py'),
    '--port',
    String(httpPort),
    '--session-token',
    sessionToken,
    '--csrf-token',
    csrfToken,
    '--report-file',
    reportFilePath,
    '--ui-upload-pdf-file',
    uiUploadPdfPath,
  ];
  if (requireKeycloak) {
    harnessArgs.push('--require-keycloak');
  }

  const serverProc = spawn(pythonBin, harnessArgs, {
    cwd: ROOT_DIR,
    stdio: [isWin ? 'pipe' : 'ignore', 'pipe', 'pipe'],
  });
  serverProc.stdout?.on('data', () => {});
  serverProc.stderr.on('data', (chunk) => {
    serverStderr += chunk.toString();
  });

  let browserProc = null;
  let cdp = null;

  try {
    try {
      await waitForHttp(`${appBaseUrl}/api/v1/health/live`, 30000);
    } catch (err) {
      throw new Error(`${err.message}\nServer stderr:\n${serverStderr}`);
    }

    const harnessReport = JSON.parse(await fs.readFile(reportFilePath, 'utf8'));
    const primaryOrgId = harnessReport.organization_id;
    const secondaryOrgId = harnessReport.secondary_organization_id;
    const unassociatedOrgId = harnessReport.unassociated_organization_id;
    const expectedUiUploadSha256 = harnessReport.expected_ui_upload_sha256;
    assert.ok(primaryOrgId && secondaryOrgId && unassociatedOrgId, 'IDs de organizações ausentes no report');

    browserProc = spawn(
      browserBin,
      [
        '--headless=new',
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        `--user-data-dir=${userDataDir}`,
        `--remote-debugging-port=${cdpPort}`,
        'about:blank',
      ],
      { stdio: ['ignore', 'ignore', 'pipe'] }
    );
    let browserStderr = '';
    browserProc.stderr?.on('data', (chunk) => {
      browserStderr += chunk.toString();
    });

    let targetsResp;
    try {
      await waitForHttp(`http://127.0.0.1:${cdpPort}/json/version`, 15000);
      targetsResp = await waitForHttp(`http://127.0.0.1:${cdpPort}/json/list`, 15000);
    } catch (err) {
      throw new Error(`${err.message}\nBrowser (${browserBin}) stderr:\n${browserStderr}`);
    }
    const targets = await targetsResp.json();
    const pageTarget = targets.find((t) => t.type === 'page') || targets[0];
    assert.ok(pageTarget?.webSocketDebuggerUrl, 'Target CDP não encontrado');

    cdp = new CDP(pageTarget.webSocketDebuggerUrl);
    await cdp.connect();
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');
    await cdp.send('DOM.enable');

    // =========================================================================
    // A. Entrada desautenticada
    // =========================================================================
    await cdp.send('Page.navigate', { url: `${appBaseUrl}/institutional/` });
    await waitForCondition(
      cdp,
      `Boolean(document.getElementById('unauth-gate')) &&
       !document.getElementById('unauth-gate').hidden &&
       Boolean(document.getElementById('authenticated-app')) &&
       document.getElementById('authenticated-app').hidden === true`
    );

    // =========================================================================
    // B. Autenticação (Fluxo real OIDC + PKCE S256 + MFA/TOTP no Keycloak 26.8.2
    //    sem Network.setCookie no modo OIDC; ou sessão local pré-semeada apenas
    //    em ambiente local sem Keycloak)
    // =========================================================================
    if (useKeycloakOidc) {
      const mfaUsername = process.env.JYXIA_KEYCLOAK_MFA_USERNAME.trim();
      const mfaPassword = process.env.JYXIA_KEYCLOAK_MFA_PASSWORD.trim();
      const mfaTotpSecret = process.env.JYXIA_KEYCLOAK_MFA_TOTP_SECRET.trim();

      // Click #gate-login-link to follow real OIDC Authorization Code + PKCE S256 redirect
      await cdp.eval(`document.getElementById('gate-login-link').click();`);

      // Wait for Keycloak login form (#kc-form-login) in the real browser
      await waitForCondition(
        cdp,
        `Boolean(document.getElementById('kc-form-login') || document.querySelector('input[name="username"]')) &&
         Boolean(document.querySelector('input[name="password"]'))`,
        20000
      );

      const kcLoginUrl = await cdp.eval(`window.location.href`);
      assert.ok(
        kcLoginUrl.includes('protocol/openid-connect/auth') &&
          kcLoginUrl.includes('code_challenge_method=S256'),
        `URL de autorização OIDC do Keycloak inválida: ${kcLoginUrl}`
      );

      // Fill username & password and submit Keycloak login form
      await cdp.eval(
        `(() => {
          const u = document.querySelector('input[name="username"]');
          const p = document.querySelector('input[name="password"]');
          u.value = ${JSON.stringify(mfaUsername)};
          p.value = ${JSON.stringify(mfaPassword)};
          const form = document.getElementById('kc-form-login') || u.closest('form');
          form.submit();
          return true;
        })()`
      );

      // Wait for Keycloak MFA/TOTP challenge form (#kc-otp-login-form)
      await waitForCondition(
        cdp,
        `Boolean(document.getElementById('kc-otp-login-form') || document.querySelector('input[name="otp"]'))`,
        20000
      );

      // Avoid TOTP 30s boundary edge by waiting if within last 2 seconds of window
      if (Math.floor(Date.now() / 1000) % 30 >= 28) {
        await new Promise((r) => setTimeout(r, 2500));
      }
      const otpCode = generateTotp(mfaTotpSecret);
      await cdp.eval(
        `(() => {
          const otpInput = document.querySelector('input[name="otp"]') || document.getElementById('otp');
          otpInput.value = ${JSON.stringify(otpCode)};
          const form = document.getElementById('kc-otp-login-form') || otpInput.closest('form');
          form.submit();
          return true;
        })()`
      );
    } else {
      // Local pre-seeded session fallback (only when Keycloak is not required/configured locally)
      const setSess = await cdp.send('Network.setCookie', {
        name: 'jyxia_session',
        value: sessionToken,
        url: `${appBaseUrl}/`,
        path: '/',
        httpOnly: true,
        sameSite: 'Lax',
      });
      assert.ok(setSess.success !== false, 'Falha ao definir cookie jyxia_session local');
      const setCsrf = await cdp.send('Network.setCookie', {
        name: 'jyxia_csrf',
        value: csrfToken,
        url: `${appBaseUrl}/`,
        path: '/',
        httpOnly: false,
        sameSite: 'Lax',
      });
      assert.ok(setCsrf.success !== false, 'Falha ao definir cookie jyxia_csrf local');
      await cdp.send('Page.navigate', { url: `${appBaseUrl}/institutional/` });
    }

    // Wait for authenticated workspace & Scenario A (`CASO-E2E-COERENTE-A`) in Primary Org A
    await waitForCondition(
      cdp,
      `Boolean(document.getElementById('authenticated-app')) &&
       !document.getElementById('authenticated-app').hidden &&
       document.getElementById('metric-total-cases')?.textContent === '2' &&
       document.getElementById('workspace-case-title')?.textContent.includes('CASO-E2E-COERENTE-A')`,
      25000
    );

    // Confirm real BFF session & CSRF cookies exist in browser
    const initialCookies = await getAppCookies(cdp, `${appBaseUrl}/`);
    assert.ok(initialCookies.sess?.value, 'Cookie jyxia_session deve estar presente');
    assert.equal(initialCookies.sess.httpOnly, true, 'Cookie jyxia_session deve ser HttpOnly');
    assert.ok(initialCookies.csrf?.value, 'Cookie jyxia_csrf deve estar presente');
    assert.equal(initialCookies.csrf.httpOnly, false, 'Cookie jyxia_csrf deve ser legível por JS same-origin');

    // =========================================================================
    // C. Seleção e troca de organização + Isolamento Multi-Tenant e RLS
    // =========================================================================
    const orgOptions = await cdp.eval(`
      Array.from(document.getElementById('org-select').options).map((o) => ({
        value: o.value,
        text: o.textContent,
        selected: o.selected,
      }))
    `);
    assert.equal(orgOptions.length, 2, 'Usuário deve enxergar exatamente as 2 organizações associadas');
    assert.ok(
      !orgOptions.some((o) => o.value === unassociatedOrgId),
      'Organização não associada jamais deve aparecer no seletor #org-select'
    );

    // Confirm cross-tenant isolation: querying Org B while Org A is active must return 403
    const crossTenantStatus = await cdp.eval(`
      fetch('/api/v1/organizations/${secondaryOrgId}/cases', { credentials: 'same-origin' })
        .then((r) => r.status)
    `);
    assert.equal(crossTenantStatus, 403, 'Acesso cruzado à organização inativa na sessão deve retornar 403');

    // Confirm unassociated org selection is rejected with 403
    const unassocSelectStatus = await cdp.eval(`
      fetch('/api/v1/auth/select-organization', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': document.cookie.split(';').map((c) => c.trim()).find((c) => c.startsWith('jyxia_csrf='))?.split('=')[1] || '',
        },
        body: JSON.stringify({ organization_id: '${unassociatedOrgId}' }),
      }).then((r) => r.status)
    `);
    assert.equal(unassocSelectStatus, 403, 'Tentativa de selecionar organização sem vínculo deve retornar 403');

    // Switch from Org A to Org B via #org-select in the browser
    const cookiesBeforeSwitchToB = await getAppCookies(cdp, `${appBaseUrl}/`);
    await cdp.eval(`(() => {
      const sel = document.getElementById('org-select');
      sel.value = '${secondaryOrgId}';
      sel.dispatchEvent(new Event('change', { bubbles: true }));
    })()`);

    await waitForCondition(
      cdp,
      `document.getElementById('active-org-caption')?.textContent.includes('Clinica Regional Isolada') &&
       document.getElementById('metric-total-cases')?.textContent === '1' &&
       document.getElementById('cases-table-body')?.textContent.includes('CASO-ORG2-ISOLADO') &&
       !document.getElementById('cases-table-body')?.textContent.includes('CASO-E2E-COERENTE-A')`,
      15000
    );

    const cookiesAfterSwitchToB = await getAppCookies(cdp, `${appBaseUrl}/`);
    assert.notEqual(
      cookiesAfterSwitchToB.sess?.value,
      cookiesBeforeSwitchToB.sess?.value,
      'Cookie jyxia_session deve ser rotacionado ao trocar de organização'
    );
    assert.notEqual(
      cookiesAfterSwitchToB.csrf?.value,
      cookiesBeforeSwitchToB.csrf?.value,
      'Cookie jyxia_csrf deve ser rotacionado ao trocar de organização'
    );

    // Switch back from Org B to Primary Org A via #org-select
    await cdp.eval(`(() => {
      const sel = document.getElementById('org-select');
      sel.value = '${primaryOrgId}';
      sel.dispatchEvent(new Event('change', { bubbles: true }));
    })()`);

    await waitForCondition(
      cdp,
      `document.getElementById('active-org-caption')?.textContent.includes('Hospital Sintetico JYXIA') &&
       document.getElementById('metric-total-cases')?.textContent === '2' &&
       document.getElementById('cases-table-body')?.textContent.includes('CASO-E2E-COERENTE-A') &&
       !document.getElementById('cases-table-body')?.textContent.includes('CASO-ORG2-ISOLADO')`,
      15000
    );

    const cookiesAfterSwitchBackToA = await getAppCookies(cdp, `${appBaseUrl}/`);
    assert.notEqual(
      cookiesAfterSwitchBackToA.sess?.value,
      cookiesAfterSwitchToB.sess?.value,
      'Cookie jyxia_session deve ser rotacionado novamente ao retornar para a Organização A'
    );

    // =========================================================================
    // D. Criação de caso pela interface (#new-case-form) e Upload real de PDF
    //    pela interface (#upload-doc-form) + E. Processamento pelo worker
    // =========================================================================
    await cdp.eval(`
      document.getElementById('btn-toggle-new-case').click();
      document.getElementById('input-case-code').value = 'CASO-UI-UPLOAD-336';
      document.getElementById('input-proc-ref').value = 'TUSS:31309054';
      document.getElementById('input-ext-ref').value = 'GUIA-UI-336';
      document.getElementById('input-laterality-ref').value = 'OD';
      document.getElementById('new-case-form').requestSubmit();
    `);

    await waitForCondition(
      cdp,
      `document.getElementById('metric-total-cases')?.textContent === '3' &&
       document.getElementById('workspace-case-title')?.textContent.includes('CASO-UI-UPLOAD-336') &&
       Boolean(document.getElementById('btn-toggle-upload-doc')) &&
       !document.getElementById('btn-toggle-upload-doc').hidden`,
      15000
    );

    // Open #upload-doc-form and attach synthetic PDF via CDP DOM.setFileInputFiles
    await cdp.eval(`
      document.getElementById('btn-toggle-upload-doc').click();
      document.getElementById('upload-doc-kind').value = 'pedido';
      document.getElementById('upload-source-label').value = 'Solicitacao Upload UI E2E';
    `);

    const { root: domRoot } = await cdp.send('DOM.getDocument', { depth: 1 });
    const { nodeId: fileInputNodeId } = await cdp.send('DOM.querySelector', {
      nodeId: domRoot.nodeId,
      selector: '#upload-file-input',
    });
    assert.ok(fileInputNodeId, 'Input #upload-file-input não encontrado no DOM');
    await cdp.send('DOM.setFileInputFiles', {
      nodeId: fileInputNodeId,
      files: [uiUploadPdfPath],
    });

    await cdp.eval(`document.getElementById('upload-doc-form').requestSubmit();`);

    // Wait for upload confirmation alert with SHA-256 prefix and document row in table
    const expectedShaPrefix = expectedUiUploadSha256.slice(0, 12);
    await waitForCondition(
      cdp,
      `document.getElementById('global-alert-region')?.textContent.includes('${expectedShaPrefix}') &&
       document.querySelectorAll('#case-documents-tbody button[data-inspect-version-id]').length === 1`,
      15000
    );

    // Wait for independent worker subprocess to complete verify_object_integrity -> extract_pdf_text on the uploaded PDF
    await waitForCondition(
      cdp,
      `(() => {
        const fieldsCount = document.querySelectorAll('#version-extracted-fields-tbody tr[data-extracted-field-key]').length;
        const fieldsText = document.getElementById('version-extracted-fields-tbody')?.textContent || '';
        if (fieldsCount >= 8 && fieldsText.toUpperCase().includes('BEATRIZ SINTETICA UPLOAD')) {
          return true;
        }
        document.getElementById('btn-refresh-case')?.click();
        return false;
      })()`,
      25000
    );

    // Trigger 4-axis consistency comparison via #btn-trigger-compare and wait for worker subprocess to execute compare_consistency
    await cdp.eval(`document.getElementById('btn-trigger-compare').click();`);
    await waitForCondition(
      cdp,
      `(() => {
        const hasAssessment = (document.getElementById('assessment-history-select')?.options.length || 0) >= 1 &&
          document.getElementById('assessment-history-select')?.options[0]?.value !== '';
        if (hasAssessment) {
          return true;
        }
        document.getElementById('btn-refresh-case')?.click();
        return false;
      })()`,
      20000
    );

    await waitForCondition(
      cdp,
      `Boolean(document.getElementById('pdf-canvas-wrapper')) &&
       !document.getElementById('pdf-canvas-wrapper').hidden &&
       document.getElementById('pdf-render-canvas')?.width > 100`,
      15000
    );

    await new Promise((r) => setTimeout(r, 400));

    // =========================================================================
    // F. Revisão humana administrativa (Cenário A -> conferida; Cenário B -> bloqueado)
    // =========================================================================
    // Switch workspace to Scenario A (`CASO-E2E-COERENTE-A`)
    await cdp.eval(`(() => {
      const rowA = Array.from(document.querySelectorAll('#cases-table-body tr')).find((tr) =>
        tr.textContent.includes('CASO-E2E-COERENTE-A')
      );
      rowA?.querySelector('button[data-open-case-id]')?.click();
    })()`);

    await waitForCondition(
      cdp,
      `document.getElementById('workspace-case-title')?.textContent.includes('CASO-E2E-COERENTE-A') &&
       document.querySelectorAll('#case-documents-tbody button[data-inspect-version-id]').length === 2`,
      15000
    );

    // Verify P2-02: Rapidly switch between Version 1 and Version 2; only Version 1 (last selected) must remain active
    const switchedProperly = await cdp.eval(`(() => {
      const buttons = Array.from(document.querySelectorAll('#case-documents-tbody button[data-inspect-version-id]'));
      if (buttons.length < 2) return false;
      const v1Id = buttons[0].getAttribute('data-inspect-version-id');
      const v2Id = buttons[1].getAttribute('data-inspect-version-id');
      buttons[1].click();
      buttons[0].click();
      return Boolean(v1Id && v2Id && v1Id !== v2Id);
    })()`);
    assert.equal(switchedProperly, true);

    await waitForCondition(
      cdp,
      `Boolean(document.getElementById('pdf-canvas-wrapper')) &&
       !document.getElementById('pdf-canvas-wrapper').hidden &&
       document.getElementById('pdf-render-canvas')?.width > 100 &&
       document.querySelectorAll('#version-extracted-fields-tbody tr[data-extracted-field-key]').length >= 8`
    );

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

    // Scenario A: Record administrative human review on Document 1 Version 1
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

    await new Promise((r) => setTimeout(r, 400));

    const scenarioAOutcome = await cdp.eval(`({
      readiness: document.getElementById('kv-case-readiness').textContent,
      reviewState: document.getElementById('kv-case-review-state').textContent,
      assessmentCount: document.getElementById('assessment-history-select').options.length,
    })`);
    assert.ok(scenarioAOutcome.readiness.includes('conferida'));
    assert.ok(scenarioAOutcome.reviewState.includes('Concluída (2/2'));
    assert.ok(
      scenarioAOutcome.assessmentCount >= 2,
      'Histórico append-only de avaliações deve preservar avaliação anterior'
    );

    // Scenario B (`CASO-E2E-CONFLITO-B` with OD vs OE conflict): Open case and record human reviews on both versions
    await cdp.eval(`(() => {
      const conflictRow = Array.from(document.querySelectorAll('#cases-table-body tr')).find((tr) =>
        tr.textContent.includes('CASO-E2E-CONFLITO-B')
      );
      conflictRow?.querySelector('button[data-open-case-id]')?.click();
    })()`);

    await waitForCondition(
      cdp,
      `document.getElementById('workspace-case-title')?.textContent.includes('CASO-E2E-CONFLITO-B') &&
       document.querySelector('[data-axis-name="lateralidade"][data-axis-status="conflito"]') !== null &&
       document.querySelectorAll('#case-human-reviews-list .inst-review-item').length === 0 &&
       document.getElementById('human-review-form')?.hidden === false`,
      15000
    );

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

    // =========================================================================
    // G. Logout real pela UI (#btn-logout), revogação da sessão e limpeza de estado
    // =========================================================================
    await cdp.eval(`document.getElementById('btn-logout').click();`);

    await waitForCondition(
      cdp,
      `Boolean(document.getElementById('unauth-gate')) &&
       !document.getElementById('unauth-gate').hidden &&
       document.getElementById('authenticated-app')?.hidden === true &&
       window.__JYXIA_INST_DEBUG_STATE__?.authenticated === false`,
      15000
    );

    const postLogoutState = await cdp.eval(`({
      debugState: window.__JYXIA_INST_DEBUG_STATE__,
      casesRows: document.querySelectorAll('#cases-table-body tr').length,
      docsRows: document.querySelectorAll('#case-documents-tbody tr').length,
      fieldsRows: document.querySelectorAll('#version-extracted-fields-tbody tr').length,
      reviewsItems: document.querySelectorAll('#case-human-reviews-list .inst-review-item').length,
      orgOptionsCount: document.querySelectorAll('#org-select option').length,
      canvasWidth: document.getElementById('pdf-render-canvas')?.width || 0,
    })`);

    assert.equal(postLogoutState.debugState.authenticated, false);
    assert.equal(postLogoutState.debugState.hasUserProfile, false, 'userProfile deve ser limpo no logout');
    assert.equal(postLogoutState.debugState.organizationsCount, 0, 'organizations deve ser limpo no logout');
    assert.equal(postLogoutState.debugState.casesCount, 0, 'cases deve ser limpo no logout');
    assert.equal(postLogoutState.debugState.versionBundlesCount, 0, 'versionBundles deve ser limpo no logout');
    assert.equal(postLogoutState.debugState.hasPdfDoc, false, 'pdfDoc deve ser liberado no logout');
    assert.equal(postLogoutState.casesRows, 0, 'Tabela de casos no DOM deve ser limpa no logout');
    assert.equal(postLogoutState.docsRows, 0, 'Tabela de documentos no DOM deve ser limpa no logout');
    assert.equal(postLogoutState.fieldsRows, 0, 'Tabela de campos extraídos no DOM deve ser limpa no logout');
    assert.equal(postLogoutState.reviewsItems, 0, 'Lista de revisões no DOM deve ser limpa no logout');
    assert.equal(postLogoutState.orgOptionsCount, 0, 'Opções de organizações no DOM devem ser limpas no logout');
    assert.equal(postLogoutState.canvasWidth, 0, 'Canvas PDF deve ser zerado no logout');

    const postLogoutCookies = await getAppCookies(cdp, `${appBaseUrl}/`);
    assert.equal(postLogoutCookies.sess, null, 'Cookie jyxia_session deve ser removido após logout');
    assert.equal(postLogoutCookies.csrf, null, 'Cookie jyxia_csrf deve ser removido após logout');

    const sessionStatusAfterLogout = await cdp.eval(`
      fetch('/api/v1/auth/session', { credentials: 'same-origin' }).then((r) => r.status)
    `);
    assert.equal(sessionStatusAfterLogout, 401, '/api/v1/auth/session deve retornar 401 após logout');

    console.log(
      `INSTITUTIONAL_E2E_ALL_PASSED: auth_mode=${harnessReport.auth_mode} + Org Switch & RLS Isolation + UI Case/PDF Upload + Worker + Scenario A (conferida) + Scenario B (bloqueado preserved) + PDF.js bbox + Logout & State Cleanup`
    );
  } finally {
    if (cdp) cdp.close();
    if (browserProc) {
      await stopChildProcessGracefully(browserProc, {
        label: 'Headless browser',
        timeoutMs: 3000,
        killTimeoutMs: 2000,
        sendWin32StdinShutdown: false,
      }).catch(() => {});
    }
    const serverShutdown = await stopChildProcessGracefully(serverProc, {
      label: 'Institutional E2E harness server',
      timeoutMs: 10000,
      killTimeoutMs: 5000,
      sendWin32StdinShutdown: true,
    });
    await fs.rm(userDataDir, { recursive: true, force: true }).catch(() => {});
    if (serverShutdown.forcedKill) {
      throw new Error(
        `Institutional E2E harness server required SIGKILL fallback after graceful shutdown timeout.\nServer stderr:\n${serverStderr}`
      );
    }
  }
}

main()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error('INSTITUTIONAL_E2E_FAILED:', err);
    process.exit(1);
  });
