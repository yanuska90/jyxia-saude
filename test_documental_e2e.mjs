import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = path.dirname(fileURLToPath(import.meta.url));
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

function parseArgs(argv) {
  const opts = { staticDir: '', subpath: '', httpPort: 8019, cdpPort: 9229 };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--static-dir' && argv[i + 1]) opts.staticDir = path.resolve(argv[++i]);
    else if (argv[i] === '--subpath' && argv[i + 1]) opts.subpath = argv[++i].replace(/^\/+|\/+$/g, '');
    else if (argv[i] === '--http-port' && argv[i + 1]) opts.httpPort = Number(argv[++i]);
    else if (argv[i] === '--cdp-port' && argv[i + 1]) opts.cdpPort = Number(argv[++i]);
  }
  return opts;
}

async function findBrowser() {
  for (const candidate of MSEDGE_CANDIDATES) {
    try {
      await fs.access(candidate);
      return candidate;
    } catch {}
  }
  throw new Error('Nenhum navegador Chromium/Edge encontrado. Defina JYXIA_BROWSER_BIN.');
}

async function waitForHttp(url, timeoutMs = 10000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(url);
      if (r.ok) return r;
    } catch {}
    await new Promise(r => setTimeout(r, 150));
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
    this.ws.addEventListener('message', ev => {
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
      throw new Error('Excecao na pagina: ' + JSON.stringify(res.exceptionDetails));
    }
    return res.result?.value;
  }
  close() {
    try { this.ws.close(); } catch {}
  }
}

async function waitUntil(fn, timeoutMs = 10000, step = 100) {
  const start = Date.now();
  let last;
  while (Date.now() - start < timeoutMs) {
    last = await fn();
    if (last) return last;
    await new Promise(r => setTimeout(r, step));
  }
  throw new Error('Timeout em waitUntil; ultimo valor: ' + JSON.stringify(last));
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const browserBin = await findBrowser();
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'jyxia-e2e-'));
  const userDataDir = path.join(tempRoot, 'profile');
  await fs.mkdir(userDataDir, { recursive: true });

  const invalidPdfPath = path.join(tempRoot, 'fora-do-catalogo.pdf');
  await fs.writeFile(invalidPdfPath, '%PDF-1.4\n% Arquivo fora do catalogo sintetico\n%%EOF\n', 'utf8');

  const staticMode = Boolean(opts.staticDir);
  const basePrefix = opts.subpath ? `/${opts.subpath}` : '';
  const baseUrl = `http://127.0.0.1:${opts.httpPort}${basePrefix}`;

  let serveRoot = opts.staticDir || ROOT_DIR;
  let server;
  if (staticMode) {
    if (opts.subpath) {
      const wrapDir = path.join(tempRoot, 'www');
      await fs.mkdir(path.join(wrapDir, path.dirname(opts.subpath)), { recursive: true });
      await fs.cp(opts.staticDir, path.join(wrapDir, opts.subpath), { recursive: true });
      serveRoot = wrapDir;
    }
    server = spawn('python', ['-m', 'http.server', String(opts.httpPort), '--bind', '127.0.0.1'], {
      cwd: serveRoot,
      stdio: 'ignore',
    });
  } else {
    server = spawn('python', ['serve_documental.py', '--bind', '127.0.0.1', '--port', String(opts.httpPort)], {
      cwd: ROOT_DIR,
      stdio: 'ignore',
    });
  }

  let browser;
  let cdp;

  try {
    await waitForHttp(`${baseUrl}/index.html`);

    const favRes = await fetch(`${baseUrl}/favicon.svg`);
    assert.equal(favRes.status, 200, 'favicon.svg deve responder HTTP 200');
    assert.match(favRes.headers.get('content-type') || '', /image\/svg\+xml/);

    const demoRes = await fetch(`${baseUrl}/demo.html`);
    assert.equal(demoRes.status, 200);
    if (!staticMode) {
      assert.equal(demoRes.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(demoRes.headers.get('referrer-policy'), 'no-referrer');
      assert.equal(demoRes.headers.get('cache-control'), 'no-store');
      assert.match(demoRes.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
    }

    for (const blocked of [
      '/app.py',
      '/demo-v2.html',
      '/serve_documental.py',
      '/test_documental.mjs',
      '/test_documental_pdfjs.mjs',
      '/test_documental_e2e.mjs',
      '/integration.py',
      '/README.md',
      '/fixtures/../app.py',
    ]) {
      const r = await fetch(`${baseUrl}${blocked}`);
      assert.equal(r.status, 404, `Esperado HTTP 404 para ${blocked}, obtido ${r.status}`);
    }
    console.log('E2E_1_HTTP_ISOLATION_AND_FAVICON_OK', staticMode ? '(static-pages)' : '(serve_documental)');

    browser = spawn(browserBin, [
      '--headless=new',
      '--disable-gpu',
      '--no-first-run',
      '--no-default-browser-check',
      `--remote-debugging-port=${opts.cdpPort}`,
      `--user-data-dir=${userDataDir}`,
      'about:blank',
    ], { stdio: 'ignore' });

    await waitForHttp(`http://127.0.0.1:${opts.cdpPort}/json/version`);
    const targets = await (await fetch(`http://127.0.0.1:${opts.cdpPort}/json/list`)).json();
    const pageTarget = targets.find(t => t.type === 'page') || targets[0];
    cdp = new CDP(pageTarget.webSocketDebuggerUrl);
    await cdp.connect();

    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('DOM.enable');
    await cdp.send('Network.enable');
    await cdp.send('Log.enable');
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 1280, height: 900, deviceScaleFactor: 1, mobile: false,
    });

    const runtimeConsoleErrors = [];
    const pageExceptions = [];
    const failedRequests = [];
    const badResponses = [];
    const browserLogEntries = [];

    cdp.ws.addEventListener('message', ev => {
      const m = JSON.parse(ev.data);
      if (m.method === 'Runtime.consoleAPICalled' && m.params?.type === 'error') {
        runtimeConsoleErrors.push(m.params);
      } else if (m.method === 'Runtime.exceptionThrown') {
        pageExceptions.push(m.params);
      } else if (m.method === 'Network.loadingFailed') {
        failedRequests.push(m.params);
      } else if (m.method === 'Network.responseReceived' && m.params?.response?.status >= 400) {
        badResponses.push({ url: m.params.response.url, status: m.params.response.status });
      } else if (m.method === 'Log.entryAdded' && m.params?.entry?.level === 'error') {
        browserLogEntries.push(m.params.entry);
      }
    });

    const waitIdle = () => waitUntil(() => cdp.eval(`!document.body.hasAttribute('aria-busy')`));

    // 2. index.html
    await cdp.send('Page.navigate', { url: `${baseUrl}/index.html` });
    await waitUntil(() => cdp.eval(`document.readyState === 'complete' && document.body.innerText.includes('JYXIA')`));
    const indexFavHref = await cdp.eval(`document.querySelector('link[rel="icon"]')?.getAttribute('href')`);
    assert.equal(indexFavHref, 'favicon.svg');
    console.log('E2E_2_INDEX_OK');

    // 3. demo.html
    await cdp.send('Page.navigate', { url: `${baseUrl}/demo.html` });
    await waitUntil(() => cdp.eval(`
      document.readyState === 'complete' &&
      !document.body.hasAttribute('aria-busy') &&
      document.getElementById('scenario')?.options?.length === 8 &&
      document.getElementById('case-meta')?.textContent?.includes('12/04/1986')
    `));
    assert.equal(await cdp.eval(`document.querySelector('link[rel="icon"]')?.getAttribute('href')`), 'favicon.svg');
    // Verify keyboard Tab navigation moves focus to an interactive control cleanly
    await cdp.eval(`document.getElementById('scenario').focus()`);
    await cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
    await cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
    assert.equal(await cdp.eval(`document.activeElement?.id`), 'load');
    console.log('E2E_3_DEMO_INIT_OK');

    // 4. Manual upload via #files: PDF + PNG + altered file rejection
    const fixturesBase = opts.staticDir || ROOT_DIR;
    const uploadFiles = async files => {
      const docNode = await cdp.send('DOM.getDocument', { depth: -1 });
      const q = await cdp.send('DOM.querySelector', { nodeId: docNode.root.nodeId, selector: '#files' });
      await cdp.send('DOM.setFileInputFiles', { nodeId: q.nodeId, files });
      await waitIdle();
    };

    await uploadFiles([path.join(fixturesBase, 'fixtures', 'laudo.pdf')]);
    await waitUntil(() => cdp.eval(`document.getElementById('document-name')?.textContent === 'laudo.pdf'`));
    await cdp.eval(`document.querySelector('button[aria-label*="Data de emissão"]')?.click()`);
    await waitIdle();
    await waitUntil(() => cdp.eval(`!document.getElementById('source-highlight').hidden && document.getElementById('pdf-canvas').width > 100`));

    const manualPdfPixels = await cdp.eval(`(() => {
      const c = document.getElementById('pdf-canvas');
      const h = document.getElementById('source-highlight');
      const x0 = Math.floor((parseFloat(h.style.left) / 100) * c.width);
      const y0 = Math.floor((parseFloat(h.style.top) / 100) * c.height);
      const rw = Math.max(1, Math.ceil((parseFloat(h.style.width) / 100) * c.width));
      const rh = Math.max(1, Math.ceil((parseFloat(h.style.height) / 100) * c.height));
      const d = c.getContext('2d').getImageData(x0, y0, rw, rh).data;
      let dark = 0;
      for (let i = 0; i < d.length; i += 4) if (d[i] < 160 && d[i + 1] < 160 && d[i + 2] < 160 && d[i + 3] > 0) dark++;
      return { width: c.width, height: c.height, dark, caption: document.getElementById('source-caption').textContent };
    })()`);
    assert(manualPdfPixels.dark > 50, `Esperados pixels escuros sob highlight de PDF manual, obtido ${manualPdfPixels.dark}`);
    assert(manualPdfPixels.caption.includes('Emissao: 11/11/2026'));

    await uploadFiles([path.join(fixturesBase, 'fixtures', 'imagem-ilegivel.png')]);
    await waitUntil(() => cdp.eval(`document.getElementById('document-name')?.textContent === 'imagem-ilegivel.png'`));
    const manualPngState = await cdp.eval(`({
      imgHidden: document.getElementById('source-image').hidden,
      caption: document.getElementById('source-caption').textContent,
      reviewFormHidden: document.getElementById('review-form').hidden,
      docsCount: document.querySelectorAll('#document-list .doc-button').length,
    })`);
    assert.equal(manualPngState.imgHidden, false);
    assert(manualPngState.caption.includes('Sem OCR nesta versão'));
    assert.equal(manualPngState.reviewFormHidden, true);
    assert.equal(manualPngState.docsCount, 2);
    assert.equal(await cdp.eval(`document.getElementById('quarantine-guidance').hidden`), false);

    await uploadFiles([invalidPdfPath]);
    const rejectedManualState = await cdp.eval(`({
      isErr: document.getElementById('message').classList.contains('error'),
      msg: document.getElementById('message').textContent,
      docsCount: document.querySelectorAll('#document-list .doc-button').length,
    })`);
    assert.equal(rejectedManualState.isErr, true);
    assert(rejectedManualState.msg.startsWith('Erro: '));
    assert.equal(rejectedManualState.docsCount, 2);
    console.log('E2E_4_MANUAL_FILES_PDF_AND_PNG_OK:', { manualPdfPixels, docsCount: manualPngState.docsCount });

    // Clear session before running scenario suite
    await cdp.eval(`document.getElementById('reset-confirm').checked = true; document.getElementById('reset').click();`);
    await waitIdle();
    assert.equal(await cdp.eval(`document.querySelectorAll('#document-list .doc-button').length`), 0);

    // 5. Scenario 1 + 390px responsiveness + validation preservation + verify + export + case-file CSV/JSON
    await cdp.eval(`document.getElementById('scenario').value = 'completo'; document.getElementById('load').click();`);
    await waitIdle();
    await cdp.eval(`[...document.querySelectorAll('#document-list .doc-button')].find(b => b.textContent.includes('laudo.pdf')).click()`);
    await waitIdle();
    await cdp.eval(`document.querySelector('button[aria-label*="Data de emissão"]')?.click()`);
    await waitIdle();

    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 390, height: 844, deviceScaleFactor: 1, mobile: true,
    });
    const mobileOverflow = await cdp.eval(`document.documentElement.scrollWidth > window.innerWidth`);
    assert.equal(mobileOverflow, false, 'Nao deve haver overflow horizontal em 390px');
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 1280, height: 900, deviceScaleFactor: 1, mobile: false,
    });

    await cdp.eval(`
      document.getElementById('identity-confirm').checked = true;
      document.getElementById('issue-date').value = '2026-11-12';
      document.getElementById('review-note').value = '';
      document.getElementById('review-form').requestSubmit();
    `);
    await waitIdle();
    assert.equal(await cdp.eval(`document.getElementById('identity-confirm').checked`), true);
    assert.equal(await cdp.eval(`document.getElementById('issue-date').value`), '2026-11-12');

    await cdp.eval(`
      document.getElementById('review-note').value = 'Correcao validada no E2E.';
      document.getElementById('review-form').requestSubmit();
    `);
    await waitIdle();
    for (const name of ['solicitacao.pdf', 'avaliacao.pdf', 'termo.pdf']) {
      await cdp.eval(`[...document.querySelectorAll('#document-list .doc-button')].find(b => b.textContent.includes(${JSON.stringify(name)})).click()`);
      await waitIdle();
      await cdp.eval(`
        document.getElementById('identity-confirm').checked = true;
        if (!document.getElementById('signature-group').hidden) document.getElementById('signature').value = 'present';
        document.getElementById('review-form').requestSubmit();
      `);
      await waitIdle();
    }
    assert.equal(await cdp.eval(`document.getElementById('readiness').textContent`), 'Documentação conferida (regras do exemplo)');

    // Non-destructive draft preservation when assigning a task or recalculating rule
    await cdp.eval(`document.getElementById('review-note').value = 'Rascunho em edicao.'; document.getElementById('rule').click();`);
    await waitIdle();
    assert.equal(await cdp.eval(`document.getElementById('review-note').value`), 'Rascunho em edicao.');

    await cdp.eval(`document.getElementById('verify').click()`);
    await waitIdle();
    assert.equal(await cdp.eval(`document.getElementById('message').classList.contains('error')`), false);
    await cdp.eval(`document.getElementById('export').click()`);
    await waitIdle();
    await cdp.eval(`document.getElementById('export-csv').click()`);
    await waitIdle();
    assert(await cdp.eval(`document.getElementById('message').textContent.includes('Exportação CSV')`));
    await cdp.eval(`document.getElementById('copy-notice').click()`);
    await waitIdle();
    assert(await cdp.eval(`document.getElementById('pdf-canvas').getAttribute('aria-label')?.includes('Página 1 de')`));

    for (const caseFile of ['casos-ficticios.csv', 'casos-ficticios.json']) {
      const docNode = await cdp.send('DOM.getDocument', { depth: -1 });
      const q = await cdp.send('DOM.querySelector', { nodeId: docNode.root.nodeId, selector: '#case-file' });
      await cdp.send('DOM.setFileInputFiles', { nodeId: q.nodeId, files: [path.join(fixturesBase, 'fixtures', caseFile)] });
      await waitIdle();
      assert(await cdp.eval(`document.getElementById('message').textContent.includes('CASO-SYN-001 (SYN-P01)')`));
    }
    console.log('E2E_5_SCENARIO_MOBILE_REVIEW_CASEFILE_OK');

    // 6. Replace (versao) + Quarantine (divergente) + Prazo (janela) + #reset
    await cdp.eval(`document.getElementById('scenario').value = 'versao'; document.getElementById('load').click();`);
    await waitIdle();
    await cdp.eval(`[...document.querySelectorAll('#document-list .doc-button')].find(b => b.textContent.includes('laudo-atualizado.pdf')).click()`);
    await waitIdle();
    await cdp.eval(`document.getElementById('identity-confirm').checked = true; document.getElementById('review-form').requestSubmit();`);
    await waitIdle();
    await cdp.eval(`
      const sel = document.getElementById('previous-document');
      sel.value = [...sel.options].find(o => o.textContent.includes('laudo.pdf')).value;
      document.getElementById('replace').click();
    `);
    await waitIdle();
    assert.equal(await cdp.eval(`document.getElementById('replace').disabled`), true);

    await cdp.eval(`document.getElementById('scenario').value = 'divergente'; document.getElementById('load').click();`);
    await waitIdle();
    assert.equal(await cdp.eval(`document.getElementById('review-form').hidden`), true);
    assert.equal(await cdp.eval(`document.getElementById('quarantine-guidance').hidden`), false);

    // Scenario 8: Lateralidade divergente (OD x OE) + Ver fonte em Lateralidade + Eixo 3 bloqueante + mobile 390px sem overflow
    await cdp.eval(`document.getElementById('reset-confirm').checked = true; document.getElementById('reset').click();`);
    await waitIdle();
    await cdp.eval(`document.getElementById('scenario').value = 'lateralidade'; document.getElementById('load').click();`);
    await waitIdle();
    await cdp.eval(`document.querySelector('button[aria-label*="Lateralidade informada"]')?.click()`);
    await waitIdle();
    await waitUntil(() => cdp.eval(`!document.getElementById('source-highlight').hidden`));
    const latE2e = await cdp.eval(`({
      axesCount: document.querySelectorAll('#consistency-axes .axis-card').length,
      latCardText: document.querySelector('.axis-card.axis-conflito')?.textContent || '',
      caption: document.getElementById('source-caption').textContent,
      notice: document.getElementById('pending-notice').textContent,
      readiness: document.getElementById('readiness').textContent,
    })`);
    assert.equal(latE2e.axesCount, 4);
    assert(latE2e.latCardText.includes('BLOQUEIO'));
    assert(latE2e.caption.includes('Lateralidade: Olho Esquerdo (OE)'));
    assert(latE2e.notice.includes('Divergência de lateralidade'));
    assert(latE2e.readiness.includes('Divergência bloqueante'));
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
    assert.equal(await cdp.eval(`document.documentElement.scrollWidth > window.innerWidth`), false);
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });

    await cdp.eval(`document.getElementById('scenario').value = 'janela'; document.getElementById('load').click();`);
    await waitIdle();
    await cdp.eval(`[...document.querySelectorAll('#document-list .doc-button')].find(b => b.textContent.includes('laudo-antigo.pdf')).click()`);
    await waitIdle();
    await cdp.eval(`document.getElementById('identity-confirm').checked = true; document.getElementById('review-form').requestSubmit();`);
    await waitIdle();
    assert.equal(await cdp.eval(`document.querySelector('#tasks input[type="date"]')?.value`), '2026-11-16');

    await cdp.eval(`document.getElementById('reset-confirm').checked = true; document.getElementById('reset').click();`);
    await waitIdle();
    assert.equal(await cdp.eval(`document.getElementById('message').classList.contains('error')`), false);
    assert.equal(await cdp.eval(`document.querySelectorAll('#document-list .doc-button').length`), 0);
    console.log('E2E_6_REPLACE_QUARANTINE_TASKS_RESET_OK');

    const nonExternalCspLogs = browserLogEntries.filter(
      e => !((e.source === 'security' || e.source === 'worker') && /child-src|the only source expression/i.test(e.text || ''))
    );

    console.log('E2E_TELEMETRY:', JSON.stringify({
      runtimeConsoleErrors: runtimeConsoleErrors.length,
      pageExceptions: pageExceptions.length,
      failedRequests: failedRequests.length,
      badResponsesAll: badResponses.length,
      externalHostCspProxyLogs: browserLogEntries.length - nonExternalCspLogs.length,
      otherBrowserLogErrors: nonExternalCspLogs,
    }));

    assert.equal(runtimeConsoleErrors.length, 0);
    assert.equal(pageExceptions.length, 0);
    assert.equal(failedRequests.length, 0);
    assert.equal(badResponses.length, 0, `Respostas HTTP >=400 inesperadas (incl. favicon): ${JSON.stringify(badResponses)}`);
    assert.equal(nonExternalCspLogs.length, 0, `Erros inesperados em Log.entryAdded: ${JSON.stringify(nonExternalCspLogs)}`);
    console.log('E2E_ALL_PASSED');
  } finally {
    if (cdp) cdp.close();
    if (browser) browser.kill();
    server.kill();
    await fs.rm(tempRoot, { recursive: true, force: true }).catch(() => {});
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
