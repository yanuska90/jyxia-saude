import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { extractLabPdfLines, extractWithExplicitAliases, LAB_LIMITS } from '../../frontend/lab/lab-extractor.mjs';

Uint8Array.prototype.toHex ??= function () { return Buffer.from(this).toString('hex'); };

const BENCH_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_DIR = path.resolve(BENCH_DIR, '..', '..');
const pdfjs = await import(pathToFileURL(path.join(REPO_DIR, 'frontend', 'public', 'vendor', 'pdf.min.mjs')).href);
pdfjs.GlobalWorkerOptions.workerSrc = pathToFileURL(path.join(REPO_DIR, 'frontend', 'public', 'vendor', 'pdf.worker.min.mjs')).href;

const CRITICAL_FIELDS = new Set(['patient', 'birthDate', 'identifier', 'laterality']);

export async function runBenchmark() {
  const manifest = JSON.parse(await fs.readFile(path.join(BENCH_DIR, 'benchmark-manifest.json'), 'utf8'));
  const perFieldStats = {};
  const perScenario = [];
  const bySplit = {};

  const ensureFieldStat = f => {
    if (!perFieldStats[f]) {
      perFieldStats[f] = {
        evaluated: 0,
        recognitionOk: 0,
        valueOk: 0,
        originAliasOk: 0,
        pageOk: 0,
        bboxOk: 0,
        ambiguityExpected: 0,
        ambiguityDetected: 0,
        abstentionExpected: 0,
        abstentionDetected: 0,
        falsePositives: 0,
        falseNegatives: 0,
        critical: CRITICAL_FIELDS.has(f),
      };
    }
    return perFieldStats[f];
  };

  for (const item of manifest.cases) {
    const filePath = path.join(BENCH_DIR, item.path);
    const bytes = new Uint8Array(await fs.readFile(filePath));
    const task = pdfjs.getDocument({ data: bytes.slice(), isEvalSupported: false, useSystemFonts: true, disableFontFace: true });
    const doc = await task.promise;
    let extracted;
    try {
      extracted = await extractLabPdfLines(doc, pdfjs.Util.transform, LAB_LIMITS.maxPages);
    } finally {
      await doc.loadingTask.destroy();
    }
    const report = extractWithExplicitAliases(extracted.lines, extracted);

    const scenarioResult = {
      id: item.id,
      split: item.split,
      scenario: item.scenario,
      readableExpected: item.expected.readable ?? true,
      readableActual: report.readable,
      fieldChecks: [],
      passed: true,
    };

    if (item.expected.readable === false && report.readable) {
      scenarioResult.passed = false;
    }

    if (typeof item.expected.unrecognizedMin === 'number' && report.unrecognizedLabels.length < item.expected.unrecognizedMin) {
      scenarioResult.passed = false;
    }
    if (typeof item.expected.unlabeledMin === 'number' && report.unlabeledItems.length < item.expected.unlabeledMin) {
      scenarioResult.passed = false;
    }

    for (const [field, exp] of Object.entries(item.expected)) {
      if (['readable', 'unrecognizedMin', 'unlabeledMin'].includes(field)) continue;
      const st = ensureFieldStat(field);
      st.evaluated++;
      const got = report.fields[field];
      const recOk = got?.status === exp.status;
      if (recOk) st.recognitionOk++;
      else {
        scenarioResult.passed = false;
        if (exp.status === 'abstencao' && got?.status === 'extraido') st.falsePositives++;
        else if (exp.status === 'extraido' && got?.status !== 'extraido') st.falseNegatives++;
      }

      if (exp.status === 'ambiguo') {
        st.ambiguityExpected++;
        if (got?.status === 'ambiguo') st.ambiguityDetected++;
        if (typeof exp.duplicateIdentical === 'boolean' && got?.duplicateIdentical !== exp.duplicateIdentical) {
          scenarioResult.passed = false;
        }
      }
      if (exp.status === 'abstencao') {
        st.abstentionExpected++;
        if (got?.status === 'abstencao') st.abstentionDetected++;
      }

      if (exp.status === 'extraido') {
        const valOk = exp.normalized ? got?.normalized === exp.normalized : got?.value === exp.value;
        const aliasOk = exp.alias_any ? exp.alias_any.includes(got?.matchedAlias) : (!exp.alias || got?.matchedAlias === exp.alias);
        const pageOk = !exp.page || got?.source?.page === exp.page;
        const b = got?.source?.box || [];
        const bboxOk = b.length === 4 && b[0] >= 0 && b[1] >= 0 && b[2] > 0 && b[3] > 0 && b[0] + b[2] <= 1.001 && b[1] + b[3] <= 1.001;
        if (valOk) st.valueOk++; else scenarioResult.passed = false;
        if (aliasOk) st.originAliasOk++; else scenarioResult.passed = false;
        if (pageOk) st.pageOk++; else scenarioResult.passed = false;
        if (bboxOk) st.bboxOk++; else scenarioResult.passed = false;
        scenarioResult.fieldChecks.push({ field, recOk, valOk, aliasOk, pageOk, bboxOk });
      } else {
        scenarioResult.fieldChecks.push({ field, recOk });
      }
    }

    perScenario.push(scenarioResult);
    bySplit[item.split] ??= { total: 0, passed: 0 };
    bySplit[item.split].total++;
    if (scenarioResult.passed) bySplit[item.split].passed++;
  }

  return {
    schema: 'jyxia.benchmark-report.v1',
    version: manifest.version,
    syntheticOnly: true,
    independentRealHoldout: false,
    warning: manifest.methodologyNote,
    totalCases: manifest.cases.length,
    bySplit,
    perFieldStats,
    perScenario,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const res = await runBenchmark();
  console.log(JSON.stringify(res, null, 2));
}
