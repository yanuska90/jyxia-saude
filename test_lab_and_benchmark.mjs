import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertLocalhostEnvironment,
  extractWithExplicitAliases,
  hasPdfMagicBytes,
} from './lab-extractor.mjs';
import { runBenchmark } from './benchmark/run_benchmark.mjs';

test('Modalidade B lab enforces localhost isolation and %PDF- magic bytes', () => {
  assert.doesNotThrow(() => assertLocalhostEnvironment('localhost'));
  assert.doesNotThrow(() => assertLocalhostEnvironment('127.0.0.1'));
  assert.throws(() => assertLocalhostEnvironment('yanuska90.github.io'), /localhost/);
  assert.equal(hasPdfMagicBytes(new TextEncoder().encode('%PDF-1.4\n...')), true);
  assert.equal(hasPdfMagicBytes(new TextEncoder().encode('<html>not a pdf</html>')), false);
});

test('Modalidade B explicit alias extraction handles variations, abstains on unknown/unlabeled and flags ambiguities', () => {
  const sample = [
    { text: 'Nome completo: Pessoa Lab Teste', page: 1, box: [0.1, 0.1, 0.5, 0.02] },
    { text: 'Data de nascimento: 12/04/1986', page: 1, box: [0.1, 0.15, 0.4, 0.02] },
    { text: 'Codigo do paciente: LAB-01', page: 1, box: [0.1, 0.2, 0.3, 0.02] },
    { text: 'Emitido em: 11/11/2026', page: 1, box: [0.1, 0.25, 0.3, 0.02] },
    { text: 'Procedimento solicitado: Biopsia guiada', page: 1, box: [0.1, 0.3, 0.4, 0.02] },
    { text: 'Regiao lateral: Lado direito', page: 2, box: [0.1, 0.35, 0.3, 0.02] },
    { text: 'Unidade: Servico Ficticio Lab', page: 2, box: [0.1, 0.4, 0.4, 0.02] },
    { text: 'RotuloDesconhecido: qualquer coisa', page: 2, box: [0.1, 0.45, 0.3, 0.02] },
    { text: '14/11/2026', page: 2, box: [0.1, 0.5, 0.2, 0.02] },
    { text: '98765432', page: 2, box: [0.1, 0.55, 0.2, 0.02] },
  ];
  const res = extractWithExplicitAliases(sample, { pagesCount: 2, pageRotations: [{ page: 1, rotate: 0 }, { page: 2, rotate: 90 }] });
  assert.equal(res.fields.patient.value, 'Pessoa Lab Teste');
  assert.equal(res.fields.patient.matchedAlias, 'Nome completo');
  assert.equal(res.fields.laterality.normalized, 'direito');
  assert.equal(res.fields.laterality.source.page, 2);
  assert.equal(res.unrecognizedLabels.length, 1);
  assert.equal(res.unrecognizedLabels[0].status, 'nao_reconhecido');
  assert.equal(res.unlabeledItems.length, 2);

  // Ambiguous duplicate aliases -> abstenção automática
  const dup = extractWithExplicitAliases([
    { text: 'Paciente: Pessoa Um', page: 1, box: [0.1, 0.1, 0.4, 0.02] },
    { text: 'Nome do paciente: Pessoa Dois', page: 1, box: [0.1, 0.2, 0.4, 0.02] },
  ]);
  assert.equal(dup.fields.patient.status, 'ambiguo');
  assert.equal(dup.fields.patient.abstained, true);
  assert.equal(dup.fields.patient.candidates.length, 2);
});

test('Separated synthetic benchmark executes all splits with zero critical identity/laterality misses', async () => {
  const report = await runBenchmark();
  assert.equal(report.independentRealHoldout, false);
  assert.equal(report.totalCases, 8);
  assert.equal(report.bySplit.development.passed, report.bySplit.development.total);
  assert.equal(report.bySplit.regression.passed, report.bySplit.regression.total);
  assert.equal(report.bySplit.reserved_evaluation.passed, report.bySplit.reserved_evaluation.total);
  assert.equal(report.perFieldStats.patient.falsePositives, 0);
  assert.equal(report.perFieldStats.patient.falseNegatives, 0);
  assert.equal(report.perFieldStats.laterality.falsePositives, 0);
  assert.equal(report.perFieldStats.laterality.falseNegatives, 0);
});
