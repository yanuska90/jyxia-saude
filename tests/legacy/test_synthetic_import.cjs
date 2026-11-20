const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');
require('../../legacy/v2/synthetic-import.js');const I=globalThis.JYXIA_DEMO_IMPORT;
const catalog=JSON.parse(fs.readFileSync(__dirname+'/../../legacy/v2/integration-demo.json','utf8'));
const packageText=fs.readFileSync(__dirname+'/../../legacy/v2/paciente-ficticio-01.json','utf8');
test('provided package imports seven records of exactly one fictional patient',()=>{
 const sources=I.parseApproved(packageText,catalog);assert.equal(sources.flatMap(s=>s.records).length,7);assert.deepEqual([...new Set(sources.flatMap(s=>s.records).map(r=>r.patient_id))],['SYN-P01']);
});
test('whitespace and BOM do not invalidate the supplied package',()=>assert.equal(I.parseApproved('\uFEFF'+JSON.stringify(JSON.parse(packageText)),catalog).length,2));
test('different patient is rejected without modifying the trusted catalog',()=>{
 const before=JSON.stringify(catalog),data=JSON.parse(packageText);data.sources[0].records[0].patient_id='SYN-OTHER';assert.throws(()=>I.parseApproved(JSON.stringify(data),catalog));assert.equal(JSON.stringify(catalog),before);
});
test('additional fields or medical text outside the approved template are rejected',()=>{
 const data=JSON.parse(packageText);data.email='ficticio@example.invalid';assert.throws(()=>I.parseApproved(JSON.stringify(data),catalog));
 data.sources[0].records[0].title='<img src=x onerror=alert(1)>';assert.throws(()=>I.parseApproved(JSON.stringify(data),catalog));
});
test('invalid and oversized files are rejected',()=>{assert.throws(()=>I.parseApproved('{',catalog));assert.throws(()=>I.parseApproved(' '.repeat(I.MAX_BYTES+1),catalog));});
test('import result cannot mutate the trusted catalog',()=>{const imported=I.parseApproved(packageText,catalog);imported[0].records[0].title='changed';assert.notEqual(catalog.sources[0].records[0].title,'changed');});
test('incomplete or wrong-source packages are rejected',()=>{const data=JSON.parse(packageText);data.sources.pop();assert.throws(()=>I.parseApproved(JSON.stringify(data),catalog));});
