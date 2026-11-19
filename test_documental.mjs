import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {DocumentarySession,addDaysISO,allowedFixture,brazilDate,extractFields,extractPdfLines,identity,isoToBrazil,parseSyntheticCase,verifyEvents} from './documental-core.mjs';
const manifest=JSON.parse(await readFile(new URL('./documental-manifest.json',import.meta.url)));
const fixture=name=>manifest.files.find(x=>x.name===name);
function lines(overrides={}){const values={type:'laudo',patient:'Pessoa Sintetica Alfa',birthDate:'12/04/1986',identifier:'SYN-P01',issueDate:'11/11/2026',origin:'Instituicao Ficticia JYXIA',...overrides};const labels={type:'Tipo',patient:'Paciente',birthDate:'Nascimento',identifier:'Identificador',issueDate:'Emissao',origin:'Origem'};return Object.entries(values).filter(([,v])=>v!==null).map(([k,v],i)=>({text:labels[k]+': '+v,page:1,box:[.1,.2+i*.03,.5,.02]}));}
async function add(s,name,overrides={}){return (await s.ingest(fixture(name),lines(overrides))).document;}
async function review(s,d,extra={}){return s.review(d.id,{identityChecked:true,issueDate:brazilDate(d.fields.issueDate.value),...extra});}
test('provided files are accepted by content hash, changed and unknown files are rejected',async()=>{for(const f of manifest.files){const b=new Uint8Array(await readFile(new URL('./'+f.path,import.meta.url)));assert.equal((await allowedFixture(b,manifest,[f.mime])).sha256,f.sha256);const changed=b.slice();changed[0]^=1;await assert.rejects(allowedFixture(changed,manifest,[f.mime]));}await assert.rejects(allowedFixture(new Uint8Array(524289),manifest));});
test('field evidence retains page and bounding box, ambiguous identity quarantined',()=>{const extracted=extractFields(lines());assert.equal(extracted.fields.issueDate.source.page,1);assert.equal(extracted.fields.issueDate.source.box.length,4);assert.equal(identity(extracted,manifest.case),'suggested');const ambiguous=extractFields([...lines(),{text:'Identificador: SYN-P02',page:1,box:[0,0,1,1]}]);assert.equal(identity(ambiguous,manifest.case),'conflict');});
test('complete set needs human review, signature observation then no documentary tasks',async()=>{const s=new DocumentarySession(manifest);for(const [name,type] of [['solicitacao.pdf','solicitacao'],['laudo.pdf','laudo'],['avaliacao.pdf','avaliacao'],['termo.pdf','termo']]){const d=await add(s,name,{type});assert.equal(d.caseId,null);await review(s,d,{signature:type==='termo'?'present':'unknown'});}assert.equal(s.summary().pending,0);assert.equal(s.summary().reviewed,4);assert(await verifyEvents(s.events));});
test('same bytes do not create a second document, different bytes do not auto-replace',async()=>{const s=new DocumentarySession(manifest);await add(s,'laudo.pdf');await add(s,'laudo.pdf');const fresh=await add(s,'laudo-atualizado.pdf',{issueDate:'14/11/2026'});assert.equal(s.documents.length,2);assert.equal(s.duplicates,1);assert.equal(fresh.replaces,null);});
test('identity conflict cannot be linked even when confirmation is requested',async()=>{const s=new DocumentarySession(manifest),d=await add(s,'identidade-divergente.pdf',{identifier:'SYN-P02',patient:'Pessoa Sintetica Beta',birthDate:'03/09/1990'});await assert.rejects(review(s,d));assert.equal(d.caseId,null);assert.equal(s.summary().quarantine,1);});
test('missing identifier requires matching name and birthdate plus manual confirmation',async()=>{const s=new DocumentarySession(manifest),d=await add(s,'sem-identificador.pdf',{identifier:null});assert.equal(d.identity,'manual');await assert.rejects(s.review(d.id,{issueDate:'2026-11-11'}));await review(s,d);assert.equal(d.caseId,manifest.case.id);assert.equal(identity(extractFields(lines({identifier:null,birthDate:null})),manifest.case),'insufficient');});
test('image remains in quarantine and cannot be made complete by a resolution',async()=>{const s=new DocumentarySession(manifest),d=(await s.ingest(fixture('imagem-ilegivel.png'),[])).document;assert.equal(d.identity,'unreadable');await assert.rejects(review(s,d));const task=s.tasks().find(t=>t.docId===d.id);await s.assign(task.id,'Revisor A','2026-11-16');await assert.rejects(s.resolve(task.id,'Conferido'));});
test('date correction preserves extraction and requires a reason',async()=>{const s=new DocumentarySession(manifest),d=await add(s,'laudo-antigo.pdf',{issueDate:'16/10/2026'});await assert.rejects(review(s,d,{issueDate:'2026-11-11'}));await review(s,d,{issueDate:'2026-11-11',note:'Correção fictícia para testar revisão.'});assert.equal(d.fields.issueDate.value,'16/10/2026');assert.equal(d.review.originalIssueDate,'2026-10-16');assert.equal(d.reviewHistory.length,1);});
test('administrative exceptions require review assignment deadline and justification',async()=>{const s=new DocumentarySession(manifest),d=await add(s,'laudo-antigo.pdf',{issueDate:'16/10/2026'});await review(s,d);const t=s.tasks().find(t=>t.id.includes(':window:'));await assert.rejects(s.resolve(t.id,'Reenvio solicitado'));await assert.rejects(s.assign(t.id,'Pessoa real','2026-11-16'));await assert.rejects(s.assign(t.id,'Revisor A','2026-02-30'));await s.assign(t.id,'Revisor A','2026-11-16');await s.resolve(t.id,'Exceção administrativa fictícia justificada.');assert(s.tasks().find(x=>x.id===t.id).resolution);await review(s,d);assert.equal(s.tasks().find(x=>x.id===t.id).resolution,null);});
test('policy changes invalidate old task resolutions while preserving audit',async()=>{const s=new DocumentarySession(manifest),d=await add(s,'laudo-antigo.pdf',{issueDate:'16/10/2026'});await review(s,d);const t=s.tasks().find(t=>t.id.includes(':window:'));await s.assign(t.id,'Revisor A','2026-11-16');await s.resolve(t.id,'Exceção fictícia documentada.');await s.configure(25);assert.equal(s.tasks().find(t=>t.id.includes(':window:')).resolution,null);assert(s.events.some(e=>e.action==='pendencia_resolvida'));await assert.rejects(s.configure(0));});
test('explicit replacement requires both reviews, keeps original and blocks cycles',async()=>{const s=new DocumentarySession(manifest),a=await add(s,'laudo.pdf'),b=await add(s,'laudo-atualizado.pdf',{issueDate:'14/11/2026'});await assert.rejects(s.replace(b.id,a.id));await review(s,a);await review(s,b);await s.replace(b.id,a.id);assert.equal(s.documents.length,2);assert.equal(s.active().length,1);assert.equal(a.supersededBy,b.id);await assert.rejects(s.replace(a.id,b.id));});
test('export is detached from state and hash chain detects payload changes and order',async()=>{const s=new DocumentarySession(manifest);const d=await add(s,'laudo.pdf');await review(s,d);const exported=s.export();exported.documents[0].name='changed';assert.equal(s.documents[0].name,'laudo.pdf');assert(await verifyEvents(exported.events));exported.events[0].data.identity='changed';assert.equal(await verifyEvents(exported.events),false);assert.equal(await verifyEvents([...s.events].reverse()),false);});
test('date parser refuses rollover and future dates are flagged',async()=>{assert.equal(brazilDate('30/02/2026'),'');const s=new DocumentarySession(manifest);const d=await add(s,'laudo.pdf',{issueDate:'15/11/2026'});await review(s,d);assert(s.tasks().some(t=>t.id.includes(':future:')));});
test('date formatting helpers convert ISO dates and offset days safely',()=>{assert.equal(isoToBrazil('1986-04-12'),'12/04/1986');assert.equal(isoToBrazil('2026-02-30'),'');assert.equal(addDaysISO('2026-11-14',2),'2026-11-16');assert.equal(addDaysISO('2026-11-29',2),'2026-12-01');});
test('synthetic case CSV and JSON fixtures parse, update session case and reject malformed data',async()=>{
 const csvText=await readFile(new URL('./fixtures/casos-ficticios.csv',import.meta.url),'utf8');
 const jsonText=await readFile(new URL('./fixtures/casos-ficticios.json',import.meta.url),'utf8');
 const parsedCsv=parseSyntheticCase(csvText,'text/csv');
 const parsedJson=parseSyntheticCase(jsonText,'application/json');
 assert.deepEqual(parsedCsv,parsedJson);
 assert.equal(parsedCsv.id,'CASO-SYN-001');
 assert.throws(()=>parseSyntheticCase('id,patient\nCASO,Nome','text/csv'));
 assert.throws(()=>parseSyntheticCase('{"synthetic":false}','application/json'));
 const s=new DocumentarySession(manifest);
 const csvKnown=await allowedFixture(new TextEncoder().encode(csvText),manifest,['text/csv']);
 const loaded=await s.loadSyntheticCase(csvKnown,csvText);
 assert.equal(loaded.identifier,'SYN-P01');
 assert(s.events.some(e=>e.action==='cadastro_importado'&&e.data.identifier==='SYN-P01'));
});
test('discard preserves history, rejects short reason and blocks discarded review',async()=>{
 const s=new DocumentarySession(manifest),d=await add(s,'laudo.pdf');
 await assert.rejects(s.discard(d.id,'abc'));
 await s.discard(d.id,'Documento substituído manualmente no teste.');
 assert.equal(d.status,'discarded');
 assert.equal(s.active().length,0);
 await assert.rejects(review(s,d));
});
test('extractPdfLines enforces page limit via loadingTask.destroy when available',async()=>{
 let destroyed=false;
 const mockDoc={numPages:6,loadingTask:{destroy:async()=>{destroyed=true;}}};
 await assert.rejects(extractPdfLines(mockDoc,()=>[1,0,0,1,0,0],5),/Limite de cinco páginas/);
 assert.equal(destroyed,true);
});
