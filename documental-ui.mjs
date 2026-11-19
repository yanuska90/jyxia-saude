import * as pdfjs from './vendor/pdf.min.mjs';
import {DocumentarySession,KINDS,SCENARIOS,addDaysISO,allowedFixture,brazilDate,extractPdfLines,isoToBrazil,verifyEvents} from './documental-core.mjs';
pdfjs.GlobalWorkerOptions.workerSrc=new URL('./vendor/pdf.worker.min.mjs',import.meta.url).href;
const $=id=>document.getElementById(id);
const manifest=await fetch('./documental-manifest.json',{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Não foi possível carregar os exemplos.');return r.json();});
let session=new DocumentarySession(manifest), selected=null, busy=false, renderTicket=0, renderedDocKey='';
const sources=new Map();
const labels={
 patient:'Nome',
 birthDate:'Nascimento',
 identifier:'Identificação',
 issueDate:'Data de emissão',
 type:'Tipo',
 subfamily:'Subfamília',
 procedure:'Procedimento informado',
 laterality:'Lateralidade informada',
 origin:'Origem informada',
 signatureCue:'Marca visual na área de assinatura'
};
const identityLabels={suggested:'Identidade sugerida · conferir',manual:'Sem identificador · conferir manualmente',conflict:'Identidade divergente · quarentena',insufficient:'Identidade insuficiente · quarentena',unreadable:'Sem extração · quarentena'};
const actionLabels={documento_recebido:'Documento recebido',duplicado_recusado:'Arquivo idêntico recusado',revisao_humana:'Revisão humana registrada',documento_descartado:'Documento retirado do fluxo',substituicao_confirmada:'Substituição confirmada',regra_administrativa_alterada:'Regra administrativa alterada',pendencia_atribuida:'Responsável e prazo atribuídos',pendencia_resolvida:'Resolução justificada',cadastro_importado:'Cadastro fictício importado'};
const axisBadges={ok:'OK · Compatível',conflito:'BLOQUEIO · Conflito',abstencao:'ABSTENÇÃO · Conferência',atencao:'ATENÇÃO · Pendente',nao_aplicavel:'N/A · Não aplicável',pendente:'AGUARDANDO'};
function el(tag,text,cls){const n=document.createElement(tag);if(['button','input','select','textarea'].includes(tag))n.disabled=busy;if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;}
function option(value,text){const n=el('option',text);n.value=value;return n;}
function message(text,error=false){const m=$('message');m.textContent=error&&!String(text).startsWith('Erro:')?'Erro: '+text:text;m.classList.toggle('error',error);}
function syncDocumentActions(d){
 const hasPrev=d&&session.documents.some(p=>p.id!==d.id&&p.kind===d.kind&&p.review&&!p.supersededBy&&p.status!=='discarded'&&(!d.subfamily||!p.subfamily||d.subfamily.toLowerCase()===p.subfamily.toLowerCase()));
 const canReplace=Boolean(d&&d.review&&!d.supersededBy&&d.status!=='discarded'&&!d.replaces&&hasPrev);
 const canDiscard=Boolean(d&&!d.supersededBy&&d.status!=='discarded');
 $('previous-document').disabled=busy||!canReplace;$('replace').disabled=busy||!canReplace;
 $('discard-note').disabled=busy||!canDiscard;$('discard').disabled=busy||!canDiscard;
}
async function run(fn,rerender=true){if(busy)return;busy=true;document.body.setAttribute('aria-busy','true');for(const b of document.querySelectorAll('button,input,select,textarea'))b.disabled=true;try{await fn();if(rerender)await refresh();}catch(e){if(rerender==='always')await refresh();message(e.message||'Não foi possível concluir. Tente novamente.',true);}finally{busy=false;document.body.removeAttribute('aria-busy');for(const b of document.querySelectorAll('button,input,select,textarea'))b.disabled=false;syncDocumentActions(selected?session.doc(selected):null);}}
async function destroyPdf(doc){try{if(doc?.loadingTask?.destroy)await doc.loadingTask.destroy();else if(doc?.destroy)await doc.destroy();else if(doc?.cleanup)await doc.cleanup();}catch{}}
async function parsePdf(bytes){const task=pdfjs.getDocument({data:bytes.slice(),isEvalSupported:false,useSystemFonts:true,disableFontFace:true});let doc;try{doc=await task.promise;}catch{try{await task.destroy?.();}catch{}throw Error('Não foi possível ler este PDF.');}try{const lines=await extractPdfLines(doc,pdfjs.Util.transform,5);return {doc,lines};}catch(e){await destroyPdf(doc);throw e;}}
async function ingestBytes(bytes){const start=performance.now();const f=await allowedFixture(bytes,manifest);if(session.documents.some(d=>d.hash===f.sha256))return session.ingest(f,[],performance.now()-start);const source={bytes:bytes.slice(),mime:f.mime};let lines=[];if(f.mime==='application/pdf'){const parsed=await parsePdf(bytes);source.doc=parsed.doc;lines=parsed.lines;}else source.url=URL.createObjectURL(new Blob([bytes],{type:f.mime}));try{const result=await session.ingest(f,lines,performance.now()-start);sources.set(result.document.id,source);selected=result.document.id;return result;}catch(e){if(source.doc)await destroyPdf(source.doc);if(source.url)URL.revokeObjectURL(source.url);throw e;}}
async function loadScenario(){const s=SCENARIOS[$('scenario').value];let duplicates=0;for(const name of s.files){const f=manifest.files.find(x=>x.name===name);const r=await fetch(f.path);if(!r.ok)throw Error('Exemplo indisponível: '+name);const result=await ingestBytes(new Uint8Array(await r.arrayBuffer()));if(result.duplicate)duplicates++;}message(s.label+' adicionado. '+(duplicates?'Duplicados recusados: '+duplicates+'.':'Selecione um documento e confira os campos.'));}
async function showSource(d,field){const ticket=++renderTicket;const source=sources.get(d.id);$('source-highlight').hidden=true;if(!source)return;const page=field?.source?.page||1;$('page-label').textContent='Página '+page;
 if(source.doc){$('source-image').hidden=true;$('pdf-canvas').hidden=false;$('pdf-canvas').setAttribute('aria-label','Página '+page+' de '+d.name);const p=await source.doc.getPage(page),viewport=p.getViewport({scale:1.4});const canvas=document.createElement('canvas');canvas.width=Math.ceil(viewport.width);canvas.height=Math.ceil(viewport.height);await p.render({canvasContext:canvas.getContext('2d'),viewport}).promise;if(ticket!==renderTicket)return;const target=$('pdf-canvas');target.width=canvas.width;target.height=canvas.height;target.getContext('2d').drawImage(canvas,0,0);
 }else{$('pdf-canvas').hidden=true;$('source-image').hidden=false;$('source-image').src=source.url;}
 if(field?.source){const [x,y,w,h]=field.source.box;const mark=$('source-highlight');mark.style.left=(x*100)+'%';mark.style.top=(y*100)+'%';mark.style.width=(w*100)+'%';mark.style.height=(h*100)+'%';mark.hidden=false;$('source-caption').textContent='Fonte, página '+page+': '+field.source.text;}else $('source-caption').textContent=source.doc?'Clique em “Ver fonte” ao lado de um campo.':'Sem OCR nesta versão. A imagem permanece disponível para conferência visual e reenvio.';
}
function renderList(){$('document-list').replaceChildren();if(!session.documents.length){$('document-list').append(el('p','Adicione um cenário para começar.'));return;}for(const d of session.documents){const b=el('button',d.name,'doc-button'+(d.id===selected?' selected':''));b.type='button';b.setAttribute('aria-pressed',String(d.id===selected));b.append(el('span',d.supersededBy?'Versão anterior preservada':d.status==='discarded'?'Retirado do fluxo':d.review?'Revisado · '+KINDS[d.kind]:identityLabels[d.identity]));b.addEventListener('click',()=>run(async()=>{selected=d.id;}));$('document-list').append(b);}}
function syncPreviousOptions(d){
 const prevList=d?session.documents.filter(p=>p.id!==d.id&&p.kind===d.kind&&p.review&&!p.supersededBy&&p.status!=='discarded'&&(!d.subfamily||!p.subfamily||d.subfamily.toLowerCase()===p.subfamily.toLowerCase())):[];
 const sel=$('previous-document'), currentVal=sel.value;
 sel.replaceChildren(option('',prevList.length?'Escolha a versão anterior':'Nenhuma versão anterior revisada disponível'));
 for(const previous of prevList)sel.append(option(previous.id,previous.name+' · '+previous.id));
 if(prevList.some(p=>p.id===currentVal))sel.value=currentVal;
}
function quarantineGuidance(d){
 if(!d)return '';
 if(d.supersededBy)return 'Versão anterior preservada no histórico após substituição explícita por '+d.supersededBy+'.';
 if(d.status==='discarded')return 'Documento retirado do fluxo ativo por ação humana, mantido apenas no histórico.';
 if(d.identity==='unreadable')return 'Abstenção automática (sem OCR nesta versão): solicite reenvio de PDF legível ou retire este arquivo do fluxo.';
 if(d.identity==='conflict')return 'Quarentena cadastral bloqueante: os dados divergem do caso ativo ('+session.case.patient+'). O vínculo automático permanece bloqueado.';
 if(d.identity==='insufficient')return 'Quarentena por evidência insuficiente: nome ou nascimento ausentes para conferência cadastral.';
 if(d.kind==='desconhecido')return 'Abstenção por classificação desconhecida: tipo documental fora das quatro classes previstas.';
 return '';
}
async function renderReview(){
 const d=selected?session.doc(selected):null;
 const docKey=d?[d.id,d.status,d.supersededBy||'',d.reviewHistory.length,d.caseId||''].join('|'):'none';
 $('review-area').hidden=!d;$('empty-review').hidden=!!d;
 if(!d){renderedDocKey=docKey;syncDocumentActions(null);return;}
 syncPreviousOptions(d);
 syncDocumentActions(d);
 if(docKey===renderedDocKey)return;
 renderedDocKey=docKey;
 $('document-name').textContent=d.name;
 $('document-status').textContent=d.supersededBy?'Substituído por '+d.supersededBy:d.status==='discarded'?'Retirado do fluxo':d.review?'Revisão registrada':identityLabels[d.identity];
 $('document-status').classList.toggle('warn',!d.review);
 $('fields').replaceChildren();
 for(const [key,label] of Object.entries(labels)){
  const f=d.fields[key]||{value:'',source:null,uncertain:false};
  if(key==='signatureCue'&&d.kind!=='termo'&&!f.value&&!f.uncertain)continue;
  const row=el('div',undefined,'field'),top=el('div',undefined,'field-top');
  top.append(el('small',label));
  if(f.source){const b=el('button','Ver fonte');b.type='button';b.setAttribute('aria-label','Ver fonte de '+label);b.addEventListener('click',()=>run(async()=>{await showSource(d,f);message('Trecho de '+label+' destacado na página original.');},false));top.append(b);}
  const emptyText=['subfamily','procedure','laterality'].includes(key)?'Não informado neste documento':key==='signatureCue'?'Marca visual não localizada (conferência manual necessária)':'Não localizado';
  row.append(top,el('strong',f.uncertain?'Ambíguo · múltiplos valores no documento':(f.value||emptyText)));
  $('fields').append(row);
 }
 const guidance=quarantineGuidance(d), guideEl=$('quarantine-guidance');
 guideEl.textContent=guidance;guideEl.hidden=!guidance;
 $('identity-confirm').checked=!!d.review;$('issue-date').value=d.review?.issueDate??brazilDate(d.fields.issueDate.value);$('signature').value=d.review?.signature||'unknown';$('review-note').value=d.review?.note||'';$('signature-group').hidden=d.kind!=='termo';
 $('review-form').hidden=Boolean(guidance);
 $('discard-note').value='';
 await showSource(d);
}
function renderAxes(){
 const wrap=$('consistency-axes');if(!wrap)return;
 wrap.replaceChildren();
 for(const a of session.consistencyAxes()){
  const card=el('article',undefined,'axis-card axis-'+a.status);
  const head=el('div',undefined,'axis-head');
  head.append(el('strong',a.label),el('span',axisBadges[a.status]||a.status,'axis-badge'));
  card.append(head,el('p',a.detail));
  wrap.append(card);
 }
 const noticeEl=$('pending-notice');
 if(noticeEl)noticeEl.textContent=session.buildPendingNotice();
}
function renderTasks(){
 $('tasks').replaceChildren();const tasks=session.tasks();const suggestedDue=addDaysISO(session.manifest.referenceDate,2);const defaultDue=(session.case.procedureDate&&suggestedDue>session.case.procedureDate)?session.case.procedureDate:(suggestedDue||session.manifest.referenceDate);
 for(const t of tasks){
  const row=el('article',undefined,'task'),text=el('div');text.append(el('h3',t.title),el('p',t.docId?'Documento '+t.docId:'Conjunto documental do caso'));
  if(t.resolution){text.append(el('p','Resolução: '+t.resolution.note),el('p','Responsável: '+t.resolution.assignment.owner+' · prazo '+t.resolution.assignment.due));row.append(text,el('span','Justificativa registrada','pill'));}
  else{const controls=el('div',undefined,'task-controls'),owner=el('select'),due=el('input');owner.setAttribute('aria-label','Responsável por '+t.title);owner.append(option('Revisor A','Revisor A'),option('Revisor B','Revisor B'));owner.value=t.assignment?.owner||'Revisor A';due.type='date';due.min=session.manifest.referenceDate;due.value=t.assignment?.due||defaultDue;due.setAttribute('aria-label','Prazo de '+t.title);const ow=el('div'),dw=el('div');ow.append(el('label','Responsável fictício'),owner);dw.append(el('label','Prazo'),due);const assign=el('button',t.assignment?'Atualizar atribuição':'Atribuir');assign.type='button';assign.addEventListener('click',()=>run(async()=>{await session.assign(t.id,owner.value,due.value);message('Responsável e prazo registrados.');}));controls.append(ow,dw,assign);if(t.manual&&session.doc(t.docId).review){const group=el('div',undefined,'task-note'),note=el('input'),resolve=el('button','Registrar resolução');note.maxLength=500;note.placeholder='Justificativa da resolução (5 a 500 caracteres)';note.setAttribute('aria-label','Justificativa para '+t.title);resolve.type='button';resolve.addEventListener('click',()=>run(async()=>{await session.resolve(t.id,note.value);message('Resolução registrada com justificativa.');}));group.append(note,resolve);controls.append(group);}else controls.append(el('p','Resolva conferindo, retirando ou substituindo o documento conflitante.'));row.append(text,controls);}
  $('tasks').append(row);
 }
 const r=session.readinessState();
 $('readiness').textContent=r.label;
 $('readiness').classList.toggle('warn',r.code!=='conferida');
 $('readiness').classList.toggle('danger',r.code==='conflito');
 if(!tasks.length)$('tasks').append(el('p','Conjunto conferido segundo as regras do exemplo. A avaliação clínica permanece fora desta demonstração.'));
}
function renderAudit(){$('audit').replaceChildren();for(const e of session.events.slice().reverse()){const li=el('li');li.append(el('strong','#'+e.seq+' '+(actionLabels[e.action]||e.action)),el('small',new Date(e.at).toLocaleString('pt-BR')+' · '+(e.data.document||e.data.taskId||'sessão')+' · hash '+e.hash.slice(0,16)+'…'));$('audit').append(li);}}
async function refresh(){$('case-name').textContent=session.case.patient;$('case-meta').textContent='Caso '+session.case.id+' · Identificação fictícia '+session.case.identifier+' · Nascimento '+(isoToBrazil(session.case.birthDate)||session.case.birthDate);const ctx=$('rule-context');if(ctx)ctx.textContent='Referência do exemplo: '+(isoToBrazil(session.manifest.referenceDate)||session.manifest.referenceDate)+'. Procedimento fictício: '+(isoToBrazil(session.case.procedureDate)||session.case.procedureDate)+'. Janela aplicada somente à data do laudo; não define validade clínica.';$('rule-meta').textContent='Regra versão '+session.policy.version+' · janela de '+session.policy.maxAgeDays+' dias';$('window').value=session.policy.maxAgeDays;const s=session.summary();$('metrics').replaceChildren();for(const [key,label] of [['documents','Documentos recebidos'],['reviewed','Ativos revisados'],['pending','Pendências abertas'],['duplicates','Duplicados recusados'],['quarantine','Em quarentena']]){const n=el('div',undefined,'metric');n.append(el('strong',String(s[key])),el('span',label));$('metrics').append(n);}renderList();renderAxes();renderTasks();renderAudit();for(const b of document.querySelectorAll('button,input,select,textarea'))b.disabled=busy;await renderReview();}
for(const [key,s] of Object.entries(SCENARIOS))$('scenario').append(option(key,s.label));
$('load').addEventListener('click',()=>run(loadScenario,'always'));
$('files').addEventListener('change',()=>run(async()=>{const files=[...$('files').files];$('files').value='';if(files.length>12)throw Error('Selecione no máximo 12 arquivos por envio.');let accepted=0;for(const file of files){if(file.size>524288)throw Error('Arquivo maior que 512 KB.');await ingestBytes(new Uint8Array(await file.arrayBuffer()));accepted++;}message(accepted+' arquivo(s) fictício(s) processado(s).');},'always'));
$('case-file').addEventListener('change',()=>run(async()=>{const f=$('case-file').files[0];$('case-file').value='';if(!f)return;if(f.size>524288)throw Error('Cadastro maior que o permitido.');const bytes=new Uint8Array(await f.arrayBuffer());const known=await allowedFixture(bytes,manifest,['application/json','text/csv']);const loaded=await session.loadSyntheticCase(known,new TextDecoder().decode(bytes));message('Cadastro fictício conferido e carregado: '+loaded.id+' ('+loaded.identifier+').');}));
$('review-form').addEventListener('submit',e=>{e.preventDefault();run(async()=>{await session.review(selected,{identityChecked:$('identity-confirm').checked,issueDate:$('issue-date').value,signature:$('signature').value,note:$('review-note').value});message('Revisão humana registrada; pendências recalculadas.');});});
$('rule').addEventListener('click',()=>run(async()=>{await session.configure(Number($('window').value));message('Nova versão da regra registrada. Justificativas anteriores permanecem no histórico.');}));
$('replace').addEventListener('click',()=>run(async()=>{await session.replace(selected,$('previous-document').value);message('Substituição confirmada. As duas versões permanecem no histórico.');}));
$('discard').addEventListener('click',()=>run(async()=>{await session.discard(selected,$('discard-note').value);message('Documento retirado do fluxo ativo e preservado no histórico.');}));
$('verify').addEventListener('click',()=>run(async()=>{const valid=await verifyEvents(session.events);message(valid?'Sequência de '+session.events.length+' eventos íntegra nesta sessão. Isso não autentica autoria nem impede reconstrução do histórico.':'Sequência divergente.',!valid);}));
$('export').addEventListener('click',()=>run(async()=>{const url=URL.createObjectURL(new Blob([JSON.stringify(session.export(),null,2)],{type:'application/json'})),a=el('a');a.href=url;a.download='JYXIA-sessao-ficticia-v3.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),2000);message('Exportação JSON gerada com fontes, consistência, revisões, regras, pendências e eventos da sessão.');}));
$('export-csv')?.addEventListener('click',()=>run(async()=>{const url=URL.createObjectURL(new Blob([session.exportCsv()],{type:'text/csv;charset=utf-8'})),a=el('a');a.href=url;a.download='JYXIA-conferencia-ficticia-v3.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),2000);message('Exportação CSV administrativa gerada para a sessão fictícia.');}));
$('copy-notice')?.addEventListener('click',()=>run(async()=>{const text=session.buildPendingNotice();try{await navigator.clipboard?.writeText(text);message('Resumo administrativo copiado para a área de transferência.');}catch{message('Resumo administrativo pronto no painel abaixo para cópia manual.');}},false));
$('reset').addEventListener('click',()=>run(async()=>{if(!$('reset-confirm').checked)throw Error('Marque a confirmação antes de limpar a sessão fictícia.');for(const s of sources.values()){if(s.doc)await destroyPdf(s.doc);if(s.url)URL.revokeObjectURL(s.url);}sources.clear();session=new DocumentarySession(manifest);selected=null;renderedDocKey='';$('reset-confirm').checked=false;message('Sessão fictícia limpa. Os registros locais da versão histórica não foram alterados.');}));
await refresh();message('Pronto. Escolha um cenário fictício ou anexe os exemplos fornecidos.');
