export const VERSION='3.1.0';
export const KINDS={solicitacao:'Solicitação',laudo:'Laudo de exame',avaliacao:'Formulário de avaliação',termo:'Termo documental',desconhecido:'Não classificado'};
export const SCENARIOS={
 completo:{label:'1 · Conjunto completo',files:['solicitacao.pdf','laudo.pdf','avaliacao.pdf','termo.pdf']},
 duplicado:{label:'2 · Arquivo duplicado',files:['laudo.pdf','laudo.pdf']},
 versao:{label:'3 · Documento atualizado',files:['laudo.pdf','laudo-atualizado.pdf']},
 divergente:{label:'4 · Identidade divergente',files:['identidade-divergente.pdf']},
 identificador:{label:'5 · Identificador ausente',files:['sem-identificador.pdf']},
 ilegivel:{label:'6 · Imagem sem texto extraível',files:['imagem-ilegivel.png']},
 janela:{label:'7 · Data e marca a conferir',files:['solicitacao.pdf','laudo-antigo.pdf','avaliacao.pdf','termo-sem-marca.pdf']}
};
const normalize=x=>String(x??'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').trim().toLowerCase().replace(/\s+/g,' ');
export function validISO(s){if(!/^\d{4}-\d{2}-\d{2}$/.test(s))return false;const d=new Date(s+'T00:00:00Z');return Number.isFinite(+d)&&d.toISOString().slice(0,10)===s;}
export function brazilDate(s){const m=String(s??'').match(/^(\d{2})\/(\d{2})\/(\d{4})$/);if(!m)return '';const v=`${m[3]}-${m[2]}-${m[1]}`;return validISO(v)?v:'';}
export function stable(value){if(Array.isArray(value))return '['+value.map(stable).join(',')+']';if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+stable(value[k])).join(',')+'}';return JSON.stringify(value);}
export async function sha256(bytes){const b=typeof bytes==='string'?new TextEncoder().encode(bytes):bytes;return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',b)),v=>v.toString(16).padStart(2,'0')).join('');}
export async function allowedFixture(bytes,manifest,mimes=['application/pdf','image/png']){
 if(!bytes||bytes.byteLength===0||bytes.byteLength>524288)throw Error('Use um dos arquivos fictícios fornecidos, com até 512 KB.');
 const hash=await sha256(bytes);const f=manifest.files.find(v=>v.sha256===hash&&v.size===bytes.byteLength&&mimes.includes(v.mime));
 if(!f)throw Error('Arquivo recusado. Esta demo aceita somente os exemplos fictícios fornecidos, sem alterações.');
 return {...f};
}
export function extractFields(lines){
 const defs={patient:'Paciente:',birthDate:'Nascimento:',identifier:'Identificador:',issueDate:'Emissao:',type:'Tipo:',origin:'Origem:'};const fields={};
 for(const [key,prefix] of Object.entries(defs)){
  const matches=lines.filter(x=>normalize(x.text).startsWith(normalize(prefix)));
  if(matches.length!==1){fields[key]={value:'',source:null,uncertain:matches.length>1};continue;}
  const line=matches[0];const value=line.text.slice(line.text.indexOf(':')+1).trim();
  fields[key]={value,source:{page:line.page,box:[...line.box],text:line.text},uncertain:false};
 }
 const type=normalize(fields.type.value);return {fields,kind:Object.hasOwn(KINDS,type)&&type!=='desconhecido'?type:'desconhecido',readable:lines.some(x=>x.text.trim().length>4)};
}
export function identity(extraction,patient){
 if(!extraction.readable)return 'unreadable';
 const f=extraction.fields;const id=f.identifier.value;const name=f.patient.value;const dob=brazilDate(f.birthDate.value);
 if(f.identifier.uncertain||f.patient.uncertain||f.birthDate.uncertain)return 'conflict';
 if((id&&id!==patient.identifier)||(name&&normalize(name)!==normalize(patient.patient))||(dob&&dob!==patient.birthDate))return 'conflict';
 if(!name||!dob)return 'insufficient';
 return id?'suggested':'manual';
}
export class DocumentarySession{
 constructor(manifest){this.manifest=structuredClone(manifest);this.case=structuredClone(manifest.case);this.documents=[];this.events=[];this.resolutions={};this.assignments={};this.duplicates=0;this.policy={version:1,maxAgeDays:30};this.startedAt=new Date().toISOString();}
 async event(action,data={}){const payload={seq:this.events.length+1,previous:this.events.at(-1)?.hash||'0'.repeat(64),at:new Date().toISOString(),actor:'Revisor de demonstração',action,data};const hash=await sha256(stable(payload));this.events.push({...payload,hash});}
 doc(id){const d=this.documents.find(x=>x.id===id);if(!d)throw Error('Documento não encontrado.');return d;}
 async ingest(fixture,lines,elapsedMs=0){
  const known=this.manifest.files.find(x=>x.sha256===fixture.sha256&&['application/pdf','image/png'].includes(x.mime));
  if(!known)throw Error('Documento fora do conjunto sintético.');
  const duplicate=this.documents.find(x=>x.hash===fixture.sha256);
  if(duplicate){this.duplicates++;await this.event('duplicado_recusado',{document:duplicate.id,hash:fixture.sha256});return {duplicate:true,document:duplicate};}
  if(this.documents.length>=20)throw Error('Limite de 20 documentos por sessão.');
  const extraction=extractFields(lines);const d={id:'DOC-'+String(this.documents.length+1).padStart(3,'0'),caseId:null,name:known.name,mime:known.mime,hash:known.sha256,kind:extraction.kind,fields:extraction.fields,identity:identity(extraction,this.case),readable:extraction.readable,review:null,reviewHistory:[],status:'received',replaces:null,supersededBy:null,elapsedMs:Math.round(elapsedMs),receivedAt:new Date().toISOString()};
  d.extractionRun={id:'EXT-'+d.id,documentId:d.id,sourceHash:d.hash,engine:known.mime==='application/pdf'?'PDF.js 6.5.438 + regras-documentais-1.0':'sem OCR',at:d.receivedAt,elapsedMs:d.elapsedMs};
  this.documents.push(d);await this.event('documento_recebido',{document:d.id,hash:d.hash,identity:d.identity,engine:d.extractionRun.engine});return {duplicate:false,document:d};
 }
 async review(id,{identityChecked=false,issueDate='',signature='unknown',note=''}={}){
  const d=this.doc(id);if(d.status==='discarded'||d.supersededBy)throw Error('Documento inativo.');
  if(!['suggested','manual'].includes(d.identity)||d.kind==='desconhecido')throw Error('Documento em quarentena: confira identidade, legibilidade e tipo.');
  if(!identityChecked)throw Error('Confirme a conferência de identidade.');
  if(issueDate&&!validISO(issueDate))throw Error('Data de emissão inválida.');
  if(!['unknown','present','absent'].includes(signature))throw Error('Marcação inválida.');
  if(typeof note!=='string'||note.length>500)throw Error('Observação deve ter até 500 caracteres.');
  const original=brazilDate(d.fields.issueDate.value);
  if(issueDate!==original&&note.trim().length<5)throw Error('Explique a correção da data na observação.');
  const review={at:new Date().toISOString(),identityChecked:true,issueDate,signature:d.kind==='termo'?signature:'unknown',note:note.trim(),policyVersion:this.policy.version,originalIssueDate:original};
  for(const key of Object.keys(this.resolutions))if(key.startsWith(id+':'))delete this.resolutions[key];
  d.review=review;d.reviewHistory.push(structuredClone(review));d.caseId=this.case.id;d.status='reviewed';
  await this.event('revisao_humana',{document:id,review});
 }
 async discard(id,reason){const d=this.doc(id);if(d.supersededBy)throw Error('Versão anterior já preservada.');if(typeof reason!=='string'||reason.trim().length<5||reason.length>500)throw Error('Informe o motivo com 5 a 500 caracteres.');d.status='discarded';await this.event('documento_descartado',{document:id,reason:reason.trim()});}
 async replace(newId,oldId){const newer=this.doc(newId),older=this.doc(oldId);if(newId===oldId||newer.kind!==older.kind||newer.kind==='desconhecido'||!newer.review||!older.review||newer.caseId!==older.caseId||older.supersededBy||newer.supersededBy||newer.status==='discarded'||older.status==='discarded'||newer.replaces||older.replaces===newId)throw Error('Revise os dois documentos do mesmo tipo antes de confirmar a substituição.');newer.replaces=oldId;older.supersededBy=newId;await this.event('substituicao_confirmada',{previous:oldId,current:newId});}
 async configure(days){if(!Number.isInteger(days)||days<1||days>365)throw Error('A janela deve ter de 1 a 365 dias.');this.policy={version:this.policy.version+1,maxAgeDays:days};await this.event('regra_administrativa_alterada',{policy:this.policy});}
 active(){return this.documents.filter(d=>d.status!=='discarded'&&!d.supersededBy);}
 tasks(){
  const tasks=[];const active=this.active();const push=(id,title,docId,manual=false)=>{const key=`${id}:v${this.policy.version}`;tasks.push({id:key,title,docId,manual,resolution:this.resolutions[key]||null,assignment:this.assignments[key]||null});};
  for(const kind of ['solicitacao','laudo','avaliacao','termo'])if(!active.some(d=>d.kind===kind&&d.review))push('missing:'+kind,'Pendente: conferir '+KINDS[kind].toLowerCase(),null);
  for(const d of active){
   if(!d.readable){push(d.id+':unreadable','Imagem sem extração disponível; requer reenvio legível',d.id);continue;}
   if(['conflict','insufficient'].includes(d.identity)){push(d.id+':identity','Identidade divergente ou insuficiente; documento em quarentena',d.id);continue;}
   if(d.kind==='desconhecido'){push(d.id+':unknown','Tipo de documento não reconhecido',d.id);continue;}
   if(!d.review)push(d.id+':review',d.identity==='manual'?'Conferir identificação manualmente e revisar campos':'Conferir identidade e campos extraídos',d.id);
   const date=d.review?d.review.issueDate:brazilDate(d.fields.issueDate.value);
   if(!date)push(d.id+':date-missing','Data de emissão ausente ou inválida',d.id,true);
   else if(date>this.manifest.referenceDate)push(d.id+':future','Data de emissão posterior à data de referência do exemplo',d.id,true);
   else if(d.kind==='laudo'&&(Date.parse(this.case.procedureDate)-Date.parse(date))/86400000>this.policy.maxAgeDays)push(d.id+':window','Laudo fora da janela administrativa de '+this.policy.maxAgeDays+' dias',d.id,true);
   if(d.kind==='termo'&&(!d.review||d.review.signature!=='present'))push(d.id+':signature','Marca na área de assinatura requer conferência visual',d.id,true);
  }
  return tasks;
 }
 async assign(taskId,owner,due){if(!this.tasks().some(x=>x.id===taskId))throw Error('Pendência não encontrada.');if(!['Revisor A','Revisor B'].includes(owner)||!validISO(due))throw Error('Escolha responsável fictício e prazo válido.');this.assignments[taskId]={owner,due};await this.event('pendencia_atribuida',{taskId,owner,due});}
 async resolve(taskId,note){const t=this.tasks().find(x=>x.id===taskId);if(!t||!t.manual||!this.doc(t.docId).review)throw Error('Esta pendência exige revisão do documento ou envio de um substituto.');if(!this.assignments[taskId])throw Error('Atribua responsável e prazo antes de resolver.');if(typeof note!=='string'||note.trim().length<5||note.length>500)throw Error('Explique a resolução com 5 a 500 caracteres.');this.resolutions[taskId]={note:note.trim(),at:new Date().toISOString(),assignment:structuredClone(this.assignments[taskId])};await this.event('pendencia_resolvida',{taskId,resolution:this.resolutions[taskId]});}
 summary(){const tasks=this.tasks();return {documents:this.documents.length,active:this.active().length,reviewed:this.active().filter(x=>x.review).length,pending:tasks.filter(x=>!x.resolution).length,duplicates:this.duplicates,quarantine:this.active().filter(x=>!['suggested','manual'].includes(x.identity)).length};}
 export(){return {schema:'jyxia.documental-session.v1',version:VERSION,synthetic:true,notice:'Demonstração em memória. Não é prontuário, auditoria imutável ou liberação clínica.',case:structuredClone(this.case),policy:structuredClone(this.policy),referenceDate:this.manifest.referenceDate,documents:structuredClone(this.documents),tasks:structuredClone(this.tasks()),events:structuredClone(this.events),metrics:this.summary(),exportedAt:new Date().toISOString()};}
}
export async function verifyEvents(events){let previous='0'.repeat(64);for(let i=0;i<events.length;i++){const {hash,...payload}=events[i];if(payload.seq!==i+1||payload.previous!==previous||await sha256(stable(payload))!==hash)return false;previous=hash;}return true;}
