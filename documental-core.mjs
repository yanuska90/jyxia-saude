export const VERSION='3.1.0';
export const KINDS={solicitacao:'Solicitação',laudo:'Laudo de exame',avaliacao:'Formulário de avaliação',termo:'Termo documental',desconhecido:'Não classificado'};
export const SCENARIOS={
 completo:{label:'1 · Conjunto completo',files:['solicitacao.pdf','laudo.pdf','avaliacao.pdf','termo.pdf']},
 duplicado:{label:'2 · Arquivo duplicado',files:['laudo.pdf','laudo.pdf']},
 versao:{label:'3 · Documento atualizado',files:['laudo.pdf','laudo-atualizado.pdf']},
 divergente:{label:'4 · Identidade divergente',files:['identidade-divergente.pdf']},
 identificador:{label:'5 · Identificador ausente',files:['sem-identificador.pdf']},
 ilegivel:{label:'6 · Imagem sem texto extraível',files:['imagem-ilegivel.png']},
 janela:{label:'7 · Data e marca a conferir',files:['solicitacao.pdf','laudo-antigo.pdf','avaliacao.pdf','termo-sem-marca.pdf']},
 lateralidade:{label:'8 · Lateralidade divergente (OD × OE)',files:['solicitacao-od.pdf','termo-oe.pdf']}
};
const normalize=x=>String(x??'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').trim().toLowerCase().replace(/\s+/g,' ');
export function validISO(s){if(!/^\d{4}-\d{2}-\d{2}$/.test(s))return false;const d=new Date(s+'T00:00:00Z');return Number.isFinite(+d)&&d.toISOString().slice(0,10)===s;}
export function brazilDate(s){const m=String(s??'').match(/^(\d{2})\/(\d{2})\/(\d{4})$/);if(!m)return '';const v=`${m[3]}-${m[2]}-${m[1]}`;return validISO(v)?v:'';}
export function isoToBrazil(s){if(!validISO(s))return '';const [y,m,d]=s.split('-');return `${d}/${m}/${y}`;}
export function addDaysISO(s,days){if(!validISO(s)||!Number.isInteger(days))return '';const d=new Date(s+'T00:00:00Z');d.setUTCDate(d.getUTCDate()+days);return d.toISOString().slice(0,10);}
export function normalizeLaterality(text){
 const n=normalize(text);
 if(!n)return '';
 if(n==='nao aplicavel'||n==='nao se aplica'||n==='n/a'||n==='na')return 'nao_aplicavel';
 const hasRight=/\b(od|direit[oa]|olho direito|lado direito)\b/.test(n);
 const hasLeft=/\b(oe|esquerd[oa]|olho esquerdo|lado esquerdo)\b/.test(n);
 const hasBoth=/\b(ao|bilateral|ambos|ambos os olhos)\b/.test(n);
 if((hasRight&&hasLeft)||(hasBoth&&(hasRight||hasLeft)))return 'abstencao';
 if(hasBoth)return 'bilateral';
 if(hasRight)return 'direito';
 if(hasLeft)return 'esquerdo';
 return 'abstencao';
}
export function parseSyntheticCase(text,mime){
 if(typeof text!=='string'||!text.trim())throw Error('Cadastro sintético vazio.');
 const clean=text.replace(/^\uFEFF/,'').trim();let item;
 if(mime==='application/json'){
  let parsed;try{parsed=JSON.parse(clean);}catch{throw Error('JSON de cadastro sintético inválido.');}
  if(!parsed?.synthetic||!Array.isArray(parsed.cases)||!parsed.cases.length)throw Error('Estrutura de cadastro sintético inválida.');
  item=parsed.cases[0];
 }else if(mime==='text/csv'){
  const rows=clean.split(/\r?\n/).map(r=>r.trim()).filter(Boolean);
  if(rows.length<2)throw Error('CSV de cadastro sintético incompleto.');
  const headers=rows[0].split(',').map(x=>x.trim()),values=rows[1].split(',').map(x=>x.trim());
  if(headers.length!==values.length)throw Error('Colunas incompatíveis no CSV sintético.');
  item=Object.fromEntries(headers.map((h,i)=>[h,values[i]]));
 }else throw Error('Formato de cadastro não suportado.');
 const required=['id','patient','birthDate','identifier','procedureDate'];
 for(const k of required)if(typeof item?.[k]!=='string'||!item[k].trim())throw Error('Campo obrigatório ausente no cadastro: '+k);
 if(!validISO(item.birthDate)||!validISO(item.procedureDate))throw Error('Datas inválidas no cadastro sintético.');
 return {id:item.id.trim(),patient:item.patient.trim(),birthDate:item.birthDate.trim(),identifier:item.identifier.trim(),procedureDate:item.procedureDate.trim()};
}
export async function extractPdfLines(doc,transformFn,maxPages=5){
 if(doc.numPages>maxPages){if(doc.loadingTask?.destroy)await doc.loadingTask.destroy();else if(doc.destroy)await doc.destroy();throw Error('Limite de cinco páginas por documento.');}
 const lines=[];
 for(let i=1;i<=doc.numPages;i++){
  const p=await doc.getPage(i),v=p.getViewport({scale:1}),content=await p.getTextContent();
  for(const item of content.items){
   if(!item.str?.trim())continue;
   const t=transformFn(v.transform,item.transform),rawH=Math.hypot(t[2],t[3]),height=Math.max(rawH,8),scaleH=rawH>0?height/rawH:1;
   const hx=rawH>0?t[2]*scaleH:0,hy=rawH>0?t[3]*scaleH:-height,angle=Math.atan2(t[1],t[0]),wx=Math.cos(angle)*item.width,wy=Math.sin(angle)*item.width;
   const xs=[t[4],t[4]+wx,t[4]+hx,t[4]+wx+hx],ys=[t[5],t[5]+wy,t[5]+hy,t[5]+wy+hy];
   const minX=Math.max(0,Math.min(...xs)/v.width),maxX=Math.min(1,Math.max(...xs)/v.width),minY=Math.max(0,Math.min(...ys)/v.height),maxY=Math.min(1,Math.max(...ys)/v.height);
   lines.push({text:item.str,page:i,box:[minX,minY,Math.max(0,maxX-minX),Math.max(0,maxY-minY)]});
  }
 }
 return lines;
}
export function stable(value){if(Array.isArray(value))return '['+value.map(stable).join(',')+']';if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+stable(value[k])).join(',')+'}';return JSON.stringify(value);}
export async function sha256(bytes){const b=typeof bytes==='string'?new TextEncoder().encode(bytes):bytes;return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',b)),v=>v.toString(16).padStart(2,'0')).join('');}
export async function allowedFixture(bytes,manifest,mimes=['application/pdf','image/png']){
 if(!bytes||bytes.byteLength===0||bytes.byteLength>524288)throw Error('Use um dos arquivos fictícios fornecidos, com até 512 KB.');
 const hash=await sha256(bytes);const f=manifest.files.find(v=>v.sha256===hash&&v.size===bytes.byteLength&&mimes.includes(v.mime));
 if(!f)throw Error('Arquivo recusado. Esta demo aceita somente os exemplos fictícios fornecidos, sem alterações.');
 return {...f};
}
export function csvSafeCell(value){
 const raw=String(value??'').replace(/\r?\n/g,' ');
 const safe=/^[=+\-@\t\r]/.test(raw)?"'"+raw:raw;
 return '"'+safe.replace(/"/g,'""')+'"';
}
export function extractFields(lines){
 const defs={patient:'Paciente:',birthDate:'Nascimento:',identifier:'Identificador:',issueDate:'Emissao:',type:'Tipo:',origin:'Origem:',subfamily:'Subfamilia:',procedure:'Procedimento:',laterality:'Lateralidade:'};
 const fields={};
 for(const [key,prefix] of Object.entries(defs)){
  const matches=lines.filter(x=>normalize(x.text).startsWith(normalize(prefix)));
  if(matches.length!==1){fields[key]={value:'',source:null,uncertain:matches.length>1};continue;}
  const line=matches[0];const value=line.text.slice(line.text.indexOf(':')+1).trim();
  fields[key]={value,source:{page:line.page,box:[...line.box],text:line.text},uncertain:false};
 }
 if(fields.laterality.value)fields.laterality.normalized=normalizeLaterality(fields.laterality.value);
 const sigMatches=lines.filter(x=>normalize(x.text)==='marca ficticia');
 fields.signatureCue=sigMatches.length===1
  ?{value:'Marca visual presente (nao autentica)',source:{page:sigMatches[0].page,box:[...sigMatches[0].box],text:sigMatches[0].text},uncertain:false}
  :{value:'',source:null,uncertain:sigMatches.length>1};
 const type=normalize(fields.type.value);
 return {fields,kind:Object.hasOwn(KINDS,type)&&type!=='desconhecido'?type:'desconhecido',readable:lines.some(x=>x.text.trim().length>4)};
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
  const extraction=extractFields(lines);
  const d={id:'DOC-'+String(this.documents.length+1).padStart(3,'0'),caseId:null,name:known.name,mime:known.mime,hash:known.sha256,kind:extraction.kind,subfamily:extraction.fields.subfamily?.value||'',fields:extraction.fields,identity:identity(extraction,this.case),readable:extraction.readable,review:null,reviewHistory:[],status:'received',replaces:null,supersededBy:null,elapsedMs:Math.round(elapsedMs),receivedAt:new Date().toISOString()};
  d.extractionRun={id:'EXT-'+d.id,documentId:d.id,sourceHash:d.hash,engine:known.mime==='application/pdf'?'PDF.js 6.5.438 + regras-documentais-1.1':'sem OCR',at:d.receivedAt,elapsedMs:d.elapsedMs};
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
 async replace(newId,oldId){
  const newer=this.doc(newId),older=this.doc(oldId);
  if(newId===oldId||newer.kind!==older.kind||newer.kind==='desconhecido'||!newer.review||!older.review||newer.caseId!==older.caseId||older.supersededBy||newer.supersededBy||newer.status==='discarded'||older.status==='discarded'||newer.replaces||older.replaces===newId)throw Error('Revise os dois documentos do mesmo tipo antes de confirmar a substituição.');
  if(newer.subfamily&&older.subfamily&&normalize(newer.subfamily)!==normalize(older.subfamily))throw Error('Subfamílias documentais distintas; confirme substituição apenas dentro da mesma subfamília.');
  newer.replaces=oldId;older.supersededBy=newId;await this.event('substituicao_confirmada',{previous:oldId,current:newId});
 }
 async configure(days){if(!Number.isInteger(days)||days<1||days>365)throw Error('A janela deve ter de 1 a 365 dias.');this.policy={version:this.policy.version+1,maxAgeDays:days};await this.event('regra_administrativa_alterada',{policy:this.policy});}
 async loadSyntheticCase(known,text){const file=this.manifest.files.find(x=>x.sha256===known?.sha256&&['application/json','text/csv'].includes(x.mime));if(!file)throw Error('Cadastro fora do conjunto sintético autorizado.');const parsed=parseSyntheticCase(text,file.mime);this.case=parsed;await this.event('cadastro_importado',{name:file.name,hash:file.sha256,caseId:this.case.id,identifier:this.case.identifier});return structuredClone(this.case);}
 active(){return this.documents.filter(d=>d.status!=='discarded'&&!d.supersededBy);}
 _coreTasks(){
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
 consistencyAxes(){
  const active=this.active();
  const baseTasks=this._coreTasks();
  if(!active.length){
   return [
    {id:'identity',label:'1. Identidade cadastral',status:'pendente',blocking:false,detail:'Nenhum documento recebido nesta sessão.'},
    {id:'procedure',label:'2. Procedimento informado',status:'pendente',blocking:false,detail:'Aguardando documentos para conferência de procedimento.'},
    {id:'laterality',label:'3. Lateralidade (quando aplicável)',status:'pendente',blocking:false,detail:'Aguardando documentos para conferência de lateralidade.'},
    {id:'temporality',label:'4. Temporalidade e versões',status:'pendente',blocking:false,detail:'Aguardando documentos e revisão humana.'}
   ];
  }
  // Eixo 1 — Identidade
  const conflicts=active.filter(d=>d.identity==='conflict');
  const abstainsId=active.filter(d=>d.identity==='unreadable'||d.identity==='insufficient');
  const unreviewedId=active.filter(d=>['suggested','manual'].includes(d.identity)&&!d.review);
  let identityAxis;
  if(conflicts.length)identityAxis={id:'identity',label:'1. Identidade cadastral',status:'conflito',blocking:true,detail:'Divergência de identidade em quarentena ('+conflicts.map(d=>d.name).join(', ')+'). Vínculo bloqueado.'};
  else if(abstainsId.length)identityAxis={id:'identity',label:'1. Identidade cadastral',status:'abstencao',blocking:true,detail:'Abstenção obrigatória por ilegibidade ou dados insuficientes ('+abstainsId.map(d=>d.name).join(', ')+').'};
  else if(unreviewedId.length)identityAxis={id:'identity',label:'1. Identidade cadastral',status:'pendente',blocking:false,detail:'Aguardando confirmação humana em '+unreviewedId.length+' documento(s).'};
  else identityAxis={id:'identity',label:'1. Identidade cadastral',status:'ok',blocking:false,detail:'Nenhuma divergência identificada nos documentos revisados para '+this.case.patient+'.'};

  // Eixo 2 — Procedimento
  const procDocs=active.filter(d=>d.readable&&d.fields.procedure);
  const procUncertain=procDocs.filter(d=>d.fields.procedure.uncertain);
  const procEntries=procDocs.filter(d=>d.fields.procedure.value?.trim()).map(d=>({doc:d.name,raw:d.fields.procedure.value.trim(),norm:normalize(d.fields.procedure.value)}));
  const procUnique=[...new Map(procEntries.map(x=>[x.norm,x])).values()];
  let procedureAxis;
  if(procUncertain.length)procedureAxis={id:'procedure',label:'2. Procedimento informado',status:'conflito',blocking:true,detail:'Múltiplos valores de procedimento no mesmo documento ('+procUncertain.map(d=>d.name).join(', ')+'). Requer revisão humana.'};
  else if(procUnique.length>1)procedureAxis={id:'procedure',label:'2. Procedimento informado',status:'conflito',blocking:true,detail:'Divergência de procedimento entre documentos ativos: '+procEntries.map(e=>`${e.doc} (${e.raw})`).join(' × ')+'.'};
  else if(procUnique.length===1)procedureAxis={id:'procedure',label:'2. Procedimento informado',status:'ok',blocking:false,detail:'Texto compatível nos documentos informados: '+procUnique[0].raw+'.'};
  else procedureAxis={id:'procedure',label:'2. Procedimento informado',status:'abstencao',blocking:false,detail:'Informação não localizada nos campos extraídos; revisão humana requerida (sem inferência clínica).'};

  // Eixo 3 — Lateralidade
  const latDocs=active.filter(d=>d.readable&&d.fields.laterality);
  const latUncertain=latDocs.filter(d=>d.fields.laterality.uncertain||(d.fields.laterality.value?.trim()&&normalizeLaterality(d.fields.laterality.value)==='abstencao'));
  const latEntries=latDocs.filter(d=>d.fields.laterality.value?.trim()).map(d=>({doc:d.name,raw:d.fields.laterality.value.trim(),code:normalizeLaterality(d.fields.laterality.value)}));
  const latDirs=latEntries.filter(x=>['direito','esquerdo','bilateral'].includes(x.code));
  const latDirCodes=[...new Set(latDirs.map(x=>x.code))];
  const latNa=latEntries.filter(x=>x.code==='nao_aplicavel');
  let lateralityAxis;
  if(latUncertain.length)lateralityAxis={id:'laterality',label:'3. Lateralidade (quando aplicável)',status:'abstencao',blocking:true,detail:'Lateralidade ambígua ou não reconhecida em '+latUncertain.map(d=>d.name).join(', ')+'. Requer revisão humana.'};
  else if(latDirCodes.length>1||(latDirs.length>0&&latNa.length>0))lateralityAxis={id:'laterality',label:'3. Lateralidade (quando aplicável)',status:'conflito',blocking:true,detail:'Divergência de lateralidade entre documentos ativos: '+latEntries.map(e=>`${e.doc} (${e.raw})`).join(' × ')+'. Abstenção automática; revisão humana obrigatória.'};
  else if(latDirCodes.length===1)lateralityAxis={id:'laterality',label:'3. Lateralidade (quando aplicável)',status:'ok',blocking:false,detail:'Lateralidade compatível nos documentos informados: '+latDirs[0].raw+'.'};
  else if(latNa.length>0)lateralityAxis={id:'laterality',label:'3. Lateralidade (quando aplicável)',status:'nao_aplicavel',blocking:false,detail:'Lateralidade declarada como não aplicável nos documentos.'};
  else lateralityAxis={id:'laterality',label:'3. Lateralidade (quando aplicável)',status:'abstencao',blocking:false,detail:'Lateralidade não informada nos documentos; conferir quando aplicável ao procedimento.'};

  // Eixo 4 — Temporalidade, validade e versão
  const openTemp=baseTasks.filter(t=>!t.resolution&&(t.id.includes(':window:')||t.id.includes(':future:')||t.id.includes(':date-missing:')||t.id.includes(':signature:')||t.id.startsWith('missing:')||t.id.includes(':review:')));
  const replacedCount=this.documents.filter(d=>d.supersededBy).length;
  let temporalityAxis;
  if(openTemp.length)temporalityAxis={id:'temporality',label:'4. Temporalidade e versões',status:'atencao',blocking:false,detail:`${openTemp.length} item(ns) documental(is) ou temporal(is) aguardando conferência/resolução (${replacedCount} substituição(ões) preservada(s)).`};
  else temporalityAxis={id:'temporality',label:'4. Temporalidade e versões',status:'ok',blocking:false,detail:`Datas, janela de ${this.policy.maxAgeDays} dias e ${replacedCount} substituição(ões) conferidas segundo as regras executadas.`};

  return [identityAxis,procedureAxis,lateralityAxis,temporalityAxis];
 }
 tasks(){
  const tasks=this._coreTasks();
  const axes=this.consistencyAxes();
  const push=(id,title)=>{const key=`${id}:v${this.policy.version}`;tasks.push({id:key,title,docId:null,manual:false,resolution:null,assignment:this.assignments[key]||null});};
  const procAxis=axes.find(a=>a.id==='procedure');
  const latAxis=axes.find(a=>a.id==='laterality');
  if(procAxis?.blocking)push('axis:procedure','Divergência de procedimento entre documentos ativos — retirar ou substituir documento conflitante');
  if(latAxis?.blocking)push('axis:laterality','Conflito ou ambiguidade de lateralidade entre documentos ativos — retirar ou substituir antes de concluir');
  return tasks;
 }
 async assign(taskId,owner,due){if(!this.tasks().some(x=>x.id===taskId))throw Error('Pendência não encontrada.');if(!['Revisor A','Revisor B'].includes(owner)||!validISO(due))throw Error('Escolha responsável fictício e prazo válido.');this.assignments[taskId]={owner,due};await this.event('pendencia_atribuida',{taskId,owner,due});}
 async resolve(taskId,note){const t=this.tasks().find(x=>x.id===taskId);if(!t||!t.manual||!this.doc(t.docId).review)throw Error('Esta pendência exige revisão do documento ou envio de um substituto.');if(!this.assignments[taskId])throw Error('Atribua responsável e prazo antes de resolver.');if(typeof note!=='string'||note.trim().length<5||note.length>500)throw Error('Explique a resolução com 5 a 500 caracteres.');this.resolutions[taskId]={note:note.trim(),at:new Date().toISOString(),assignment:structuredClone(this.assignments[taskId])};await this.event('pendencia_resolvida',{taskId,resolution:this.resolutions[taskId]});}
 summary(){const tasks=this.tasks();const active=this.active();return {documents:this.documents.length,active:active.length,reviewed:active.filter(x=>x.review).length,pending:tasks.filter(x=>!x.resolution).length,duplicates:this.duplicates,quarantine:active.filter(x=>!['suggested','manual'].includes(x.identity)).length};}
 readinessState(){
  const active=this.active(),axes=this.consistencyAxes(),s=this.summary(),tasks=this.tasks();
  if(!this.documents.length)return {code:'aguardando',label:'Aguardando documentos',administrativeOnly:true};
  if(axes.some(a=>a.status==='conflito')||s.quarantine>0)return {code:'conflito',label:s.quarantine?'Documento em quarentena · revisão obrigatória':'Divergência bloqueante · revisão obrigatória',administrativeOnly:true};
  if(s.pending>0)return {code:'pendente',label:`${s.pending} pendência(s) documental(is)`,administrativeOnly:true};
  const allFour=['solicitacao','laudo','avaliacao','termo'].every(k=>active.some(d=>d.kind===k&&d.review));
  if(allFour&&tasks.every(t=>t.resolution))return {code:'conferida',label:'Documentação conferida (regras do exemplo)',administrativeOnly:true};
  return {code:'pendente',label:'Conferência incompleta',administrativeOnly:true};
 }
 buildPendingNotice(){
  const axes=this.consistencyAxes(),tasks=this.tasks().filter(t=>!t.resolution),r=this.readinessState();
  const lines=[
   `JYXIA · Resumo Administrativo de Conferência Documental (Dados Fictícios)`,
   `Caso: ${this.case.id} · Paciente fictício: ${this.case.patient} (${this.case.identifier}) · Procedimento previsto: ${isoToBrazil(this.case.procedureDate)||this.case.procedureDate}`,
   `Estado administrativo: ${r.label}`,
   ``,
   `Eixos de consistência:`
  ];
  for(const a of axes)lines.push(`- ${a.label} [${a.status.toUpperCase()}]: ${a.detail}`);
  if(tasks.length){
   lines.push(``,`Itens em aberto (${tasks.length}):`);
   for(const t of tasks){
    const doc=t.docId?this.doc(t.docId):null;
    const prazo=t.assignment?` · Resp.: ${t.assignment.owner}, prazo ${isoToBrazil(t.assignment.due)||t.assignment.due}`:'';
    lines.push(`- ${t.title}${doc?' ['+doc.name+']':''}${prazo}`);
   }
  }else{
   lines.push(``,`Nenhuma divergência ou pendência aberta nas regras executadas.`);
  }
  lines.push(``,`Aviso: uso exclusivamente administrativo sobre dados fictícios; não substitui avaliação médica nem libera procedimento.`);
  return lines.join('\n');
 }
 exportCsv(){
  const headers=['documento_id','arquivo','tipo_documental','subfamilia','identidade','caso_vinculado','procedimento_extraido','lateralidade_extraida','marca_visual','emissao_extraida','emissao_revisada','status','substitui_id','substituido_por','observacao_revisao'];
  const rows=[headers.map(csvSafeCell).join(',')];
  for(const d of this.documents){
   rows.push([
    d.id,
    d.name,
    KINDS[d.kind]||d.kind,
    d.subfamily||'',
    d.identity,
    d.caseId||'',
    d.fields.procedure?.value||'',
    d.fields.laterality?.value||'',
    d.fields.signatureCue?.value||'',
    d.fields.issueDate?.value||'',
    d.review?.issueDate||'',
    d.status,
    d.replaces||'',
    d.supersededBy||'',
    d.review?.note||''
   ].map(csvSafeCell).join(','));
  }
  return rows.join('\n');
 }
 export(){return {schema:'jyxia.documental-session.v1',version:VERSION,synthetic:true,notice:'Demonstração em memória. Não é prontuário, auditoria imutável ou liberação clínica.',case:structuredClone(this.case),policy:structuredClone(this.policy),referenceDate:this.manifest.referenceDate,readiness:this.readinessState(),consistencyAxes:this.consistencyAxes(),documents:structuredClone(this.documents),tasks:structuredClone(this.tasks()),events:structuredClone(this.events),metrics:this.summary(),exportedAt:new Date().toISOString()};}
}
export async function verifyEvents(events){let previous='0'.repeat(64);for(let i=0;i<events.length;i++){const {hash,...payload}=events[i];if(payload.seq!==i+1||payload.previous!==previous||await sha256(stable(payload))!==hash)return false;previous=hash;}return true;}
