(() => {
 'use strict';
 const $ = id => document.getElementById(id);
 const form = $('record-form');
 const apiMode = window.JYXIA_STORAGE === 'api';
 const maxFile = 10 * 1024 * 1024;
 const allowed = new Set(['application/pdf','image/png','image/jpeg','text/plain']);
 let db, rows = [], editing = null, token = '', retained = [];
 const say = (text, error = false) => { $('record-message').textContent = text; $('record-message').className = error ? 'form-message error' : 'form-message'; };
 const req = request => new Promise((resolve,reject) => { request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error); });
 const transaction = (operation) => new Promise((resolve,reject) => {
  const tx = db.transaction('records','readwrite'); operation(tx.objectStore('records'));
  tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(tx.error);
 });
 async function api(path, options={}) {
  const response=await fetch('/api'+path,{...options,headers:{Authorization:'Bearer '+token,...options.headers}});
  if(!response.ok){ let detail='Não foi possível concluir a operação.';try {const body=await response.json();if(typeof body.detail==='string')detail=body.detail;}catch{}throw Error(detail); }
  return response.status===204 ? null : response.json();
 }
 async function load() {
  rows=apiMode ? await api('/records') : await req(db.transaction('records').objectStore('records').getAll()); render();
 }
 const paragraph=(parent,label,value)=>{const p=document.createElement('p');const strong=document.createElement('strong');strong.textContent=label+': ';p.append(strong,document.createTextNode(value||'Não informado'));parent.append(p);};
 function cancelEdit(){editing=null;retained=[];form.reset();$('record-dose').required=true;$('record-dose-group').hidden=false;$('save-record').textContent='Salvar registro';$('cancel-record').hidden=true;$('retained-files').textContent='';}
 function render() {
  const list=$('record-list');list.replaceChildren();$('record-count').textContent=rows.length+' registro(s) adicionado(s)';
  if(!rows.length){const p=document.createElement('p');p.textContent='Nenhum registro adicionado. Preencha os campos acima.';list.append(p);return;}
  for(const row of [...rows].sort((a,b)=>b.created_at.localeCompare(a.created_at))){
   const article=document.createElement('article');article.className='record user-record';
   const tag=document.createElement('span');tag.className='tag warn';tag.textContent='Informado manualmente · não validado clinicamente';article.append(tag);
   const title=document.createElement('h3');title.textContent=row.name;article.append(title);
   paragraph(article,'Tipo',{medicamento:'Medicamento',exame:'Exame ou laudo',outro:'Outro registro'}[row.kind]);
   if(row.kind==='medicamento')paragraph(article,'Dosagem informada',row.dosage);
   paragraph(article,'Data do registro',row.record_date.split('-').reverse().join('/'));
   paragraph(article,'Origem',row.source);paragraph(article,'Observações',row.notes);
   const files=document.createElement('div');files.className='attachment-list';
   for(const file of row.attachments||[]){
    const button=document.createElement('button');button.type='button';button.className='secondary';button.textContent='Baixar '+file.name;
    button.onclick=async()=>{try{
     let blob=file.blob;
     if(apiMode){const r=await fetch('/api/records/'+row.id+'/attachments/'+file.id,{headers:{Authorization:'Bearer '+token}});if(!r.ok)throw Error('Não foi possível baixar o anexo.');blob=await r.blob();}
     const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=file.name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    }catch(e){say(e.message,true);}};files.append(button);
   }article.append(files);
   const actions=document.createElement('div');actions.className='actions';
   const edit=document.createElement('button');edit.className='secondary';edit.type='button';edit.textContent='Editar registro';edit.onclick=()=>{
    editing=row.id;retained=row.attachments||[];$('record-kind').value=row.kind;$('record-name').value=row.name;$('record-dose').value=row.dosage||'';$('record-date').value=row.record_date;$('record-source').value=row.source;$('record-notes').value=row.notes||'';$('record-files').value='';$('record-dose-group').hidden=row.kind!=='medicamento';$('record-dose').required=row.kind==='medicamento';$('save-record').textContent='Salvar alterações';$('cancel-record').hidden=false;$('retained-files').textContent=retained.length+' anexo(s) existente(s) será(ão) mantido(s).';form.scrollIntoView({behavior:'smooth',block:'start'});$('record-name').focus();
   };
   const remove=document.createElement('button');remove.type='button';remove.className='secondary';remove.textContent='Remover registro';
   const confirm=document.createElement('button');confirm.type='button';confirm.textContent='Confirmar remoção de '+row.name;confirm.hidden=true;
   const back=document.createElement('button');back.type='button';back.className='secondary';back.textContent='Cancelar remoção';back.hidden=true;
   remove.onclick=()=>{remove.hidden=true;confirm.hidden=false;back.hidden=false;};back.onclick=()=>{remove.hidden=false;confirm.hidden=true;back.hidden=true;};
   confirm.onclick=async()=>{confirm.disabled=true;try{if(apiMode)await api('/records/'+row.id,{method:'DELETE'});else await transaction(store=>store.delete(row.id));if(editing===row.id)cancelEdit();await load();say('Registro removido.');}catch(e){say(e.message,true);confirm.disabled=false;}};
   actions.append(edit,remove,confirm,back);article.append(actions);list.append(article);
  }
 }
 form.addEventListener('submit',async event=>{
  event.preventDefault();if(!form.reportValidity())return;
  const selected=[...$('record-files').files];
  if(selected.length+retained.length>5){say('Use no máximo 5 anexos por registro.',true);return;}
  if(selected.some(f=>!allowed.has(f.type)||f.size>maxFile||!f.size)){say('Use PDF, PNG, JPG ou TXT, com até 10 MB por arquivo e tamanho maior que zero.',true);return;}
  const fields={kind:$('record-kind').value,name:$('record-name').value.trim(),dosage:$('record-kind').value==='medicamento'?$('record-dose').value.trim():'',record_date:$('record-date').value,source:$('record-source').value.trim(),notes:$('record-notes').value.trim()};
  if(!fields.name||!fields.source||(fields.kind==='medicamento'&&!fields.dosage)){say('Preencha os campos obrigatórios, sem usar somente espaços.',true);return;}
  $('save-record').disabled=true;
  try{
   if(apiMode){
    const data=new FormData();data.append('record',JSON.stringify(fields));for(const file of selected)data.append('files',file);
    const previous=rows.find(r=>r.id===editing);
    await api(editing?'/records/'+editing:'/records',{method:editing?'PUT':'POST',body:data,headers:editing?{'If-Match':String(previous.version)}:{}});
   }else{
    const existing=rows.find(r=>r.id===editing);
    if(!editing&&rows.length>=100)throw Error('Limite de 100 registros deste protótipo atingido. Remova um registro antes de adicionar outro.');
    const record={...fields,id:editing||crypto.randomUUID(),created_at:existing?.created_at||new Date().toISOString(),updated_at:new Date().toISOString(),attachments:[...retained,...selected.map(file=>({id:crypto.randomUUID(),name:file.name,type:file.type,size:file.size,blob:file}))]};
    await transaction(store=>store.put(record));
   }
   cancelEdit();await load();say(apiMode?'Registro salvo no banco do ambiente Docker.':'Registro e anexos salvos neste navegador.');
  }catch(e){say('Não foi possível salvar. '+(e.name==='QuotaExceededError'?'O armazenamento do navegador está cheio.':e.message),true);}finally{$('save-record').disabled=false;}
 });
 $('record-kind').onchange=()=>{const medication=$('record-kind').value==='medicamento';$('record-dose-group').hidden=!medication;$('record-dose').required=medication;};
 $('cancel-record').onclick=cancelEdit;
 if(apiMode){
  $('storage-note').textContent='Ambiente Docker de desenvolvimento: os registros ficam no MongoDB e os anexos no GridFS. Use apenas dados fictícios. Este protótipo ainda não possui gestão de usuários ou autorização clínica.';
  $('api-access').hidden=false;$('record-workspace').hidden=true;
  $('api-login').onsubmit=async event=>{event.preventDefault();token=$('api-token').value;try{await load();$('record-workspace').hidden=false;$('api-token').value='';$('api-access').hidden=true;$('api-logout').hidden=false;say('Ambiente de desenvolvimento conectado.');}catch(e){token='';say(e.message,true);}};
  $('api-logout').onclick=()=>{token='';rows=[];cancelEdit();render();$('record-workspace').hidden=true;$('api-access').hidden=false;$('api-logout').hidden=true;say('Sessão de teste encerrada.');};
 }else{
  const open=indexedDB.open('jyxia-demo-records-v1',1);open.onupgradeneeded=()=>open.result.createObjectStore('records',{keyPath:'id'});
  req(open).then(database=>{db=database;return load();}).catch(()=>{form.querySelectorAll('input,select,textarea,button').forEach(e=>e.disabled=true);say('O navegador bloqueou o armazenamento. O cadastro não está disponível; use outro navegador com armazenamento habilitado.',true);});
 }
})();
