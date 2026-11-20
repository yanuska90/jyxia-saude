/* One encrypted local vault per browser profile, for synthetic demonstration only. */
(() => {
 'use strict';
 if(window.JYXIA_STORAGE==='api')return;
 const $=id=>document.getElementById(id), crypt=window.JYXIA_CRYPTO;
 let db,meta,key=null,epoch=0,lastActivity=0,failures=0,blockedUntil=0,busy=false,legacyCount=0;
 const channel=typeof BroadcastChannel==='function'?new BroadcastChannel('jyxia-vault-lock'):null;
 const req=r=>new Promise((resolve,reject)=>{r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
 const message=(value,error=false)=>{$('vault-message').textContent=value;$('vault-message').className=error?'form-message error':'form-message';};
 const lockedError=()=>Error('Área bloqueada. Entre novamente para continuar.');
 function assertOpen(expected=epoch){if(!key || expected!==epoch)throw lockedError();}
 function notify(type){document.dispatchEvent(new Event(type));}
 function lock(text='Área bloqueada. Entre novamente para ver os registros.',broadcast=true) {
  key=null;epoch++;lastActivity=0;
  $('record-workspace').hidden=true;$('vault-session').hidden=true;$('vault-login').hidden=false;
  $('vault-password').value='';$('vault-confirm').value='';
  notify('jyxia:locked');message(text);
  if(broadcast)channel?.postMessage('lock');
 }
 function showOpen(){lastActivity=Date.now();$('vault-login').hidden=true;$('vault-session').hidden=false;message('Área aberta neste navegador. Bloqueio após 5 minutos sem atividade ou ao sair desta aba.');notify('jyxia:unlocked');}
 const readAll=()=>req(db.transaction('records').objectStore('records').getAll());
 function mutate(operation){return new Promise((resolve,reject)=>{const tx=db.transaction('records','readwrite');operation(tx.objectStore('records'));tx.oncomplete=resolve;tx.onabort=()=>reject(tx.error||Error('Alteração cancelada.'));tx.onerror=()=>reject(tx.error);});}
 async function initializeAccount(username,password) {
  const expected=epoch;
  const original=await readAll();
  if(original.some(r=>r.encrypted))throw Error('Há dados protegidos sem configuração compatível. Nada foi alterado.');
  const fresh=await crypt.create(username,password);
  const sealed=[];
  for(const row of original)sealed.push(await crypt.encryptRecord(fresh.key,fresh.meta.vaultId,row));
  if(expected!==epoch)throw lockedError();
  // Re-check and commit metadata plus every migrated record in one transaction.
  await new Promise((resolve,reject)=>{
   const tx=db.transaction(['records','settings'],'readwrite');
   let conflict=false;
   tx.objectStore('settings').get('vault').onsuccess=e=>{
    if(e.target.result){conflict=true;tx.abort();return;}
    tx.objectStore('records').getAll().onsuccess=e2=>{
     const current=e2.target.result;
     const signature=rows=>JSON.stringify(rows.map(r=>[r.id,r.updated_at,r.created_at,r.attachments?.length]));
     if(expected!==epoch || signature(current)!==signature(original)){conflict=true;tx.abort();return;}
     const store=tx.objectStore('records');store.clear();sealed.forEach(r=>store.put(r));tx.objectStore('settings').put(fresh.meta);
    };
   };
   tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(conflict?Error('O armazenamento mudou em outra aba. Recarregue para continuar.'):tx.error);
  });
  meta=fresh.meta;
  $('vault-setup').hidden=true;$('vault-confirm').required=false;$('vault-accept').required=false;$('vault-submit').textContent='Entrar';$('vault-title').textContent='Entre na área de registros';
  if(expected!==epoch)throw lockedError();
  key=fresh.key;
 }
 window.JYXIA_VAULT=Object.freeze({
  isOpen:()=>Boolean(key),
  lock,
  async list(){assertOpen();const expected=epoch,active=key;const envelopes=await readAll();const rows=[];for(const row of envelopes){rows.push(await crypt.decryptRecord(active,meta.vaultId,row));assertOpen(expected);}assertOpen(expected);return rows;},
  async put(row){assertOpen();const expected=epoch;const envelope=await crypt.encryptRecord(key,meta.vaultId,row);assertOpen(expected);await mutate(store=>store.put(envelope));assertOpen(expected);},
  async remove(id){assertOpen();const expected=epoch;await mutate(store=>store.delete(id));assertOpen(expected);}
 });
 $('vault-access').hidden=false;
 $('vault-login').onsubmit=async event=>{
  event.preventDefault();if(busy || !$('vault-login').reportValidity())return;
  if(Date.now()<blockedUntil){message('Aguarde um minuto após as tentativas incorretas antes de tentar novamente.',true);return;}
  const username=$('vault-user').value.trim();let password=$('vault-password').value;
  if(!meta && password!==$('vault-confirm').value){message('As senhas precisam ser iguais.',true);return;}
  $('vault-password').value='';$('vault-confirm').value='';busy=true;$('vault-submit').disabled=true;const expected=epoch;
  message(meta?'Verificando acesso…':'Protegendo o armazenamento. Aguarde nesta aba…');
  try {
   if(meta){const candidate=await crypt.unlock(meta,username,password);if(expected!==epoch)throw lockedError();key=candidate;}
   else await initializeAccount(username,password);
   password='';failures=0;showOpen();
  }catch(e){password='';key=null;failures++;if(failures>=5){blockedUntil=Date.now()+60000;failures=0;}message(e.message,true);}
  finally{busy=false;$('vault-submit').disabled=false;}
 };
 $('vault-lock').onclick=()=>{lock();$('vault-user').focus();};
 channel && (channel.onmessage=event=>{if(event.data==='lock')lock('Área bloqueada por outra aba.',false);});
 for(const event of ['pointerdown','keydown','touchstart'])document.addEventListener(event,()=>{if(key)lastActivity=Date.now();},{passive:true});
 setInterval(()=>{if(key&&Date.now()-lastActivity>=300000)lock('Área bloqueada após 5 minutos sem atividade.');},1000);
 document.addEventListener('visibilitychange',()=>{if(document.hidden)lock('Área bloqueada ao sair desta aba.');});
 window.addEventListener('pagehide',()=>lock());
 window.addEventListener('pageshow',event=>{if(event.persisted)lock();});
 $('vault-submit').disabled=true;
 if(!window.isSecureContext || !crypto.subtle || !crypt){message('Não foi possível ativar a proteção. Acesse a versão HTTPS em um navegador atualizado.',true);return;}
 const open=indexedDB.open('jyxia-demo-records-v1',2);
 open.onupgradeneeded=()=>{const database=open.result;if(!database.objectStoreNames.contains('records'))database.createObjectStore('records',{keyPath:'id'});if(!database.objectStoreNames.contains('settings'))database.createObjectStore('settings',{keyPath:'id'});};
 open.onblocked=()=>message('Feche outras abas antigas da demonstração para ativar a proteção neste navegador. Os registros não serão mostrados.',true);
 req(open).then(async database=>{
  db=database;db.onversionchange=()=>{lock();db.close();};
  meta=await req(db.transaction('settings').objectStore('settings').get('vault'));
  if(!meta){
   legacyCount=await req(db.transaction('records').objectStore('records').count());
   $('vault-title').textContent='Crie seu acesso neste navegador';$('vault-setup').hidden=false;
   $('vault-confirm').required=true;$('vault-accept').required=true;$('vault-submit').textContent='Criar acesso e proteger';$('vault-password').autocomplete='new-password';
   $('vault-legacy').textContent=legacyCount?'Existem registros anteriores neste navegador. Eles só receberão criptografia quando você concluir a criação do acesso. Faça isso apenas em seu dispositivo pessoal e se esses registros forem seus. Nada será exibido antes.':'Este acesso protege os registros de demonstração que você cadastrar neste navegador.';
  }
  $('vault-submit').disabled=false;message('Registros bloqueados. A senha não será enviada ao GitHub.');
 }).catch(()=>message('Armazenamento indisponível. Nenhum registro será exibido. Reabra a página em um navegador com armazenamento habilitado.',true));
})();
