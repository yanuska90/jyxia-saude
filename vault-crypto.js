/* Browser-local encryption primitives. No credentials or clinical data in this file. */
(() => {
 'use strict';
 const enc = new TextEncoder(), dec = new TextDecoder();
 const iterations = 600000;
 const aad = (vaultId, purpose) => enc.encode('JYXIA-v1|' + vaultId + '|' + purpose);
 async function derive(password, salt) {
  const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 }
 async function seal(key, vaultId, purpose, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(vaultId,purpose)},key,bytes);
  return {iv,cipher};
 }
 async function unseal(key, vaultId, purpose, envelope) {
  return crypto.subtle.decrypt({name:'AES-GCM',iv:envelope.iv,additionalData:aad(vaultId,purpose)},key,envelope.cipher);
 }
 async function create(username, password) {
  if(!/^[a-zA-Z0-9_.-]{3,64}$/.test(username) || /^\d{3}\.?\d{3}\.?\d{3}-?\d{2}$/.test(username))throw Error('Use um nome de usuário de 3 a 64 letras, números, ponto, traço ou sublinhado. Não use CPF.');
  if(password.length<15 || password.length>128)throw Error('Escolha uma senha exclusiva de 15 a 128 caracteres. Uma frase longa ajuda.');
  const salt=crypto.getRandomValues(new Uint8Array(16)), vaultId=crypto.randomUUID();
  const key=await derive(password,salt);
  const proof=await seal(key,vaultId,'account',enc.encode(JSON.stringify({username,purpose:'jyxia-local-vault'})));
  return {key,meta:{id:'vault',version:1,iterations,salt,vaultId,proof}};
 }
 async function unlock(meta, username, password) {
  try {
   if(meta.version!==1 || meta.iterations!==iterations)throw Error();
   const key=await derive(password,meta.salt);
   const proof=JSON.parse(dec.decode(await unseal(key,meta.vaultId,'account',meta.proof)));
   if(proof.purpose!=='jyxia-local-vault' || proof.username!==username)throw Error();
   return key;
  }catch{throw Error('Usuário ou senha incorretos, ou armazenamento indisponível.');}
 }
 async function encryptRecord(key, vaultId, row) {
  const attachments=[], files=[];
  for(const file of row.attachments||[]) {
   const {blob,...metadata}=file;
   if(!(blob instanceof Blob))throw Error('Anexo indisponível. O registro anterior foi preservado.');
   attachments.push(metadata);
   files.push({id:file.id,...await seal(key,vaultId,'file|'+row.id+'|'+file.id,await blob.arrayBuffer())});
  }
  const payload=enc.encode(JSON.stringify({...row,attachments}));
  return {id:row.id,encrypted:1,...await seal(key,vaultId,'record|'+row.id,payload),files};
 }
 async function decryptRecord(key,vaultId,envelope) {
  if(envelope.encrypted!==1)throw Error('Registro sem proteção. Acesso interrompido.');
  const row=JSON.parse(dec.decode(await unseal(key,vaultId,'record|'+envelope.id,envelope)));
  if(row.id!==envelope.id)throw Error('Identificador incompatível.');
  for(const file of row.attachments||[]) {
   const content=envelope.files.find(f=>f.id===file.id);
   if(!content)throw Error('Anexo não encontrado.');
   file.blob=new Blob([await unseal(key,vaultId,'file|'+row.id+'|'+file.id,content)],{type:file.type});
  }
  return row;
 }
 globalThis.JYXIA_CRYPTO=Object.freeze({create,unlock,encryptRecord,decryptRecord});
})();
