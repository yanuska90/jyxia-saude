/* Only the public, approved synthetic package is accepted. No user-provided fields are rendered. */
(() => {
 'use strict';
 const MAX_BYTES=256*1024;
 function packageFor(catalog){
  if(!catalog || !Array.isArray(catalog.sources) || catalog.sources.length!==2)throw Error('Catálogo de demonstração indisponível.');
  const ids=new Set();let count=0;
  for(const source of catalog.sources){
   if(!['lab-demo','hospital-demo'].includes(source.id)||ids.has(source.id)||!Array.isArray(source.records))throw Error('Catálogo incompatível.');
   ids.add(source.id);
   for(const row of source.records){if(row.patient_id!=='SYN-P01'||row.source!==source.id)throw Error('Paciente ou fonte incompatível.');count++;}
  }
  if(count!==7)throw Error('Catálogo incompleto.');
  return {format:'JYXIA-SYNTHETIC-1',synthetic:true,patient_id:'SYN-P01',sources:catalog.sources};
 }
 function parseApproved(text,catalog){
  if(typeof text!=='string'||new TextEncoder().encode(text).byteLength>MAX_BYTES)throw Error('Use o arquivo de demonstração, com até 256 KB.');
  let input;try{input=JSON.parse(text.replace(/^\uFEFF/,''));}catch{throw Error('Arquivo JSON inválido. Baixe novamente o exemplo fornecido.');}
  const approved=packageFor(catalog);
  if(JSON.stringify(input)!==JSON.stringify(approved))throw Error('Este arquivo não corresponde ao exemplo fornecido. Baixe paciente-ficticio-01.json sem alterar seu conteúdo. Para criar registros fictícios próprios, use o cadastro manual.');
  // Return trusted fixture data, never fields supplied by a rejected file.
  return structuredClone(approved.sources);
 }
 globalThis.JYXIA_DEMO_IMPORT=Object.freeze({MAX_BYTES,packageFor,parseApproved});
})();
