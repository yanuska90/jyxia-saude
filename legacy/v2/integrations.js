(() => {
 'use strict';
 const $=id=>document.getElementById(id);
 const records=new Map();
 const sources=new Set();
 const types={Observation:'Resultado de exame',DiagnosticReport:'Laudo',AllergyIntolerance:'Alergia registrada',Condition:'Condição registrada',Procedure:'Procedimento',Encounter:'Atendimento',MedicationStatement:'Medicamento informado'};
 function line(parent,label,value){const p=document.createElement('p');p.textContent=label+': '+(value||'Não informado');parent.append(p);}
 function render(){
  $('integrated-count').textContent=records.size+' registros · '+sources.size+' fontes fictícias · paciente SYN-P01';
  const list=$('integrated-list');list.replaceChildren();
  const sorted=[...records.values()].sort((a,b)=>(b.event_date||'').localeCompare(a.event_date||''));
  for(const row of sorted){
   const card=document.createElement('article');card.className='record';
   const h=document.createElement('h3');h.textContent=row.title;card.append(h);
   line(card,'Tipo',types[row.resource_type]);line(card,'Origem',row.source==='lab-demo'?'Laboratório fictício A':'Hospital fictício B');
   line(card,'Data na origem',row.event_date);line(card,'Versão de origem',row.source_version);
   if(row.value){line(card,'Resultado fictício',row.value.value+' '+row.value.unit);line(card,'Referência da origem',row.reference_ranges.map(r=>r.text||JSON.stringify(r)).join('; '));line(card,'Método',row.method?.text);}
   if(row.issued)line(card,'Liberação na origem',row.issued);
   if(row.resource_type==='AllergyIntolerance')line(card,'Conferência','Informação da origem, pendente de avaliação profissional. Não classifica automaticamente o risco.');
   line(card,'Revisão',row.review_status);
   const details=document.createElement('details');const summary=document.createElement('summary');summary.textContent='Ver registro original sintético';
   const pre=document.createElement('pre');pre.style.whiteSpace='pre-wrap';pre.style.overflowWrap='anywhere';pre.textContent=JSON.stringify(row.original,null,2);details.append(summary,pre);card.append(details);list.append(card);
  }
 }
 let catalogPromise,busy=false;
 async function catalog(){
  if(!catalogPromise)catalogPromise=fetch('integration-demo.json').then(r=>{if(!r.ok)throw Error('Não foi possível carregar o exemplo. Tente novamente.');return r.json();}).then(data=>{window.JYXIA_DEMO_IMPORT.packageFor(data);return data;}).catch(e=>{catalogPromise=null;throw e;});
  return catalogPromise;
 }
 function commit(selected){
  const next=new Map(records),nextSources=new Set(sources);let added=0;
  for(const source of selected){for(const row of source.records){if(row.patient_id!=='SYN-P01'||row.source!==source.id)throw Error('Paciente ou fonte incompatível.');if(!next.has(row.key)){next.set(row.key,row);added++;}}nextSources.add(source.id);}
  records.clear();for(const [key,row]of next)records.set(key,row);sources.clear();for(const source of nextSources)sources.add(source);
  render();$('integration-status').textContent=added?added+' registros fictícios importados. Total: '+records.size+' registros de '+sources.size+' fontes inventadas. Nenhuma instituição real foi acessada.':'Exemplo já importado. Os '+records.size+' registros foram mantidos sem duplicação.';
 }
 async function run(action){
  if(busy)return;busy=true;
  const controls=[...document.querySelectorAll('[data-import-source],#import-complete,#import-file-submit')];controls.forEach(b=>b.disabled=true);
  try{await action();}catch(e){$('integration-status').textContent=e.message||'Não foi possível importar. Nenhum registro novo foi adicionado.';}finally{busy=false;controls.forEach(b=>b.disabled=false);}
 }
 document.querySelectorAll('[data-import-source]').forEach(button=>button.onclick=()=>run(async()=>{
  const data=await catalog();const source=data.sources.find(s=>s.id===button.dataset.importSource);if(!source)throw Error('Fonte de demonstração indisponível.');commit([source]);
 }));
 $('import-complete').onclick=()=>run(async()=>commit((await catalog()).sources));
 $('synthetic-file-form').onsubmit=event=>{
  event.preventDefault();
  run(async()=>{
   const file=$('synthetic-file').files[0];
   try{
    if(!file||!file.name.toLowerCase().endsWith('.json')||file.size>window.JYXIA_DEMO_IMPORT.MAX_BYTES||file.size===0)throw Error('Selecione paciente-ficticio-01.json, com até 256 KB.');
    const selected=window.JYXIA_DEMO_IMPORT.parseApproved(await file.text(),await catalog());commit(selected);
   }finally{$('synthetic-file').value='';}
  });
 };
 render();
})();
