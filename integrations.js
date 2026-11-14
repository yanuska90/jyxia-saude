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
 document.querySelectorAll('[data-import-source]').forEach(button=>button.onclick=async()=>{
  button.disabled=true;
  try{
   const response=await fetch('integration-demo.json');if(!response.ok)throw Error();
   const data=await response.json();const source=data.sources.find(s=>s.id===button.dataset.importSource);if(!source)throw Error();
   let added=0;
   for(const row of source.records){if(row.patient_id!=='SYN-P01')throw Error();if(!records.has(row.key)){records.set(row.key,row);added++;}}
   sources.add(source.id);render();
   $('integration-status').textContent=added?added+' registros fictícios adicionados de '+source.title+'. Nenhuma instituição real foi consultada.':'Essa fonte já foi importada. Nenhuma duplicata foi criada.';
  }catch{$('integration-status').textContent='Não foi possível carregar o exemplo. Tente novamente.';}finally{button.disabled=false;}
 });
 render();
})();
