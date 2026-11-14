const sources={'SYN-R01':'Ficha sintética de 12/11/2026. Campo de alergias não preenchido. Não equivale a alergias negadas.','SYN-R02':'Relato sintético de 12/11/2026: informa uso de Medicamento demonstrativo A. Não é medicamento real ou prescrição.','SYN-R03':'Relato sintético de 13/11/2026: informa não usar Medicamento demonstrativo A. Divergência não reconciliada.','SYN-R04':'Documento sintético anexado em 13/11/2026, sem data de coleta. Não inferir atualidade ou normalidade.'};
const text='Alergias: não informadas; campo sem preenchimento [SYN-R01].\n\nMedicamentos: divergência entre relatos de uso e não uso de Medicamento demonstrativo A. Necessária conferência [SYN-R02, SYN-R03].\n\nExames: documento sem data de coleta; atualidade desconhecida [SYN-R04].\n\nEste exemplo não avalia aptidão para cirurgia.';
const el=id=>document.getElementById(id);
function log(message){const li=document.createElement('li');li.textContent=new Date().toLocaleTimeString('pt-BR')+' — '+message;el('audit').append(li)}
document.querySelectorAll('[data-source]').forEach(b=>b.addEventListener('click',()=>{el('source-title').textContent=b.dataset.source;el('source-text').textContent=sources[b.dataset.source];el('source').showModal();log('Fonte consultada: '+b.dataset.source)}));
el('close').onclick=()=>el('source').close();
el('load').onclick=()=>{el('summary').value=text;el('review').hidden=false;el('load').hidden=true;el('state').textContent='Rascunho carregado. Revisão pendente.';log('Resumo pré-escrito carregado. Sem chamada de IA.')};
el('summary').addEventListener('input',()=>{el('state').textContent='Texto editado. Revisão pendente.'});
el('approve').onclick=()=>{if(!el('summary').value.trim()){el('state').textContent='Insira conteúdo antes da revisão.';return}el('state').textContent='Aprovação simulada registrada nesta sessão. Sem validade clínica.';log('Aprovação simulada; texto '+(el('summary').value===text?'original.':'editado.'))};
el('reject').onclick=()=>{el('state').textContent='Exemplo rejeitado. Consulte as fontes.';log('Resumo rejeitado.')};
el('failure').onclick=()=>{el('review').hidden=true;el('load').hidden=false;el('state').textContent='Resumo indisponível na simulação. Fontes continuam acessíveis.';log('Falha simulada. Fontes preservadas.')};
el('reset').onclick=()=>location.reload();
