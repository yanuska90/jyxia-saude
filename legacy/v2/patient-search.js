(() => {
 'use strict';
 const form=document.getElementById('patient-search');
 const input=document.getElementById('patient-cpf');
 const status=document.getElementById('patient-search-status');
 form.addEventListener('submit',event=>{
  event.preventDefault();
  const digits=input.value.replace(/\D/g,'');
  input.value='';
  if(digits==='00000000000'){
   status.textContent='Paciente fictício SYN-P01 localizado. A jornada e os registros desta página pertencem a esse único paciente de demonstração. Nenhum hospital ou laboratório foi consultado.';
  }else{
   status.textContent='Paciente não localizado na base demonstrativa. Use somente 000.000.000-00. A busca real por CPF ainda não está conectada; nenhum dado foi enviado ou armazenado por este formulário.';
  }
 });
 document.getElementById('use-demo-cpf').onclick=()=>{input.value='000.000.000-00';input.focus();status.textContent='Identificador fictício preenchido. Selecione Buscar paciente.';};
})();
