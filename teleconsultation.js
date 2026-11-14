/* Validate an externally supplied room URL; never store meeting tokens in URLs. */
(() => {
 'use strict';
 function roomURL(value) {
  if(!value)return '';
  let url;try{url=new URL(value);}catch{throw Error('Informe um link HTTPS válido de sala Daily.');}
  if(url.protocol!=='https:' || url.username || url.password || url.port || url.search || url.hash || !/^[a-z0-9][a-z0-9-]*\.daily\.co$/.test(url.hostname) || !/^\/[a-zA-Z0-9_-]{1,128}$/.test(url.pathname))
   throw Error('Use somente o endereço da sala Daily, sem senha, código de acesso ou parâmetros.');
  return url.href;
 }
 globalThis.JYXIA_TELE=Object.freeze({roomURL});
})();
