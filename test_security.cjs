const {test,before}=require('node:test');
const assert=require('node:assert/strict');
const {randomBytes}=require('node:crypto');
require('./vault-crypto.js');require('./teleconsultation.js');
const C=globalThis.JYXIA_CRYPTO;let account,password;
const row={id:'synthetic-record',name:'Registro inteiramente fictício',kind:'exame',attachments:[{id:'file1',name:'ficticio.txt',type:'text/plain',size:4,blob:new Blob(['TEST'],{type:'text/plain'})}]};
before(async()=>{password=randomBytes(24).toString('hex');account=await C.create('teste_sintetico',password);});
test('correct local credentials recover encrypted records and attachments',async()=>{
 const key=await C.unlock(account.meta,'teste_sintetico',password);
 const sealed=await C.encryptRecord(key,account.meta.vaultId,row);
 assert.equal('name' in sealed,false);assert.equal('name' in sealed.files[0],false);
 const opened=await C.decryptRecord(key,account.meta.vaultId,sealed);
 assert.equal(opened.name,row.name);assert.equal(await opened.attachments[0].blob.text(),'TEST');
 assert.equal(key.extractable,false);
});
test('wrong password cannot unlock',async()=>{await assert.rejects(C.unlock(account.meta,'teste_sintetico',randomBytes(24).toString('hex')));});
test('wrong user cannot unlock even with the correct password',async()=>{await assert.rejects(C.unlock(account.meta,'outro_usuario',password));});
test('ciphertext tampering fails closed',async()=>{
 const sealed=await C.encryptRecord(account.key,account.meta.vaultId,row);new Uint8Array(sealed.cipher)[0]^=1;
 await assert.rejects(C.decryptRecord(account.key,account.meta.vaultId,sealed));
});
test('record swapping and vault swapping fail closed',async()=>{
 const sealed=await C.encryptRecord(account.key,account.meta.vaultId,row);
 await assert.rejects(C.decryptRecord(account.key,account.meta.vaultId,{...sealed,id:'other-record'}));
 await assert.rejects(C.decryptRecord(account.key,'other-vault',sealed));
});
test('tampered attachment cannot be opened',async()=>{
 const sealed=await C.encryptRecord(account.key,account.meta.vaultId,row);new Uint8Array(sealed.files[0].cipher)[0]^=1;
 await assert.rejects(C.decryptRecord(account.key,account.meta.vaultId,sealed));
});
test('repeated encryption uses different IVs and ciphertext',async()=>{
 const a=await C.encryptRecord(account.key,account.meta.vaultId,row),b=await C.encryptRecord(account.key,account.meta.vaultId,row);
 assert.notDeepEqual(a.iv,b.iv);assert.notDeepEqual(a.cipher,b.cipher);
});
test('weak password and CPF-like username are not accepted',async()=>{
 await assert.rejects(C.create('teste','short'));await assert.rejects(C.create('000.000.000-00',password));
});
test('missing attachment is detected without rewriting the original',async()=>{
 const sealed=await C.encryptRecord(account.key,account.meta.vaultId,row);
 await assert.rejects(C.decryptRecord(account.key,account.meta.vaultId,{...sealed,files:[]}));
 assert.equal(sealed.files.length,1);
});
test('teleconsultation accepts an HTTPS Daily room without credential parameters',()=>{
 assert.equal(globalThis.JYXIA_TELE.roomURL('https://synthetic-demo.daily.co/test-room'),'https://synthetic-demo.daily.co/test-room');
 assert.equal(globalThis.JYXIA_TELE.roomURL(''),'');
});
test('teleconsultation rejects phishing, embedded credentials, tokens and non-HTTPS',()=>{
 for(const url of ['javascript:alert(1)','http://synthetic-demo.daily.co/test','https://daily.co.evil.example/test','https://user:pass@synthetic-demo.daily.co/test','https://synthetic-demo.daily.co/test?t=secret','https://synthetic-demo.daily.co/test#secret','https://evil.example/test','https://synthetic-demo.daily.co:444/test'])assert.throws(()=>globalThis.JYXIA_TELE.roomURL(url));
});
