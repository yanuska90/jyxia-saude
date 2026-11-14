"""API de desenvolvimento JYXIA. Somente dados sintéticos; não é um prontuário clínico."""
import io,json,os,secrets,hashlib,mimetypes,re
from contextlib import asynccontextmanager
from datetime import date,datetime,timezone
from pathlib import Path
from typing import Literal
from urllib.parse import quote,urlsplit
from bson import ObjectId
from fastapi import FastAPI,Depends,HTTPException,UploadFile,File,Form,Header,Request
from fastapi.responses import FileResponse,Response,StreamingResponse
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials
from gridfs import GridFS
from pydantic import BaseModel,Field,ValidationError,model_validator,ConfigDict
from pymongo import MongoClient
from pymongo.errors import PyMongoError,DuplicateKeyError
from integration import normalize,apply_batch,review_flags,IntegrationError

MAX_FILE=10*1024*1024
ROOT=Path(__file__).parent
STATIC={'synthetic-import.js','paciente-ficticio-01.json','anexo-ficticio-01.txt','teleconsultation.js','vault.js','vault-crypto.js','index.html','demo.html','demo.js','records.js','runtime-config.js','style.css','patient-search.js','integrations.js','integration-demo.json'}
token=os.environ.get('JYXIA_API_TOKEN','')
client=None;db=None;fs=None

@asynccontextmanager
async def lifespan(app):
 global client,db,fs
 if len(token)<32:raise RuntimeError('Defina JYXIA_API_TOKEN com pelo menos 32 caracteres.')
 client=MongoClient(os.environ['MONGODB_URI'],serverSelectionTimeoutMS=5000)
 client.admin.command('ping');db=client['jyxia'];fs=GridFS(db)
 db.records.create_index([('patient_id',1),('created_at',-1)])
 yield
 client.close()

app=FastAPI(title='JYXIA API de desenvolvimento',version='2.1',lifespan=lifespan)
security=HTTPBearer(auto_error=False)
def authorized(credentials:HTTPAuthorizationCredentials|None=Depends(security)):
 if not credentials or not secrets.compare_digest(credentials.credentials,token):
  raise HTTPException(401,'Chave de teste inválida.',headers={'WWW-Authenticate':'Bearer'})

class Record(BaseModel):
 model_config=ConfigDict(str_strip_whitespace=True,extra='forbid')
 kind:Literal['medicamento','alergia','doenca','cirurgia','exame','outro','teleconsulta']
 name:str=Field(min_length=1,max_length=160)
 dosage:str=Field(default='',max_length=120)
 record_date:date
 source:str=Field(min_length=1,max_length=240)
 notes:str=Field(default='',max_length=3000)
 reaction:str=Field(default='',max_length=500)
 severity:Literal['desconhecida','leve','moderada','grave']='desconhecida'
 event_date:date|None=None
 institution:str=Field(default='',max_length=240)
 clinical_status:Literal['desconhecida','acompanhamento','historico']='desconhecida'
 appointment_date:date|None=None
 appointment_time:str=Field(default='',max_length=5)
 professional:str=Field(default='',max_length=160)
 specialty:str=Field(default='',max_length=120)
 meeting_url:str=Field(default='',max_length=400)
 @model_validator(mode='after')
 def medication_has_dosage(self):
  if self.kind=='medicamento' and not self.dosage:raise ValueError('Informe a dosagem transcrita do documento.')
  if self.kind!='medicamento':self.dosage=''
  if self.kind!='alergia':self.reaction='';self.severity='desconhecida'
  if self.kind not in ['doenca','cirurgia']:self.event_date=None;self.institution=''
  if self.kind!='doenca':self.clinical_status='desconhecida'
  if self.kind=='teleconsulta':
   if not self.appointment_date or not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]',self.appointment_time) or not self.professional:raise ValueError('Informe data, horário e profissional.')
   if self.meeting_url:
    link=urlsplit(self.meeting_url)
    if link.scheme!='https' or not re.fullmatch(r'[a-z0-9][a-z0-9-]*\.daily\.co',link.netloc) or not re.fullmatch(r'/[a-zA-Z0-9_-]{1,128}',link.path) or link.query or link.fragment:raise ValueError('Link de sala inválido ou contém credenciais.')
  else:self.appointment_date=None;self.appointment_time='';self.professional='';self.specialty='';self.meeting_url=''
  return self

def parse_record(raw):
 try:return Record.model_validate_json(raw).model_dump(mode='json')
 except (ValidationError,ValueError):raise HTTPException(422,'Confira tipo, nome, dosagem, data, origem e observações.')
def oid(value):
 try:return ObjectId(value)
 except Exception:raise HTTPException(404,'Registro não encontrado.')
def get_record(record_id):
 record=db.records.find_one({'_id':oid(record_id),'patient_id':'SYN-P01'})
 if not record:raise HTTPException(404,'Registro não encontrado.')
 return record
def public(record):
 return {**{k:v for k,v in record.items() if k!='_id'},'id':str(record['_id'])}

async def validated_files(files):
 if len(files)>5:raise HTTPException(422,'Use no máximo 5 anexos por registro.')
 result=[]
 for upload in files:
  try:
   data=await upload.read(MAX_FILE+1)
   if not data or len(data)>MAX_FILE:raise HTTPException(413,'Cada anexo deve ter entre 1 byte e 10 MB.')
   name=(upload.filename or 'anexo').replace('\\','/').split('/')[-1]
   name=re.sub(r'[\x00-\x1f\x7f]','',name)[:180] or 'anexo'
   ext=Path(name).suffix.lower()
   mime={'pdf':'application/pdf','png':'image/png','jpg':'image/jpeg','jpeg':'image/jpeg','txt':'text/plain'}.get(ext.lstrip('.'))
   valid=(ext=='.pdf' and data.startswith(b'%PDF-')) or (ext=='.png' and data.startswith(b'\x89PNG\r\n\x1a\n')) or (ext in ['.jpg','.jpeg'] and data.startswith(b'\xff\xd8\xff'))
   if ext=='.txt':
    try:data.decode('utf-8');valid=b'\0' not in data
    except UnicodeDecodeError:valid=False
   if not mime or not valid:raise HTTPException(415,'Arquivo incompatível. Use PDF, PNG, JPG ou TXT UTF-8.')
   result.append((name,mime,data))
  finally:await upload.close()
 return result

def store_files(files):
 stored=[]
 try:
  for name,mime,data in files:
   file_id=fs.put(data,filename=name,content_type=mime,metadata={'patient_id':'SYN-P01','sha256':hashlib.sha256(data).hexdigest()})
   stored.append({'id':str(file_id),'name':name,'type':mime,'size':len(data)})
  return stored
 except Exception:
  for entry in stored:fs.delete(ObjectId(entry['id']))
  raise
def remove_files(files):
 for entry in files:fs.delete(ObjectId(entry['id']))

@app.get('/health')
def health():
 try:client.admin.command('ping')
 except PyMongoError:raise HTTPException(503,'Banco indisponível.')
 return {'status':'ok','purpose':'synthetic-development'}

@app.get('/api/records',dependencies=[Depends(authorized)])
def list_records():return [public(r) for r in db.records.find({'patient_id':'SYN-P01'}).sort('created_at',-1).limit(100)]

@app.post('/api/records',status_code=201,dependencies=[Depends(authorized)])
async def create_record(record:str=Form(...),files:list[UploadFile]=File(default=[])):
 fields=parse_record(record);validated=await validated_files(files)
 if db.records.count_documents({'patient_id':'SYN-P01'})>=100:raise HTTPException(409,'Limite de 100 registros do protótipo atingido.')
 attachments=store_files(validated);now=datetime.now(timezone.utc).isoformat()
 row={**fields,'patient_id':'SYN-P01','created_at':now,'updated_at':now,'attachments':attachments,'version':1}
 try:row['_id']=db.records.insert_one(row).inserted_id
 except Exception:remove_files(attachments);raise
 return public(row)

@app.put('/api/records/{record_id}',dependencies=[Depends(authorized)])
async def update_record(record_id:str,record:str=Form(...),files:list[UploadFile]=File(default=[]),if_match:str|None=Header(default=None)):
 existing=get_record(record_id);fields=parse_record(record)
 if if_match!=str(existing['version']):raise HTTPException(409,'O registro mudou. Recarregue antes de editar novamente.')
 if len(existing['attachments'])+len(files)>5:raise HTTPException(422,'Limite total de 5 anexos atingido.')
 validated=await validated_files(files);added=store_files(validated)
 try:
  result=db.records.update_one({'_id':existing['_id'],'version':existing['version']},{'$set':{**fields,'attachments':existing['attachments']+added,'updated_at':datetime.now(timezone.utc).isoformat()},'$inc':{'version':1}})
  if not result.modified_count:raise HTTPException(409,'Edição concorrente. Recarregue os registros.')
 except Exception:remove_files(added);raise
 return public(get_record(record_id))

@app.delete('/api/records/{record_id}',status_code=204,dependencies=[Depends(authorized)])
def delete_record(record_id:str):
 row=get_record(record_id)
 result=db.records.delete_one({'_id':row['_id'],'version':row['version']})
 if not result.deleted_count:raise HTTPException(409,'O registro mudou. Recarregue antes de remover.')
 remove_files(row['attachments']);return Response(status_code=204)

@app.get('/api/records/{record_id}/attachments/{file_id}',dependencies=[Depends(authorized)])
def download(record_id:str,file_id:str):
 record=get_record(record_id);metadata=next((f for f in record['attachments'] if f['id']==file_id),None)
 if not metadata:raise HTTPException(404,'Anexo não encontrado neste registro.')
 stream=fs.get(oid(file_id))
 def chunks():
  try:
   while data:=stream.read(65536):yield data
  finally:stream.close()
 return StreamingResponse(chunks(),media_type=metadata['type'],headers={'Content-Disposition':"attachment; filename*=UTF-8''"+quote(metadata['name'],safe=''),'X-Content-Type-Options':'nosniff','Cache-Control':'no-store'})

@app.post('/api/integrations/{source}',dependencies=[Depends(authorized)])
async def ingest_synthetic(source:str,request:Request):
 raw=bytearray()
 async for chunk in request.stream():
  raw.extend(chunk)
  if len(raw)>1024*1024:raise HTTPException(413,'Lote maior que 1 MB.')
 try:incoming=normalize(source,json.loads(raw))
 except (ValueError,TypeError,KeyError,AttributeError):raise HTTPException(422,'Lote inválido, identificação não autorizada ou recurso não suportado. Consulte o contrato do ambiente sintético.')
 # One document per synthetic patient: atomic revision and embedded audit.
 collection=db.integration_state
 for attempt in range(3):
  existing=collection.find_one({'_id':'SYN-P01'})
  try:rows,stats=apply_batch(existing['records'] if existing else [],incoming)
  except IntegrationError as exc:raise HTTPException(409,str(exc))
  if len(rows)>1000:raise HTTPException(409,'Limite de 1000 versões neste ambiente de teste.')
  try:flags=review_flags(rows)
  except (ValueError,TypeError,KeyError,AttributeError):raise HTTPException(422,'Lote incompatível. Nenhuma alteração foi gravada.')
  now=datetime.now(timezone.utc).isoformat()
  audit={'at':now,'source':source,**stats,'purpose':'synthetic-development'}
  if existing:
   result=collection.update_one({'_id':'SYN-P01','revision':existing['revision']},{'$set':{'records':rows},'$inc':{'revision':1},'$push':{'audit':{'$each':[audit],'$slice':-100}}})
   if not result.modified_count:continue
  else:
   try:collection.insert_one({'_id':'SYN-P01','revision':1,'records':rows,'audit':[audit]})
   except DuplicateKeyError:continue
  return {**stats,'patient_id':'SYN-P01','flags':flags,'purpose':'synthetic-development'}
 raise HTTPException(409,'Importação concorrente. Reenvie o lote.')

@app.get('/api/integrations',dependencies=[Depends(authorized)])
def integrated_records():
 state=db.integration_state.find_one({'_id':'SYN-P01'})
 rows=state['records'] if state else []
 return {'patient_id':'SYN-P01','records':rows,'flags':review_flags(rows),'audit':state.get('audit',[]) if state else [],'purpose':'synthetic-development'}

@app.get('/runtime-config.js')
def config():return Response("window.JYXIA_STORAGE = 'api';",media_type='application/javascript',headers={'Cache-Control':'no-store'})

@app.get('/')
def index():return FileResponse(ROOT/'index.html')

@app.get('/{filename}')
def static(filename:str):
 if filename not in STATIC:raise HTTPException(404,'Página não encontrada.')
 return FileResponse(ROOT/filename)

@app.middleware('http')
async def security_headers(request,call_next):
 response=await call_next(request)
 response.headers['X-Content-Type-Options']='nosniff'
 response.headers['Referrer-Policy']='no-referrer'
 response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
 if request.url.path.startswith('/api/'):response.headers['Cache-Control']='no-store'
 return response
