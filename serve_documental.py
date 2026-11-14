"""Static synthetic demo only. No upload endpoint, credentials or database."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, unquote
import argparse, json
ROOT=Path(__file__).resolve().parent
PUBLIC={'index.html','demo.html','documental.css','documental-core.mjs','documental-ui.mjs','documental-manifest.json','fixtures-jyxia.zip','Projeto_JYXIA_Inteligencia_Documental_v3.docx','vendor/pdf.min.mjs','vendor/pdf.worker.min.mjs','vendor/PDFJS-LICENSE.txt'}
PUBLIC.update(f['path'] for f in json.loads((ROOT/'documental-manifest.json').read_text(encoding='utf-8'))['files'])
class Handler(SimpleHTTPRequestHandler):
    def __init__(self,*args,**kwargs): super().__init__(*args,directory=str(ROOT),**kwargs)
    def allowed(self): return unquote(urlsplit(self.path).path).lstrip('/') in PUBLIC or urlsplit(self.path).path=='/'
    def do_GET(self):
        if not self.allowed(): self.send_error(404); return
        super().do_GET()
    def do_HEAD(self):
        if not self.allowed(): self.send_error(404); return
        super().do_HEAD()
    def end_headers(self):
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; worker-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        super().end_headers()
    def log_message(self,*args): pass
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--bind',default='127.0.0.1');p.add_argument('--port',type=int,default=8000);a=p.parse_args()
    ThreadingHTTPServer((a.bind,a.port),Handler).serve_forever()
