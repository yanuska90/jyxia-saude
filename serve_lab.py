"""Localhost-only experimental lab server (Modalidade B). Never included in GitHub Pages or public demo."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, unquote
import argparse

ROOT = Path(__file__).resolve().parent
LAB_ALLOWLIST = {
    'lab-local.html',
    'lab-local.mjs',
    'lab-extractor.mjs',
    'documental-core.mjs',
    'documental.css',
    'favicon.svg',
    'vendor/pdf.min.mjs',
    'vendor/pdf.worker.min.mjs',
    'vendor/PDFJS-LICENSE.txt',
}
LOOPBACK_HOSTS = {'127.0.0.1', 'localhost', '::1'}


class LabHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def allowed(self):
        rel = unquote(urlsplit(self.path).path).lstrip('/')
        return rel == '' or rel in LAB_ALLOWLIST

    def translate_path(self, path):
        rel = unquote(urlsplit(path).path).lstrip('/')
        if rel == '':
            rel = 'lab-local.html'
        return str(ROOT / rel)

    def do_GET(self):
        if not self.allowed():
            self.send_error(404)
            return
        super().do_GET()

    def do_HEAD(self):
        if not self.allowed():
            self.send_error(404)
            return
        super().do_HEAD()

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header(
            'Content-Security-Policy',
            "default-src 'self'; script-src 'self'; worker-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        super().end_headers()

    def log_message(self, *args):
        # Strictly zero logging of request paths or document content
        pass


if __name__ == '__main__':
    p = argparse.ArgumentParser(description='JYXIA Modalidade B Local Lab (localhost only)')
    p.add_argument('--bind', default='127.0.0.1')
    p.add_argument('--port', type=int, default=8099)
    a = p.parse_args()
    if a.bind not in LOOPBACK_HOSTS:
        raise SystemExit('Erro de seguranca: serve_lab.py permite exclusivamente bind em loopback (localhost/127.0.0.1).')
    ThreadingHTTPServer((a.bind, a.port), LabHandler).serve_forever()
