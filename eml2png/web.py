"""Web server for browser-based EML analysis (no Playwright needed)."""

import cgi
import io
import os
import secrets
import tempfile
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler

from .parser import parse_eml
from .pipeline import run_analysis
from .renderers.page import PageRenderer


def _build_upload_page():
    """Return HTML for the drag-and-drop upload page."""
    return """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>eml2png — Phishing Analyzer</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background: #0a0e17;
    color: #c8d6e5;
    font-family: 'Inter', sans-serif;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
}
.topbar {
    position: fixed; top: 0; left: 0; right: 0;
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    border-bottom: 1px solid #00f0ff33;
    padding: 14px 24px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    color: #00f0ff;
    letter-spacing: 2px;
    z-index: 100;
}
.card {
    background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
    border: 1px solid #00f0ff22;
    border-radius: 12px;
    padding: 48px;
    max-width: 560px;
    width: 90%;
    text-align: center;
}
.card h2 {
    font-family: 'JetBrains Mono', monospace;
    color: #00f0ff;
    font-size: 18px;
    letter-spacing: 2px;
    margin-bottom: 8px;
}
.card p {
    font-size: 13px;
    color: #8899aa;
    margin-bottom: 28px;
}
.dropzone {
    border: 2px dashed #00f0ff44;
    border-radius: 10px;
    padding: 48px 24px;
    cursor: pointer;
    transition: border-color 0.2s, background 0.2s;
    margin-bottom: 20px;
}
.dropzone.drag-over {
    border-color: #00f0ff;
    background: #00f0ff0a;
}
.dropzone-icon {
    font-size: 36px;
    color: #00f0ff55;
    margin-bottom: 12px;
}
.dropzone-text {
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    color: #8899aa;
}
.dropzone-text em { color: #00f0ff; font-style: normal; cursor: pointer; }
.file-name {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #00f0ffcc;
    margin-top: 10px;
    min-height: 18px;
}
.btn {
    display: inline-block;
    background: linear-gradient(135deg, #00f0ff22 0%, #00f0ff11 100%);
    border: 1px solid #00f0ff44;
    color: #00f0ff;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    letter-spacing: 2px;
    padding: 12px 36px;
    border-radius: 6px;
    cursor: pointer;
    transition: background 0.2s, border-color 0.2s;
}
.btn:hover { background: #00f0ff1a; border-color: #00f0ff88; }
.btn:disabled { opacity: 0.4; cursor: not-allowed; }
.loading {
    display: none;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #00f0ff88;
    margin-top: 16px;
    align-items: center;
    justify-content: center;
    gap: 12px;
}
.loading.active { display: flex; }
.spinner {
    width: 20px; height: 20px;
    border: 2px solid #00f0ff22;
    border-top-color: #00f0ff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.error {
    display: none;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: #ff4444;
    margin-top: 16px;
}
.error.active { display: block; }
</style>
</head>
<body>
<div class="topbar">&#9650; EML2PNG PHISHING ANALYZER</div>
<div class="card">
    <h2>UPLOAD .EML FILE</h2>
    <p>Drag &amp; drop or browse to analyze a phishing email</p>
    <form id="form" action="/analyze" method="POST" enctype="multipart/form-data">
        <div class="dropzone" id="dropzone">
            <div class="dropzone-icon">&#9878;</div>
            <div class="dropzone-text">Drop .eml file here or <em id="browse">browse</em></div>
            <div class="file-name" id="file-name"></div>
        </div>
        <input type="file" name="file" id="file-input" accept=".eml" hidden>
        <button type="submit" class="btn" id="submit-btn" disabled>ANALYZE</button>
    </form>
    <div class="loading" id="loading"><div class="spinner"></div><span>Analyzing email&hellip; this may take a moment</span></div>
    <div class="error" id="error"></div>
</div>
<script>
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('file-input');
const fileName = document.getElementById('file-name');
const submitBtn = document.getElementById('submit-btn');
const form = document.getElementById('form');
const loading = document.getElementById('loading');
const errorDiv = document.getElementById('error');

dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('drag-over'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));
dropzone.addEventListener('drop', e => {
    e.preventDefault();
    dropzone.classList.remove('drag-over');
    if (e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        onFile(e.dataTransfer.files[0]);
    }
});
document.getElementById('browse').addEventListener('click', () => fileInput.click());
dropzone.addEventListener('click', e => { if (e.target === dropzone || e.target.closest('.dropzone-icon')) fileInput.click(); });
fileInput.addEventListener('change', () => { if (fileInput.files.length) onFile(fileInput.files[0]); });

function onFile(f) {
    fileName.textContent = f.name;
    submitBtn.disabled = !f.name.toLowerCase().endsWith('.eml');
    errorDiv.classList.remove('active');
}

form.addEventListener('submit', e => {
    e.preventDefault();
    if (!fileInput.files.length) return;
    submitBtn.disabled = true;
    loading.classList.add('active');
    errorDiv.classList.remove('active');

    const fd = new FormData(form);
    fetch('/analyze', { method: 'POST', body: fd })
        .then(r => {
            if (!r.ok) return r.text().then(t => { throw new Error(t); });
            return r.text();
        })
        .then(html => {
            document.open();
            document.write(html);
            document.close();
        })
        .catch(err => {
            loading.classList.remove('active');
            submitBtn.disabled = false;
            errorDiv.textContent = err.message || 'Analysis failed';
            errorDiv.classList.add('active');
        });
});
</script>
</body>
</html>"""


def _build_error_page(message):
    """Return a dark-themed error page."""
    from html import escape
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"><title>Error — eml2png</title>
<style>
body {{ background: #0a0e17; color: #ff4444; font-family: 'JetBrains Mono', monospace;
       display: flex; align-items: center; justify-content: center; min-height: 100vh; text-align: center; }}
.box {{ max-width: 480px; }}
h2 {{ font-size: 16px; margin-bottom: 12px; }}
p {{ font-size: 13px; color: #8899aa; margin-bottom: 24px; }}
a {{ color: #00f0ff; text-decoration: none; }}
</style>
</head>
<body><div class="box">
<h2>&#9888; ANALYSIS ERROR</h2>
<p>{escape(message)}</p>
<a href="/">&larr; Try Again</a>
</div></body>
</html>"""


class AnalysisHandler(BaseHTTPRequestHandler):
    """HTTP handler for the upload/analysis web UI."""

    do_api = True
    do_gemini = False
    gemini_model = "gemini-2.5-flash"

    def _send_security_headers(self, nonce=None):
        """Add security headers to the response."""
        if nonce:
            csp = (
                f"default-src 'none'; "
                f"script-src 'nonce-{nonce}'; "
                f"style-src 'unsafe-inline' https://fonts.googleapis.com; "
                f"font-src https://fonts.gstatic.com; "
                f"img-src data: https:; "
                f"frame-src 'self'; "
                f"connect-src 'self'; "
                f"object-src 'none'; "
                f"base-uri 'none'; "
                f"form-action /analyze"
            )
        else:
            csp = (
                "default-src 'none'; "
                "script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src https://fonts.gstatic.com; "
                "img-src data: https:; "
                "connect-src 'self'; "
                "object-src 'none'; "
                "base-uri 'none'; "
                "form-action /analyze"
            )
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

    def do_GET(self):
        if self.path == "/" or self.path == "":
            body = _build_upload_page().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/analyze":
            self.send_error(404)
            return

        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send_error_response(400, "Expected multipart/form-data")
            return

        try:
            # Parse multipart form data
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": content_type,
                },
            )

            file_field = form["file"]
            if not file_field.filename:
                self._send_error_response(400, "No file uploaded")
                return

            file_data = file_field.file.read()

        except Exception as e:
            self._send_error_response(400, f"Failed to read upload: {e}")
            return

        # Save to temp file for parse_eml (expects a file path)
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
                tmp.write(file_data)
                tmp_path = tmp.name

            parsed = parse_eml(tmp_path)
            analysis = run_analysis(
                parsed,
                do_api=self.do_api,
                do_gemini=self.do_gemini,
                gemini_model=self.gemini_model,
            )
            nonce = secrets.token_urlsafe(32)
            renderer = PageRenderer()
            html = renderer.build(parsed, analysis, interactive=True, csp_nonce=nonce)

            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._send_security_headers(nonce=nonce)
            self.end_headers()
            self.wfile.write(body)

        except Exception as e:
            error_html = _build_error_page(str(e)).encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(error_html)))
            self._send_security_headers()
            self.end_headers()
            self.wfile.write(error_html)

        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def _send_error_response(self, code, message):
        body = _build_error_page(message).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        print(f"  [{self.log_date_time_string()}] {format % args}")


def start_server(port=8080, do_api=True, do_gemini=False, gemini_model="gemini-2.5-flash"):
    """Start the web UI server on 127.0.0.1:<port>."""
    AnalysisHandler.do_api = do_api
    AnalysisHandler.do_gemini = do_gemini
    AnalysisHandler.gemini_model = gemini_model

    server = HTTPServer(("127.0.0.1", port), AnalysisHandler)
    url = f"http://127.0.0.1:{port}"
    print(f"\n  eml2png web UI running at {url}")
    print("  Press Ctrl+C to stop\n")

    webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down...")
        server.server_close()
