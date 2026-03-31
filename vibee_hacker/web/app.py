"""FastAPI web dashboard for VIBEE-Hacker."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from vibee_hacker.core.engine import ScanEngine
from vibee_hacker.core.models import Target
from vibee_hacker.core.plugin_loader import PluginLoader

app = FastAPI(title="VIBEE-Hacker Dashboard", version="0.1.0")

# In-memory scan result store
_scan_results: dict[str, dict] = {}
MAX_STORED_RESULTS = 100


class ScanRequest(BaseModel):
    target: str
    mode: str = "blackbox"


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><title>VIBEE-Hacker Dashboard</title>
<style>
body{font-family:sans-serif;background:#1a1a2e;color:#eee;padding:20px;max-width:900px;margin:0 auto}
h1{color:#e94560}
.scan-form{background:#16213e;padding:20px;border-radius:8px;margin:20px 0}
input,select,button{padding:8px 12px;margin:5px;border-radius:4px;border:1px solid #333;background:#0f0f23;color:#eee}
button{background:#e94560;border:none;cursor:pointer;font-weight:bold}
button:hover{background:#c73a52}
table{width:100%;border-collapse:collapse;margin-top:20px}
th{background:#16213e;padding:10px;text-align:left}
td{padding:8px 10px;border-bottom:1px solid #333}
a{color:#4da6ff}
.badge{padding:2px 8px;border-radius:3px;font-size:.8em}
.critical{color:#ff4444}.high{color:#ff8c00}.medium{color:#ffd700}
</style>
</head>
<body>
<h1>VIBEE-Hacker Dashboard</h1>
<div class="scan-form">
<h3>New Scan</h3>
<form id="scanForm">
<input id="target" placeholder="https://example.com or /path/to/code" style="width:400px">
<select id="mode"><option value="blackbox">Blackbox</option><option value="whitebox">Whitebox</option></select>
<button type="submit">Scan</button>
</form>
<div id="status"></div>
</div>
<h2>Scan History</h2>
<table><thead><tr><th>ID</th><th>Target</th><th>Mode</th><th>Findings</th><th>Date</th></tr></thead>
<tbody id="results"></tbody></table>
<script>
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
async function loadResults(){
  const r=await fetch('/api/results');const data=await r.json();
  document.getElementById('results').innerHTML=data.map(s=>
    `<tr><td><a href="/api/results/${esc(s.id)}">${esc(s.id.slice(0,8))}</a></td><td>${esc(s.target)}</td><td>${esc(s.mode)}</td><td>${esc(s.total_findings)}</td><td>${esc(s.scan_date)}</td></tr>`
  ).join('');
}
document.getElementById('scanForm').onsubmit=async(e)=>{
  e.preventDefault();const st=document.getElementById('status');st.textContent='Scanning...';
  const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({target:document.getElementById('target').value,mode:document.getElementById('mode').value})});
  const data=await r.json();st.textContent=`Done! ${data.total_findings} findings.`;loadResults();
};
loadResults();
</script>
</body></html>"""


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return DASHBOARD_HTML


@app.post("/api/scan")
async def run_scan(req: ScanRequest):
    if req.mode == "blackbox":
        if not (req.target.startswith("http://") or req.target.startswith("https://")):
            raise HTTPException(status_code=400, detail="Blackbox target must start with http:// or https://")
        target = Target(url=req.target, mode=req.mode)
    else:
        p = Path(req.target)
        if not p.exists() or not p.is_dir():
            raise HTTPException(status_code=400, detail="Whitebox target must be an existing directory")
        target = Target(path=req.target, mode=req.mode)

    loader = PluginLoader()
    loader.load_builtin()
    engine = ScanEngine(timeout_per_plugin=30, safe_mode=True)
    for p in loader.plugins:
        engine.register_plugin(p)

    results = await engine.scan(target)
    scan_id = str(uuid.uuid4())
    scan_data = {
        "id": scan_id,
        "target": req.target,
        "mode": req.mode,
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(results),
        "findings": [r.to_dict() for r in results],
    }
    _scan_results[scan_id] = scan_data
    if len(_scan_results) > MAX_STORED_RESULTS:
        oldest = min(_scan_results, key=lambda k: _scan_results[k]["scan_date"])
        del _scan_results[oldest]
    return scan_data


@app.get("/api/results")
async def list_results():
    return sorted(_scan_results.values(), key=lambda x: x["scan_date"], reverse=True)


@app.get("/api/results/{scan_id}")
async def get_result(scan_id: str):
    if scan_id not in _scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_results[scan_id]
