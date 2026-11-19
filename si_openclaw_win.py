"""
SI-OpenClaw-Win — 1-Click Windows Preflight, Safe Sandbox & WhatsApp/Telegram Guard UI.
Runs a clean local dark-mode dashboard on http://127.0.0.1:8775 or CLI flags (--check, --apply-safe).
"""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from openclaw_win_engine import (
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_UI_PORT,
    apply_safe_config,
    copy_install_commands,
    default_config_path,
    default_safe_workspace,
    evaluate_chat_command,
    get_ready_presets,
    probe_environment,
    rollback_latest_backup,
)

APP_VERSION = "1.0.0"

WEB_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SI-OpenClaw-Win — Safe Windows Setup & WhatsApp AI Guard</title>
<style>
:root {
  --bg: #070b14; --panel: #0d1524; --card: #121d30; --border: #233654;
  --accent: #00e5a3; --blue: #38bdf8; --amber: #f59e0b; --red: #ef4444;
  --text: #eef4ff; --muted: #94a8c7;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, sans-serif; }
body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; }
.topbar {
  height: 64px; background: #0a101c; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between; padding: 0 26px;
}
.brand { display: flex; align-items: center; gap: 12px; font-weight: 800; font-size: 20px; }
.pill { background: rgba(0,229,163,0.14); color: var(--accent); border: 1px solid rgba(0,229,163,0.45); padding: 5px 12px; border-radius: 999px; font-size: 12.5px; font-weight: 700; }
.pill.blue { background: rgba(56,189,248,0.14); color: var(--blue); border-color: rgba(56,189,248,0.45); }
.wrap { max-width: 1240px; width: 100%; margin: 20px auto; padding: 0 24px; display: flex; flex-direction: column; gap: 16px; }
.grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
.grid-2 { display: grid; grid-template-columns: 1.15fr 0.85fr; gap: 16px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 18px 20px; }
.card h2 { font-size: 17px; margin-bottom: 8px; }
.sub { font-size: 13.5px; color: var(--muted); margin-bottom: 12px; line-height: 1.45; }
.metric-lbl { font-size: 11.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.7px; }
.metric-val { font-size: 26px; font-weight: 800; margin: 4px 0; color: var(--accent); }
.metric-val.warn { color: var(--amber); }
.metric-val.err { color: var(--red); }
.row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
.btn { padding: 11px 16px; border-radius: 9px; border: none; font-weight: 700; font-size: 13.5px; cursor: pointer; background: var(--accent); color: #041b12; }
.btn.blue { background: var(--blue); color: #041926; }
.btn.warn { background: var(--amber); color: #1d1202; }
.btn.ghost { background: #192842; color: #dbeafe; border: 1px solid var(--border); }
.list { display: flex; flex-direction: column; gap: 8px; }
.item { background: #0c1422; border: 1px solid #1e304d; border-radius: 10px; padding: 11px 13px; font-size: 13.5px; }
.item strong { color: #fff; }
.code { font-family: Consolas, monospace; background: #070c16; border: 1px solid #1d2f4b; padding: 9px 11px; border-radius: 8px; font-size: 13px; color: #7dd3fc; display: flex; justify-content: space-between; align-items: center; gap: 10px; }
input[type=text] {
  flex: 1; background: #080d17; border: 1px solid var(--border); color: var(--text);
  padding: 10px 12px; border-radius: 8px; font-size: 14px; font-family: Consolas, monospace;
}
.badge-ok { color: var(--accent); font-weight: 700; }
.badge-bad { color: var(--red); font-weight: 700; }
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">
    <span>SI-OpenClaw-Win</span>
    <span class="pill">SAFE WINDOWS GUARD v1.0</span>
    <span class="pill blue">WHATSAPP + TELEGRAM + LOCAL AI</span>
  </div>
  <div class="row">
    <button class="btn ghost" onclick="refreshAudit()">Re-Scan PC</button>
    <button class="btn" onclick="applySafe()">1-Click Safe Setup</button>
    <button class="btn warn" onclick="rollbackCfg()">Restore Backup</button>
  </div>
</div>

<div class="wrap">
  <div class="grid-4" id="metrics">
    <div class="card"><div class="metric-lbl">Node.js (v24+)</div><div class="metric-val" id="m-node">...</div><div class="sub" id="s-node">Checking</div></div>
    <div class="card"><div class="metric-lbl">OpenClaw CLI</div><div class="metric-val" id="m-oc">...</div><div class="sub" id="s-oc">Checking</div></div>
    <div class="card"><div class="metric-lbl">Local Ollama ($0)</div><div class="metric-val" id="m-ol">...</div><div class="sub" id="s-ol">Checking</div></div>
    <div class="card"><div class="metric-lbl">Safety Score</div><div class="metric-val" id="m-sec">...</div><div class="sub" id="s-sec">Checking</div></div>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>Step-by-Step Windows Safety Audit</h2>
      <p class="sub">Checks pairing lock on WhatsApp &amp; Telegram, workspace isolation, and local $0 Ollama routing in <code>~/.openclaw/openclaw.json</code>.</p>
      <div class="list" id="findings"></div>
      <div id="action-banner" class="item" style="margin-top:12px; display:none;"></div>
    </div>

    <div class="card">
      <h2>Live Chat Command Safety Guard</h2>
      <p class="sub">Test any shell request before allowing remote execution from your phone.</p>
      <div class="row" style="margin-bottom:10px;">
        <input id="cmd-input" type="text" value="dir OpenClawWorkspace" />
        <button class="btn blue" onclick="testCmd()">Test Guard</button>
      </div>
      <div class="row" style="margin-bottom:10px;">
        <button class="btn ghost" onclick="setCmd('dir OpenClawWorkspace')">Safe Test</button>
        <button class="btn ghost" onclick="setCmd('rm -rf C:\\Users\\Public')">Attack Test</button>
      </div>
      <div class="item" id="cmd-result">Ready to test command safety.</div>
    </div>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>Verified Windows Setup Commands</h2>
      <p class="sub">Copy and paste directly into Windows PowerShell.</p>
      <div class="list" id="commands"></div>
    </div>
    <div class="card">
      <h2>5 Safe WhatsApp / Telegram Prompts</h2>
      <p class="sub">High-utility everyday tasks that stay safe inside your workspace.</p>
      <div class="list" id="presets"></div>
    </div>
  </div>
</div>

<script>
async function refreshAudit() {
  const res = await fetch('/api/audit');
  const data = await res.json();
  const n = data.node, oc = data.openclaw, ol = data.ollama, cfg = data.config;

  const setMetric = (mId, sId, val, sub, cls) => {
    const el = document.getElementById(mId);
    el.textContent = val;
    el.className = 'metric-val ' + (cls || '');
    document.getElementById(sId).textContent = sub;
  };

  setMetric('m-node', 's-node', n.meets_min_v24 ? 'READY' : (n.installed ? 'OLD' : 'MISSING'), n.version, n.meets_min_v24 ? '' : 'warn');
  setMetric('m-oc', 's-oc', oc.installed ? 'READY' : 'INSTALL', oc.version, oc.installed ? '' : 'warn');
  setMetric('m-ol', 's-ol', ol.api_online ? 'ONLINE' : (ol.cli_installed ? 'START' : 'OPTIONAL'), ol.models.length ? ol.models.slice(0,2).join(', ') : ol.cli_version, ol.api_online ? '' : 'warn');
  setMetric('m-sec', 's-sec', cfg.score + '/100', 'Workspace: ' + (cfg.workspace_only ? 'LOCKED' : 'OPEN'), cfg.score >= 85 ? '' : 'err');

  const fList = document.getElementById('findings');
  fList.innerHTML = cfg.findings.map(f => `<div class="item"><strong>[${f.severity.toUpperCase()}]</strong> ${f.message}</div>`).join('');

  const cmdList = document.getElementById('commands');
  cmdList.innerHTML = Object.entries(data.commands).map(([k, v]) => `<div class="code"><span>${v}</span><button class="btn ghost" onclick="navigator.clipboard.writeText('${v.replace(/'/g, "\\'")}')">Copy</button></div>`).join('');

  const pList = document.getElementById('presets');
  pList.innerHTML = data.presets.map(p => `<div class="item"><strong>${p.title}</strong><br><span style="color:#93c5fd">"${p.prompt}"</span></div>`).join('');
}

async function applySafe() {
  const res = await fetch('/api/apply-safe', { method: 'POST' });
  const data = await res.json();
  const b = document.getElementById('action-banner');
  b.style.display = 'block';
  b.innerHTML = `<span class="badge-ok">Safe config saved</span> to <code>${data.config_path}</code> (Workspace locked: <code>${data.workspace_dir}</code>).`;
  refreshAudit();
}

async function rollbackCfg() {
  const res = await fetch('/api/rollback', { method: 'POST' });
  const data = await res.json();
  const b = document.getElementById('action-banner');
  b.style.display = 'block';
  b.innerHTML = data.ok ? `<span class="badge-ok">Restored backup</span> (${data.sha256.slice(0,12)}...).` : `<span class="badge-bad">${data.error}</span>`;
  refreshAudit();
}

function setCmd(val) {
  document.getElementById('cmd-input').value = val;
  testCmd();
}

async function testCmd() {
  const command = document.getElementById('cmd-input').value;
  const res = await fetch('/api/check-command', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ command })
  });
  const data = await res.json();
  document.getElementById('cmd-result').innerHTML = data.allowed
    ? `<span class="badge-ok">ALLOWED</span> — ${data.reason}`
    : `<span class="badge-bad">BLOCKED</span> — ${data.reason}`;
}

refreshAudit();
</script>
</body>
</html>
"""


def build_status_payload(home_dir: Path | None = None) -> dict[str, Any]:
    """Assemble the complete audit payload returned by /api/audit and --check."""
    payload = probe_environment(home_dir=home_dir)
    payload["commands"] = copy_install_commands()
    payload["presets"] = get_ready_presets()
    return payload


class OpenClawHandler(BaseHTTPRequestHandler):
    """Serve the local SI-OpenClaw-Win Web UI and JSON API endpoints."""

    home_dir: Path | None = None

    def _send_json(self, code: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            raw = WEB_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        elif parsed.path == "/api/audit":
            self._send_json(200, build_status_payload(self.home_dir))
        else:
            self._send_json(404, {"ok": False, "error": "Not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            req = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            req = {}

        cfg_path = default_config_path(self.home_dir)
        ws_dir = default_safe_workspace(self.home_dir)

        if parsed.path == "/api/apply-safe":
            model = str(req.get("ollama_model") or DEFAULT_OLLAMA_MODEL)
            self._send_json(200, apply_safe_config(cfg_path, ws_dir, enable_local_ollama=True, ollama_model=model))
        elif parsed.path == "/api/rollback":
            self._send_json(200, rollback_latest_backup(cfg_path))
        elif parsed.path == "/api/check-command":
            cmd_text = str(req.get("command") or "")
            self._send_json(200, evaluate_chat_command(cmd_text, str(ws_dir)))
        else:
            self._send_json(404, {"ok": False, "error": "Not found"})

    def log_message(self, format: str, *args: Any) -> None:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SI-OpenClaw-Win Safe Setup & Guard")
    parser.add_argument("--check", action="store_true", help="Print JSON environment & safety audit and exit")
    parser.add_argument("--apply-safe", action="store_true", help="Write workspace-locked openclaw.json with SHA-256 backup and exit")
    parser.add_argument("--rollback", action="store_true", help="Restore latest SHA-256 verified backup and exit")
    parser.add_argument("--port", type=int, default=DEFAULT_UI_PORT, help="Local UI HTTP port")
    parser.add_argument("--no-browser", action="store_true", help="Do not auto-open the web browser")
    args = parser.parse_args(argv)

    cfg_path = default_config_path()
    ws_dir = default_safe_workspace()

    if args.check:
        print(json.dumps(build_status_payload(), indent=2))
        return 0
    if args.apply_safe:
        print(json.dumps(apply_safe_config(cfg_path, ws_dir), indent=2))
        return 0
    if args.rollback:
        res = rollback_latest_backup(cfg_path)
        print(json.dumps(res, indent=2))
        return 0 if res.get("ok") else 1

    server = ThreadingHTTPServer(("127.0.0.1", args.port), OpenClawHandler)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"SI-OpenClaw-Win v{APP_VERSION} running at {url}")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
