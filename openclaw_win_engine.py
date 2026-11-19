"""
SI-OpenClaw-Win Core Engine — Windows Preflight, Safe Sandbox Config & Chat Guard.

Helps non-expert Windows users verify Node.js 24+, OpenClaw, and local Ollama,
apply a safe workspace-locked openclaw.json with SHA-256 verified backups,
and test incoming WhatsApp/Telegram commands against a destructive-command guard.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

MIN_NODE_MAJOR = 24
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:7b"
DEFAULT_UI_PORT = 8775

DANGEROUS_COMMAND_RULES: tuple[tuple[str, str], ...] = (
    ("destructive_delete", r"(?:^|\s)(?:rm\s+-rf|del\s+/[sqf]|rmdir\s+/s|erase\s+/[sqf]|remove-item\s+.*-recurse)"),
    ("disk_format", r"(?:^|\s)(?:format\s+[a-z]:|diskpart|cipher\s+/w|bcdedit)"),
    ("registry_tamper", r"(?:^|\s)reg\s+(?:delete|add)\s+hklm"),
    ("encoded_payload", r"(?:powershell(?:\.exe)?\s+.*-(?:e|enc|encodedcommand)\b|invoke-expression|\biex\s*\()"),
    ("pipe_to_shell", r"(?:curl|wget|iwr|invoke-webrequest)[^\n|]*\|\s*(?:bash|sh|iex|powershell)"),
    ("system_power", r"(?:^|\s)(?:shutdown\s+/[sr]|stop-computer|restart-computer)"),
    ("path_traversal", r"(?:\.\.[\\/]){2,}"),
)

READY_WORKFLOW_PRESETS: tuple[dict[str, str], ...] = (
    {
        "id": "pc_health_check",
        "title": "PC Health & Storage Check",
        "prompt": "Check CPU load, free RAM, and remaining free space on drive C and reply in 4 bullet points.",
        "why_safe": "Read-only system check inside Windows status tools.",
    },
    {
        "id": "downloads_digest",
        "title": "Summarize New Downloads",
        "prompt": "List the 10 newest files in my safe workspace folder grouped by PDF, ZIP, and installers without deleting anything.",
        "why_safe": "Scans filenames only; never moves or deletes files.",
    },
    {
        "id": "log_error_finder",
        "title": "Find Errors in App Logs",
        "prompt": "Scan app_errors.log inside my safe workspace, extract the last 3 crash lines, and explain the fix in plain English.",
        "why_safe": "Reads log files inside your sandbox workspace.",
    },
    {
        "id": "daily_todo_brief",
        "title": "Morning Notes Digest",
        "prompt": "Read today_notes.md from my workspace and turn it into a 3-item priority checklist for my phone.",
        "why_safe": "Markdown summary only; ideal for WhatsApp/Telegram morning briefings.",
    },
    {
        "id": "gateway_watchdog",
        "title": "Verify Local AI & Gateway",
        "prompt": "Confirm local Ollama is responding on localhost and report which local model is active.",
        "why_safe": "Confirms $0.00 local AI routing with zero external API charges.",
    },
)


def default_openclaw_dir(home_dir: Path | None = None) -> Path:
    """Return the OpenClaw state directory (~/.openclaw)."""
    base = home_dir or Path.home()
    return base / ".openclaw"


def default_config_path(home_dir: Path | None = None) -> Path:
    """Return the primary OpenClaw configuration path (~/.openclaw/openclaw.json)."""
    return default_openclaw_dir(home_dir) / "openclaw.json"


def default_safe_workspace(home_dir: Path | None = None) -> Path:
    """Return the dedicated safe workspace directory for host tool execution."""
    base = home_dir or Path.home()
    return base / "OpenClawWorkspace"


def parse_node_major(version_text: str) -> int | None:
    """Extract the major Node.js version integer from strings like 'v24.22.1'."""
    match = re.search(r"v?(\d+)(?:\.\d+)?", (version_text or "").strip())
    return int(match.group(1)) if match else None


def _default_runner(cmd: list[str], timeout: int = 5) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
            shell=os.name == "nt" and cmd[0] in {"openclaw", "npm"},
        )
        output = (proc.stdout or proc.stderr or "").strip()
        return proc.returncode == 0, output
    except Exception as exc:
        return False, str(exc)


def _check_ollama_http(base_url: str = DEFAULT_OLLAMA_URL, timeout: float = 1.5) -> tuple[bool, list[str]]:
    url = f"{base_url.rstrip('/')}/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status != 200:
                return False, []
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
            models = [m.get("name", "") for m in payload.get("models", []) if m.get("name")]
            return True, models
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return False, []


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def audit_openclaw_config(config_path: Path) -> dict[str, Any]:
    """Audit ~/.openclaw/openclaw.json for security, pairing lock, and local AI readiness."""
    findings: list[dict[str, str]] = []
    if not config_path.exists():
        findings.append({
            "severity": "warn",
            "code": "CONFIG_MISSING",
            "message": f"Config file not found at {config_path}. Click Apply Safe Config to create one.",
        })
        return {
            "exists": False,
            "path": str(config_path),
            "score": 25,
            "whatsapp_policy": "unset",
            "telegram_policy": "unset",
            "workspace_only": False,
            "local_ollama_configured": False,
            "findings": findings,
        }

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append({
            "severity": "error",
            "code": "INVALID_JSON",
            "message": f"openclaw.json contains invalid JSON: {exc}",
        })
        return {
            "exists": True,
            "path": str(config_path),
            "score": 10,
            "whatsapp_policy": "error",
            "telegram_policy": "error",
            "workspace_only": False,
            "local_ollama_configured": False,
            "findings": findings,
        }

    score = 100
    channels = data.get("channels") or {}
    wa_policy = str((channels.get("whatsapp") or {}).get("dmPolicy", "unset")).lower()
    tg_policy = str((channels.get("telegram") or {}).get("dmPolicy", "unset")).lower()

    for ch_name, pol in (("WhatsApp", wa_policy), ("Telegram", tg_policy)):
        if pol in {"open", "*"}:
            score -= 25
            findings.append({
                "severity": "error",
                "code": f"{ch_name.upper()}_OPEN_DM",
                "message": f"{ch_name} dmPolicy is '{pol}' (anyone with your number/handle could message your bot). Lock to 'pairing'.",
            })
        elif pol not in {"pairing", "allowlist"}:
            score -= 10
            findings.append({
                "severity": "warn",
                "code": f"{ch_name.upper()}_UNSET_POLICY",
                "message": f"{ch_name} dmPolicy is '{pol}'. Recommended: 'pairing'.",
            })

    exec_cfg = (data.get("tools") or {}).get("exec") or {}
    workspace_only = bool(exec_cfg.get("workspaceOnly", False))
    if not workspace_only:
        score -= 25
        findings.append({
            "severity": "error",
            "code": "HOST_UNRESTRICTED",
            "message": "Host tool execution is not locked to a safe workspace folder (tools.exec.workspaceOnly=false).",
        })

    providers = (data.get("models") or {}).get("providers") or {}
    primary_model = str((((data.get("agents") or {}).get("defaults") or {}).get("model") or {}).get("primary", ""))
    local_ollama = ("ollama" in providers) or primary_model.startswith("ollama/")
    if not local_ollama:
        score -= 10
        findings.append({
            "severity": "info",
            "code": "NO_LOCAL_OLLAMA",
            "message": "Local Ollama provider is not wired yet (wire it for $0.00/month local AI calls).",
        })

    if not findings:
        findings.append({
            "severity": "ok",
            "code": "ALL_SAFE",
            "message": "DM pairing lock, workspace guard, and local configuration look healthy.",
        })

    return {
        "exists": True,
        "path": str(config_path),
        "score": max(0, score),
        "whatsapp_policy": wa_policy,
        "telegram_policy": tg_policy,
        "workspace_only": workspace_only,
        "local_ollama_configured": local_ollama,
        "primary_model": primary_model or "default",
        "findings": findings,
    }


def probe_environment(
    home_dir: Path | None = None,
    runner: Callable[[list[str]], tuple[bool, str]] | None = None,
    ollama_probe: Callable[[], tuple[bool, list[str]]] | None = None,
) -> dict[str, Any]:
    """Inspect Node.js, OpenClaw CLI, Ollama runtime, and ~/.openclaw/openclaw.json."""
    exec_fn = runner or _default_runner
    ollama_fn = ollama_probe or _check_ollama_http

    node_ok, node_raw = exec_fn(["node", "-v"])
    node_major = parse_node_major(node_raw) if node_ok else None
    node_ready = bool(node_ok and node_major is not None and node_major >= MIN_NODE_MAJOR)

    oc_ok, oc_raw = exec_fn(["openclaw", "--version"])
    gw_ok, gw_raw = exec_fn(["openclaw", "gateway", "status"]) if oc_ok else (False, "Install OpenClaw in Step 1 first")

    ollama_cli_ok, ollama_cli_raw = exec_fn(["ollama", "--version"])
    if "client version is" in ollama_cli_raw:
        ollama_cli_ok = True
        m_ol = re.search(r"client version is ([\d.]+)", ollama_cli_raw)
        ollama_cli_raw = f"v{m_ol.group(1)}" if m_ol else ollama_cli_raw.splitlines()[-1]
    ollama_http_ok, ollama_models = ollama_fn()

    cfg_path = default_config_path(home_dir)
    cfg_audit = audit_openclaw_config(cfg_path)

    return {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "node": {
            "installed": node_ok,
            "version": node_raw if node_ok else "Not installed",
            "major": node_major,
            "meets_min_v24": node_ready,
        },
        "openclaw": {
            "installed": oc_ok,
            "version": oc_raw.splitlines()[0] if oc_ok and oc_raw else "Not installed yet",
            "gateway_running": gw_ok,
            "gateway_status": gw_raw[:180],
        },
        "ollama": {
            "cli_installed": ollama_cli_ok,
            "cli_version": ollama_cli_raw if ollama_cli_ok else "Not installed (optional)",
            "api_online": ollama_http_ok,
            "models": ollama_models,
        },
        "config": cfg_audit,
        "safe_workspace": str(default_safe_workspace(home_dir)),
    }


def apply_safe_config(
    config_path: Path,
    workspace_dir: Path,
    enable_local_ollama: bool = True,
    ollama_model: str = DEFAULT_OLLAMA_MODEL,
    strict_pairing: bool = True,
) -> dict[str, Any]:
    """Safely create or patch openclaw.json with workspace isolation and SHA-256 backup."""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    workspace_dir.mkdir(parents=True, exist_ok=True)

    backup_info: dict[str, str] | None = None
    existing: dict[str, Any] = {}
    if config_path.exists():
        raw_bytes = config_path.read_bytes()
        backup_dir = config_path.parent / "si_backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        backup_file = backup_dir / f"openclaw_{stamp}.json.bak"
        backup_file.write_bytes(raw_bytes)
        digest = _sha256_bytes(raw_bytes)
        manifest = backup_dir / "latest_backup.json"
        backup_info = {"backup_path": str(backup_file), "sha256": digest, "created_at_utc": stamp}
        manifest.write_text(json.dumps(backup_info, indent=2), encoding="utf-8")
        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
            if isinstance(parsed, dict):
                existing = parsed
        except Exception:
            existing = {}

    channels = existing.setdefault("channels", {})
    for ch in ("whatsapp", "telegram"):
        ch_cfg = channels.setdefault(ch, {})
        if strict_pairing:
            ch_cfg["dmPolicy"] = "pairing"

    tools = existing.setdefault("tools", {})
    exec_cfg = tools.setdefault("exec", {})
    exec_cfg["workspaceOnly"] = True
    exec_cfg["workspaceRoot"] = str(workspace_dir)
    exec_cfg["ask"] = "on-miss"

    agents = existing.setdefault("agents", {})
    defaults = agents.setdefault("defaults", {})
    defaults["workspace"] = str(workspace_dir)

    update_cfg = existing.setdefault("update", {})
    update_cfg["checkOnStart"] = False

    if enable_local_ollama:
        models_cfg = existing.setdefault("models", {})
        providers = models_cfg.setdefault("providers", {})
        providers["ollama"] = {
            "baseUrl": f"{DEFAULT_OLLAMA_URL}/v1",
            "apiKey": "ollama-local",
            "api": "openai-completions",
            "models": [{"id": ollama_model, "name": f"{ollama_model} (Local $0)"}],
        }
        model_def = defaults.setdefault("model", {})
        model_def["primary"] = f"ollama/{ollama_model}"

    config_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return {
        "ok": True,
        "config_path": str(config_path),
        "workspace_dir": str(workspace_dir),
        "backup": backup_info,
        "audit": audit_openclaw_config(config_path),
    }


def rollback_latest_backup(config_path: Path) -> dict[str, Any]:
    """Restore the most recent SHA-256 verified backup of openclaw.json."""
    manifest = config_path.parent / "si_backups" / "latest_backup.json"
    if not manifest.exists():
        return {"ok": False, "error": "No SI-OpenClaw-Win backup manifest found yet."}

    info = json.loads(manifest.read_text(encoding="utf-8"))
    backup_file = Path(info["backup_path"])
    if not backup_file.exists():
        return {"ok": False, "error": f"Backup file missing: {backup_file}"}

    raw_bytes = backup_file.read_bytes()
    actual_hash = _sha256_bytes(raw_bytes)
    if actual_hash != info.get("sha256"):
        return {"ok": False, "error": "Backup SHA-256 verification failed; aborting restore."}

    config_path.write_bytes(raw_bytes)
    return {
        "ok": True,
        "restored_from": str(backup_file),
        "sha256": actual_hash,
        "audit": audit_openclaw_config(config_path),
    }


def evaluate_chat_command(command_text: str, allowed_workspace: str) -> dict[str, Any]:
    """Check whether a chat-triggered shell command stays safe and inside the workspace."""
    text = (command_text or "").strip()
    if not text:
        return {"allowed": False, "reason": "Command cannot be empty.", "matched_rule": "empty_command"}

    for rule_name, pattern in DANGEROUS_COMMAND_RULES:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return {
                "allowed": False,
                "reason": f"Blocked by {rule_name}: potentially destructive or obfuscated command.",
                "matched_rule": rule_name,
            }

    drive_refs = re.findall(r"([a-zA-Z]:\\[^\s\"']+)", text)
    if drive_refs:
        try:
            ws_resolved = Path(allowed_workspace).resolve()
        except Exception:
            ws_resolved = Path(allowed_workspace)
        for ref in drive_refs:
            try:
                ref_resolved = Path(ref).resolve()
                if ws_resolved != ref_resolved and ws_resolved not in ref_resolved.parents:
                    return {
                        "allowed": False,
                        "reason": f"Blocked outside_workspace: '{ref}' is outside '{allowed_workspace}'.",
                        "matched_rule": "outside_workspace",
                    }
            except Exception:
                return {
                    "allowed": False,
                    "reason": f"Blocked invalid path reference: '{ref}'.",
                    "matched_rule": "outside_workspace",
                }

    return {
        "allowed": True,
        "reason": "Allowed: non-destructive command within safe workspace boundaries.",
        "matched_rule": None,
    }


def get_ready_presets() -> list[dict[str, str]]:
    """Return copy-ready WhatsApp/Telegram prompts for non-technical Windows users."""
    return [dict(item) for item in READY_WORKFLOW_PRESETS]


def copy_install_commands() -> dict[str, str]:
    """Return the exact verified OpenClaw Windows setup commands shown in the tutorial."""
    return {
        "install_windows": "iwr -useb https://openclaw.ai/install.ps1 | iex",
        "install_npm": "npm install -g openclaw@latest --allow-scripts=openclaw",
        "onboard": "openclaw onboard --install-daemon",
        "status": "openclaw gateway status",
        "dashboard": "openclaw dashboard",
        "approve_whatsapp": "openclaw pairing approve whatsapp YOUR_CODE",
        "approve_telegram": "openclaw pairing approve telegram YOUR_CODE",
    }


def ensure_default_launcher_notes() -> str:
    """Return a clean plain-English safety summary for the Web UI."""
    return shutil.which("openclaw") or "Install OpenClaw first using Step 1 in PowerShell."
