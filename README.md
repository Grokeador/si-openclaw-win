# SI-OpenClaw-Win

> **1-Click Windows Preflight, Safe Workspace Lock & Local $0 Ollama Setup for OpenClaw (WhatsApp & Telegram)**

**[Watch the Step-by-Step Video Tutorial & Subscribe on SI NEWS](https://www.youtube.com/playlist?list=PLM1AqSHm9rWk)** | **[OpenClaw Official Repo](https://github.com/openclaw/openclaw)**

## Why Use SI-OpenClaw-Win?

Installing **OpenClaw** on Windows lets you message your PC from WhatsApp or Telegram with local AI — **at $0.00 API cost**.  
By default, however, beginners often hit Node.js version mismatches (`< v24`), leave host shell execution unlocked outside a safe folder, or accidentally expose DM policies.

**SI-OpenClaw-Win** gives you a single zero-dependency Windows control panel & CLI:

1. **Windows Readiness Scanner**: Checks `Node.js >= 24`, `openclaw` CLI, Gateway status, and local `Ollama` in one scan.
2. **1-Click Safe Sandbox (`~/.openclaw/openclaw.json`)**:
   - Locks WhatsApp & Telegram `dmPolicy` to `"pairing"` so unknown senders cannot trigger commands.
   - Restricts `tools.exec` to a dedicated `~/OpenClawWorkspace` sandbox folder (`workspaceOnly: true`).
   - Wires local Ollama (`http://127.0.0.1:11434/v1`) for **$0/month** usage.
   - Saves a **SHA-256 verified backup** under `~/.openclaw/si_backups/` with **1-Click Rollback**.
3. **Live Chat Command Guard**: Test any prompt or command before execution to block destructive deletions, encoded PowerShell payloads, or path escapes.

## Quick Start

Double-click **`Launch_SI_OpenClaw_Win.bat`**, or run via PowerShell:

```powershell
python si_openclaw_win.py
```

CLI-only modes:

```powershell
python si_openclaw_win.py --check
python si_openclaw_win.py --apply-safe
python si_openclaw_win.py --rollback
```

## Run Tests

```powershell
python -m unittest test_openclaw_win.py -v
```

## License

MIT License — Built for the [SI NEWS](https://www.youtube.com/channel/UC4m6veQiZdc_pAfxKQluRgA) community.
