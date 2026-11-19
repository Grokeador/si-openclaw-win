"""Unit tests for SI-OpenClaw-Win engine and CLI."""

import json
import tempfile
import unittest
from pathlib import Path

from openclaw_win_engine import (
    apply_safe_config,
    audit_openclaw_config,
    evaluate_chat_command,
    get_ready_presets,
    parse_node_major,
    probe_environment,
    rollback_latest_backup,
)
from si_openclaw_win import build_status_payload, main


class TestOpenClawWinEngine(unittest.TestCase):
    def test_parse_node_major_versions(self) -> None:
        self.assertEqual(parse_node_major("v24.22.1"), 24)
        self.assertEqual(parse_node_major("26.1.0"), 26)
        self.assertIsNone(parse_node_major("unknown"))

    def test_audit_detects_open_dm_and_unrestricted_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / ".openclaw" / "openclaw.json"
            cfg.parent.mkdir(parents=True, exist_ok=True)
            cfg.write_text(
                json.dumps({
                    "channels": {"whatsapp": {"dmPolicy": "*"}, "telegram": {"dmPolicy": "open"}},
                    "tools": {"exec": {"workspaceOnly": False}},
                }),
                encoding="utf-8",
            )
            res = audit_openclaw_config(cfg)
            codes = {f["code"] for f in res["findings"]}
            self.assertIn("WHATSAPP_OPEN_DM", codes)
            self.assertIn("TELEGRAM_OPEN_DM", codes)
            self.assertIn("HOST_UNRESTRICTED", codes)
            self.assertLess(res["score"], 50)

    def test_apply_safe_config_preserves_tokens_and_supports_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            cfg = home / ".openclaw" / "openclaw.json"
            ws = home / "OpenClawWorkspace"
            cfg.parent.mkdir(parents=True, exist_ok=True)
            original = {
                "channels": {"telegram": {"botToken": "KEEP-SECRET-123", "dmPolicy": "open"}},
                "tools": {"exec": {"workspaceOnly": False}},
            }
            cfg.write_text(json.dumps(original), encoding="utf-8")

            applied = apply_safe_config(cfg, ws, enable_local_ollama=True, ollama_model="qwen2.5-coder:7b")
            self.assertTrue(applied["ok"])
            self.assertEqual(applied["audit"]["score"], 100)
            patched = json.loads(cfg.read_text(encoding="utf-8"))
            self.assertEqual(patched["channels"]["telegram"]["botToken"], "KEEP-SECRET-123")
            self.assertEqual(patched["channels"]["telegram"]["dmPolicy"], "pairing")
            self.assertEqual(patched["channels"]["whatsapp"]["dmPolicy"], "pairing")
            self.assertTrue(patched["tools"]["exec"]["workspaceOnly"])
            self.assertEqual(patched["agents"]["defaults"]["model"]["primary"], "ollama/qwen2.5-coder:7b")

            restored = rollback_latest_backup(cfg)
            self.assertTrue(restored["ok"])
            self.assertEqual(json.loads(cfg.read_text(encoding="utf-8")), original)

    def test_evaluate_chat_command_blocks_destructive_and_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = str(Path(tmp) / "OpenClawWorkspace")
            Path(ws).mkdir(parents=True, exist_ok=True)

            safe = evaluate_chat_command(f"dir {ws}", ws)
            self.assertTrue(safe["allowed"])

            bad_rm = evaluate_chat_command("rm -rf C:\\Windows\\System32", ws)
            self.assertFalse(bad_rm["allowed"])
            self.assertEqual(bad_rm["matched_rule"], "destructive_delete")

            bad_enc = evaluate_chat_command("powershell -EncodedCommand ZQBjAGgAbwA=", ws)
            self.assertFalse(bad_enc["allowed"])
            self.assertEqual(bad_enc["matched_rule"], "encoded_payload")

            bad_out = evaluate_chat_command("type C:\\Windows\\win.ini", ws)
            self.assertFalse(bad_out["allowed"])
            self.assertEqual(bad_out["matched_rule"], "outside_workspace")

    def test_probe_environment_and_presets(self) -> None:
        def fake_runner(cmd: list[str]) -> tuple[bool, str]:
            mapping = {
                ("node", "-v"): (True, "v24.22.1"),
                ("openclaw", "--version"): (True, "2026.11.0"),
                ("openclaw", "gateway", "status"): (True, "Gateway running"),
                ("ollama", "--version"): (True, "0.6.2"),
            }
            return mapping.get(tuple(cmd), (False, "missing"))

        with tempfile.TemporaryDirectory() as tmp:
            env = probe_environment(
                home_dir=Path(tmp),
                runner=fake_runner,
                ollama_probe=lambda: (True, ["qwen2.5-coder:7b"]),
            )
            self.assertTrue(env["node"]["meets_min_v24"])
            self.assertTrue(env["openclaw"]["installed"])
            self.assertTrue(env["ollama"]["api_online"])
            self.assertEqual(len(get_ready_presets()), 5)

    def test_cli_check_mode_exits_zero(self) -> None:
        self.assertEqual(main(["--check"]), 0)
        payload = build_status_payload()
        self.assertIn("commands", payload)
        self.assertIn("presets", payload)


if __name__ == "__main__":
    unittest.main()
