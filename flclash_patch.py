# -*- coding: utf-8 -*-
"""Client patcher and restart helper (FlClash / Clash Verge Rev / Mihomo Party).

FlClash stores its core settings in shared_preferences.json and only exposes a
clash controller when ``external-controller`` asks for it; the other GUI
clients manage that themselves, so the patch is a no-op unless the FlClash
marker file is present.
"""

import json
import os
import subprocess
import time

from path_utils import default_flclash_config_dir

CLIENT_PROCESSES = {
    "flclash": ["FlClash.exe", "FlClashCore.exe"],
    "verge": ["clash-verge.exe", "clash-verge-service.exe"],
    "mihomo": ["Mihomo Party.exe", "mihomo-party.exe"],
}

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def patch_flclash_external_controller(config_dir: str = "") -> bool:
    """Ensure FlClash exposes 127.0.0.1:9090. No-op for other clients."""
    config_dir = config_dir or default_flclash_config_dir()
    updated = False

    # 1. shared_preferences.json (the FlClash marker file)
    sp_path = os.path.join(config_dir, "shared_preferences.json")
    if os.path.exists(sp_path):
        try:
            with open(sp_path, "r", encoding="utf-8") as f:
                sp = json.load(f)
            raw_cfg = sp.get("flutter.config", "{}")
            cfg = json.loads(raw_cfg)
            patch = cfg.get("patchClashConfig", {})
            if patch.get("external-controller") != "127.0.0.1:9090":
                patch["external-controller"] = "127.0.0.1:9090"
                cfg["patchClashConfig"] = patch
                sp["flutter.config"] = json.dumps(cfg, ensure_ascii=False)
                with open(sp_path, "w", encoding="utf-8") as f:
                    json.dump(sp, f, ensure_ascii=False)
                updated = True
        except Exception:
            pass
    else:
        # Not a FlClash directory (Verge / Mihomo Party need no patching).
        return updated

    # 2. config.yaml
    cfg_path = os.path.join(config_dir, "config.yaml")
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                content = f.read()
            if 'external-controller: ""' in content:
                content = content.replace(
                    'external-controller: ""',
                    'external-controller: 127.0.0.1:9090')
                updated = True
            elif "external-controller:" not in content:
                content = "external-controller: 127.0.0.1:9090\n" + content
                updated = True
            else:
                return updated
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            pass

    return updated


def _find_exe(process_name: str) -> str:
    """Resolve the full path of a running client executable."""
    try:
        cmd = ["powershell", "-NoProfile", "-Command",
               f"(Get-Process -Name '{os.path.splitext(process_name)[0]}' "
               f"-ErrorAction SilentlyContinue | Select-Object -First 1).Path"]
        p = subprocess.run(cmd, capture_output=True, text=True,
                           creationflags=CREATE_NO_WINDOW)
        for line in p.stdout.splitlines():
            candidate = line.strip()
            if candidate and os.path.exists(candidate):
                return candidate
    except Exception:
        pass
    return ""


def restart_client(client_key: str = "flclash") -> bool:
    """Terminate and relaunch one supported client; False when unknown."""
    processes = CLIENT_PROCESSES.get(client_key)
    if not processes:
        return False
    exe = _find_exe(processes[0])
    try:
        for name in processes:
            subprocess.run(["taskkill", "/F", "/IM", name],
                           capture_output=True, creationflags=CREATE_NO_WINDOW)
        time.sleep(1.5)
        if exe and os.path.exists(exe):
            subprocess.Popen([exe], cwd=os.path.dirname(exe),
                             creationflags=CREATE_NO_WINDOW)
            time.sleep(2.0)
            return True
    except Exception:
        pass
    return False


def restart_flclash() -> bool:
    """Backwards-compatible alias."""
    return restart_client("flclash")
