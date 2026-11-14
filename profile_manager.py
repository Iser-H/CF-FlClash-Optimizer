# -*- coding: utf-8 -*-
"""YAML profile manager – read/write the FlClash profile with ruamel.yaml.

All writes are atomic and serialised through a per-path lock, because the GUI
thread, the LAN subscription server and the background auto-guardian can touch
the same profile concurrently.
"""

import base64
import copy
import datetime
import io
import json
import os
import shutil
from typing import Any, Dict, List, Optional, Tuple

from ruamel.yaml import YAML

from config_templates import (
    build_happ_subscription, build_happ_xray_json, build_optimized_profile,
    dump_yaml_text, harden_cf_nodes, merged_options, strip_for_ios,
)
from storage_utils import atomic_write_text, get_file_lock, read_text
from cidr_pool import subnet_of

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.allow_unicode = True


class ProfileManager:
    """Manages the FlClash YAML profile for CF node operations."""

    def __init__(self, profile_path: str, backups_dir: str, node_names: List[str],
                 options: Optional[Dict[str, Any]] = None):
        self.profile_path = profile_path
        self.backups_dir = backups_dir
        self.node_names = node_names  # e.g. ["🇺🇸 洛杉矶-CF优选1", ...]
        self.options = merged_options(dict(options or {}, cf_node_names=node_names))
        self._data = None
        self._loaded_mtime = 0.0
        self._lock = get_file_lock(profile_path)

    # ── loading / saving ─────────────────────────────────────────
    def load(self) -> Any:
        """Load YAML profile (thread-safe, fresh from disk)."""
        with self._lock:
            with open(self.profile_path, "r", encoding="utf-8") as f:
                self._data = yaml.load(f)
            try:
                self._loaded_mtime = os.path.getmtime(self.profile_path)
            except OSError:
                self._loaded_mtime = 0.0
            return self._data

    def _ensure_loaded(self) -> Any:
        """Return cached YAML, reloading if another thread changed the file."""
        if self._data is None:
            return self.load()
        try:
            if os.path.getmtime(self.profile_path) > self._loaded_mtime + 1e-6:
                return self.load()
        except OSError:
            pass
        return self._data

    def save(self) -> str:
        """Atomically save YAML profile back to disk."""
        with self._lock:
            if self._data is None:
                raise RuntimeError("profile not loaded")
            buf = io.StringIO()
            yaml.dump(self._data, buf)
            path = atomic_write_text(self.profile_path, buf.getvalue())
            try:
                self._loaded_mtime = os.path.getmtime(self.profile_path)
            except OSError:
                self._loaded_mtime = 0.0
            return path

    # ── node access ──────────────────────────────────────────────
    def get_cf_nodes(self) -> List[Any]:
        """Return the 3 target CF node mappings from the proxies list."""
        data = self._ensure_loaded()
        names = set(self.node_names)
        return [p for p in data.get("proxies", []) if p.get("name") in names]

    def get_current_ips(self) -> List[Tuple[str, str]]:
        return [(n["name"], str(n["server"])) for n in self.get_cf_nodes()]

    def get_node_full_info(self) -> List[Dict[str, Any]]:
        """Return full connection info for each CF node."""
        result: List[Dict[str, Any]] = []
        for node in self.get_cf_nodes():
            ws_opts = node.get("ws-opts") or {}
            headers = ws_opts.get("headers") or {}
            info = {
                "name": node.get("name", ""),
                "type": node.get("type", ""),
                "server": str(node.get("server", "")),
                "port": node.get("port", 443),
                "uuid": node.get("uuid", ""),
                "tls": node.get("tls", True),
                "network": node.get("network", "ws"),
                "servername": node.get("servername", ""),
                "client-fingerprint": node.get("client-fingerprint", "chrome"),
                "skip-cert-verify": node.get("skip-cert-verify", False),
                "subnet": subnet_of(str(node.get("server", ""))) or "",
            }
            info["ws-path"] = ws_opts.get("path", "/ws")
            info["ws-host"] = headers.get("Host", info["servername"])
            result.append(info)
        return result

    # ── backups ──────────────────────────────────────────────────
    def backup(self) -> str:
        os.makedirs(self.backups_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(self.backups_dir, f"profile_backup_{ts}.yaml")
        with self._lock:
            shutil.copy2(self.profile_path, backup_path)
        return backup_path

    def get_latest_backup(self) -> Optional[str]:
        if not os.path.exists(self.backups_dir):
            return None
        backups = sorted(
            (f for f in os.listdir(self.backups_dir)
             if f.startswith("profile_backup_") and f.endswith(".yaml")),
            reverse=True,
        )
        return os.path.join(self.backups_dir, backups[0]) if backups else None

    def restore_backup(self, backup_path: str):
        with self._lock:
            shutil.copy2(backup_path, self.profile_path)
            self.load()

    # ── mutations ────────────────────────────────────────────────
    def update_node_ips(self, ip_list: List[Tuple[str, str]]):
        """Update server IPs for CF nodes. ip_list = [(node_name, new_ip), ...]"""
        data = self._ensure_loaded()
        ip_map = {name: ip for name, ip in ip_list}
        with self._lock:
            for proxy in data.get("proxies", []):
                name = proxy.get("name")
                if name in ip_map:
                    proxy["server"] = ip_map[name]
            harden_cf_nodes(data.get("proxies", []), self.node_names)
            self.save()

    def update_node_ips_by_index(self, new_ips: List[str]):
        """Update the 3 CF nodes by index with new IPs (mux stays disabled)."""
        data = self._ensure_loaded()
        with self._lock:
            idx = 0
            for proxy in data.get("proxies", []):
                if proxy.get("name") in self.node_names and idx < len(new_ips):
                    proxy["server"] = new_ips[idx]
                    idx += 1
            harden_cf_nodes(data.get("proxies", []), self.node_names)
            self.save()

    def get_mixed_port(self) -> int:
        return int(self._ensure_loaded().get("mixed-port", 7890))

    def get_external_controller(self) -> str:
        return str(self._ensure_loaded().get("external-controller", "127.0.0.1:9090"))

    # ── topology ─────────────────────────────────────────────────
    def apply_optimized_topology(self) -> Dict[str, Any]:
        """Install the multi-client topology into the live FlClash profile.

        Backs up first; preserves every unrelated proxy/rule/comment.
        """
        data = self._ensure_loaded()
        backup_path = self.backup()
        optimized, summary = build_optimized_profile(data, self.options)
        with self._lock:
            self._data = optimized
            self.save()
        # Re-parse from disk so ruamel's comment tables are rebuilt against the
        # written file before any export dump happens.
        self.load()
        summary["backup"] = backup_path
        # Remember what this run merged, so a future airport change can remove
        # stale nodes; the GUI persists these values into config.json.
        if summary.get("airport_path"):
            self.options["airport_profile_path"] = summary["airport_path"]
        self.options["airport_managed_nodes"] = summary.get("managed_nodes", [])
        return summary

    # ── exports ──────────────────────────────────────────────────
    def _optimized_snapshot(self) -> Tuple[Any, Dict[str, Any]]:
        """Build the optimized topology in memory (never mutates the live file).

        Always re-parses the profile: reusing an in-memory ruamel tree that was
        just dumped can carry stale comment tables and serialise ``rules: -``
        (invalid YAML) on the next dump.
        """
        data = self.load()
        return build_optimized_profile(data, self.options)

    def generate_ios_yaml(self, output_path: str) -> str:
        """Export a Clash-for-iOS compatible YAML (IPv6/mux hardened)."""
        optimized, _summary = self._optimized_snapshot()
        ios_data = strip_for_ios(optimized)
        text = dump_yaml_text(ios_data)
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        atomic_write_text(output_path, text)
        return output_path

    def generate_vless_links(self, nodes: Optional[List[Any]] = None) -> List[str]:
        """Generate vless:// links for the 3 CF nodes (legacy plain format)."""
        from urllib.parse import quote

        nodes = nodes if nodes is not None else self.get_node_full_info()
        links = []
        for n in nodes:
            if not isinstance(n, dict):
                continue
            tls_str = "tls" if n.get("tls") else "none"
            path = quote(n.get("ws-path", "/ws"), safe="")
            name = quote(n.get("name", ""), safe="")
            host = n.get("ws-host", n.get("servername", ""))
            sni = n.get("servername", "")
            fp = n.get("client-fingerprint", "chrome")
            link = (
                f"vless://{n['uuid']}@{n['server']}:{n['port']}"
                f"?encryption=none&security={tls_str}&sni={sni}"
                f"&fp={fp}&type={n['network']}&host={host}&path={path}"
                f"#{name}"
            )
            links.append(link)
        return links

    def generate_happ_subscription(self, output_path: str) -> str:
        """Happ TV subscription text with auto-update/autoconnect headers."""
        optimized, _summary = self._optimized_snapshot()
        text = build_happ_subscription(optimized, self.options)
        atomic_write_text(output_path, text)
        return output_path

    def generate_happ_xray_json(self, output_path: str) -> str:
        """Happ / Xray JSON: DNS queryStrategy UseIPv4, mux disabled."""
        optimized, _summary = self._optimized_snapshot()
        config = build_happ_xray_json(optimized, self.options)
        atomic_write_text(output_path, json.dumps(config, ensure_ascii=False, indent=2) + "\n")
        return output_path

    def generate_all_exports(self, exports_dir: str) -> Dict[str, str]:
        """Regenerate every multi-end export in one call.

        Builds the optimized topology once and reuses it for:
        FlClash (full), Clash for iOS (desktop keys stripped), Happ text,
        Happ Xray JSON and the legacy Base64 subscription.

        Returns mapping name -> absolute path.  Safe to call from a background
        thread: each file is written atomically and the profile is only read.
        """
        os.makedirs(exports_dir, exist_ok=True)
        flclash_path = os.path.join(exports_dir, "FlClash_Optimized.yaml")
        ios_path = os.path.join(exports_dir, "iOS_Clash_Config.yaml")
        tv_path = os.path.join(exports_dir, "TV_VLESS_Links.txt")
        sub_path = os.path.join(exports_dir, "tv_sub.txt")
        happ_path = os.path.join(exports_dir, "tv_happ.txt")
        xray_path = os.path.join(exports_dir, "happ_xray.json")

        optimized, _summary = self._optimized_snapshot()
        atomic_write_text(flclash_path, dump_yaml_text(optimized))
        atomic_write_text(ios_path, dump_yaml_text(strip_for_ios(optimized)))
        atomic_write_text(happ_path, build_happ_subscription(optimized, self.options))
        atomic_write_text(xray_path, json.dumps(
            build_happ_xray_json(optimized, self.options), ensure_ascii=False, indent=2) + "\n")

        links = self.generate_vless_links()
        atomic_write_text(tv_path, "\n".join(links))
        combined = "\n".join(links)
        atomic_write_text(sub_path, base64.b64encode(combined.encode("utf-8")).decode("ascii"))

        return {
            "flclash": flclash_path,
            "ios": ios_path,
            "happ": happ_path,
            "happ_xray": xray_path,
            "tv": tv_path,
            "tv_sub": sub_path,
        }
