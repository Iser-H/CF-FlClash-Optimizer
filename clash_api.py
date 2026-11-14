# -*- coding: utf-8 -*-
"""Clash API helper – talks to FlClash/Mihomo external controller."""

import requests
import time


class ClashAPI:
    """Wrapper for Clash RESTful API."""

    def __init__(self, controller: str = "127.0.0.1:9090", secret: str = ""):
        self.base = f"http://{controller}"
        self.headers = {"Content-Type": "application/json"}
        if secret:
            self.headers["Authorization"] = f"Bearer {secret}"
        self._timeout = 5

    # ── connectivity ──────────────────────────────────────────────
    def is_alive(self) -> bool:
        try:
            r = requests.get(f"{self.base}/version", headers=self.headers, timeout=self._timeout)
            return r.status_code == 200
        except Exception:
            return False

    def get_version(self) -> str:
        try:
            r = requests.get(f"{self.base}/version", headers=self.headers, timeout=self._timeout)
            return r.json().get("version", "unknown")
        except Exception:
            return "N/A"

    # ── mode control ──────────────────────────────────────────────
    def get_mode(self) -> str:
        try:
            r = requests.get(f"{self.base}/configs", headers=self.headers, timeout=self._timeout)
            return r.json().get("mode", "rule")
        except Exception:
            return "rule"

    def set_mode(self, mode: str) -> bool:
        """Set mode: rule / direct / global."""
        try:
            r = requests.patch(
                f"{self.base}/configs",
                json={"mode": mode},
                headers=self.headers,
                timeout=self._timeout,
            )
            return r.status_code == 204 or r.status_code == 200
        except Exception:
            return False

    # ── config reload ─────────────────────────────────────────────
    def reload_config(self, config_path: str) -> bool:
        """PUT /configs?force=true to hot-reload the profile."""
        try:
            r = requests.put(
                f"{self.base}/configs?force=true",
                json={"path": config_path},
                headers=self.headers,
                timeout=10,
            )
            return r.status_code in (200, 204)
        except Exception:
            return False

    # ── proxy testing ─────────────────────────────────────────────
    def test_proxy_delay(self, proxy_name: str, url: str = "https://www.gstatic.com/generate_204", timeout_ms: int = 5000) -> int:
        """GET /proxies/:name/delay  returns delay in ms or -1."""
        try:
            r = requests.get(
                f"{self.base}/proxies/{requests.utils.quote(proxy_name)}/delay",
                params={"url": url, "timeout": timeout_ms},
                headers=self.headers,
                timeout=timeout_ms / 1000 + 2,
            )
            if r.status_code == 200:
                return r.json().get("delay", -1)
            return -1
        except Exception:
            return -1

    # ── proxy group switching ─────────────────────────────────────
    def get_proxies(self) -> dict:
        try:
            r = requests.get(f"{self.base}/proxies", headers=self.headers, timeout=self._timeout)
            return r.json().get("proxies", {})
        except Exception:
            return {}

    def switch_proxy(self, group_name: str, proxy_name: str) -> bool:
        """PUT /proxies/:group to switch selected proxy in a Selector group."""
        try:
            r = requests.put(
                f"{self.base}/proxies/{requests.utils.quote(group_name)}",
                json={"name": proxy_name},
                headers=self.headers,
                timeout=self._timeout,
            )
            return r.status_code in (200, 204)
        except Exception:
            return False
