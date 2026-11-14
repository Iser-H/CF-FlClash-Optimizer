# -*- coding: utf-8 -*-
"""Kernel routing level TUN bypass context manager.

Injects specific /32 or CIDR subnet routes via the physical network gateway,
ensuring traffic bypasses FlClash's 0.0.0.0/0 TUN virtual interface
due to the Longest Prefix Match principle.
"""

import os
import sys
import atexit
import subprocess
import ipaddress
from typing import List, Tuple, Set


_ACTIVE_ROUTES: Set[Tuple[str, str, str]] = set()


def get_physical_gateway() -> str:
    """Detect the active physical network gateway (excluding 198.18.* / FlClash TUN)."""
    # Method 1: route print 0.0.0.0
    try:
        res = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=3,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gw = parts[2]
                if not gw.startswith("198.18.") and gw != "0.0.0.0":
                    return gw
    except Exception:
        pass

    # Method 2: PowerShell Get-NetRoute
    try:
        cmd = [
            "powershell", "-NoProfile", "-Command",
            'Get-NetRoute -DestinationPrefix "0.0.0.0/0" | '
            'Where-Object { $_.NextHop -notlike "198.18.*" -and $_.NextHop -ne "0.0.0.0" } | '
            'Select-Object -ExpandProperty NextHop'
        ]
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=4,
        )
        for line in res.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("198.18.") and line != "0.0.0.0":
                return line
    except Exception:
        pass

    return "192.168.101.1"


def _cleanup_routes():
    """Emergency cleanup on process exit."""
    global _ACTIVE_ROUTES
    for net, mask, gw in list(_ACTIVE_ROUTES):
        try:
            subprocess.run(
                ["route", "delete", net, "mask", mask, gw],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=2,
            )
        except Exception:
            pass
    _ACTIVE_ROUTES.clear()


atexit.register(_cleanup_routes)


class RouteBypassContext:
    """Context manager for adding and removing temporary direct routes."""

    def __init__(self, targets: List[str], gateway: str = ""):
        """
        targets can be:
        - single IP: '162.159.160.217'
        - CIDR: '104.16.0.0/12'
        - path to ip.txt file
        """
        self.gateway = gateway or get_physical_gateway()
        self.raw_targets = targets
        self.route_specs: List[Tuple[str, str]] = []  # [(network_str, netmask_str), ...]
        self._parse_targets()

    def _parse_targets(self):
        for item in self.raw_targets:
            item = item.strip()
            if not item or item.startswith("#"):
                continue
            # If item is a file path
            if os.path.isfile(item):
                try:
                    with open(item, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                self._add_cidr(line)
                except Exception:
                    pass
            else:
                self._add_cidr(item)

    def _add_cidr(self, cidr_str: str):
        try:
            if "/" not in cidr_str:
                cidr_str = f"{cidr_str}/32"
            net = ipaddress.IPv4Network(cidr_str, strict=False)
            spec = (str(net.network_address), str(net.netmask))
            if spec not in self.route_specs:
                self.route_specs.append(spec)
        except Exception:
            pass

    def __enter__(self):
        global _ACTIVE_ROUTES
        for net, mask in self.route_specs:
            try:
                # Delete first to prevent "The object already exists" error
                subprocess.run(
                    ["route", "delete", net, "mask", mask, self.gateway],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=2,
                )
                res = subprocess.run(
                    ["route", "add", net, "mask", mask, self.gateway],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=2,
                )
                _ACTIVE_ROUTES.add((net, mask, self.gateway))
            except Exception:
                pass
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        global _ACTIVE_ROUTES
        for net, mask in self.route_specs:
            try:
                subprocess.run(
                    ["route", "delete", net, "mask", mask, self.gateway],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=2,
                )
                _ACTIVE_ROUTES.discard((net, mask, self.gateway))
            except Exception:
                pass
        return False
