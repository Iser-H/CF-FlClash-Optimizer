# -*- coding: utf-8 -*-
"""Background workers (QThread) for all I/O-heavy tasks."""

import os
import time
import requests
from typing import List, Tuple, Optional, Dict, Any

from PySide6.QtCore import QThread, Signal, QObject

import core_test
from core_test import probe_tls_ws  # re-exported for backwards compatibility


# ═══════════════════════════════════════════════════════════════════
# Worker 1: Current IP Health Check (cfst on existing 3 IPs)
# ═══════════════════════════════════════════════════════════════════
class HealthCheckWorker(QThread):
    """Run cfst.exe on the 3 current IPs to get speed/latency/loss with route bypass and dual-engine latency probe."""
    progress = Signal(str)              # log line
    result_ready = Signal(list)         # list of dicts
    finished_signal = Signal()
    error = Signal(str)

    def __init__(self, cfst_exe: str, node_info: List[dict],
                 clash_api, bin_dir: str, parent=None):
        super().__init__(parent)
        self.cfst_exe = cfst_exe
        self.node_info = node_info  # list of dicts from profile_mgr.get_node_full_info()
        self.clash_api = clash_api
        self.bin_dir = bin_dir
        self._stop = False
        self._proc = None

    def stop(self):
        self._stop = True
        if self._proc:
            try:
                self._proc.kill()
            except Exception:
                pass

    def _register(self, proc):
        self._proc = proc

    def run(self):
        try:
            results = core_test.run_health_check(
                self.cfst_exe, self.node_info, self.clash_api, self.bin_dir,
                log=self.progress.emit,
                is_stopped=lambda: self._stop,
                register_proc=self._register,
            )
            if results:
                self.result_ready.emit(results)
        except Exception as e:
            self.error.emit(str(e))
            self.progress.emit(f"❌ 体检出错: {e}")
        finally:
            self.finished_signal.emit()


# ═══════════════════════════════════════════════════════════════════
# Worker 2: Full CloudflareSpeedTest
# ═══════════════════════════════════════════════════════════════════
class SpeedTestWorker(QThread):
    """Run full cfst.exe speed test with kernel route bypass."""
    progress = Signal(str)
    result_ready = Signal(list)  # list of dicts from CSV
    finished_signal = Signal()
    error = Signal(str)

    def __init__(self, cfst_exe: str, bin_dir: str, clash_api,
                 threads: int = 200, tl: int = 400, sl: float = 5.0,
                 dn: int = 10, url: str = "", ip_file: Optional[str] = None,
                 parent=None):
        super().__init__(parent)
        self.cfst_exe = cfst_exe
        self.bin_dir = bin_dir
        self.clash_api = clash_api
        self.threads = threads
        self.tl = tl
        self.sl_filter = sl  # Filter threshold in Python post-processing ONLY!
        self.dn = dn
        self.url = url
        self.ip_file = ip_file or os.path.join(bin_dir, "ip.txt")
        self._stop = False
        self._proc = None

    def stop(self):
        self._stop = True
        if self._proc:
            try:
                self._proc.kill()
            except Exception:
                pass

    def _register(self, proc):
        self._proc = proc

    def run(self):
        try:
            results = core_test.run_speed_test(
                self.cfst_exe, self.bin_dir, ip_file=self.ip_file,
                threads=self.threads, tl=self.tl, sl_filter=self.sl_filter,
                dn=self.dn, url=self.url,
                log=self.progress.emit,
                is_stopped=lambda: self._stop,
                register_proc=self._register,
            )
            self.result_ready.emit(results)
        except Exception as e:
            self.error.emit(str(e))
            self.progress.emit(f"❌ 测速出错: {e}")
        finally:
            self.finished_signal.emit()


# ═══════════════════════════════════════════════════════════════════


# Worker 5: LAN HTTP Subscription Server
# ═══════════════════════════════════════════════════════════════════
from lan_server import LANServerWorker

