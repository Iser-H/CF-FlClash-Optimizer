# -*- coding: utf-8 -*-
"""Background auto-guardian: periodic health check, auto IP replacement, sync.

Runs in its own daemon thread (never on the Qt GUI thread) and talks to the UI
only through Qt signals.  The decision rule is deliberately conservative:

* run the same silence health check as the manual button on the 3 configured
  IPs;
* if at least 2 of 3 are still above the speed floor with acceptable latency
  and loss, skip the global scan (avoids needless stream interruption);
* if 2+ are degraded, sample the CIDR pool, run a full speed test, keep the
  healthy nodes, select replacements with the cross-/24 rule, write the
  profile, hot-reload via the 9090 API and regenerate every export file.
"""

import datetime
import os
import random
import threading
import time
import traceback
from typing import Any, Callable, Dict, Iterable, List, Optional

from PySide6.QtCore import QObject, Signal

import core_test
from cidr_pool import SubnetScoreStore, sample_candidates, select_top_ips, subnet_of
from storage_utils import atomic_write_text


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def node_health(result: Dict[str, Any], speed_floor: float = 5.0,
                max_latency: float = 400.0, max_loss: float = 5.0) -> Dict[str, Any]:
    """Classify one health-check row."""
    speed = _num(result.get("speed"))
    latency = _num(result.get("proxy_delay"), -1)
    if latency <= 0:
        latency = _num(result.get("cf_latency"))
    loss = _num(result.get("loss"))
    healthy = (speed >= speed_floor and latency > 0 and latency <= max_latency
               and loss <= max_loss)
    return {
        "name": str(result.get("name", "")),
        "ip": str(result.get("ip", "")),
        "speed": speed,
        "latency": latency,
        "loss": loss,
        "healthy": healthy,
        "subnet": str(result.get("subnet") or subnet_of(str(result.get("ip", ""))) or ""),
    }


def evaluate_health(results: Iterable[Dict[str, Any]], speed_floor: float = 5.0,
                    max_latency: float = 400.0, max_loss: float = 5.0,
                    expected_nodes: int = 3) -> Dict[str, Any]:
    """Decide whether a global scan is needed.

    ``needs_replace`` is True when fewer than 2 of the 3 configured nodes are
    healthy (= at least two degraded), matching the operator's anti-degradation
    rule.
    """
    details = [node_health(r, speed_floor, max_latency, max_loss) for r in results or []]
    good = [d for d in details if d["healthy"]]
    degraded = [d for d in details if not d["healthy"]]
    missing = max(0, int(expected_nodes) - len(details))
    degraded_count = len(degraded) + missing
    return {
        "good_count": len(good),
        "degraded_count": degraded_count,
        "requires_replace": len(good) < 2,
        "good": good,
        "degraded": degraded,
        "expected_nodes": int(expected_nodes),
    }


class AutoGuardian(QObject):
    """Periodic health-check / auto-replacement service (daemon thread)."""

    log = Signal(str)
    status_changed = Signal(str)
    health_result_ready = Signal(list)
    profile_updated = Signal(list)      # new IP list written to FlClash
    exports_updated = Signal(dict)      # export paths
    cycle_finished = Signal(dict)       # summary of one cycle
    error = Signal(str)

    def __init__(self, profile_factory: Callable[[], Any], clash_api: Any,
                 cfst_exe: str, bin_dir: str, exports_dir: str,
                 config: Dict[str, Any], store: Optional[SubnetScoreStore] = None,
                 health_runner: Optional[Callable[..., List[Dict[str, Any]]]] = None,
                 scan_runner: Optional[Callable[..., List[Dict[str, Any]]]] = None,
                 parent=None):
        super().__init__(parent)
        self._profile_factory = profile_factory
        self._clash_api = clash_api
        self._cfst_exe = cfst_exe
        self._bin_dir = bin_dir
        self._exports_dir = exports_dir
        self._config = config or {}
        self._store = store
        self._health_runner = health_runner
        self._scan_runner = scan_runner

        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._cycle_lock = threading.Lock()
        self._interval_secs = 1800.0
        self.last_run_ts = 0.0
        self.last_summary: Dict[str, Any] = {}
        self.running_cycle = False

    # ── lifecycle ────────────────────────────────────────────────
    def start(self, interval_minutes: Optional[float] = None):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._wake.clear()
        minutes = float(interval_minutes if interval_minutes is not None
                        else self._config.get("auto_guard_interval_min", 30) or 30)
        self._interval_secs = max(1.0, minutes * 60.0)
        self._thread = threading.Thread(target=self._loop, name="CFAutoGuardian", daemon=True)
        self._thread.start()
        self.log.emit(f"🛡️ 后台自动巡检已启动（每 {minutes:g} 分钟；独立守护线程）")

    def set_interval_minutes(self, minutes: float):
        self._interval_secs = max(1.0, float(minutes) * 60.0)
        self._wake.set()  # re-arm with the new interval

    def stop(self, timeout: float = 5.0):
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout)
            if thread.is_alive():
                self.log.emit("⚠ 后台巡检线程未在超时内退出（将在当前 cfst 结束后自行结束）")
        self._thread = None
        self.log.emit("🛡️ 后台自动巡检已停止")

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def trigger_now(self):
        self._wake.set()

    # ── thread loop ──────────────────────────────────────────────
    def _loop(self):
        # First check happens after one interval; the user can press
        # "立即巡检" to run immediately.
        while not self._stop.is_set():
            self._wake.wait(timeout=self._interval_secs)
            if self._stop.is_set():
                break
            self._wake.clear()
            self.cycle()

    # ── one cycle ────────────────────────────────────────────────
    def cycle(self) -> Dict[str, Any]:
        """Run one health cycle. Never raises; returns the summary."""
        if not self._cycle_lock.acquire(blocking=False):
            self.log.emit("ℹ 上一次巡检仍在进行，跳过本轮")
            return {"skipped": "busy"}

        summary: Dict[str, Any] = {"skipped": "", "ts": time.time(), "replaced": []}
        try:
            if core_test.CFST_LOCK.locked():
                self.log.emit("ℹ 检测到手动测速正在运行，本轮巡检跳过")
                summary["skipped"] = "cfst_busy"
                return summary

            cfg = self._config
            floor = _num(cfg.get("cfst_sl", 5.0), 5.0)
            max_latency = _num(cfg.get("cfst_tl", 400), 400.0)
            max_loss = _num(cfg.get("auto_guard_max_loss", 5.0), 5.0)

            self.running_cycle = True
            self.status_changed.emit("🩺 后台巡检中：正在体检 3 个已配置 IP...")
            pm = self._profile_factory()
            node_info = pm.get_node_full_info()
            if len(node_info) < 3:
                self.log.emit(f"⚠ 当前只有 {len(node_info)} 个 CF 节点，跳过自动换血")

            results = self._run_health(node_info, floor, max_latency)
            if not results:
                self.log.emit("ℹ 本轮巡检未取得体检数据（可能被停止），等待下一轮")
                summary["skipped"] = "no_result"
                return summary

            self.health_result_ready.emit(results)
            self._record_scores(results, floor, max_latency)
            decision = evaluate_health(results, floor, max_latency, max_loss,
                                       expected_nodes=len(node_info) or 3)
            summary.update(decision)
            self.last_run_ts = time.time()

            if not decision["requires_replace"]:
                message = (f"🛡️ 巡检完成：{decision['good_count']}/{len(results)} 个节点达标，"
                           f"保持现状并跳过全网扫描")
                self.log.emit(message)
                self.status_changed.emit(f"✅ 上次巡检 {self._stamp()} · 状态良好（{decision['good_count']}/{len(results)}）")
                summary["status"] = "healthy"
                self.cycle_finished.emit(summary)
                return summary

            self.log.emit(f"⚠ 检测到 {decision['degraded_count']} 个节点劣化，自动触发全网优选...")
            self.status_changed.emit("⚡ 检测到劣化，正在全网优选并自动换 IP...")
            new_ips = self._auto_replace(pm, node_info, results, floor, max_latency, max_loss, summary)
            if new_ips:
                summary["replaced"] = new_ips
                summary["status"] = "replaced"
                self.log.emit(f"✅ 自动换血完成: {', '.join(new_ips)}")
                self.status_changed.emit(f"✅ 上次巡检 {self._stamp()} · 已自动换 IP 并同步多端")
            else:
                summary["status"] = "no_change"
                self.status_changed.emit(f"✅ 上次巡检 {self._stamp()} · 无需换 IP")
            self.cycle_finished.emit(summary)
            return summary
        except Exception as exc:
            self.log.emit(f"❌ 后台巡检异常: {exc}")
            self.error.emit(str(exc))
            summary["status"] = "error"
            summary["error"] = str(exc)
            self.status_changed.emit(f"⚠ 上次巡检异常: {exc}")
            try:
                traceback.print_exc()
            except Exception:
                pass
            return summary
        finally:
            self.running_cycle = False
            self._cycle_lock.release()

    # ── steps ────────────────────────────────────────────────────
    def _run_health(self, node_info: List[Dict[str, Any]], floor: float,
                    max_latency: float) -> List[Dict[str, Any]]:
        log = self._emit_log
        is_stopped = self._stop.is_set
        if self._health_runner:
            return self._health_runner(node_info=node_info, log=log, is_stopped=is_stopped)
        return core_test.run_health_check(
            self._cfst_exe, node_info, self._clash_api, self._bin_dir,
            log=log, is_stopped=is_stopped)

    def _record_scores(self, results: List[Dict[str, Any]], floor: float,
                       max_latency: float) -> None:
        if not self._store:
            return
        try:
            stats = self._store.record_results(results, speed_floor=floor, max_latency=max_latency)
            self._store.save()
            if stats.get("recorded"):
                self.log.emit(f"📊 已记录 {stats['recorded']} 个样本到 /24 评分池（{stats['subnets']} 个子网）")
        except Exception as exc:
            self.log.emit(f"⚠ 评分写入失败（已忽略）: {exc}")

    def _auto_replace(self, pm: Any, node_info: List[Dict[str, Any]],
                      health: List[Dict[str, Any]], floor: float, max_latency: float,
                      max_loss: float, summary: Dict[str, Any]) -> List[str]:
        cfg = self._config
        total = int(cfg.get("cidr_sample_size", 2000) or 2000)
        ratio = _num(cfg.get("cidr_exploit_ratio", 0.7), 0.7)
        top_n = int(cfg.get("cidr_top_subnets", 40) or 40)
        rng = random.Random()

        candidates = sample_candidates(self._store, total=total, exploit_ratio=ratio,
                                       top_n=top_n, rng=rng)
        if not candidates:
            self.log.emit("⚠ 候选池为空，取消自动换血")
            return []
        ip_file = os.path.join(self._bin_dir, f"ip_guard_{int(time.time())}.txt")
        atomic_write_text(ip_file, "\n".join(candidates) + "\n")
        self.log.emit(f"🎲 已生成 {len(candidates)} 个候选 "
                      f"({int(ratio * 100)}% 历史优选 / {100 - int(ratio * 100)}% 全网探索)")

        scan = self._run_scan(ip_file, floor)
        if not scan:
            self.log.emit("⚠ 全网测速没有返回结果，保留现有 IP")
            return []
        self._record_scores(scan, floor, max_latency)

        # Keep nodes that are still healthy; replace the rest.
        healthy_by_ip = {}
        for row in health:
            info = node_health(row, floor, max_latency, max_loss)
            healthy_by_ip[info["ip"]] = info["healthy"]
        current_ips = [str(n.get("server", "")) for n in node_info]
        keep_ips = [ip for ip in current_ips if healthy_by_ip.get(ip)]
        keep_subnets = [subnet_of(ip) for ip in keep_ips if subnet_of(ip)]
        slots_to_fill = max(0, min(3, len(node_info)) - len(keep_ips))

        picked = select_top_ips(scan, count=slots_to_fill, exclude_ips=current_ips,
                                avoid_subnets=keep_subnets,
                                require_distinct_subnet=True) if slots_to_fill else []
        picks = [row["ip"] for row in picked]

        target_ips: List[str] = []
        pick_iter = iter(picks)
        for ip in current_ips:
            if healthy_by_ip.get(ip):
                target_ips.append(ip)
            else:
                try:
                    target_ips.append(next(pick_iter))
                except StopIteration:
                    target_ips.append(ip)
        if len(target_ips) < len(current_ips):
            target_ips.extend(current_ips[len(target_ips):])

        changed = any(old != new for old, new in zip(current_ips, target_ips))
        if not changed:
            self.log.emit("ℹ 未找到比现有 IP 更优的候选，保留当前配置")
            return []

        self.log.emit("📦 创建配置备份...")
        backup_path = pm.backup()
        pm.update_node_ips_by_index(target_ips[:3])
        self.log.emit(f"✅ 已写入新 IP: {', '.join(target_ips[:3])} (备份: {os.path.basename(backup_path)})")

        reloaded = False
        try:
            if self._clash_api is not None and self._clash_api.is_alive():
                reloaded = self._clash_api.reload_config(pm.profile_path)
        except Exception as exc:
            self.log.emit(f"⚠ 9090 热重载失败: {exc}")
        if reloaded:
            self.log.emit("🔄 FlClash 9090 端口热重载成功")
        else:
            self.log.emit("ℹ 9090 暂不可用，配置已落盘，FlClash 下次读取时生效")

        try:
            paths = pm.generate_all_exports(self._exports_dir)
            self.exports_updated.emit(paths)
            self.log.emit("📲 已自动重新生成 iOS / Happ / Base64 订阅文件")
        except Exception as exc:
            self.log.emit(f"⚠ 自动导出失败: {exc}")

        self.profile_updated.emit(target_ips[:3])
        summary["target_ips"] = target_ips[:3]
        summary["backup"] = backup_path
        summary["reloaded"] = reloaded
        return target_ips[:3]

    def _run_scan(self, ip_file: str, floor: float) -> List[Dict[str, Any]]:
        cfg = self._config
        if self._scan_runner:
            return self._scan_runner(ip_file=ip_file, log=self._emit_log,
                                     is_stopped=self._stop.is_set)
        return core_test.run_speed_test(
            self._cfst_exe, self._bin_dir, ip_file=ip_file,
            threads=int(cfg.get("cfst_threads", 200) or 200),
            tl=int(cfg.get("cfst_tl", 400) or 400),
            sl_filter=floor,
            dn=int(cfg.get("cfst_dn", 10) or 10),
            url=str(cfg.get("cfst_url", "") or ""),
            log=self._emit_log,
            is_stopped=self._stop.is_set,
        )

    # ── misc ─────────────────────────────────────────────────────
    def _emit_log(self, message: str):
        self.log.emit(str(message))

    @staticmethod
    def _stamp() -> str:
        return datetime.datetime.now().strftime("%H:%M:%S")
