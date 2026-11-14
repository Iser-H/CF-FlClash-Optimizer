# -*- coding: utf-8 -*-
"""Main GUI – CF-FlClash-Optimizer: single-tab PySide6 application."""

import os
import sys

# Ensure sys.stdout and sys.stderr are valid in GUI (noconsole) mode
if sys.stdout is None:
    try:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    except Exception:
        pass
if sys.stderr is None:
    try:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    except Exception:
        pass

# Ensure Qt platform plugins can be found in PyInstaller frozen bundle
if getattr(sys, "frozen", False):
    base_dir = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    plugin_path = os.path.join(base_dir, "PySide6", "plugins")
    if os.path.exists(plugin_path):
        os.environ["QT_PLUGIN_PATH"] = plugin_path
        os.environ["QT_QPA_PLATFORM_PLUGIN_PATH"] = os.path.join(plugin_path, "platforms")
    elif os.path.exists(os.path.join(base_dir, "platforms")):
        os.environ["QT_PLUGIN_PATH"] = base_dir
        os.environ["QT_QPA_PLATFORM_PLUGIN_PATH"] = os.path.join(base_dir, "platforms")

def _get_log_path():
    if getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(sys.executable), "app_debug.log")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_debug.log")

DEBUG_LOG = _get_log_path()

def dbg(msg):
    try:
        with open(DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(str(msg) + "\n")
    except Exception:
        pass

dbg("1. main_gui module starting")

import base64
import random
import shutil
import threading
import time

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox,
    QLabel, QPushButton, QSpinBox, QDoubleSpinBox, QLineEdit,
    QTableWidget, QTableWidgetItem, QPlainTextEdit, QHeaderView,
    QComboBox, QProgressBar, QSplitter, QCheckBox, QMessageBox,
    QFrame, QMenu, QSystemTrayIcon, QFileDialog,
    QScrollArea, QSizePolicy, QToolButton,
)
from PySide6.QtCore import Qt, QTimer, QPointF, QRectF, QObject, Signal, QSize
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtGui import (
    QFont, QColor, QIcon, QPixmap, QPainter, QBrush, QPen,
    QPolygonF, QLinearGradient,
)

from path_utils import (
    APP_ROOT, BIN_DIR, BACKUPS_DIR, EXPORTS_DIR, CFST_EXE,
    DESKTOP_EXPORT_DIR, load_config, save_config,
    get_app_dir, ensure_app_cwd, is_auto_start_enabled, set_auto_start,
    build_auto_start_command, AUTO_START_KEY_NAME, default_flclash_config_dir,
)
from clash_api import ClashAPI
from profile_manager import ProfileManager
from flclash_patch import patch_flclash_external_controller, restart_client
from workers import (
    HealthCheckWorker, SpeedTestWorker,
    LANServerWorker,
)
from clients import (
    CLIENT_LABELS, discover as discover_clients, first_profile,
    normalize_api, restart_hint, detect_api, looks_like_profile,
)
from export_dialog import ExportDialog
from auto_guard import AutoGuardian
from lan_server import (
    ensure_firewall_rule_detailed, firewall_rule_name,
    ensure_lan_token, generate_token, is_valid_token,
)
from cidr_pool import (
    SubnetScoreStore, ensure_cidr_file, sample_candidates, select_top_ips, subnet_of,
)
from storage_utils import atomic_write_text

def excepthook(exc_type, exc_value, exc_tb):
    import traceback
    try:
        with open(os.path.join(APP_ROOT, "crash.log"), "w", encoding="utf-8") as f:
            traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
    except Exception:
        pass
    sys.__excepthook__(exc_type, exc_value, exc_tb)

sys.excepthook = excepthook


# ══════════════════════════════════════════════════════════════════
# Application / system-tray icon
# ══════════════════════════════════════════════════════════════════
TRAY_ICON_CANDIDATES = (
    "icon.ico", "app.ico", "logo.ico", "cf.ico", "CF-FlClash-Optimizer.ico",
    os.path.join("assets", "icon.ico"),
    os.path.join("assets", "app.ico"),
    os.path.join("images", "icon.ico"),
    os.path.join("resources", "icon.ico"),
)


def _icon_search_dirs() -> list:
    """Directories that may carry a shipped .ico (source tree and PyInstaller)."""
    dirs = [APP_ROOT]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass and meipass not in dirs:
        dirs.append(meipass)
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        if exe_dir not in dirs:
            dirs.append(exe_dir)
    return dirs


def _paint_tray_pixmap(size: int = 64) -> QPixmap:
    """Draw the rounded orange/red "CF + lightning" tile.

    Drawn entirely in code (no external asset required) and given a white rim,
    so the same icon stays legible on a light and on a dark Windows taskbar.
    """
    size = max(8, int(size))
    pix = QPixmap(size, size)
    pix.fill(Qt.transparent)
    painter = QPainter(pix)
    try:
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setRenderHint(QPainter.TextAntialiasing, True)

        margin = max(1.0, size * 0.04)
        radius = size * 0.22
        gradient = QLinearGradient(0, 0, size, size)
        gradient.setColorAt(0.0, QColor("#FFA726"))
        gradient.setColorAt(0.55, QColor("#FB8C00"))
        gradient.setColorAt(1.0, QColor("#E53935"))
        painter.setBrush(QBrush(gradient))
        painter.setPen(QPen(QColor("#FFFFFF"), max(1.0, size * 0.035)))
        painter.drawRoundedRect(
            QRectF(margin, margin, size - 2 * margin, size - 2 * margin),
            radius, radius)

        # Lightning bolt, upper part of the tile.
        bolt = [(0.64, 0.06), (0.30, 0.50), (0.47, 0.50),
                (0.40, 0.62), (0.72, 0.38), (0.55, 0.38)]
        polygon = QPolygonF([QPointF(x * size, y * size) for x, y in bolt])
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(QColor("#FFFFFF")))
        painter.drawPolygon(polygon)

        # "CF" monogram below the bolt (only where it can be resolved).
        if size >= 32:
            font = QFont("Arial")
            font.setBold(True)
            font.setPixelSize(max(8, int(size * 0.30)))
            painter.setFont(font)
            painter.setPen(QPen(QColor("#FFFFFF")))
            painter.drawText(QRectF(0, size * 0.58, size, size * 0.34),
                             Qt.AlignCenter, "CF")
    finally:
        painter.end()
    return pix


def build_app_icon() -> QIcon:
    """Project .ico when one exists, otherwise a painted, never-null QIcon."""
    for directory in _icon_search_dirs():
        for relative in TRAY_ICON_CANDIDATES:
            path = os.path.join(directory, relative)
            try:
                if not os.path.exists(path):
                    continue
                icon = QIcon(path)
                if not icon.isNull() and not icon.pixmap(32, 32).isNull():
                    dbg(f"icon: using {path}")
                    return icon
            except Exception:
                continue
    icon = QIcon()
    for size in (16, 20, 24, 32, 40, 48, 64, 128, 256):
        icon.addPixmap(_paint_tray_pixmap(size))
    if icon.isNull():  # last resort — an empty QIcon is invisible in the tray
        icon = QIcon(_paint_tray_pixmap(64))
    dbg("icon: painted fallback icon in use")
    return icon


# ══════════════════════════════════════════════════════════════════
# Single-instance guard
#
# A second double-click must not start a second tray icon, a second copy of
# the speed test or a LAN server bumped to 8687. The first process owns a
# QLocalServer; later processes connect, send "SHOW", and exit 0 after asking
# the owner to raise its window.
#
#   CFFO_ALLOW_MULTI_INSTANCE=1  -> skip the guard (parallel test runs)
#   CFFO_SINGLE_INSTANCE_NAME=x  -> use another pipe name (tests, profiles)
# ══════════════════════════════════════════════════════════════════
SINGLE_INSTANCE_DEFAULT_NAME = "CF-FlClash-Optimizer-SingleInstance-v1"


def single_instance_name() -> str:
    return os.environ.get("CFFO_SINGLE_INSTANCE_NAME") or SINGLE_INSTANCE_DEFAULT_NAME


def multi_instance_allowed() -> bool:
    return os.environ.get("CFFO_ALLOW_MULTI_INSTANCE", "").strip().lower() in (
        "1", "true", "yes", "on")


def notify_existing_instance(timeout_ms: int = 300) -> bool:
    """True when another instance answered and was asked to show its window."""
    if multi_instance_allowed():
        return False
    sock = QLocalSocket()
    sock.connectToServer(single_instance_name())
    if not sock.waitForConnected(timeout_ms):
        sock.abort()
        return False
    sock.write(b"SHOW")
    sock.flush()
    sock.waitForBytesWritten(timeout_ms)
    sock.disconnectFromServer()
    sock.abort()
    return True


class SingleInstanceServer(QObject):
    """Owns the named pipe and re-raises the window on a "SHOW" message."""

    activated = Signal()

    def __init__(self, name: str = None, parent=None):
        super().__init__(parent)
        self.name = name or single_instance_name()
        self._server = QLocalServer(self)
        # A crash can leave the pipe/socket file behind; listen() would then fail.
        QLocalServer.removeServer(self.name)
        self._listening = self._server.listen(self.name)
        self._server.newConnection.connect(self._drain)
        dbg(f"single-instance: listen({self.name}) -> {self._listening}")

    def _drain(self):
        while self._server.hasPendingConnections():
            conn = self._server.nextPendingConnection()
            if conn is None:
                break
            conn.readyRead.connect(lambda c=conn: self._on_ready(c))
            conn.disconnected.connect(conn.deleteLater)
            if conn.bytesAvailable():
                self._on_ready(conn)

    def _on_ready(self, conn):
        try:
            data = bytes(conn.readAll())
        except RuntimeError:
            return
        if b"SHOW" in data:
            self.activated.emit()

    def close(self):
        try:
            self._server.close()
        except Exception:
            pass
        QLocalServer.removeServer(self.name)


class NodeCard(QFrame):
    """A card widget displaying a single CF node's health status."""

    def __init__(self, node_index: int = 0, parent=None):
        super().__init__(parent)
        self.node_index = node_index
        self.rating = "unknown"  # "good", "medium", "bad", "unknown"
        self.current_speed = 0.0

        self.setFrameShape(QFrame.StyledPanel)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.setMinimumWidth(230)
        self.setStyleSheet("""
            NodeCard {
                border: 2px solid #ccc; border-radius: 10px;
                background: #f9f9f9; padding: 8px;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        header_layout = QHBoxLayout()
        self.name_label = QLabel(f"节点 {node_index + 1}")
        self.name_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        header_layout.addWidget(self.name_label)
        header_layout.addStretch()

        self.target_chk = QCheckBox("🎯 设为替换目标")
        self.target_chk.setToolTip("勾选后，全网优选表格选中的新 IP 将优先写入并替换此节点")
        self.target_chk.setStyleSheet("font-size: 11px; font-weight: bold; color: #1976D2;")
        header_layout.addWidget(self.target_chk)
        layout.addLayout(header_layout)

        self.ip_label = QLabel("IP: —")
        self.ip_label.setStyleSheet("font-size: 12px; color: #555;")
        layout.addWidget(self.ip_label)

        self.sni_label = QLabel("SNI: —")
        self.sni_label.setStyleSheet("font-size: 11px; color: #777;")
        layout.addWidget(self.sni_label)

        # Metrics grid
        metrics = QGridLayout()
        metrics.setSpacing(2)
        self.proxy_delay_lbl = QLabel("代理延迟: —")
        self.cf_latency_lbl = QLabel("CF 延迟: —")
        self.loss_lbl = QLabel("丢包率: —")
        self.speed_lbl = QLabel("下载速度: —")
        metrics.addWidget(self.proxy_delay_lbl, 0, 0)
        metrics.addWidget(self.cf_latency_lbl, 0, 1)
        metrics.addWidget(self.loss_lbl, 1, 0)
        metrics.addWidget(self.speed_lbl, 1, 1)
        layout.addLayout(metrics)

        self.status_label = QLabel("⏳ 待检测")
        self.status_label.setStyleSheet("font-size: 13px; font-weight: bold; padding: 3px;")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

    def update_info(self, name: str, ip: str, sni: str):
        self.name_label.setText(name)
        self.ip_label.setText(f"IP: {ip}")
        self.sni_label.setText(f"SNI: {sni}")

    def update_metrics(self, proxy_delay: int, delay_type: str, cf_latency: float, loss: float, speed: float):
        self.current_speed = speed
        if proxy_delay > 0:
            if delay_type == "api":
                self.proxy_delay_lbl.setText(f"代理延迟: {proxy_delay}ms")
            else:
                self.proxy_delay_lbl.setText(f"隧道握手: {proxy_delay}ms")
        else:
            self.proxy_delay_lbl.setText("延迟: 超时")

        self.cf_latency_lbl.setText(f"CF 延迟: {cf_latency:.0f}ms")
        self.loss_lbl.setText(f"丢包率: {loss:.1f}%")
        self.speed_lbl.setText(f"下载速度: {speed:.2f} MB/s")

        # Status rating based on requirements:
        # 🟢 >= 5.0 MB/s & loss == 0: 状态优良
        # 🟡 1.5 ~ 5.0 MB/s: 速度一般
        # 🔴 < 1.5 MB/s or timeout: 性能劣化
        if speed >= 5.0 and loss == 0:
            self.rating = "good"
            self.status_label.setText("🟢 状态优良 — 无需换IP")
            self.setStyleSheet("NodeCard { border: 2px solid #4CAF50; border-radius: 10px; background: #e8f5e9; padding: 8px; }")
            self.target_chk.setChecked(False)
            self.target_chk.setText("🛡️ 优良保留")
            self.target_chk.setStyleSheet("font-size: 11px; color: #2E7D32;")
        elif speed >= 1.5:
            self.rating = "medium"
            self.status_label.setText("🟡 速度一般 — 可考虑优选")
            self.setStyleSheet("NodeCard { border: 2px solid #FF9800; border-radius: 10px; background: #fff3e0; padding: 8px; }")
            self.target_chk.setChecked(True)
            self.target_chk.setText("🎯 替换目标")
            self.target_chk.setStyleSheet("font-size: 11px; color: #E65100; font-weight: bold;")
        else:
            self.rating = "bad"
            self.status_label.setText("🔴 性能劣化 — 建议立即换IP")
            self.setStyleSheet("NodeCard { border: 2px solid #f44336; border-radius: 10px; background: #ffebee; padding: 8px; }")
            self.target_chk.setChecked(True)
            self.target_chk.setText("🎯 优先替换")
            self.target_chk.setStyleSheet("font-size: 11px; color: #C62828; font-weight: bold;")


class CollapsibleSection(QWidget):
    """Compact panel for low-frequency settings (looks like a QGroupBox).

    The body is hidden while collapsed, so a panel added later cannot squeeze
    the primary work area. Callers use ``section.body_layout`` exactly like a
    QGroupBox layout, therefore no widget or signal/slot wiring has to change.
    """

    toggled = Signal(bool)

    def __init__(self, title: str, expanded: bool = True, parent=None):
        super().__init__(parent)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._header = QFrame()
        self._header.setObjectName("collapsibleHeader")
        self._header.setStyleSheet(
            "#collapsibleHeader { background: #ECEFF1; border: 1px solid #CFD8DC;"
            " border-radius: 4px; }")
        header_layout = QHBoxLayout(self._header)
        header_layout.setContentsMargins(6, 2, 8, 2)
        header_layout.setSpacing(6)

        self._toggle_btn = QToolButton()
        self._toggle_btn.setCheckable(True)
        self._toggle_btn.setChecked(bool(expanded))
        self._toggle_btn.setAutoRaise(True)
        self._toggle_btn.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self._toggle_btn.setArrowType(Qt.DownArrow if expanded else Qt.RightArrow)
        self._toggle_btn.setText(title)
        self._toggle_btn.setCursor(Qt.PointingHandCursor)
        self._toggle_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._toggle_btn.setStyleSheet(
            "QToolButton { border: none; background: transparent; text-align: left;"
            " font-weight: bold; font-size: 12px; color: #263238; padding: 4px 2px; }")
        header_layout.addWidget(self._toggle_btn, 1)

        self._summary = QLabel("")
        self._summary.setStyleSheet("font-size: 11px; color: #607D8B; background: transparent;")
        self._summary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        header_layout.addWidget(self._summary, 0)
        root.addWidget(self._header)

        self.body = QFrame()
        self.body.setObjectName("collapsibleBody")
        self.body.setStyleSheet(
            "#collapsibleBody { background: transparent; border: 1px solid #CFD8DC;"
            " border-top: none; border-radius: 0 0 4px 4px; }")
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(10, 8, 10, 10)
        self.body_layout.setSpacing(6)
        self.body.setVisible(bool(expanded))
        root.addWidget(self.body)

        self._toggle_btn.toggled.connect(self._on_toggled)

    def _on_toggled(self, expanded: bool):
        self.body.setVisible(expanded)
        self._toggle_btn.setArrowType(Qt.DownArrow if expanded else Qt.RightArrow)
        self.toggled.emit(bool(expanded))

    def is_expanded(self) -> bool:
        return self._toggle_btn.isChecked()

    def set_expanded(self, expanded: bool):
        self._toggle_btn.setChecked(bool(expanded))

    def set_summary(self, text: str):
        """One-line status shown in the header while the body is collapsed."""
        self._summary.setText(text or "")


def order_for_subnet_diversity(ips: list) -> list:
    """Reorder IPs so distinct /24 subnets come first (never drops an IP)."""
    ordered, deferred, seen = [], [], set()
    for ip in ips:
        subnet = subnet_of(ip)
        if subnet and subnet in seen:
            deferred.append(ip)
            continue
        if subnet:
            seen.add(subnet)
        ordered.append(ip)
    return ordered + deferred


class MainWindow(QMainWindow):
    """Main application window with 2 tabs."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CF-FlClash-Optimizer — Cloudflare 优选 IP 体检与多端配置导出")
        # Both sizes are derived from the current screen work area, so a small
        # desktop or 150 % scaling can never push the window off-screen. The
        # tab content scrolls, so the minimum is allowed to shrink with it.
        minimum_size, preferred_size = self._window_sizes()
        self.setMinimumSize(minimum_size)
        self.resize(preferred_size)

        # Tray / shutdown state — created before any UI so closeEvent is always safe.
        self._force_quit = False          # set by the tray "完全退出程序" action
        self._tray_icon = None
        self._tray_menu = None
        self._tray_hint_shown = False     # balloon is shown only on the first hide
        self._shutdown_done = False       # makes background teardown idempotent

        # Load config
        self.cfg = load_config()
        self.profile_path = self._resolve_profile_path()
        self.config_dir = (self.cfg.get("flclash_config_dir")
                           or os.path.dirname(self.profile_path)
                           or default_flclash_config_dir())
        self.cfg["flclash_config_dir"] = self.config_dir
        self.mixed_port = self.cfg["mixed_port"]

        # Ensure FlClash 9090 port is patched in configs (FlClash only).
        if self.config_dir and os.path.isdir(self.config_dir):
            try:
                patch_flclash_external_controller(self.config_dir)
            except Exception as exc:
                dbg(f"flclash patch skipped: {exc}")

        # Initialize core objects. A machine with no profile yet must still
        # open the GUI so the user can pick one in the 客户端与配置文件 panel.
        self.clash_api = ClashAPI(self.cfg["external_controller"], self.cfg["secret"])
        self.profile_mgr = ProfileManager(
            self.profile_path or os.path.join(APP_ROOT, "config.yaml"),
            BACKUPS_DIR, self.cfg["cf_node_names"],
            options=self.cfg,
        )
        if self.profile_path and os.path.isfile(self.profile_path):
            try:
                self.profile_mgr.load()
            except Exception as exc:
                dbg(f"profile load failed: {exc}")

        # /24 score history (persisted; first run starts empty -> 100% explore)
        self.cidr_store = SubnetScoreStore(
            os.path.join(APP_ROOT, self.cfg.get("cidr_score_file", "cidr_score_history.json")))
        try:
            self.cidr_store.load()
        except Exception:
            pass
        try:
            ensure_cidr_file(os.path.join(BIN_DIR, "ip.txt"))
        except Exception:
            pass

        # Cache of health results: ip -> dict
        self._current_health_results = {}

        # Workers
        self._health_worker = None
        self._speed_worker = None
        self._lan_server = None
        self._lan_ip = ""
        self._lan_port = self.cfg["lan_server_port"]
        self._lan_base_url = ""
        self._lan_urls = []
        self._auto_replace = False
        self._guard = None
        self._instance_server = None
        self._client_rows = []

        # Build UI
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(8, 8, 8, 8)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_tab1(), "🩺 CF 优选测速 & IP 体检 & 多端导出")
        main_layout.addWidget(self.tabs)

        # Status bar
        self.statusBar().showMessage("就绪 — 请点击按钮开始检测")

        # Load initial node info
        self._refresh_node_cards()

        # System tray + startup/close behaviour (must exist before any hide/show).
        self._init_tray()
        self._sync_auto_start_from_registry()

        # Start LAN subscription service + auto guardian (daemon threads, never
        # blocks the GUI thread). LAN sharing is opt-in: only an explicit
        # True saved by the user starts it, and a token is mandatory.
        if self.cfg.get("lan_server_enabled", False):
            self._start_lan_server()
        else:
            self.lan_info_lbl.setText("⏸ 局域网订阅服务已关闭（默认关闭，勾选上方开关可启用）")
        self._update_lan_auth_label()
        if self.cfg.get("auto_guard_enabled"):
            self.guard_chk.setChecked(True)

    # ══════════════════════════════════════════════════════════════
    # TAB 1: CF Speed Test + Health Check + Export
    # ══════════════════════════════════════════════════════════════
    def _resolve_profile_path(self) -> str:
        """Configured YAML, else auto-discover a local client profile."""
        configured = str(self.cfg.get("flclash_profile_path") or "").strip()
        if configured and os.path.isfile(configured):
            return os.path.abspath(configured)
        try:
            found = first_profile(str(self.cfg.get("flclash_config_dir") or ""))
        except Exception as exc:
            dbg(f"client discovery failed: {exc}")
            found = None
        if found:
            dbg(f"profile auto-discovered: {found['path']}")
            self.cfg["flclash_profile_path"] = found["path"]
            self.cfg.setdefault("client_type", found.get("key", "auto"))
            return found["path"]
        return configured

    @staticmethod
    def _screen_work_area() -> QSize:
        """Logical size of the primary screen's work area (0x0 when unknown)."""
        screen = QApplication.primaryScreen()
        if screen is None:
            return QSize(0, 0)
        return screen.availableGeometry().size()

    @classmethod
    def _window_sizes(cls) -> tuple:
        """(minimum, preferred) sizes that always fit the screen work area.

        The tab content scrolls, so on a small or heavily scaled desktop the
        minimum may drop below the usual 980x640 instead of pushing the window
        off-screen. The 40/48 px margins leave room for the frame and taskbar.
        """
        preferred_w, preferred_h = 1180, 1000
        minimum_w, minimum_h = 980, 640
        avail = cls._screen_work_area()
        if avail.width() > 0 and avail.height() > 0:
            usable_w = max(480, avail.width() - 40)
            usable_h = max(360, avail.height() - 48)
            preferred_w = min(preferred_w, usable_w)
            preferred_h = min(preferred_h, usable_h)
            minimum_w = min(minimum_w, preferred_w)
            minimum_h = min(minimum_h, preferred_h)
        return QSize(minimum_w, minimum_h), QSize(preferred_w, preferred_h)

    def _build_tab1(self) -> QWidget:
        """Single workflow tab: health check → speed test → write / export.

        v1.1 layout rules:
        * the tab content sits in a QScrollArea, so a small window or 125/150 %
          DPI scaling scrolls instead of squeezing every control;
        * the speed-test area keeps the vertical stretch and a real minimum
          height, so the table and log stay readable;
        * the client panel and the startup panel are collapsible and start
          closed; their widgets and signal/slot wiring are unchanged.
        """
        tab = QWidget()
        outer = QVBoxLayout(tab)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.main_scroll = QScrollArea()
        self.main_scroll.setWidgetResizable(True)
        self.main_scroll.setFrameShape(QFrame.NoFrame)
        self.main_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        outer.addWidget(self.main_scroll)

        content = QWidget()
        self.main_scroll.setWidget(content)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)

        # ── Section 1: Health Check Dashboard ─────────────────
        health_group = QGroupBox("📊 已配置 IP 深度体检看板")
        health_layout = QVBoxLayout(health_group)
        health_layout.setSpacing(4)

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(8)
        self.node_cards = []
        for i in range(3):
            card = NodeCard(node_index=i)
            self.node_cards.append(card)
            cards_layout.addWidget(card, 1)
        health_layout.addLayout(cards_layout)

        self.health_btn = QPushButton("🩺 一键检测当前已配置 IP 速度与延迟 (内核路由直连探测)")
        self.health_btn.setStyleSheet(
            "font-size: 14px; padding: 8px; background: #2196F3; color: white; border-radius: 5px;")
        self.health_btn.setMinimumHeight(38)
        self.health_btn.clicked.connect(self._run_health_check)
        health_layout.addWidget(self.health_btn)

        layout.addWidget(health_group, 0)

        # ── Section 2: Auto guardian (compact, always visible) ─
        guard_group = QGroupBox("🛡️ 后台自动巡检与劣化自动换 IP")
        guard_layout = QVBoxLayout(guard_group)
        guard_layout.setSpacing(4)

        guard_row = QHBoxLayout()
        self.guard_chk = QCheckBox("开启后台自动巡检（每")
        self.guard_chk.setStyleSheet("font-weight: bold; color: #6A1B9A;")
        guard_row.addWidget(self.guard_chk)

        self.guard_interval_spin = QSpinBox()
        self.guard_interval_spin.setRange(5, 1440)
        self.guard_interval_spin.setValue(int(self.cfg.get("auto_guard_interval_min", 30) or 30))
        self.guard_interval_spin.setSuffix(" 分钟）")
        self.guard_interval_spin.setToolTip("巡检间隔（分钟）：独立守护线程中静默体检已配置 IP")
        guard_row.addWidget(self.guard_interval_spin)

        self.guard_now_btn = QPushButton("⚡ 立即巡检一次")
        self.guard_now_btn.setStyleSheet("padding: 5px; background: #8E24AA; color: white; border-radius: 4px;")
        self.guard_now_btn.clicked.connect(self._guard_now)
        guard_row.addWidget(self.guard_now_btn)
        guard_row.addStretch()
        guard_layout.addLayout(guard_row)

        self.guard_status_lbl = QLabel("⏸ 未启用 — 勾选后由独立守护线程定时体检，2 个节点劣化时自动全网优选换 IP 并同步多端")
        self.guard_status_lbl.setStyleSheet("font-size: 11px; color: #666;")
        self.guard_status_lbl.setWordWrap(True)
        guard_layout.addWidget(self.guard_status_lbl)

        self.guard_chk.toggled.connect(self._toggle_auto_guard)
        self.guard_interval_spin.valueChanged.connect(self._on_guard_interval_changed)

        layout.addWidget(guard_group, 0)

        # ── Section 3: Full speed test (primary work area) ────
        speed_group = QGroupBox("🚀 全网优选测速")
        speed_layout = QVBoxLayout(speed_group)
        speed_layout.setSpacing(4)

        # Two balanced parameter rows instead of seven widgets on one line:
        # labels cannot be truncated at 125 % DPI or on a narrow window.
        params = QGridLayout()
        params.setHorizontalSpacing(8)
        params.setVerticalSpacing(6)

        params.addWidget(QLabel("并发线程:"), 0, 0)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 500)
        self.threads_spin.setValue(self.cfg.get("cfst_threads", 200))
        self.threads_spin.setMinimumWidth(78)
        params.addWidget(self.threads_spin, 0, 1)

        params.addWidget(QLabel("延迟上限(ms):"), 0, 2)
        self.tl_spin = QSpinBox()
        self.tl_spin.setRange(100, 2000)
        self.tl_spin.setValue(self.cfg.get("cfst_tl", 400))
        self.tl_spin.setMinimumWidth(78)
        params.addWidget(self.tl_spin, 0, 3)

        params.addWidget(QLabel("速度过滤下限(MB/s):"), 0, 4)
        self.sl_spin = QDoubleSpinBox()
        self.sl_spin.setRange(0, 100)
        self.sl_spin.setValue(float(self.cfg.get("cfst_sl", 5.0)))
        self.sl_spin.setSingleStep(0.5)
        self.sl_spin.setMinimumWidth(78)
        params.addWidget(self.sl_spin, 0, 5)

        params.addWidget(QLabel("测速数量:"), 1, 0)
        self.dn_spin = QSpinBox()
        self.dn_spin.setRange(1, 50)
        self.dn_spin.setValue(self.cfg.get("cfst_dn", 10))
        self.dn_spin.setMinimumWidth(78)
        params.addWidget(self.dn_spin, 1, 1)

        params.addWidget(QLabel("自定义URL:"), 1, 2)
        self.url_edit = QLineEdit(self.cfg.get("cfst_url", ""))
        self.url_edit.setPlaceholderText("留空使用默认CF测速源")
        self.url_edit.setMinimumWidth(200)
        params.addWidget(self.url_edit, 1, 3, 1, 3)
        params.setColumnStretch(3, 1)
        speed_layout.addLayout(params)

        # Action buttons
        btns = QHBoxLayout()
        btns.setSpacing(8)
        self.auto_btn = QPushButton("🚀 全网优选并智能替换 (保优防降级)")
        self.auto_btn.setStyleSheet(
            "font-size: 13px; padding: 6px; background: #4CAF50; color: white; border-radius: 4px;")
        self.auto_btn.setMinimumHeight(34)
        self.auto_btn.clicked.connect(lambda: self._run_speed_test(auto_replace=True))
        btns.addWidget(self.auto_btn, 1)

        self.manual_btn = QPushButton("🔍 仅全网测速（手动勾选）")
        self.manual_btn.setStyleSheet(
            "font-size: 13px; padding: 6px; background: #FF9800; color: white; border-radius: 4px;")
        self.manual_btn.setMinimumHeight(34)
        self.manual_btn.clicked.connect(lambda: self._run_speed_test(auto_replace=False))
        btns.addWidget(self.manual_btn, 1)

        self.stop_btn = QPushButton("⏹️ 停止任务")
        self.stop_btn.setStyleSheet(
            "font-size: 13px; padding: 6px; background: #f44336; color: white; border-radius: 4px;")
        self.stop_btn.setMinimumHeight(34)
        self.stop_btn.clicked.connect(self._stop_speed_test)
        self.stop_btn.setEnabled(False)
        btns.addWidget(self.stop_btn, 1)
        speed_layout.addLayout(btns)

        # Splitter: table + log. Minimum sizes keep both panes usable; the
        # stretch factor lets the speed group absorb spare window height.
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(6)

        self.result_table = QTableWidget(0, 7)
        self.result_table.setHorizontalHeaderLabels(
            ["✓ 勾选", "排名", "IP 地址", "丢包率", "平均延迟(ms)", "下载速度(MB/s)", "达标状态"])
        # Content-sized sections (last one stretches) keep every header label
        # readable; the table itself scrolls horizontally when very narrow.
        table_header = self.result_table.horizontalHeader()
        table_header.setSectionResizeMode(QHeaderView.ResizeToContents)
        table_header.setStretchLastSection(True)
        self.result_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.result_table.setMinimumSize(360, 180)
        splitter.addWidget(self.result_table)

        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMinimumWidth(240)
        self.log_text.setMaximumWidth(560)
        self.log_text.setStyleSheet(
            "font-family: Consolas, monospace; font-size: 11px; background: #1e1e1e; color: #ddd;")
        splitter.addWidget(self.log_text)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([620, 380])
        splitter.setMinimumHeight(180)

        speed_layout.addWidget(splitter, 1)
        layout.addWidget(speed_group, 1)

        # ── Section 4: Write + Export ─────────────────────────
        bottom_group = QGroupBox("💾 写入配置、热重载与多端导出")
        bottom_outer = QVBoxLayout(bottom_group)
        bottom_outer.setSpacing(6)

        # Five long-labelled buttons in a 3-column grid: two rows of equal
        # width instead of one row that clips at 125 % DPI.
        bottom_layout = QGridLayout()
        bottom_layout.setHorizontalSpacing(8)
        bottom_layout.setVerticalSpacing(6)

        self.write_btn = QPushButton("✅ 将勾选的 IP 写入 FlClash 并热重载")
        self.write_btn.setStyleSheet(
            "padding: 7px; background: #2196F3; color: white; border-radius: 4px; font-weight: bold;")
        self.write_btn.setMinimumHeight(32)
        self.write_btn.clicked.connect(self._write_selected_ips)
        bottom_layout.addWidget(self.write_btn, 0, 0)

        self.restart_flclash_btn = QPushButton("🔄 一键重启 FlClash (生效9090端口与新IP)")
        self.restart_flclash_btn.setStyleSheet(
            "padding: 7px; background: #607D8B; color: white; border-radius: 4px;")
        self.restart_flclash_btn.setMinimumHeight(32)
        self.restart_flclash_btn.clicked.connect(self._restart_flclash)
        bottom_layout.addWidget(self.restart_flclash_btn, 0, 1)

        self.rollback_btn = QPushButton("⏪ 一键回滚上次备份")
        self.rollback_btn.setStyleSheet(
            "padding: 7px; background: #9E9E9E; color: white; border-radius: 4px;")
        self.rollback_btn.setMinimumHeight(32)
        self.rollback_btn.clicked.connect(self._rollback)
        bottom_layout.addWidget(self.rollback_btn, 0, 2)

        self.export_btn = QPushButton("📲 一键导出手机与电视端配置")
        self.export_btn.setStyleSheet(
            "padding: 7px; background: #9C27B0; color: white; border-radius: 4px; font-weight: bold;")
        self.export_btn.setMinimumHeight(32)
        self.export_btn.clicked.connect(self._export_configs)
        bottom_layout.addWidget(self.export_btn, 1, 0)

        self.topology_btn = QPushButton("🧩 应用多端优化拓扑 (机场链式代理 + IPv6加固)")
        self.topology_btn.setStyleSheet(
            "padding: 7px; background: #00897B; color: white; border-radius: 4px;")
        self.topology_btn.setMinimumHeight(32)
        self.topology_btn.setToolTip("把机场链式落地、流媒体/AI 分流、IPv6/mux 加固写入当前 FlClash 配置（自动备份）")
        self.topology_btn.clicked.connect(self._apply_topology)
        bottom_layout.addWidget(self.topology_btn, 1, 1, 1, 2)

        for col in range(3):
            bottom_layout.setColumnStretch(col, 1)
        bottom_outer.addLayout(bottom_layout)

        lan_row = QHBoxLayout()
        self.lan_chk = QCheckBox("启用局域网 HTTP 订阅服务")
        self.lan_chk.setToolTip(
            "默认关闭。开启后每条订阅地址都带独立访问 Token；关闭服务或重新生成 Token 后，"
            "旧地址立即失效。")
        self.lan_chk.setChecked(bool(self.cfg.get("lan_server_enabled", False)))
        self.lan_chk.toggled.connect(self._toggle_lan_server)
        lan_row.addWidget(self.lan_chk)

        self.fw_btn = QPushButton("🛡️ 一键放行防火墙端口")
        self.fw_btn.setStyleSheet("padding: 4px; background: #455A64; color: white; border-radius: 4px;")
        self.fw_btn.setToolTip(
            "检查并添加 TCP 入站规则：仅专用网络 + 本地子网，必要时弹一次 UAC 提权")
        self.fw_btn.clicked.connect(self._open_firewall_port)
        lan_row.addWidget(self.fw_btn)

        self.rotate_token_btn = QPushButton("🔄 重新生成 Token")
        self.rotate_token_btn.setStyleSheet("padding: 4px; background: #6A1B9A; color: white; border-radius: 4px;")
        self.rotate_token_btn.setToolTip(
            "立即轮换访问令牌：所有设备上的旧订阅地址马上失效，需要重新复制新链接")
        self.rotate_token_btn.clicked.connect(self._rotate_lan_token)
        lan_row.addWidget(self.rotate_token_btn)

        self.copy_lan_btn = QPushButton("📋 复制订阅链接")
        self.copy_lan_btn.setStyleSheet("padding: 4px; background: #1565C0; color: white; border-radius: 4px;")
        self.copy_lan_btn.setToolTip("复制 4 条带 Token 的订阅地址（FlClash / iOS / Happ / Happ JSON）")
        self.copy_lan_btn.setEnabled(False)
        self.copy_lan_btn.clicked.connect(self._copy_lan_links)
        lan_row.addWidget(self.copy_lan_btn)
        lan_row.addStretch()
        bottom_outer.addLayout(lan_row)

        self.lan_auth_lbl = QLabel("🔐 访问认证：未启用（开启服务时自动生成高强度 Token）")
        self.lan_auth_lbl.setStyleSheet("font-size: 11px; color: #6A1B9A; padding: 2px;")
        self.lan_auth_lbl.setWordWrap(True)
        self.lan_auth_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        bottom_outer.addWidget(self.lan_auth_lbl)

        self.firewall_lbl = QLabel("🛡️ 防火墙规则：未检查（服务未启用）")
        self.firewall_lbl.setStyleSheet("font-size: 11px; color: #37474F; padding: 2px;")
        self.firewall_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        bottom_outer.addWidget(self.firewall_lbl)

        self.lan_info_lbl = QLabel("🌐 局域网订阅服务启动中...")
        self.lan_info_lbl.setStyleSheet("font-size: 11px; color: #1565C0; padding: 2px;")
        self.lan_info_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        bottom_outer.addWidget(self.lan_info_lbl)

        layout.addWidget(bottom_group, 0)

        # ── Section 5: Client & profile (collapsible, closed) ──
        client_section = CollapsibleSection(
            "🔌 客户端与配置文件（FlClash / Clash Verge Rev / Mihomo Party / 本地 YAML）",
            expanded=False)
        self.client_section = client_section
        client_section.toggled.connect(self._on_section_toggled)
        client_layout = client_section.body_layout

        client_grid = QGridLayout()
        client_grid.setHorizontalSpacing(8)
        client_grid.setVerticalSpacing(6)
        client_grid.setColumnStretch(1, 1)

        client_grid.addWidget(QLabel("客户端:"), 0, 0)
        self.client_combo = QComboBox()
        self.client_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.client_combo.addItem("自动检测（推荐）", "auto")
        for key, label in CLIENT_LABELS.items():
            if key == "manual":
                continue
            self.client_combo.addItem(label, key)
        self.client_combo.addItem("手动选择 YAML…", "manual")
        self.client_combo.currentIndexChanged.connect(self._on_client_changed)
        client_grid.addWidget(self.client_combo, 0, 1)

        self.client_rescan_btn = QPushButton("🔄 重新扫描")
        self.client_rescan_btn.setStyleSheet("padding: 4px;")
        self.client_rescan_btn.setToolTip("重新扫描本机 FlClash / Clash Verge Rev / Mihomo Party 的配置目录")
        self.client_rescan_btn.clicked.connect(lambda: self._refresh_client_choices(refresh=True))
        client_grid.addWidget(self.client_rescan_btn, 0, 2)

        client_grid.addWidget(QLabel("配置:"), 1, 0)
        self.profile_combo = QComboBox()
        self.profile_combo.setMinimumWidth(280)
        self.profile_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.profile_combo.currentIndexChanged.connect(self._on_profile_selected)
        client_grid.addWidget(self.profile_combo, 1, 1)

        self.browse_btn = QPushButton("📂 浏览…")
        self.browse_btn.setStyleSheet("padding: 4px;")
        self.browse_btn.clicked.connect(self._browse_profile)
        client_grid.addWidget(self.browse_btn, 1, 2)

        client_grid.addWidget(QLabel("YAML 路径:"), 2, 0)
        self.client_path_edit = QLineEdit(self.profile_path or "")
        self.client_path_edit.setPlaceholderText("选择任意本地 Clash / Mihomo YAML 配置文件")
        self.client_path_edit.textChanged.connect(self._update_client_summary)
        client_grid.addWidget(self.client_path_edit, 2, 1, 1, 2)

        client_grid.addWidget(QLabel("外部控制 API:"), 3, 0)
        self.api_url_edit = QLineEdit(self.cfg.get("external_controller", "127.0.0.1:9090"))
        self.api_url_edit.setPlaceholderText("127.0.0.1:9090")
        self.api_url_edit.setMinimumWidth(160)
        client_grid.addWidget(self.api_url_edit, 3, 1)

        self.api_test_btn = QPushButton("🔌 测试连接")
        self.api_test_btn.setStyleSheet("padding: 4px;")
        self.api_test_btn.clicked.connect(self._test_clash_api)
        client_grid.addWidget(self.api_test_btn, 3, 2)

        client_grid.addWidget(QLabel("Secret:"), 4, 0)
        self.api_secret_edit = QLineEdit(self.cfg.get("secret", ""))
        self.api_secret_edit.setPlaceholderText("留空表示无密钥")
        self.api_secret_edit.setMinimumWidth(160)
        client_grid.addWidget(self.api_secret_edit, 4, 1)

        self.client_apply_btn = QPushButton("✅ 应用配置")
        self.client_apply_btn.setStyleSheet(
            "padding: 5px 12px; background: #1565C0; color: white; border-radius: 4px; font-weight: bold;")
        self.client_apply_btn.clicked.connect(self._apply_client_settings)
        client_grid.addWidget(self.client_apply_btn, 4, 2)

        client_layout.addLayout(client_grid)

        self.client_status_lbl = QLabel("")
        self.client_status_lbl.setStyleSheet("font-size: 11px; color: #555;")
        self.client_status_lbl.setWordWrap(True)
        self.client_status_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        client_layout.addWidget(self.client_status_lbl)

        layout.addWidget(client_section, 0)
        self._refresh_client_choices()

        # ── Section 6: Startup & close behaviour (collapsible) ─
        startup_section = CollapsibleSection(
            "🖥️ 启动与关闭行为（系统托盘 / 开机自启）", expanded=False)
        self.startup_section = startup_section
        startup_section.toggled.connect(self._on_section_toggled)
        startup_layout = startup_section.body_layout

        self.close_to_tray_chk = QCheckBox("关闭窗口时最小化到系统托盘（保持后台巡检）")
        self.close_to_tray_chk.setStyleSheet("font-weight: bold; color: #00695C;")
        self.close_to_tray_chk.setToolTip(
            "勾选后点击右上角 × 只会隐藏到右下角托盘，后台自动巡检与局域网订阅服务继续运行；\n"
            "在托盘菜单选择「❌ 完全退出程序」才会真正停止全部后台服务。")
        self.close_to_tray_chk.setChecked(bool(self.cfg.get("close_to_tray", True)))
        self.close_to_tray_chk.toggled.connect(self._toggle_close_to_tray)
        startup_layout.addWidget(self.close_to_tray_chk)

        self.auto_start_chk = QCheckBox("开机自动启动（静默缩至右下角托盘）")
        self.auto_start_chk.setStyleSheet("font-weight: bold; color: #1565C0;")
        self.auto_start_chk.setToolTip(
            "写入当前用户注册表 HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run，\n"
            "登录后以 --minimized 参数静默启动，无需管理员权限。")
        self.auto_start_chk.toggled.connect(self._toggle_auto_start)
        startup_layout.addWidget(self.auto_start_chk)

        self.auto_start_lbl = QLabel("")
        self.auto_start_lbl.setStyleSheet("font-size: 11px; color: #555;")
        self.auto_start_lbl.setWordWrap(True)
        self.auto_start_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        startup_layout.addWidget(self.auto_start_lbl)

        layout.addWidget(startup_section, 0)
        return tab

    # ══════════════════════════════════════════════════════════════
    # Helpers
    # ══════════════════════════════════════════════════════════════
    # ── Client / profile configuration ─────────────────────────
    def _profile_rows(self) -> list:
        rows = []
        for client in getattr(self, "_client_rows", []):
            for prof in client["profiles"]:
                rows.append({
                    "key": client["key"], "client": client["label"],
                    "label": prof["label"], "path": prof["path"],
                    "api": client["api"], "secret": client.get("secret", ""),
                })
        return rows

    def _refresh_client_choices(self, refresh: bool = False):
        """Scan client directories and mirror the result into the two combos."""
        if refresh or not getattr(self, "_client_rows", None):
            try:
                self._client_rows = discover_clients(self.cfg.get("flclash_config_dir", ""))
            except Exception as exc:
                dbg(f"client scan failed: {exc}")
                self._client_rows = []
        key = self.cfg.get("client_type", "auto")
        idx = self.client_combo.findData(key)
        if idx >= 0:
            self.client_combo.blockSignals(True)
            self.client_combo.setCurrentIndex(idx)
            self.client_combo.blockSignals(False)
        self._on_client_changed(self.client_combo.currentIndex())
        if refresh:
            total = sum(len(c["profiles"]) for c in self._client_rows)
            self.statusBar().showMessage(
                f"已扫描 {len(self._client_rows)} 个客户端目录，发现 {total} 个 YAML 配置")

    def _update_client_summary(self, *_text):
        """Keep the collapsed panel header in sync with the selected YAML.

        The path box is the source of truth for the pending selection; when it
        differs from the applied profile the header says 待应用, so switching
        client / browsing / applying stays accurate while the body is hidden.
        """
        section = getattr(self, "client_section", None)
        if section is None:
            return
        edit = getattr(self, "client_path_edit", None)
        selected = (edit.text() or "").strip() if edit is not None else ""
        applied = (self.profile_path or "").strip()
        if selected:
            same = False
            if applied:
                try:
                    same = (os.path.normcase(os.path.abspath(selected))
                            == os.path.normcase(os.path.abspath(applied)))
                except (OSError, ValueError):
                    same = False
            prefix = "当前配置" if same else "待应用"
            section.set_summary(f"{prefix}：{os.path.basename(selected)}")
        elif applied:
            section.set_summary(f"当前配置：{os.path.basename(applied)}")
        else:
            section.set_summary("尚未选择配置")

    def _on_section_toggled(self, _expanded: bool):
        """Relayout the scroll content after a panel is shown or hidden."""
        scroll = getattr(self, "main_scroll", None)
        if scroll is None:
            return
        content = scroll.widget()
        if content is not None and content.layout() is not None:
            content.layout().activate()
        # Hiding the body shrinks the content in this event-loop turn; clamp on
        # the next turn so the bar cannot keep a value past its new maximum
        # (which would leave the viewport showing a blank strip).
        QTimer.singleShot(0, self._clamp_main_scroll)

    def _clamp_main_scroll(self):
        scroll = getattr(self, "main_scroll", None)
        if scroll is None:
            return
        bar = scroll.verticalScrollBar()
        bar.setValue(min(bar.value(), bar.maximum()))

    def _on_client_changed(self, index: int):
        key = self.client_combo.currentData() or "auto"
        rows = self._profile_rows()
        if key not in ("auto", "manual"):
            rows = [r for r in rows if r["key"] == key]
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        for row in rows:
            self.profile_combo.addItem(f"[{row['client']}] {row['label']}", row)
        self.profile_combo.blockSignals(False)

        chosen = -1
        target = os.path.normcase(os.path.abspath(self.profile_path)) if self.profile_path else ""
        for i in range(self.profile_combo.count()):
            row = self.profile_combo.itemData(i)
            if row and target and os.path.normcase(os.path.abspath(row["path"])) == target:
                chosen = i
                break
        if chosen < 0 and rows:
            chosen = 0
        if chosen >= 0:
            self.profile_combo.setCurrentIndex(chosen)
            self._on_profile_selected(chosen)
        elif self.profile_combo.count() == 0:
            self.profile_combo.addItem("未发现配置 — 请点击「浏览…」选择本地 YAML", None)

        total = sum(len(c["profiles"]) for c in self._client_rows)
        self.client_status_lbl.setText(
            f"已识别 {len(self._client_rows)} 个客户端目录 / {total} 个可用配置；"
            f"当前使用: {os.path.basename(self.profile_path) if self.profile_path else '未选择'}")
        self._update_client_summary()

    def _on_profile_selected(self, index: int):
        row = self.profile_combo.itemData(index)
        if not row:
            return
        self.client_path_edit.setText(row["path"])
        if row.get("api"):
            self.api_url_edit.setText(row["api"])
        if row.get("secret"):
            self.api_secret_edit.setText(row["secret"])

    def _browse_profile(self):
        start = os.path.dirname(self.profile_path) if self.profile_path else ""
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 Clash / Mihomo 配置文件", start,
            "YAML 配置 (*.yaml *.yml);;所有文件 (*.*)")
        if not path:
            return
        if not looks_like_profile(path):
            QMessageBox.warning(
                self, "不是可用的 Clash 配置",
                "该文件没有 `proxies:` 列表，无法作为 Clash / Mihomo 配置使用。\n\n" + path)
            return
        self.client_path_edit.setText(path)
        info = detect_api(os.path.dirname(path))
        if info.get("api"):
            self.api_url_edit.setText(info["api"])
        if info.get("secret"):
            self.api_secret_edit.setText(info["secret"])
        self.client_status_lbl.setText(f"已选择: {path}（点击「✅ 应用配置」生效）")

    def _test_clash_api(self):
        api = normalize_api(self.api_url_edit.text()) or "127.0.0.1:9090"
        secret = self.api_secret_edit.text().strip()
        probe = ClashAPI(api, secret)
        if probe.is_alive():
            version = probe.get_version()
            self.client_status_lbl.setText(f"✅ API 可用: http://{api} 内核版本 {version}")
            self.statusBar().showMessage(f"Clash API 连接成功: {api} ({version})")
        else:
            self.client_status_lbl.setText(f"⚠ API 不可达: http://{api}（检查客户端是否运行 / Secret）")
            self.statusBar().showMessage("Clash API 连接失败")

    def _validate_client_settings(self, raw_path: str) -> tuple:
        """(ok, absolute path or error message) — shared with the tests."""
        raw = (raw_path or "").strip()
        if not raw:
            return False, "请先选择一个本地 YAML 配置文件。"
        path = os.path.abspath(raw)
        if not os.path.isfile(path):
            return False, f"找不到配置文件:\n{path}"
        return True, path

    def _apply_client_settings(self):
        ok, path = self._validate_client_settings(self.client_path_edit.text())
        if not ok:
            QMessageBox.warning(self, "未选择配置", path)
            return
        api = normalize_api(self.api_url_edit.text()) or "127.0.0.1:9090"
        secret = self.api_secret_edit.text().strip()

        try:
            mgr = ProfileManager(path, BACKUPS_DIR, self.cfg["cf_node_names"],
                                 options=self.cfg)
            mgr.load()
        except Exception as exc:
            QMessageBox.critical(
                self, "配置解析失败",
                f"无法解析该 YAML（应为 Clash / Mihomo 配置）:\n{exc}")
            return

        self.cfg["flclash_profile_path"] = path
        self.cfg["flclash_config_dir"] = os.path.dirname(path)
        self.cfg["client_type"] = self.client_combo.currentData() or "auto"
        self.cfg["external_controller"] = api
        self.cfg["secret"] = secret
        try:
            save_config(self.cfg)
        except Exception as exc:
            self.statusBar().showMessage(f"⚠ 配置保存失败: {exc}")

        self.profile_path = path
        self.profile_mgr = mgr
        self.clash_api = ClashAPI(api, secret)

        # LAN subscription and the guardian captured the old objects: restart them.
        if self._lan_server is not None:
            self._stop_lan_server()
            if self.lan_chk.isChecked():
                self._start_lan_server()
        if self._guard is not None and self._guard.is_running():
            self._stop_guard()
            self._start_guard()
        self._refresh_node_cards()
        self._refresh_client_choices()
        self._update_client_summary()
        self.client_status_lbl.setText(
            f"✅ 已应用: {os.path.basename(path)}  ·  API http://{api}")
        self.statusBar().showMessage(f"客户端配置已更新: {path}")
        self.log_text.appendPlainText(
            f"🔌 已切换到配置: {path}\n🔌 外部控制 API: http://{api}")

    def _refresh_node_cards(self):
        """Refresh node card info from YAML."""
        try:
            nodes = self.profile_mgr.get_node_full_info()
            for i, node in enumerate(nodes[:3]):
                sni = node.get("servername", "") or node.get("ws-opts", {}).get("headers", {}).get("Host", "")
                self.node_cards[i].update_info(
                    node.get("name", f"节点 {i+1}"), node.get("server", ""), sni,
                )
        except Exception as e:
            self.statusBar().showMessage(f"加载节点信息失败: {e}")

    def _profile_factory(self):
        """Fresh ProfileManager for background/LAN threads (own YAML cache)."""
        return ProfileManager(self.profile_path, BACKUPS_DIR,
                              self.cfg["cf_node_names"], options=self.cfg)

    def _ensure_lan_access_token(self) -> str:
        """Load or create the 384-bit LAN access token (persisted)."""
        return ensure_lan_token(self.cfg, save_config)

    def _start_lan_server(self):
        """Start the token-protected LAN HTTP subscription service."""
        if self._lan_server is not None:
            return
        token = self._ensure_lan_access_token()
        if not is_valid_token(token):
            self._on_lan_error("访问 Token 未初始化，服务未启动")
            return
        try:
            self._regenerate_exports(silent=True)
        except Exception as exc:
            self.statusBar().showMessage(f"预生成导出文件失败: {exc}")
        self._lan_server = LANServerWorker(
            EXPORTS_DIR, self._lan_port, profile_mgr=None,
            profile_factory=self._profile_factory,
            profile_path=self.profile_path,
            host=self.cfg.get("lan_bind_host") or "auto",
            port_fallback=int(self.cfg.get("lan_port_fallback", 10) or 0),
            ensure_firewall=True,
            token_provider=lambda: self.cfg.get("lan_auth_token", ""),
            remote_scope=self.cfg.get("lan_firewall_remote", "LocalSubnet"),
        )
        self._lan_server.started.connect(self._on_lan_started)
        self._lan_server.warning.connect(lambda msg: self.statusBar().showMessage(msg))
        self._lan_server.firewall.connect(self._on_firewall_status)
        self._lan_server.error.connect(self._on_lan_error)
        self._lan_server.start()
        if hasattr(self, "firewall_lbl"):
            self.firewall_lbl.setText("🛡️ 防火墙规则检查中...")
        if hasattr(self, "lan_info_lbl"):
            self.lan_info_lbl.setText("🌐 局域网订阅服务启动中…（Token 认证已启用）")
        if hasattr(self, "copy_lan_btn"):
            self.copy_lan_btn.setEnabled(False)
        self._update_lan_auth_label()

    def _regenerate_exports(self, silent: bool = False):
        """Regenerate every multi-end export file from the current profile."""
        paths = self.profile_mgr.generate_all_exports(EXPORTS_DIR)
        if not silent and hasattr(self, "log_text"):
            self.log_text.appendPlainText("📲 已重新生成 iOS / Happ / Base64 订阅文件")
        return paths

    def _lan_is_running(self) -> bool:
        return (self._lan_server is not None
                and bool(getattr(self._lan_server, "actual_port", 0)))

    def _refresh_lan_urls(self):
        """Build the four token-bearing subscription URLs (kept out of logs)."""
        token = str(self.cfg.get("lan_auth_token") or "")
        if not self._lan_base_url or not is_valid_token(token):
            self._lan_urls = []
            return
        base = f"{self._lan_base_url}/s/{token}"
        self._lan_urls = [f"{base}/{name}" for name in
                          ("flclash.yaml", "ios.yaml", "tv_happ.txt", "happ.json")]

    def _update_lan_auth_label(self):
        if not hasattr(self, "lan_auth_lbl"):
            return
        token = self.cfg.get("lan_auth_token", "")
        if not is_valid_token(token):
            text = "🔐 访问认证：未启用（开启服务时自动生成高强度 Token）"
        elif self._lan_is_running():
            text = "🔐 访问认证：已启用 · 订阅地址必须携带 Token，未认证请求无法获取配置"
        else:
            text = "🔐 访问认证：Token 已保存 · 服务关闭时订阅地址不可访问"
        self.lan_auth_lbl.setText(text)

    def _on_lan_started(self, ip: str, port: int):
        self._lan_ip = ip
        self._lan_port = int(port)
        self._lan_base_url = f"http://{ip}:{port}"
        self._refresh_lan_urls()
        masked = (f"{self._lan_base_url}/s/••••••••/ios.yaml  ·  "
                  f"{self._lan_base_url}/s/••••••••/tv_happ.txt  ·  "
                  f"{self._lan_base_url}/s/••••••••/happ.json")
        text = (f"🌐 局域网订阅就绪: {masked}"
                f"（🔐 Token 认证，点击「复制订阅链接」获取完整地址）")
        if hasattr(self, "lan_info_lbl"):
            self.lan_info_lbl.setText(text)
        self.statusBar().showMessage(
            f"局域网订阅服务运行中: http://{ip}:{port}/s/…/ios.yaml（Token 认证）")
        if hasattr(self, "log_text"):
            self.log_text.appendPlainText(text)
        if hasattr(self, "copy_lan_btn"):
            self.copy_lan_btn.setEnabled(bool(self._lan_urls))
        self._update_lan_auth_label()

    def _stop_lan_server(self):
        if self._lan_server is not None:
            try:
                self._lan_server.stop()
            except Exception:
                pass
            self._lan_server = None
        self._lan_base_url = ""
        self._lan_urls = []
        if hasattr(self, "copy_lan_btn"):
            self.copy_lan_btn.setEnabled(False)
        if hasattr(self, "lan_info_lbl"):
            self.lan_info_lbl.setText("⏸ 局域网订阅服务已关闭（订阅地址当前不可访问）")
        if hasattr(self, "firewall_lbl"):
            self.firewall_lbl.setText("🛡️ 服务已关闭，未开放端口")
        self._update_lan_auth_label()

    def _toggle_lan_server(self, enabled: bool):
        self.cfg["lan_server_enabled"] = bool(enabled)
        try:
            save_config(self.cfg)
        except Exception:
            pass
        if enabled:
            self._start_lan_server()
        else:
            self._stop_lan_server()
            self.statusBar().showMessage("局域网订阅服务已关闭")
        self._sync_tray_menu()

    def _copy_lan_links(self):
        if not self._lan_urls:
            self.statusBar().showMessage("请先启用局域网订阅服务，再复制订阅链接")
            return
        QApplication.clipboard().setText("\n".join(self._lan_urls))
        self.statusBar().showMessage("已复制 4 条带 Token 的订阅链接（请勿公开分享）")

    def _rotate_lan_token(self):
        answer = QMessageBox.question(
            self, "重新生成访问 Token",
            "重新生成后，所有设备上保存的旧订阅地址会立即失效，需要重新添加订阅。\n\n继续吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        self.cfg["lan_auth_token"] = generate_token()
        try:
            save_config(self.cfg)
        except Exception as exc:
            self.statusBar().showMessage(f"⚠ Token 保存失败: {exc}")
            return
        if self._lan_is_running():
            # The handler reads the token through a live provider: old links
            # stop working on the very next request, no restart needed.
            self._refresh_lan_urls()
            self._on_lan_started(self._lan_ip, self._lan_port)
        else:
            self._lan_urls = []
            self._update_lan_auth_label()
            if hasattr(self, "copy_lan_btn"):
                self.copy_lan_btn.setEnabled(False)
        QMessageBox.information(
            self, "Token 已更新",
            "新的访问 Token 已生成并立即生效。\n"
            "旧订阅地址不再返回任何配置，请重新复制链接到各设备。")

    def _on_firewall_status(self, message: str):
        if hasattr(self, "firewall_lbl"):
            self.firewall_lbl.setText(f"🛡️ {message}")
        if hasattr(self, "log_text"):
            self.log_text.appendPlainText(f"🛡️ {message}")
        self.statusBar().showMessage(message)

    def _open_firewall_port(self):
        """One-click: check/add the inbound TCP rule for the LAN port."""
        port = int(self._lan_port or self.cfg.get("lan_server_port", 8686))
        remote = self.cfg.get("lan_firewall_remote", "LocalSubnet")
        info = ensure_firewall_rule_detailed(port, allow_uac=True, remote_ip=remote)
        self._on_firewall_status(f"{info.get('rule')}: {info.get('status')} — {info.get('detail')}")
        icon = "✅" if info.get("status") in (
            "exists", "exists_unhardened", "added", "added_uac") else "⚠"
        QMessageBox.information(
            self, "防火墙端口放行",
            f"{icon} 端口: {port}\n"
            f"规则名: {info.get('rule')}\n"
            f"状态: {info.get('status')}\n"
            f"作用域: 专用网络 / {info.get('remoteip', remote)}\n"
            f"详情: {info.get('detail')}\n\n"
            f"手动命令（管理员 CMD）:\n"
            f"netsh advfirewall firewall add rule name=\"{firewall_rule_name(port)}\" "
            f"dir=in action=allow protocol=TCP localport={port} "
            f"profile=private remoteip={info.get('remoteip', remote)}",
        )

    def _on_lan_error(self, msg: str):
        self._lan_base_url = ""
        self._lan_urls = []
        if hasattr(self, "copy_lan_btn"):
            self.copy_lan_btn.setEnabled(False)
        if hasattr(self, "lan_info_lbl"):
            self.lan_info_lbl.setText(f"⚠ 局域网订阅服务异常: {msg}")
        self._update_lan_auth_label()
        self.statusBar().showMessage(f"局域网订阅服务错误: {msg}")

    # ── Background auto guardian ──────────────────────────────
    def _build_guard(self):
        guard = AutoGuardian(
            self._profile_factory, self.clash_api, CFST_EXE, BIN_DIR,
            EXPORTS_DIR, self.cfg, store=self.cidr_store,
        )
        guard.log.connect(self.log_text.appendPlainText)
        guard.status_changed.connect(self._on_guard_status)
        guard.health_result_ready.connect(self._on_guard_health)
        guard.profile_updated.connect(self._on_guard_profile)
        guard.exports_updated.connect(self._on_guard_exports)
        guard.error.connect(lambda e: self.log_text.appendPlainText(f"⚠ 自动巡检错误: {e}"))
        return guard

    def _start_guard(self):
        if self._guard is not None and self._guard.is_running():
            return
        self._guard = self._build_guard()
        self._guard.start(self.guard_interval_spin.value())
        self.guard_status_lbl.setText(
            f"🟢 自动巡检运行中（每 {self.guard_interval_spin.value()} 分钟，独立守护线程）")

    def _stop_guard(self):
        if self._guard is not None:
            self._guard.stop()
            self._guard = None
        if hasattr(self, "guard_status_lbl"):
            self.guard_status_lbl.setText("⏸ 自动巡检已停止 — 勾选后可重新启用")

    def _toggle_auto_guard(self, checked: bool):
        self.cfg["auto_guard_enabled"] = bool(checked)
        self.cfg["auto_guard_interval_min"] = int(self.guard_interval_spin.value())
        try:
            save_config(self.cfg)
        except Exception:
            pass
        if checked:
            self._start_guard()
        else:
            self._stop_guard()
        self._sync_tray_menu()

    def _on_guard_interval_changed(self, value: int):
        self.cfg["auto_guard_interval_min"] = int(value)
        try:
            save_config(self.cfg)
        except Exception:
            pass
        guard = getattr(self, "_guard", None)
        if guard is not None and guard.is_running():
            guard.set_interval_minutes(value)
            self.guard_status_lbl.setText(
                f"🟢 自动巡检运行中（每 {value} 分钟，独立守护线程）")

    def _guard_now(self):
        if self._guard is None or not self._guard.is_running():
            # One-shot run: do not persist "enabled", just execute one cycle on
            # a daemon thread so the GUI stays responsive.
            self._guard = self._build_guard()
            threading.Thread(target=self._guard.cycle, name="CFAutoGuardianOnce",
                             daemon=True).start()
            self.guard_status_lbl.setText("🩺 正在执行一次后台巡检...")
        else:
            self._guard.trigger_now()
            self.guard_status_lbl.setText("🩺 已请求立即巡检，等待守护线程执行...")
        self.statusBar().showMessage("已触发后台巡检（不影响界面操作）")

    def _on_guard_status(self, message: str):
        if hasattr(self, "guard_status_lbl"):
            self.guard_status_lbl.setText(message)
        self.statusBar().showMessage(message)

    def _on_guard_health(self, results: list):
        for i, result in enumerate(results[:3]):
            self.node_cards[i].update_metrics(
                result.get("proxy_delay", -1),
                result.get("delay_type", "tls"),
                result.get("cf_latency", 0),
                result.get("loss", 0),
                result.get("speed", 0),
            )
            self._current_health_results[result.get("ip", "")] = result

    def _on_guard_profile(self, new_ips: list):
        try:
            self.profile_mgr.load()
            self._refresh_node_cards()
        except Exception:
            pass
        self.log_text.appendPlainText(f"🔄 后台已自动换血并热重载: {', '.join(new_ips)}")

    def _on_guard_exports(self, paths: dict):
        self.log_text.appendPlainText(
            f"📲 后台自动同步导出: {os.path.basename(paths.get('ios', ''))} / "
            f"{os.path.basename(paths.get('happ', ''))} / "
            f"{os.path.basename(paths.get('happ_xray', ''))}")
        if self._lan_ip:
            self.lan_info_lbl.setText(
                f"🌐 局域网订阅就绪: http://{self._lan_ip}:{self._lan_port}/ios.yaml  ·  "
                f"http://{self._lan_ip}:{self._lan_port}/tv_happ.txt  ·  "
                f"http://{self._lan_ip}:{self._lan_port}/happ.json")

    # ── Health Check ──────────────────────────────────────────
    def _run_health_check(self):
        self.health_btn.setEnabled(False)
        self.health_btn.setText("🔄 路由绕过探测中...")
        self.log_text.appendPlainText("🩺 开始当前已配置 3 个 IP 深度体检看板测试...")

        nodes = self.profile_mgr.get_node_full_info()
        self._health_worker = HealthCheckWorker(
            CFST_EXE, nodes, self.clash_api, BIN_DIR,
        )
        self._health_worker.progress.connect(lambda msg: self.log_text.appendPlainText(msg))
        self._health_worker.result_ready.connect(self._on_health_result)
        self._health_worker.error.connect(lambda e: QMessageBox.warning(self, "体检错误", e))
        self._health_worker.finished_signal.connect(lambda: (
            self.health_btn.setEnabled(True),
            self.health_btn.setText("🩺 一键检测当前已配置 IP 速度与延迟 (内核路由直连探测)"),
        ))
        self._health_worker.start()

    def _on_health_result(self, results: list):
        for i, r in enumerate(results[:3]):
            self.node_cards[i].update_metrics(
                r.get("proxy_delay", -1),
                r.get("delay_type", "tls"),
                r.get("cf_latency", 0),
                r.get("loss", 0),
                r.get("speed", 0),
            )
            # Record in cache for smart anti-degradation
            self._current_health_results[r.get("ip", "")] = r

        self.statusBar().showMessage("✅ 当前已配置 IP 体检完成")

    # ── Full Speed Test ───────────────────────────────────────
    def _run_speed_test(self, auto_replace: bool = False):
        self.auto_btn.setEnabled(False)
        self.manual_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.result_table.setRowCount(0)
        self.log_text.clear()

        self._auto_replace = auto_replace

        # Dynamic Exploit-Explore sampling: 70% from the best /24 subnets,
        # 30% uniform over the whole Cloudflare CIDR library.
        sample_size = int(self.cfg.get("cidr_sample_size", 2000) or 2000)
        exploit_ratio = float(self.cfg.get("cidr_exploit_ratio", 0.7) or 0.7)
        top_n = int(self.cfg.get("cidr_top_subnets", 40) or 40)
        ip_file = None
        try:
            candidates = sample_candidates(self.cidr_store, total=sample_size,
                                           exploit_ratio=exploit_ratio, top_n=top_n,
                                           rng=random.Random())
            if candidates:
                ip_file = os.path.join(BIN_DIR, f"ip_sample_{int(time.time())}.txt")
                atomic_write_text(ip_file, "\n".join(candidates) + "\n")
                history = self.cidr_store.top_subnets(top_n)
                self.log_text.appendPlainText(
                    f"🎲 动态抽样: {len(candidates)} 个候选 "
                    f"({exploit_ratio:.0%} 历史高分 /24 + {1 - exploit_ratio:.0%} 全网探索; "
                    f"历史子网 {len(history)} 个)")
                self.log_text.appendPlainText(f"📊 评分池 Top: {self.cidr_store.summary(3)}")
        except Exception as exc:
            self.log_text.appendPlainText(f"⚠ 动态抽样失败，回退全量 ip.txt: {exc}")

        self._speed_worker = SpeedTestWorker(
            CFST_EXE, BIN_DIR, self.clash_api,
            threads=self.threads_spin.value(),
            tl=self.tl_spin.value(),
            sl=self.sl_spin.value(),
            dn=self.dn_spin.value(),
            url=self.url_edit.text().strip(),
            ip_file=ip_file,
        )
        self._speed_worker.progress.connect(lambda msg: self.log_text.appendPlainText(msg))
        self._speed_worker.result_ready.connect(self._on_speed_result)
        self._speed_worker.error.connect(lambda e: QMessageBox.warning(self, "测速错误", e))
        self._speed_worker.finished_signal.connect(self._on_speed_finished)
        self._speed_worker.start()

    def _stop_speed_test(self):
        if self._speed_worker:
            self._speed_worker.stop()
        if self._health_worker:
            self._health_worker.stop()
        self.stop_btn.setEnabled(False)

    def _on_speed_result(self, results: list):
        # Sort results by speed descending
        results = sorted(results, key=lambda x: x.get("speed_num", 0.0), reverse=True)

        # Persist /24 health scores for the next sampling round.
        try:
            stats = self.cidr_store.record_results(results, self.sl_spin.value(),
                                                   self.tl_spin.value())
            self.cidr_store.save()
            if stats.get("recorded"):
                self.log_text.appendPlainText(
                    f"📊 已写入 /24 评分池: {stats['recorded']} 个样本 / {stats['subnets']} 个子网")
                self.log_text.appendPlainText(f"   当前 Top: {self.cidr_store.summary(3)}")
        except Exception as exc:
            self.log_text.appendPlainText(f"⚠ 评分持久化失败（不影响本次测速）: {exc}")

        current_nodes = self.profile_mgr.get_node_full_info()
        protect_threshold = max(5.0, float(self.sl_spin.value()))

        # Identify which current nodes are fast enough to protect.
        retained = []
        replace_indices = []
        for idx, cnode in enumerate(current_nodes[:3]):
            cip = cnode.get("server", "").strip()
            cname = cnode.get("name", f"节点{idx+1}")
            hdata = self._current_health_results.get(cip, {})
            cspeed = float(hdata.get("speed", 0.0))
            if cspeed >= protect_threshold:
                retained.append((idx, cname, cip, cspeed))
            else:
                replace_indices.append((idx, cname, cip, cspeed))

        for idx, cname, cip, cspeed in retained:
            self.node_cards[idx].target_chk.setChecked(False)
            self.node_cards[idx].target_chk.setText("🛡️ 优良保留")
        for idx, cname, cip, cspeed in replace_indices:
            self.node_cards[idx].target_chk.setChecked(True)
            self.node_cards[idx].target_chk.setText("🎯 优先替换")

        if retained:
            self.log_text.appendPlainText("=" * 45)
            self.log_text.appendPlainText(f"🛡️ 【智能保优机制生效】已锁定 {len(retained)} 个高速节点：")
            for idx, cname, cip, cspeed in retained:
                self.log_text.appendPlainText(
                    f"   ✓ 保留 {cname} [{cip}] 实测: {cspeed:.2f} MB/s "
                    f"(>= {protect_threshold:.1f} MB/s，绝不降级)")
            if replace_indices:
                self.log_text.appendPlainText(f"   ⚡ 仅对 {len(replace_indices)} 个性能劣化/未达标节点执行替换：")
                for idx, cname, cip, cspeed in replace_indices:
                    self.log_text.appendPlainText(f"      - 待替换 {cname} [{cip}] 实测: {cspeed:.2f} MB/s")
            self.log_text.appendPlainText("=" * 45)

        # Cross-/24 Top-N selection for the slots that need replacement.
        retained_ips = {r[2] for r in retained}
        retained_subnets = [subnet_of(ip) for ip in retained_ips if subnet_of(ip)]
        need = len(replace_indices)
        picked = select_top_ips(
            results, count=need, exclude_ips=retained_ips,
            avoid_subnets=retained_subnets, require_distinct_subnet=True,
        ) if need else []
        picked_ips = [row["ip"] for row in picked]

        target_ips = [cnode.get("server", "") for cnode in current_nodes[:3]]
        for (idx, _name, _ip, _speed), new_ip in zip(replace_indices, picked_ips):
            target_ips[idx] = new_ip

        if picked:
            detail = ", ".join(
                f"{row['ip']}({row['subnet']}{'·同网段替补' if row.get('same_subnet_fallback') else ''})"
                for row in picked)
            self.log_text.appendPlainText(f"🧩 跨 /24 去重选优: {detail}")
        subnets = [subnet_of(ip) for ip in target_ips]
        distinct = len({s for s in subnets if s})
        self.log_text.appendPlainText(
            f"🧩 最终 3 节点分布在 {distinct} 个 /24 网段 "
            + ("✅ 通过跨网段分散约束" if distinct >= min(3, len(target_ips)) else "⚠ 候选子网不足，允许同网段替补"))

        # Populate result table
        self.result_table.setRowCount(len(results))
        for i, r in enumerate(results):
            ip = r.get("IP地址", r.get("ip", "N/A")).strip()

            chk = QTableWidgetItem()
            chk.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            chk.setCheckState(Qt.Checked if ip in target_ips else Qt.Unchecked)
            self.result_table.setItem(i, 0, chk)

            self.result_table.setItem(i, 1, QTableWidgetItem(str(i + 1)))
            self.result_table.setItem(i, 2, QTableWidgetItem(ip))

            loss = r.get("丢包率", r.get("loss", "0"))
            self.result_table.setItem(i, 3, QTableWidgetItem(str(loss)))

            latency = r.get("平均延迟", r.get("avg_latency", r.get("latency", "0")))
            self.result_table.setItem(i, 4, QTableWidgetItem(str(latency)))

            speed = r.get("下载速度(MB/s)", r.get("download_speed", r.get("speed", "0")))
            self.result_table.setItem(i, 5, QTableWidgetItem(str(speed)))

            is_pass = r.get("is_pass", False)
            pass_str = "🟢 达标" if is_pass else "🟡 达标以下"
            self.result_table.setItem(i, 6, QTableWidgetItem(pass_str))

        if self._auto_replace and target_ips:
            self._apply_new_ips(target_ips)

    def _on_speed_finished(self):
        self.auto_btn.setEnabled(True)
        self.manual_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.statusBar().showMessage("✅ 全网测速完成")

    # ── Write IPs ─────────────────────────────────────────────
    def _write_selected_ips(self):
        # 1. 提取全网测速结果表格中所有已勾选的 IP（按表格从上到下顺序）
        selected_ips = []
        for i in range(self.result_table.rowCount()):
            chk = self.result_table.item(i, 0)
            if chk and chk.checkState() == Qt.Checked:
                ip = self.result_table.item(i, 2).text().strip()
                if ip and ip != "N/A" and ip not in selected_ips:
                    selected_ips.append(ip)

        if not selected_ips:
            QMessageBox.warning(self, "未勾选 IP", "请在下方的全网测速结果表格中至少勾选 1 个新 IP！")
            return

        # 手动勾选同样优先保证跨 /24 分散（只调整顺序，绝不丢弃用户勾选的 IP）
        ordered_ips = order_for_subnet_diversity(selected_ips)
        if ordered_ips != selected_ips:
            self.log_text.appendPlainText(
                "🧩 手动勾选已按跨 /24 分散排序（同网段 IP 自动后置）: " + ", ".join(ordered_ips))
        selected_ips = ordered_ips

        current_nodes = self.profile_mgr.get_node_full_info()
        target_ips = [c.get("server", "") for c in current_nodes[:3]]

        # 2. 判定目标替换槽位 (自由映射与精准替换规则):
        # 优先检查用户是否在顶部卡片上手动指定了替换目标
        manually_selected_slots = [i for i in range(len(self.node_cards)) if self.node_cards[i].target_chk.isChecked()]

        if manually_selected_slots:
            # 用户在卡片上有勾选指定的替换目标
            replacement_slots = manually_selected_slots
        else:
            # 默认智能保优规则：优先替换 🔴严重劣化，其次 🟡速度一般，最后按速度从低到高替换
            def get_slot_priority(idx):
                card = self.node_cards[idx]
                score = 0
                if card.rating == "bad":
                    score = 10
                elif card.rating == "medium":
                    score = 20
                elif card.rating == "good":
                    score = 30
                else:  # unknown
                    score = 25
                return (score, card.current_speed)

            replacement_slots = sorted(range(min(3, len(current_nodes))), key=get_slot_priority)

        # 3. 按勾选顺序点对点替换
        num_to_replace = min(len(selected_ips), len(replacement_slots))
        assigned_slots = replacement_slots[:num_to_replace]

        # 若勾选的 IP 数量多于优先替换槽位数，继续替换其余剩余槽位
        if len(selected_ips) > num_to_replace:
            unassigned = [i for i in range(min(3, len(current_nodes))) if i not in assigned_slots]
            for u in unassigned:
                if len(assigned_slots) < len(selected_ips):
                    assigned_slots.append(u)

        for k, slot in enumerate(assigned_slots):
            if k < len(selected_ips):
                target_ips[slot] = selected_ips[k]

        # 4. 在界面日志中输出清晰明了的保留与替换详情
        self.log_text.appendPlainText("=" * 48)
        self.log_text.appendPlainText(f"🎯 【点对点精准替换】已选定 {len(selected_ips)} 个新 IP 写入 FlClash：")
        for idx, cnode in enumerate(current_nodes[:3]):
            cname = cnode.get("name", f"节点{idx+1}")
            old_ip = cnode.get("server", "")
            new_ip = target_ips[idx]
            if old_ip == new_ip:
                self.log_text.appendPlainText(f"   🛡️ 【保留】 {cname}: {old_ip} (优良节点未受影响)")
            else:
                self.log_text.appendPlainText(f"   ⚡ 【替换】 {cname}: {old_ip} ➔ 【{new_ip}】")
        self.log_text.appendPlainText("=" * 48)

        # 5. 执行写入与热重载
        self._apply_new_ips(target_ips[:3])

    def _apply_new_ips(self, new_ips: list):
        """Backup, update YAML, and reload or prompt restart."""
        try:
            # 1. 自动备份
            backup_path = self.profile_mgr.backup()
            self.log_text.appendPlainText(f"📦 备份已创建: {backup_path}")

            # 2. 无损修改写入 YAML
            self.profile_mgr.update_node_ips_by_index(new_ips)
            self.log_text.appendPlainText(f"✅ 已写入新 IP: {', '.join(new_ips)}")

            # 3. 检查 API 热重载与友好提示
            if self.clash_api.is_alive():
                ok = self.clash_api.reload_config(self.profile_path)
                if ok:
                    self.log_text.appendPlainText("🔄 FlClash 核心配置秒级热重载成功！")
                    QMessageBox.information(
                        self, "写入并热重载成功",
                        "已成功将新优选 IP 写入 FlClash 配置文件，并通过 9090 控制端口完成秒级热重载！"
                    )
                else:
                    self.log_text.appendPlainText("✅ 已成功将新优选 IP 写入 FlClash 配置文件！")
                    self.log_text.appendPlainText("💡 若需立即生效，请点旁边的一键重启 FlClash 按钮或手动重启一次客户端。")
                    self._show_restart_prompt()
            else:
                self.log_text.appendPlainText("✅ 已成功将新优选 IP 写入 FlClash 配置文件！")
                self.log_text.appendPlainText("💡 若需立即生效，请点旁边的一键重启 FlClash 按钮或手动重启一次客户端。")
                self._show_restart_prompt()

            # Refresh cards + regenerate every multi-end export immediately so
            # the LAN subscription already serves the new IPs.
            self.profile_mgr.load()
            self._refresh_node_cards()
            try:
                self._regenerate_exports(silent=False)
            except Exception as exc:
                self.log_text.appendPlainText(f"⚠ 自动导出失败: {exc}")
            self.statusBar().showMessage("✅ 新 IP 已成功写入 FlClash 配置文件")
        except Exception as e:
            QMessageBox.critical(self, "写入失败", f"写入配置文件出错: {e}")

    def _show_restart_prompt(self):
        msg = (
            "已成功将新优选 IP 写入 FlClash 配置文件！\n\n"
            "若需立即生效，请点旁边的一键重启 FlClash 按钮或手动重启一次客户端。\n\n"
            "您现在要立即一键重启 FlClash 客户端吗？"
        )
        box = QMessageBox(self)
        box.setWindowTitle("配置写入成功")
        box.setText(msg)
        box.setIcon(QMessageBox.Information)
        btn_restart = box.addButton("🔄 立即重启 FlClash", QMessageBox.AcceptRole)
        btn_later = box.addButton("稍后手动重启", QMessageBox.RejectRole)
        box.setDefaultButton(btn_restart)
        box.exec()
        if box.clickedButton() == btn_restart:
            self._restart_flclash()

    # ── Client restart helper (FlClash / Verge / Mihomo Party) ──
    def _restart_flclash(self):
        client_key = self.cfg.get("client_type", "flclash")
        self.log_text.appendPlainText(f"🔄 正在自动重启客户端进程 ({restart_hint(client_key) or '未识别'})...")
        ok = restart_client(client_key)
        if ok:
            self.log_text.appendPlainText("✅ 客户端已重新启动，等待核心初始化 (约 2~3 秒)...")
            QTimer.singleShot(2500, self._check_flclash_status)
        else:
            self.log_text.appendPlainText("⚠ 重启失败，请手动打开桌面客户端程序")

    def _check_flclash_status(self):
        if self.clash_api.is_alive():
            ver = self.clash_api.get_version()
            self.log_text.appendPlainText(f"✅ 控制端口已打通！核心版本: {ver}")
            self.statusBar().showMessage(
                f"客户端已连接 (API: {self.cfg.get('external_controller')})")
        else:
            self.log_text.appendPlainText("ℹ 客户端已运行，若控制端口暂未就绪，隧道直连握手探测将继续作为兜底保障")

    # ── Rollback ──────────────────────────────────────────────
    def _rollback(self):
        backup = self.profile_mgr.get_latest_backup()
        if not backup:
            QMessageBox.information(self, "无备份", "没有找到备份文件。")
            return

        reply = QMessageBox.question(
            self, "确认回滚",
            f"将恢复备份:\n{os.path.basename(backup)}\n\n确定回滚？",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            try:
                self.profile_mgr.restore_backup(backup)
                if self.clash_api.is_alive():
                    self.clash_api.reload_config(self.profile_path)
                self.profile_mgr.load()
                self._refresh_node_cards()
                self.log_text.appendPlainText("⏪ 已回滚到上一次备份配置")
                self.statusBar().showMessage("⏪ 回滚成功")
            except Exception as e:
                QMessageBox.critical(self, "回滚失败", str(e))

    # ── Export ────────────────────────────────────────────────
    def _export_configs(self):
        try:
            os.makedirs(EXPORTS_DIR, exist_ok=True)
            os.makedirs(DESKTOP_EXPORT_DIR, exist_ok=True)

            paths = self.profile_mgr.generate_all_exports(EXPORTS_DIR)
            links = self.profile_mgr.generate_vless_links()

            # Copy every export to the desktop folders so the TV/mobile can also
            # use a file if they are not on the LAN.
            desktops = [DESKTOP_EXPORT_DIR]
            for directory in set(desktops):
                if not os.path.exists(directory):
                    continue
                for path in paths.values():
                    if not os.path.exists(path):
                        continue
                    try:
                        shutil.copy2(path, os.path.join(directory, os.path.basename(path)))
                    except Exception:
                        pass

            self.log_text.appendPlainText("📲 多端配置已生成并同步至桌面与局域网服务！")
            if self._lan_ip:
                self.log_text.appendPlainText(
                    f"📱 iOS: http://{self._lan_ip}:{self._lan_port}/ios.yaml  |  "
                    f"📺 Happ: http://{self._lan_ip}:{self._lan_port}/tv_happ.txt")

            dlg = ExportDialog(
                links, paths["ios"], paths["tv"],
                self._lan_ip, self._lan_port, EXPORTS_DIR,
                desktop_export_dir=DESKTOP_EXPORT_DIR,
                parent=self,
            )
            dlg.exec()
        except Exception as e:
            QMessageBox.critical(self, "导出失败", str(e))

    # ── Optimized topology (chain proxy / IPv6 / mux) ───────────
    def _apply_topology(self):
        """Write the chained-airport + streaming/AI + IPv6-hardened topology."""
        try:
            summary = self.profile_mgr.apply_optimized_topology()
            # Persist resolved airport identity + merged node list so a future
            # airport change can clean stale nodes safely.
            if summary.get("airport_path"):
                self.cfg["airport_profile_path"] = summary["airport_path"]
            self.cfg["airport_managed_nodes"] = summary.get("managed_nodes", [])
            try:
                save_config(self.cfg)
            except Exception:
                pass
            reloaded = False
            try:
                if self.clash_api.is_alive():
                    reloaded = self.clash_api.reload_config(self.profile_path)
            except Exception:
                reloaded = False

            self.profile_mgr.load()
            self._refresh_node_cards()
            try:
                self._regenerate_exports(silent=False)
            except Exception as exc:
                self.log_text.appendPlainText(f"⚠ 自动导出失败: {exc}")

            lines = [
                f"CF 节点: {', '.join(summary.get('cf_nodes', [])) or '未找到'}",
                f"机场配置: {summary.get('airport_profile', {}).get('label', '')} "
                f"[{summary.get('airport_path', '')}]",
                f"机场节点合并: {summary.get('airport_nodes', 0)} 个",
                f"清理过期节点: {len(summary.get('removed_nodes', []))} 个",
                f"流媒体 url-test: {summary.get('stream_group') or '未创建'}",
                f"机场前置组: {summary.get('front_group') or '未创建'}",
                f"AI 链式落地: {summary.get('chain_node') or '未创建'}",
                f"分流规则更新: {summary.get('rules_touched', 0)} 条",
                f"备份: {summary.get('backup', '')}",
                f"热重载: {'✅ 成功' if reloaded else '未生效（下次启动生效）'}",
            ]
            if summary.get("warnings"):
                lines.append("警告: " + "; ".join(summary["warnings"]))
            self.log_text.appendPlainText("🧩 多端优化拓扑已应用:\n  " + "\n  ".join(lines))
            QMessageBox.information(self, "多端优化拓扑已应用", "\n".join(lines))
        except Exception as e:
            QMessageBox.critical(self, "应用优化拓扑失败", str(e))

    # System tray
    # ══════════════════════════════════════════════════════════
    def _init_tray(self):
        """Create the tray icon + context menu (safe under QT_QPA_PLATFORM=offscreen)."""
        icon = build_app_icon()
        self.setWindowIcon(icon)  # window and tray share the same icon

        self._tray_icon = QSystemTrayIcon(icon)
        self._tray_icon.setToolTip("CF-FlClash-Optimizer — CF 优选 IP 体检 / 局域网订阅")

        menu = QMenu()
        self._tray_show_action = menu.addAction("🖥️ 显示主界面")
        self._tray_show_action.triggered.connect(lambda *_: self._show_main_window())

        self._tray_guard_now_action = menu.addAction("⚡ 立即执行一次巡检")
        self._tray_guard_now_action.triggered.connect(lambda *_: self._guard_now())

        self._tray_guard_action = menu.addAction("🔄 开启后台自动巡检")
        self._tray_guard_action.setCheckable(True)
        self._tray_guard_action.triggered.connect(self._on_tray_toggle_guard)

        self._tray_lan_action = menu.addAction("🌐 开启局域网订阅服务")
        self._tray_lan_action.setCheckable(True)
        self._tray_lan_action.triggered.connect(self._on_tray_toggle_lan)

        menu.addSeparator()

        self._tray_quit_action = menu.addAction("❌ 完全退出程序")
        self._tray_quit_action.triggered.connect(lambda *_: self.quit_application())

        self._tray_menu = menu
        self._tray_icon.setContextMenu(menu)
        self._tray_icon.activated.connect(self._on_tray_activated)

        if QSystemTrayIcon.isSystemTrayAvailable():
            self._tray_icon.show()
        else:
            dbg("tray: system tray unavailable (headless?) — icon created but not shown")
        self._sync_tray_menu()

    def _sync_tray_menu(self):
        """Mirror the main-window checkboxes onto the tray menu actions."""
        pairs = (
            (getattr(self, "_tray_guard_action", None), getattr(self, "guard_chk", None)),
            (getattr(self, "_tray_lan_action", None), getattr(self, "lan_chk", None)),
        )
        for action, checkbox in pairs:
            if action is None or checkbox is None:
                continue
            action.blockSignals(True)
            action.setChecked(bool(checkbox.isChecked()))
            action.blockSignals(False)

    def _on_tray_toggle_guard(self, checked: bool):
        chk = getattr(self, "guard_chk", None)
        if chk is not None:
            chk.setChecked(bool(checked))
        self._sync_tray_menu()

    def _on_tray_toggle_lan(self, checked: bool):
        chk = getattr(self, "lan_chk", None)
        if chk is not None:
            chk.setChecked(bool(checked))
        self._sync_tray_menu()

    def _on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self._show_main_window()

    def _show_main_window(self):
        """Restore + raise the main window from the tray."""
        try:
            self.showNormal()
            self.raise_()
            self.activateWindow()
        except Exception as exc:
            dbg(f"tray: show main window failed: {exc}")

    def _show_tray_hint_once(self):
        """First hide only: one short balloon so the user knows where the app went."""
        if self._tray_hint_shown:
            return
        self._tray_hint_shown = True
        try:
            if self._tray_icon is None or not QSystemTrayIcon.supportsMessages():
                return
            self._tray_icon.showMessage(
                "CF-FlClash-Optimizer",
                "程序已最小化到系统托盘，后台自动巡检与订阅服务继续运行",
                QSystemTrayIcon.Information, 4000)
        except Exception as exc:
            dbg(f"tray: showMessage failed: {exc}")

    # ══════════════════════════════════════════════════════════
    # Startup / close behaviour
    # ══════════════════════════════════════════════════════════
    def _close_to_tray_enabled(self) -> bool:
        chk = getattr(self, "close_to_tray_chk", None)
        if chk is None:
            return bool(getattr(self, "cfg", {}).get("close_to_tray", True))
        return bool(chk.isChecked())

    def _toggle_close_to_tray(self, checked: bool):
        self.cfg["close_to_tray"] = bool(checked)
        try:
            save_config(self.cfg)
        except Exception as exc:
            dbg(f"config: save close_to_tray failed: {exc}")
        self.statusBar().showMessage(
            "✅ 关闭窗口时将最小化到系统托盘" if checked
            else "⏹ 关闭窗口时将直接退出程序")

    def _sync_auto_start_from_registry(self):
        """Trust the registry (not the JSON) as the source of truth at startup."""
        enabled = is_auto_start_enabled()
        chk = getattr(self, "auto_start_chk", None)
        if chk is not None:
            chk.blockSignals(True)
            chk.setChecked(enabled)
            chk.blockSignals(False)
        previous = bool(self.cfg.get("auto_start_enabled", False))
        self.cfg["auto_start_enabled"] = enabled
        if previous != enabled:
            try:
                save_config(self.cfg)
            except Exception as exc:
                dbg(f"config: save auto_start_enabled failed: {exc}")
        if hasattr(self, "auto_start_lbl"):
            if enabled:
                self.auto_start_lbl.setText(
                    f"✅ 开机自启已注册（HKCU Run / {AUTO_START_KEY_NAME}）: "
                    + build_auto_start_command(True))
            else:
                self.auto_start_lbl.setText(
                    "⏸ 未设置开机自启 — 勾选后将以 --minimized 静默启动到右下角托盘")

    def _toggle_auto_start(self, checked: bool):
        ok, message = set_auto_start(bool(checked), minimized=True)
        actual = is_auto_start_enabled() if ok else bool(self.cfg.get("auto_start_enabled", False))
        self.cfg["auto_start_enabled"] = actual
        try:
            save_config(self.cfg)
        except Exception as exc:
            dbg(f"config: save auto_start_enabled failed: {exc}")

        if not ok:
            chk = getattr(self, "auto_start_chk", None)
            if chk is not None:
                chk.blockSignals(True)
                chk.setChecked(actual)
                chk.blockSignals(False)
            if hasattr(self, "auto_start_lbl"):
                self.auto_start_lbl.setText(f"⚠ 开机自启设置失败: {message}")
            self.statusBar().showMessage(f"⚠ 开机自启设置失败: {message}")
            QMessageBox.warning(self, "开机自启设置失败", message)
            return

        if hasattr(self, "auto_start_lbl"):
            self.auto_start_lbl.setText(("✅ " if checked else "⏸ ") + message)
        self.statusBar().showMessage(("✅ " if checked else "⏸ ") + message)
        self._sync_tray_menu()

    # ══════════════════════════════════════════════════════════
    # Cleanup (thread-safe, idempotent)
    # ══════════════════════════════════════════════════════════
    def _shutdown_background(self):
        """Stop guardian + LAN server + workers exactly once, in that order."""
        if self._shutdown_done:
            return
        self._shutdown_done = True
        # Guardian first: it is the only thread that rewrites the profile.
        guard = getattr(self, "_guard", None)
        if guard is not None:
            try:
                guard.stop()
            except Exception as exc:
                dbg(f"shutdown: guardian stop failed: {exc}")
            self._guard = None
        lan = getattr(self, "_lan_server", None)
        if lan is not None:
            try:
                lan.stop()
            except Exception as exc:
                dbg(f"shutdown: lan server stop failed: {exc}")
            self._lan_server = None
        # Release the single-instance pipe before the process leaves.
        server = getattr(self, "_instance_server", None)
        if server is not None:
            try:
                server.close()
            except Exception as exc:
                dbg(f"shutdown: instance server close failed: {exc}")
            self._instance_server = None
        for attr in ("_health_worker", "_speed_worker"):
            worker = getattr(self, attr, None)
            if worker is not None and worker.isRunning():
                try:
                    worker.stop()
                    worker.wait(1000)
                except Exception as exc:
                    dbg(f"shutdown: {attr} stop failed: {exc}")

    def _cleanup_tray(self):
        """Hide/remove the tray icon before the process leaves the message loop."""
        icon = getattr(self, "_tray_icon", None)
        if icon is None:
            return
        try:
            icon.hide()
        except Exception:
            pass
        try:
            icon.setContextMenu(None)
        except Exception:
            pass
        self._tray_icon = None

    def quit_application(self):
        """Tray "❌ 完全退出程序": force quit, stop every background service."""
        self._force_quit = True
        self._shutdown_background()
        self._cleanup_tray()
        try:
            self.close()
        except Exception as exc:
            dbg(f"quit: window close failed: {exc}")
        app = QApplication.instance()
        if app is not None:
            app.quit()

    def closeEvent(self, event):
        # Click on × while "close to tray" is on: hide, keep services alive.
        if not getattr(self, "_force_quit", False) and self._close_to_tray_enabled():
            event.ignore()
            self.hide()
            self._show_tray_hint_once()
            self.statusBar().showMessage(
                "已最小化到系统托盘（后台自动巡检与局域网订阅继续运行）")
            return

        self._shutdown_background()
        self._cleanup_tray()
        event.accept()
        super().closeEvent(event)
        # QuitOnLastWindowClosed is False (tray support), so quit explicitly.
        app = QApplication.instance()
        if app is not None:
            QTimer.singleShot(0, app.quit)


def parse_start_minimized(argv=None, cfg=None) -> bool:
    """Silent start when --minimized is on the command line or start_minimized=True."""
    argv = list(sys.argv if argv is None else argv)
    if "--minimized" in argv:
        return True
    if cfg is None:
        cfg = load_config()
    return bool(cfg.get("start_minimized", False))


def main(argv=None):
    dbg("2. entering main()")
    argv = list(sys.argv if argv is None else argv)
    # explorer.exe launches autostart entries with CWD=%SystemRoot%\System32;
    # fix the working directory before any relative path is touched.
    ensure_app_cwd()
    dbg(f"2a. working directory forced to {os.getcwd()}")
    try:
        app = QApplication(argv)
        dbg("3. QApplication created")
        # Second launch: tell the running instance to raise its window, then leave.
        if notify_existing_instance():
            dbg("3a. existing instance detected -> SHOW sent, new process exits 0")
            return 0
        # The tray icon must keep the app alive after the window is hidden.
        app.setQuitOnLastWindowClosed(False)
        app.setStyle("Fusion")
        dbg("4. creating MainWindow")
        window = MainWindow()
        # Own the named pipe for later launches.
        server = SingleInstanceServer()
        server.activated.connect(window._show_main_window)
        window._instance_server = server
        start_minimized = parse_start_minimized(argv, window.cfg)
        tray_available = QSystemTrayIcon.isSystemTrayAvailable()
        if start_minimized and tray_available:
            dbg("5a. --minimized active: window stays in the tray; "
                "auto guard / LAN service started from config.json")
        else:
            if start_minimized:
                dbg("5b. --minimized requested but no system tray available; showing window")
            dbg("5. MainWindow created, calling show()")
            window.show()
        dbg(f"6. window ready (visible={window.isVisible()}), calling app.exec()")
        ret = app.exec()
        dbg(f"7. app.exec() exited with {ret}")
        return ret
    except Exception as e:
        import traceback
        try:
            with open(DEBUG_LOG, "a", encoding="utf-8") as f:
                traceback.print_exc(file=f)
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
