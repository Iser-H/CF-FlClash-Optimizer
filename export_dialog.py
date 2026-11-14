# -*- coding: utf-8 -*-
"""Export dialog – multi-device sync center with QR codes."""

import os
import base64
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTabWidget, QWidget, QTextEdit, QApplication, QMessageBox,
)
from PySide6.QtGui import QPixmap, QImage
from PySide6.QtCore import Qt

import qrcode
from io import BytesIO


class ExportDialog(QDialog):
    """Multi-device sync dialog with VLESS links, QR codes, LAN subscription."""

    def __init__(self, vless_links: list, ios_yaml_path: str, tv_links_path: str,
                 lan_ip: str, lan_port: int, exports_dir: str, desktop_export_dir: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("📲 多端同步中心")
        self.setMinimumSize(700, 550)
        self.vless_links = vless_links
        self.ios_yaml_path = ios_yaml_path
        self.tv_links_path = tv_links_path
        self.lan_ip = lan_ip
        self.lan_port = lan_port
        self.exports_dir = exports_dir
        self.desktop_export_dir = desktop_export_dir
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Title
        title = QLabel("📲 多端配置同步中心")
        title.setStyleSheet("font-size: 18px; font-weight: bold; padding: 5px;")
        layout.addWidget(title)

        tabs = QTabWidget()

        # ── Tab 1: VLESS Links ────────────────────────────────
        vless_tab = QWidget()
        vl = QVBoxLayout(vless_tab)

        vl.addWidget(QLabel("📋 电视端 VLESS 链接 (共 3 条):"))
        self.vless_text = QTextEdit()
        self.vless_text.setReadOnly(True)
        self.vless_text.setPlainText("\n\n".join(self.vless_links))
        self.vless_text.setMaximumHeight(150)
        vl.addWidget(self.vless_text)

        btn_row = QHBoxLayout()
        copy_btn = QPushButton("📋 一键复制 3 条 VLESS 链接")
        copy_btn.clicked.connect(self._copy_vless)
        btn_row.addWidget(copy_btn)

        open_btn = QPushButton("📂 打开导出文件夹")
        open_btn.clicked.connect(self._open_exports)
        btn_row.addWidget(open_btn)
        vl.addLayout(btn_row)

        tabs.addTab(vless_tab, "📋 VLESS 链接")

        # ── Tab 2: QR Codes ───────────────────────────────────
        qr_tab = QWidget()
        ql = QVBoxLayout(qr_tab)
        ql.addWidget(QLabel("📷 扫码导入配置:"))

        qr_tabs = QTabWidget()

        # Combined VLESS QR
        combined = "\n".join(self.vless_links)
        qr_tabs.addTab(self._make_qr_widget(combined), "VLESS 聚合二维码")

        # Individual VLESS QR
        for i, link in enumerate(self.vless_links):
            qr_tabs.addTab(self._make_qr_widget(link), f"节点 {i+1}")

        # LAN subscription QR
        if self.lan_ip and self.lan_ip != "127.0.0.1":
            ios_url = f"http://{self.lan_ip}:{self.lan_port}/ios.yaml"
            tv_url = f"http://{self.lan_ip}:{self.lan_port}/tv_happ.txt"
            qr_tabs.addTab(self._make_qr_widget(ios_url, f"iOS Clash 订阅:\n{ios_url}"), "iOS 局域网订阅")
            qr_tabs.addTab(self._make_qr_widget(tv_url, f"Happ 电视订阅:\n{tv_url}"), "电视局域网订阅")

        ql.addWidget(qr_tabs)
        tabs.addTab(qr_tab, "📷 二维码")

        # ── Tab 3: LAN Subscription ──────────────────────────
        lan_tab = QWidget()
        ll = QVBoxLayout(lan_tab)
        ll.addWidget(QLabel("🌐 局域网 HTTP 订阅微服务"))
        if self.lan_ip and self.lan_ip != "127.0.0.1":
            info = (
                f"当前局域网 IP: {self.lan_ip}\n"
                f"服务端口: {self.lan_port}\n\n"
                f"📱 iOS Clash 订阅地址:\n  http://{self.lan_ip}:{self.lan_port}/ios.yaml\n\n"
                f"📺 电视 Happ 订阅地址（自带自动更新/自动连接）:\n  http://{self.lan_ip}:{self.lan_port}/tv_happ.txt\n\n"
                f"🧩 Happ Xray JSON（DNS UseIPv4 / mux 关闭）:\n  http://{self.lan_ip}:{self.lan_port}/happ.json\n\n"
                f"📦 电视 Base64 订阅:\n  http://{self.lan_ip}:{self.lan_port}/tv\n\n"
                f"📋 VLESS 明文链接:\n  http://{self.lan_ip}:{self.lan_port}/vless"
            )
        else:
            info = "⚠ 无法获取局域网 IP，请确保连接了局域网。"
        info_label = QTextEdit()
        info_label.setReadOnly(True)
        info_label.setPlainText(info)
        ll.addWidget(info_label)

        if self.lan_ip and self.lan_ip != "127.0.0.1":
            lan_btn_row = QHBoxLayout()
            copy_ios_btn = QPushButton("📋 复制 iOS Clash 订阅地址")
            copy_ios_btn.clicked.connect(lambda: (
                QApplication.clipboard().setText(f"http://{self.lan_ip}:{self.lan_port}/ios.yaml"),
                QMessageBox.information(self, "复制成功", f"已复制 iOS Clash 订阅地址:\nhttp://{self.lan_ip}:{self.lan_port}/ios.yaml")
            ))
            lan_btn_row.addWidget(copy_ios_btn)

            copy_tv_btn = QPushButton("📺 复制 Happ 订阅地址")
            copy_tv_btn.clicked.connect(lambda: (
                QApplication.clipboard().setText(f"http://{self.lan_ip}:{self.lan_port}/tv_happ.txt"),
                QMessageBox.information(self, "复制成功", f"已复制 Happ 订阅地址:\nhttp://{self.lan_ip}:{self.lan_port}/tv_happ.txt")
            ))
            lan_btn_row.addWidget(copy_tv_btn)

            copy_json_btn = QPushButton("🧩 复制 Happ Xray JSON 地址")
            copy_json_btn.clicked.connect(lambda: (
                QApplication.clipboard().setText(f"http://{self.lan_ip}:{self.lan_port}/happ.json"),
                QMessageBox.information(self, "复制成功", f"已复制 Xray JSON 地址:\nhttp://{self.lan_ip}:{self.lan_port}/happ.json")
            ))
            lan_btn_row.addWidget(copy_json_btn)
            ll.addLayout(lan_btn_row)

        tabs.addTab(lan_tab, "🌐 局域网订阅")

        layout.addWidget(tabs)

        # File paths
        paths_label = QLabel(
            f"iOS YAML: {self.ios_yaml_path}\n"
            f"VLESS 链接: {self.tv_links_path}"
        )
        paths_label.setStyleSheet("font-size: 11px; color: gray; padding: 5px;")
        paths_label.setWordWrap(True)
        layout.addWidget(paths_label)

    def _make_qr_widget(self, data: str, caption: str = "") -> QWidget:
        w = QWidget()
        vl = QVBoxLayout(w)
        if caption:
            lbl = QLabel(caption)
            lbl.setWordWrap(True)
            vl.addWidget(lbl)

        # Generate QR
        qr = qrcode.QRCode(version=1, box_size=6, border=2, error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buf = BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        qimg = QImage.fromData(buf.read())
        pixmap = QPixmap.fromImage(qimg)

        lbl = QLabel()
        lbl.setPixmap(pixmap.scaled(300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        lbl.setAlignment(Qt.AlignCenter)
        vl.addWidget(lbl)
        return w

    def _copy_vless(self):
        text = "\n".join(self.vless_links)
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "已复制", "3 条 VLESS 链接已复制到剪贴板！")

    def _open_exports(self):
        target = self.desktop_export_dir if (self.desktop_export_dir and os.path.exists(self.desktop_export_dir)) else self.exports_dir
        if os.path.exists(target):
            os.startfile(target)
