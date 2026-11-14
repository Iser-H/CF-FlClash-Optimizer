# CF-FlClash-Optimizer

Windows 桌面工具：用 [CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest) 优选 Cloudflare IP，把结果安全写回本机 Clash / Mihomo 客户端配置，并持续体检、自动换 IP、导出多端订阅。

A Windows desktop app that benchmarks Cloudflare IPs with CloudflareSpeedTest, writes the winners back into your local Clash / Mihomo profile, keeps watching node health, and serves multi-device subscriptions.

> 本项目与 Cloudflare、XIU2、FlClash、Clash Verge Rev、Mihomo Party 均无隶属关系，仅调用其公开接口与本地配置文件。

---

## 中文

### 功能

- **CF IP 优选**：调用 `bin/cfst.exe` 测速，表格展示丢包 / 延迟 / 下载速度，可手动勾选或一键智能替换。
- **多客户端支持**：自动发现 **FlClash**、**Clash Verge Rev**、**Mihomo Party** 的配置目录；也可「浏览…」选择任意本地 Clash / Mihomo YAML。
- **自定义外部控制 API**：`external-controller`（如 `127.0.0.1:9090`）+ `secret`，支持一键测试连通性。
- **节点健康巡检**：已配置 IP 深度体检，>5% 丢包或延迟劣化时自动重新优选并换 IP；后台守护线程按分钟级间隔运行。
- **跨 /24 分散**：`cidr_pool` 维护子网评分历史（读写原子化、损坏自愈），70% 利用 / 30% 探索抽样，Top-N 选择时优先不同 `/24`。
- **多端导出**：iOS Clash YAML、Happ 订阅（含自动更新/自动连接指令）、电视 Base64、Happ Xray JSON、VLESS 明文链接。
- **局域网订阅**：默认关闭；开启后内置 HTTP 服务（端口 `8686`，被占用自动顺延）只提供 `/s/<token>/…` 形式的订阅地址，Token 由 `secrets` 生成、可一键轮换，关闭服务或轮换后旧地址立即失效；防火墙规则仅限专用网络 + 本地子网。
- **系统托盘 + 开机自启**：关闭窗口最小化到托盘，后台服务继续；自启写入 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`，免管理员权限，路径迁移后自动判定失效。
- **单实例**：已有一个实例在托盘时再次双击，会唤起并置顶旧窗口，新进程立即以退出码 0 退出，不会出现双托盘 / 8687 端口顺延。
- **无遥测**：不联网上传任何配置、IP 或使用数据；所有状态保存在本地文件。

### 环境要求

| 项目 | 要求 |
| --- | --- |
| 系统 | Windows 10 / 11（依赖注册表、托盘、`netsh` 防火墙） |
| Python | 3.10+（打包后运行无需 Python） |
| 依赖 | `PySide6>=6.5`、`ruamel.yaml`、`requests`、`qrcode`、`Pillow` |
| 测速核心 | 下载 `cfst.exe`（CloudflareSpeedTest）放入 `bin/` |

```bash
pip install PySide6 ruamel.yaml requests qrcode pillow
```

### 快速开始

```bash
git clone <your-repo-url>
cd CF-FlClash-Optimizer
copy config.example.json config.json      # Windows
# cp config.example.json config.json      # Git Bash / PowerShell
python main_gui.py
```

首次启动会扫描本机客户端目录；识别不到时，在「🔌 客户端与配置文件」里点「📂 浏览…」选择 YAML，再点「✅ 应用配置」。

### 配置说明（config.json）

| 键 | 说明 |
| --- | --- |
| `client_type` | `auto` / `flclash` / `verge` / `mihomo` / `manual` |
| `flclash_profile_path` | 当前使用的 YAML 绝对路径（GUI 会自动写入） |
| `flclash_config_dir` | 客户端配置目录，用于发现与 FlClash 端口补丁 |
| `mixed_port` | 客户端混合端口，仅用于展示 |
| `external_controller` / `secret` | Clash 外部控制 API 地址与密钥 |
| `cf_node_names` | 要写入 / 替换的三个 CF 节点名 |
| `lan_server_port` | 局域网订阅端口（默认 8686，占用时顺延 10 个） |
| `lan_server_enabled` | 局域网订阅开关；新安装默认 `false`，只保留用户显式保存的 `true` |
| `lan_bind_host` | `auto`（绑定检测到的局域网地址）或显式 IP；`0.0.0.0` 仍可用但按本地子网限制 |
| `lan_auth_token` | 访问 Token（`secrets.token_urlsafe(48)`，384 bit）；缺失或过弱时启动自动生成 |
| `lan_firewall_remote` | 防火墙远程范围：`LocalSubnet`（默认）或私有 CIDR |
| `auto_guard_enabled` / `auto_guard_interval_min` | 后台巡检开关与间隔 |
| `cidr_sample_size` / `cidr_exploit_ratio` | 抽样数量与利用/探索比 |
| `close_to_tray` / `auto_start_enabled` / `start_minimized` | 托盘与自启行为 |

`config.json`、`dist/config.json`、`exports/`、`backups/` 都已被 `.gitignore` 排除，请勿提交个人配置。

### 打包

```bash
python -m PyInstaller --noconfirm --clean CF-FlClash-Optimizer.spec
# 产物: dist\CF-FlClash-Optimizer.exe
```

`bin\cfst.exe` 不打进 exe，运行时从程序目录的 `bin\` 读取。

### 目录结构

```text
main_gui.py           GUI 入口、托盘、单实例、客户端配置面板
clients.py            FlClash / Verge / Mihomo Party 目录与配置发现
profile_manager.py    YAML 读取、原子写回、备份/回滚、导出生成
config_templates.py   拓扑优化、iOS/Happ/电视导出、校验
workers.py            测速 / 体检 / 局域网服务线程
auto_guard.py         后台巡检与劣化自动换 IP
cidr_pool.py          /24 评分池与跨网段抽样
lan_server.py         局域网 HTTP 订阅与防火墙规则
path_utils.py         路径、配置、开机自启注册表
flclash_patch.py      FlClash 控制端口补丁与客户端重启
clash_api.py          Clash REST API 封装
export_dialog.py      导出二维码窗口
storage_utils.py      原子写文件与文件锁
```

### 工作原理（简）

1. `cfst.exe` 按 CIDR 库抽样测速，输出 CSV；
2. 结果进入表格，用户勾选或自动择优；
3. `ProfileManager` 用 ruamel.yaml 保留注释地改写 3 个节点的 `server`，原子落盘并备份；
4. 通过 Clash API `PUT /configs?force=true` 热重载，失败时提示重启客户端；
5. 守护线程周期性体检，劣化超过阈值即重复 1–4；
6. 导出器生成 iOS / Happ / 电视订阅，局域网服务对外提供最新文件。

### 致谢

- [XIU2/CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest)：测速核心与 CIDR 数据来源
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)、[Clash](https://github.com/Dreamacro/clash)：配置格式与 API 约定
- [FlClash](https://github.com/chen08209/FlClash)、[Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev)、[Mihomo Party](https://github.com/mihomo-party-org/mihomo-party)：客户端与配置目录规范
- [PySide6](https://doc.qt.io/qtforpython/)：GUI 框架

### 许可

建议以 MIT 协议发布（仓库尚未附带 LICENSE 文件，上传前请补一份）。

---

## English

### Features

- **Cloudflare IP optimization** via the bundled-at-runtime `bin/cfst.exe` (CloudflareSpeedTest), with loss / latency / throughput table and manual or automatic replacement.
- **Multi-client**: auto-discovers **FlClash**, **Clash Verge Rev** and **Mihomo Party** profile directories, plus a manual "browse any local Clash/Mihomo YAML" path.
- **Custom controller API**: `external-controller` + `secret`, with a one-click connectivity test.
- **Health guardian**: periodic checks of the configured IPs, automatic re-optimization when loss/latency degrades.
- **Subnet diversity**: a persistent `/24` score store with 70/30 exploit/explore sampling and cross-subnet Top-N selection.
- **Multi-device export**: iOS Clash YAML, Happ subscription (auto-update/auto-connect directives), TV Base64, Happ Xray JSON, plain VLESS links.
- **LAN subscription server**: off by default; when enabled, HTTP on `8686` (auto fallback) serves only token-protected `/s/<token>/…` URLs. Tokens are generated with `secrets`, can be rotated from the GUI, and stop working when the service stops or the token is rotated; the firewall rule is limited to the private profile and LocalSubnet.
- **Tray + autostart**: closing the window hides to tray; autostart is a per-user `HKCU` Run entry (no admin), invalidated automatically if the exe moves.
- **Single instance**: a second launch asks the running instance to raise its window and exits 0 — no duplicate tray icons, no 8687 fallback.
- **No telemetry**: nothing is uploaded; all state stays in local files.

### Requirements

Windows 10/11, Python 3.10+, `PySide6`, `ruamel.yaml`, `requests`, `qrcode`, `Pillow`, and `cfst.exe` in `bin/`.

```bash
pip install PySide6 ruamel.yaml requests qrcode pillow
copy config.example.json config.json
python main_gui.py
```

### Build

```bash
python -m PyInstaller --noconfirm --clean CF-FlClash-Optimizer.spec
# output: dist\CF-FlClash-Optimizer.exe
```

### Configuration

Copy `config.example.json` to `config.json`; every path is empty by default and filled by the GUI after discovery. `config.json`, `dist/config.json`, `exports/` and `backups/` are gitignored — never commit personal profiles or API secrets.

### Credits

CloudflareSpeedTest by XIU2, mihomo/Clash, FlClash, Clash Verge Rev, Mihomo Party, and PySide6.

### License

MIT is recommended; add a LICENSE file before publishing.
