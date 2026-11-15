CF-FlClash-Optimizer v1.2 — 发布说明
=====================================

文件
----
CF-FlClash-Optimizer-v1.2.exe   PyInstaller onefile 单文件（与 v1.1 相同的打包模式）
                               PyInstaller 6.22.3 / Python 3.13.16 / 未签名

首次运行会在 EXE 所在目录自动创建（不会覆盖已有文件）：
  config.json   默认配置（脱敏模板，LOCAL 首次生成）
  bin\          测速工作目录（ip.txt 按 CIDR 库自动生成）
  backups\      应用拓扑前的自动备份
  exports\      多端导出（FlClash_Optimized.yaml / iOS_Clash_Config.yaml / Happ / Xray）

v1.2 新增
---------
1. VPS VLESS 直连节点「🇺🇸 洛杉矶-VPS-直连(AI)」：复制链式落地节点后去掉
   dialer-proxy，作为不经机场前置的直连落地。
2. 🤖 AI-链式落地 变为 select，成员顺序：链式落地 → VPS 直连。
3. PROXY 顺序：日常机场组 → 流媒体组 → AI 链式组 → VPS 直连 → DIRECT。

测速核心（cfst.exe）
--------------------
cfst.exe 不打进 EXE（沿用原设计，也便于替换新版本）。需要测速时，把
CloudflareSpeedTest 的 cfst.exe 放到 EXE 同目录的 bin\ 下即可；放之前测速
按钮会提示找不到文件。LAN 服务默认关闭；开启时自动生成 384-bit Token，
订阅地址为 http://<本机IP>:8686/s/<token>/<文件名>。

注意
----
v1.1 的托盘实例若仍在运行，会占用单实例管道与 8686 端口：先从托盘菜单
「❌ 完全退出程序」退出旧实例，再启动 v1.2。
