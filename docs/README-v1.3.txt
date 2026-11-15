CF-FlClash-Optimizer v1.3 — 使用说明（Windows）
================================================

一、这个包里有什么
------------------
CF-FlClash-Optimizer-v1.3.exe   主程序（单文件，双击即可运行）
bin\cfst.exe                    CFST 测速核心（CloudflareSpeedTest v2.3.5，已随包提供，
                                不需要自行下载或复制）
README-v1.3.txt                 本文件
THIRD-PARTY-NOTICES.txt         第三方组件来源与许可证声明
SHA256SUMS.txt                  所有文件的校验值
licenses\                       CloudflareSpeedTest 的 GPL-3.0 许可证原文

解压后请保持目录结构（EXE 与 bin\ 必须在同一层），直接双击 EXE 运行。


二、用户数据放在哪里（v1.3 起与 EXE 解耦）
-----------------------------------------
v1.3 起配置与运行数据统一存放在固定目录：

    %APPDATA%\CF-FlClash-Optimizer\
        config.json          你的全部设置（Token、机场、VPS 落地节点名、CF 节点名…）
        backups\             每次写入前的自动备份
        exports\             FlClash / iOS / Happ / Xray 导出文件
        bin\                 测速工作目录（ip.txt 等），也可放自己的 cfst.exe
        cidr_score_history.json

这样做的好处：以后升级只要替换 EXE，设置、Token、订阅链接都不会变。

* 首次运行 v1.3 时，如果检测到旧版（同目录或相邻的 release_v1.2\、dist\）里有
  config.json，会自动复制到上面的目录，并在 backups\migration-<时间>\ 里保留一份
  来源备份。旧目录中的文件原样保留，不会删除。
* 如果 %APPDATA%\CF-FlClash-Optimizer\config.json 已经存在，v1.3 绝不会覆盖它。
* 想便携使用（把所有数据放在 EXE 旁边）：删除 %APPDATA% 下的上述目录，并设置环境
  变量 CFFO_DATA_DIR=<你想要的目录> 后启动程序即可。
* cfst.exe 查找顺序：%APPDATA%\CF-FlClash-Optimizer\bin\cfst.exe →
  EXE 所在目录\bin\cfst.exe（包内自带）。两者都存在时优先用 AppData 里的那份。


三、首次使用
------------
1. 双击 CF-FlClash-Optimizer-v1.3.exe。
2. 在「客户端与配置文件」里选择 FlClash 正在使用的 YAML（工作配置），点「✅ 应用配置」。
3. 在同一个面板里设置「机场订阅」：这项只作为节点来源，和工作配置必须是两个不同的
   文件；CFO 会把机场节点合并进工作配置。
4. 点「🧩 应用多端优化拓扑」。v1.3 会先做预检查并弹窗显示目标文件、CF 节点数、
   机场来源、VPS 落地节点、即将写入的两个策略组；确认后才写入，写入前自动备份。
   任何一项检查不通过（例如把机场订阅选成了工作配置、CF 节点 0 个、找不到 VPS 落地
   节点）都不会修改任何文件。
5. 期望结果：工作配置里出现「🇺🇸 洛杉矶-VPS-链式落地(AI)」「🇺🇸 洛杉矶-VPS-直连(AI)」，
   「🤖 AI-链式落地」= 链式 → 直连，PROXY = 日常 → 流媒体 → AI 链式 → VPS 直连 → DIRECT。
6. CF 测速：需要时点「一键检测当前已配置 IP」或「全网优选」；v1.3 已内置 cfst.exe，
   不会再出现“系统找不到指定的文件”。


四、手机订阅同步（局域网）
--------------------------
1. 电脑和手机连同一个 Wi-Fi/路由器（不要用访客网络；访客网络通常开了 AP 隔离）。
2. 勾选「启用局域网 HTTP 订阅服务」。服务默认端口 8686，绑定 0.0.0.0，界面会显示
   检测到的局域网 IP（例如 http://192.168.5.6:8686/...）。
3. 点「🛡️ 一键放行防火墙端口」，如出现 UAC 提示请允许。v1.3 的规则是
   TCP 入站、专用+公用网络、作用域=本地子网（LocalSubnet），既能在家用
   “公用网络”分类的 Wi-Fi 上生效，又不会对公网开放。
4. 点「📋 复制订阅链接」，得到 4 条带 Token 的地址：
       .../s/<Token>/flclash.yaml     FlClash 手机端 / 电脑端
       .../s/<Token>/ios.yaml         Clash for iOS / Stash
       .../s/<Token>/tv_happ.txt      Happ 电视端
       .../s/<Token>/happ.json        Happ / Xray JSON
   在手机客户端里「添加订阅」粘贴对应地址即可。
5. 手机打不开时，先点「🧪 局域网自检」。它会真实请求 4 个接口并逐项报告：
   服务监听、局域网 IP、防火墙规则（含当前网络类别是否被规则覆盖）、Token 是否配置、
   每个接口的 HTTP 状态/Content-Type/字节数、YAML 能否解析、HEAD 支持、非法 Token
   是否被拒绝。日志里不会出现 Token 明文。

安全说明：
* 所有订阅地址都必须带 Token；没有 Token 或 Token 错误一律返回 404。
* 订阅服务不返回 CORS 通配符，不允许 POST/OPTIONS，端口只对本地子网放行。
* 点「🔄 重新生成 Token」后，手机上保存的旧地址立即失效，需要重新添加订阅。


五、常见问题
------------
1) 手机提示无法连接 / 一直转圈
   - 先点「🧪 局域网自检」看哪一项是 ❌。
   - “服务监听”❌：检查服务是否被勾选、端口是否被别的程序占用（自检会显示实际端口）。
   - “局域网 IP”❌：电脑没连 Wi-Fi，或只检测到 TUN 虚拟网卡。
   - “防火墙规则”❌：点「一键放行防火墙端口」并允许 UAC；自检会显示当前网络类别
     （公用/专用）与规则的差异。
   - 全部 ✅ 但手机仍不行：多半是路由器开了“AP 隔离/访客网络”，或手机连的是 5G 访客
     热点；换到主 SSID 再试。
2) 浏览器能打开但 Clash 导入失败
   - Clash for iOS 请用 ios.yaml；FlClash 手机端用 flclash.yaml；Happ 用 tv_happ.txt
     或 happ.json，不要混用。
   - 地址粘贴时不要漏掉 /s/ 后面的 Token，也不要在末尾加空格。
3) 改了 Token 后旧链接失效
   - 正常行为。用「复制订阅链接」重新复制，在手机端删除旧订阅后重新添加。
4) 提示“禁止写入：目标配置不安全”
   - 说明预检查发现目标文件不合适：最常见是「工作配置」和「机场订阅」指向了同一个
     文件，或选了机场订阅当工作配置。请把工作配置改成 FlClash 实际在用的 profile。
5) 测速提示找不到 cfst.exe
   - v1.3 包内已带 bin\cfst.exe；若你移动了 EXE，请把 bin\ 一起移动。
6) 想回滚
   - 设置：%APPDATA%\CF-FlClash-Optimizer\backups\migration-<时间>\config.json 是迁移前
     的原配置；每次「应用拓扑」也会在 backups\ 里生成 profile_backup_*.yaml。
   - 程序：直接使用旧的 release_v1.2\CF-FlClash-Optimizer-v1.2.exe（旧目录未被改动）。


六、校验与卸载
--------------
* 校验：certutil -hashfile CF-FlClash-Optimizer-v1.3.exe SHA256
        与 SHA256SUMS.txt 对照。
* 卸载：删除本程序文件夹；如需彻底清理，再删除 %APPDATA%\CF-FlClash-Optimizer\
  （会同时删除备份与导出，请先自行导出需要的配置）。


七、已知限制
------------
* 手机真机测试无法由打包流程自动完成：发布前完成的是“本机真实 HTTP 请求 +
  防火墙/网络类别检查 + 令牌鉴权验证”，真实手机需你按上面第四节操作一次。
* 首次运行若被 Windows SmartScreen 拦截，点“更多信息 → 仍要运行”（程序未做代码签名）。
