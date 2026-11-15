# -*- coding: utf-8 -*-
"""v1.3 stability tests: landing-node identification, topology write guards,
user-data migration and the LAN self-check.

Everything runs on throw-away copies in %TEMP%; the real FlClash profiles, the
real user config and the real AppData folder are never touched.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from unittest import mock

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import config_templates as ct
import lan_server
import path_utils
from config_templates import (
    build_optimized_profile, dump_yaml_text, landing_candidates,
    resolve_landing_node, vless_node_problem,
)
from lan_server import LANServerWorker, generate_token, is_valid_token, lan_self_check
from profile_manager import ProfileManager

CF_NAMES = ["🇺🇸 洛杉矶-CF优选1", "🇺🇸 洛杉矶-CF优选2", "🇺🇸 洛杉矶-CF优选3"]
CF_IPS = ["162.159.160.217", "104.17.135.99", "104.29.125.38"]
VPS_NAME = "TEST-VPS-Reality-203.0.113.45"
CHAIN = ct.DEFAULT_OPTIONS["ai_chain_node_name"]
DIRECT = ct.DEFAULT_OPTIONS["direct_landing_node_name"]
AI_GROUP = ct.DEFAULT_OPTIONS["ai_chain_group_name"]

PASS = 0
FAIL = 0
FAILURES = []


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print("  ✅ " + name + (f"  [{detail}]" if detail else ""))
    else:
        FAIL += 1
        FAILURES.append(name)
        print("  ❌ " + name + (f"  [{detail}]" if detail else ""))


# ── fixtures ─────────────────────────────────────────────────────────────
def node(name, kind="vless", server="203.0.113.9", port=443, **extra):
    data = {"name": name, "type": kind, "server": server, "port": port}
    if kind == "vless":
        data["uuid"] = "44444444-4444-4444-4444-444444444444"
        data["network"] = "tcp"
        data["tls"] = True
        data["servername"] = "example.test"
        data["reality-opts"] = {"public-key": "pubkey-test", "short-id": "abcd1234"}
        data["flow"] = "xtls-rprx-vision"
    data.update(extra)
    return data


def cf_yaml_proxies():
    return "\n".join(
        "- name: \"%s\"\n"
        "  type: vless\n"
        "  server: %s\n"
        "  port: 8443\n"
        "  uuid: \"55555555-5555-5555-5555-555555555555\"\n"
        "  network: ws\n"
        "  tls: true\n"
        "  servername: cf.example.com\n"
        "  ws-opts: {path: /ws, headers: {Host: cf.example.com}}\n" % (n, ip)
        for n, ip in zip(CF_NAMES, CF_IPS))


def vps_yaml(name=VPS_NAME):
    return ("- name: \"%s\"\n"
            "  type: vless\n"
            "  server: 203.0.113.45\n"
            "  port: 443\n"
            "  uuid: \"44444444-4444-4444-4444-444444444444\"\n"
            "  network: tcp\n"
            "  tls: true\n"
            "  servername: vps.example.com\n"
            "  flow: xtls-rprx-vision\n"
            "  reality-opts:\n"
            "    public-key: pubkey-vps-test\n"
            "    short-id: \"a1b2c3d4\"\n"
            "  client-fingerprint: chrome\n" % name)


AIRPORT_YAML = """\
proxies:
- name: "🇺🇸United States 01"
  type: vless
  server: us1.airport.example
  port: 443
  uuid: "11111111-1111-1111-1111-111111111111"
  network: tcp
  tls: true
- name: "剩余流量：100GB"
  type: vless
  server: ad.airport.example
  port: 443
  uuid: "33333333-3333-3333-3333-333333333333"
proxy-groups:
- name: PROXY
  type: select
  proxies: [DIRECT]
"""


def profile_yaml(vps_block=None, extra_nodes="", with_cf=True):
    vps = vps_yaml() if vps_block is None else vps_block
    return ("mixed-port: 7890\n"
            "ipv6: true\n"
            "proxies:\n" + (cf_yaml_proxies() if with_cf else "") + vps + extra_nodes +
            "proxy-groups:\n"
            "- name: PROXY\n"
            "  type: select\n"
            "  proxies: [DIRECT]\n"
            "dns:\n"
            "  enable: true\n"
            "rules:\n"
            "- MATCH,PROXY\n")


def write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def sha(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def make_options(tmp, profile_path, airport_path, **over):
    opts = dict(ct.DEFAULT_OPTIONS)
    opts.update({
        "cf_node_names": list(CF_NAMES),
        "airport_profile_path": airport_path,
        "airport_profile_name": "",
        "airport_exclude_paths": [],
        "airport_managed_nodes": [],
        "chain_landing_node_name": VPS_NAME,
        "flclash_profile_path": profile_path,
        "flclash_config_dir": os.path.join(tmp, "no-client"),
    })
    opts.update(over)
    return opts


def workspace(tmp, tag, profile_text="", airport_text=AIRPORT_YAML, **over):
    root = os.path.join(tmp, tag)
    os.makedirs(root, exist_ok=True)
    profile_path = write_text(os.path.join(root, "profile.yaml"),
                              profile_text or profile_yaml())
    airport_path = write_text(os.path.join(root, "airport.yaml"), airport_text)
    return profile_path, airport_path, make_options(root, profile_path, airport_path, **over)


# ══════════════════════════════════════════════════════════════════
def test_landing_identification(tmp):
    print("\n📋 1. VPS 落地节点识别（排除自身生成节点）")
    opts = dict(ct.DEFAULT_OPTIONS, chain_landing_node_name="")

    real = node(VPS_NAME)
    chain = node(CHAIN, **{"dialer-proxy": ct.DEFAULT_OPTIONS["front_group_name"]})
    direct = node(DIRECT)

    candidates = landing_candidates([chain, real, direct], opts)
    check("候选只保留真实 VPS 节点", [c["name"] for c in candidates] == [VPS_NAME],
          str([c["name"] for c in candidates]))
    summary = {}
    picked = resolve_landing_node([chain, real, direct], opts, summary)
    check("真实 VPS 节点被唯一识别", picked is not None and picked["name"] == VPS_NAME)
    check("正常识别不产生歧义告警", summary.get("warnings") == [], str(summary.get("warnings")))

    # Only the previously generated nodes exist -> nothing to chain from.
    summary = {}
    picked = resolve_landing_node([chain, direct], opts, summary)
    check("只有生成节点时不会把它们当落地", picked is None, str(picked and picked.get("name")))
    check("跳过时不伪造链式节点", True)

    # Configured name accidentally wired to the generated chain node.
    summary = {}
    picked = resolve_landing_node([chain, real], dict(opts, chain_landing_node_name=CHAIN), summary)
    check("配置指向生成节点时改用兜底识别", picked is not None and picked["name"] == VPS_NAME)
    check("配置指向生成节点时给出告警",
          any("生成" in str(w) for w in summary.get("warnings") or []),
          str(summary.get("warnings")))

    # Two genuine candidates -> refuse to guess.
    other = node("TEST-VPS-Reality-203.0.113.77", server="203.0.113.77")
    summary = {}
    picked = resolve_landing_node([real, other], opts, summary)
    check("两个真实候选时安全跳过", picked is None)
    check("两个真实候选时报告歧义",
          any("无法确定唯一落地节点" in str(w) for w in summary.get("warnings") or []))

    # Empty / duplicate names must not become candidates.
    empty_named = node("")
    dup_a = node(VPS_NAME)
    dup_b = node(VPS_NAME, server="203.0.113.55")
    cands = landing_candidates([empty_named, dup_a, dup_b], opts)
    check("空名称节点不参与候选", all(c.get("name") for c in cands) and len(cands) == 2,
          str([c["name"] for c in cands]))
    summary = {}
    check("重复同名候选视为歧义并跳过",
          resolve_landing_node([dup_a, dup_b], opts, summary) is None
          and any("无法确定" in str(w) for w in summary.get("warnings") or []))

    # Configured empty string + no candidates at all.
    summary = {}
    check("无候选时返回 None",
          resolve_landing_node([node("🇯🇵Japan 01")], opts, summary) is None)

    # vless_node_problem on the generated chain node is irrelevant for landing,
    # but the real node must pass validation.
    check("真实落地节点 VLESS 校验通过", vless_node_problem(real) == "")


def test_topology_guards(tmp):
    print("\n📋 2. 拓扑写入防误写（preflight）")
    # A) healthy target -> allowed
    profile_path, airport_path, opts = workspace(tmp, "guard_ok")
    pm = ProfileManager(profile_path, os.path.join(tmp, "b1"), CF_NAMES, options=opts)
    pre = pm.topology_preflight()
    check("正常目标通过预检查", pre["ok"] is True, str(pre["problems"]))
    check("预检查给出目标路径", pre["target"] == os.path.abspath(profile_path))
    check("预检查报告链式/直连节点",
          pre["chain_node"] == CHAIN and pre["direct_node"] == DIRECT)
    check("预检查报告 AI/PROXY 成员",
          pre["ai_members"] == [CHAIN, DIRECT]
          and pre["proxy_members"][-1] == "DIRECT")

    # B) airport and target are the same file -> blocked, file untouched
    before = sha(profile_path)
    opts_same = dict(opts, airport_profile_path=profile_path)
    pm_same = ProfileManager(profile_path, os.path.join(tmp, "b2"), CF_NAMES, options=opts_same)
    pre_same = pm_same.topology_preflight()
    check("机场与工作配置同一文件时禁止写入", pre_same["ok"] is False
          and any("同一个文件" in p for p in pre_same["problems"]), str(pre_same["problems"]))
    check("预检查不写文件", sha(profile_path) == before)

    # C) zero CF nodes -> blocked
    no_cf, _a, opts_nocf = workspace(tmp, "guard_nocf", profile_yaml(with_cf=False))
    pm_nocf = ProfileManager(no_cf, os.path.join(tmp, "b3"), CF_NAMES, options=opts_nocf)
    pre_nocf = pm_nocf.topology_preflight()
    check("CF 优选节点为 0 时禁止写入", pre_nocf["ok"] is False
          and any("CF 优选节点" in p for p in pre_nocf["problems"]), str(pre_nocf["problems"]))

    # D) landing missing -> blocked
    no_vps, _a2, opts_novps = workspace(tmp, "guard_novps", profile_yaml(vps_block=""),
                                        chain_landing_node_name="")
    pm_novps = ProfileManager(no_vps, os.path.join(tmp, "b4"), CF_NAMES, options=opts_novps)
    pre_novps = pm_novps.topology_preflight()
    check("VPS 落地节点缺失时禁止写入", pre_novps["ok"] is False
          and any("落地节点" in p for p in pre_novps["problems"]), str(pre_novps["problems"]))

    # E) airport source empty -> chain cannot be built -> blocked
    empty_airport = write_text(os.path.join(tmp, "empty_airport.yaml"), "proxies: []\n")
    p_e, _a3, opts_noair = workspace(tmp, "guard_noair", airport_text="proxies: []\n")
    opts_noair["airport_profile_path"] = empty_airport
    pm_noair = ProfileManager(p_e, os.path.join(tmp, "b5"), CF_NAMES, options=opts_noair)
    pre_noair = pm_noair.topology_preflight()
    check("机场为空导致链式节点缺失时禁止写入", pre_noair["ok"] is False
          and any("链式" in p for p in pre_noair["problems"]), str(pre_noair["problems"]))

    # F) landing is not VLESS -> direct node missing -> blocked
    ss_vps = ("- name: \"%s\"\n  type: ss\n  server: 203.0.113.45\n  port: 8388\n"
              "  cipher: aes-256-gcm\n  password: test-only\n" % VPS_NAME)
    p_f, _a4, opts_ss = workspace(tmp, "guard_ss", profile_yaml(vps_block=ss_vps))
    pm_ss = ProfileManager(p_f, os.path.join(tmp, "b6"), CF_NAMES, options=opts_ss)
    pre_ss = pm_ss.topology_preflight()
    check("非 VLESS 落地导致直连缺失时禁止写入", pre_ss["ok"] is False
          and any("直连" in p for p in pre_ss["problems"]), str(pre_ss["problems"]))

    # G) the real apply path still writes the healthy target
    summary = pm.apply_optimized_topology()
    data = pm.load()
    names = [str(p.get("name")) for p in data["proxies"]]
    check("预检查通过后写入成功", summary.get("direct_node") == DIRECT and DIRECT in names)
    check("写入前自动备份", os.path.isfile(summary.get("backup", "")))


def test_landing_then_build_on_copy(tmp):
    print("\n📋 3. 真实拓扑组合（工作配置 + 机场来源）在副本上完整生成")
    root = os.path.join(tmp, "combo")
    os.makedirs(root, exist_ok=True)
    work = write_text(os.path.join(root, "work.yaml"),
                      profile_yaml(extra_nodes=("- name: \"%s\"\n  type: vless\n"
                                                "  server: 203.0.113.45\n  port: 443\n"
                                                "  uuid: \"44444444-4444-4444-4444-444444444444\"\n"
                                                "  dialer-proxy: \"%s\"\n"
                                                % (CHAIN, ct.DEFAULT_OPTIONS["front_group_name"])))
                      )
    airport = write_text(os.path.join(root, "airport.yaml"), AIRPORT_YAML)
    opts = make_options(root, work, airport)
    before = sha(work)
    data = ct.new_yaml().load(open(work, encoding="utf-8"))
    profile, summary = build_optimized_profile(data, opts)
    nodes = {str(p.get("name")): p for p in profile["proxies"]}
    groups = {str(g.get("name")): g for g in profile["proxy-groups"]}
    check("含上一轮链式节点也能确定唯一落地", summary["landing_node"] == VPS_NAME,
          summary["landing_node"])
    check("链式/直连均生成", CHAIN in nodes and DIRECT in nodes)
    check("AI 组顺序正确", groups[AI_GROUP]["proxies"] == [CHAIN, DIRECT])
    check("副本文件未被修改", sha(work) == before)


def test_user_data_migration(tmp):
    print("\n📋 4. 用户数据目录解耦与迁移")
    # clash_config_dir_for
    fake_profiles = os.path.join(tmp, "mig", "clash", "profiles")
    os.makedirs(fake_profiles, exist_ok=True)
    profile_file = write_text(os.path.join(fake_profiles, "1.yaml"), "proxies: []\n")
    check("profiles 子目录被规范到 clash 根目录",
          path_utils.clash_config_dir_for(profile_file)
          == os.path.abspath(os.path.join(tmp, "mig", "clash")))
    check("普通目录原样返回",
          path_utils.clash_config_dir_for(r"C:\data\config.yaml") == r"C:\data")
    check("空路径返回空字符串", path_utils.clash_config_dir_for("") == "")

    norm = path_utils._normalise_profile_dirs({
        "flclash_profile_path": profile_file,
        "flclash_config_dir": fake_profiles,
    })
    check("load_config 规范化 profiles -> clash 目录",
          norm["flclash_config_dir"] == os.path.abspath(os.path.join(tmp, "mig", "clash")))
    custom = path_utils._normalise_profile_dirs({
        "flclash_profile_path": profile_file,
        "flclash_config_dir": r"D:\custom-dir",
    })
    check("自定义目录不被强行改写", custom["flclash_config_dir"] == r"D:\custom-dir")

    # Migration: legacy release_v1.2 wins over dist; data copied; source untouched.
    base = os.path.join(tmp, "migration")
    data_root = os.path.join(base, "appdata", "CF-FlClash-Optimizer")
    legacy_release = os.path.join(base, "release_v1.2")
    legacy_dist = os.path.join(base, "dist")
    os.makedirs(legacy_release, exist_ok=True)
    os.makedirs(legacy_dist, exist_ok=True)

    token = generate_token()
    source_cfg = {
        "flclash_profile_path": profile_file,
        "flclash_config_dir": fake_profiles,
        "chain_landing_node_name": VPS_NAME,
        "airport_profile_path": "C:\\airport\\kitty.yaml",
        "airport_profile_name": "kitty network",
        "cf_node_names": list(CF_NAMES),
        "lan_auth_token": token,
        "lan_server_enabled": True,
        "auto_guard_enabled": True,
        "direct_landing_node_name": DIRECT,
    }
    write_text(os.path.join(legacy_release, "config.json"),
               json.dumps(source_cfg, ensure_ascii=False, indent=2) + "\n")
    write_text(os.path.join(legacy_dist, "config.json"), json.dumps(
        {"flclash_profile_path": "C:\\dist\\other.yaml", "lan_auth_token": "old-dist-token",
         "chain_landing_node_name": "OLD"}, ensure_ascii=False, indent=2) + "\n")
    for sub, name in (("backups", "profile_backup_1.yaml"), ("exports", "iOS_Clash_Config.yaml"),
                      ("bin", "ip.txt")):
        folder = os.path.join(legacy_release, sub)
        os.makedirs(folder, exist_ok=True)
        write_text(os.path.join(folder, name), "test\n")
    write_text(os.path.join(legacy_release, "cidr_score_history.json"), '{"subnets": {}}\n')
    legacy_before = {p: sha(p) for p in (
        os.path.join(legacy_release, "config.json"),
        os.path.join(legacy_release, "cidr_score_history.json"),
        os.path.join(legacy_release, "exports", "iOS_Clash_Config.yaml"))}

    report = path_utils.ensure_user_data(
        data_root=data_root,
        legacy_roots=[legacy_release, legacy_dist])
    new_cfg_path = os.path.join(data_root, "config.json")
    new_cfg = json.load(open(new_cfg_path, encoding="utf-8"))
    check("迁移状态为 migrated", report["status"] == "migrated", report["status"])
    check("优先采用 release_v1.2 配置（不是 dist）",
          report["config_source"].startswith(legacy_release)
          and new_cfg.get("chain_landing_node_name") == VPS_NAME,
          report["config_source"])
    check("LAN Token 与开关被保留",
          new_cfg.get("lan_auth_token") == token and new_cfg.get("lan_server_enabled") is True)
    check("机场配置与 VPS 落地名被保留",
          new_cfg.get("airport_profile_name") == "kitty network"
          and new_cfg.get("airport_profile_path") == "C:\\airport\\kitty.yaml"
          and new_cfg.get("chain_landing_node_name") == VPS_NAME)
    check("CF 节点名与 Auto-Guard 被保留",
          new_cfg.get("cf_node_names") == CF_NAMES and new_cfg.get("auto_guard_enabled") is True)
    check("迁移写入前已备份来源配置",
          bool(report["backup_dir"]) and os.path.isfile(os.path.join(report["backup_dir"],
                                                                    "config.json")))
    check("backups/exports/bin/cidr 已复制",
          os.path.isfile(os.path.join(data_root, "backups", "profile_backup_1.yaml"))
          and os.path.isfile(os.path.join(data_root, "exports", "iOS_Clash_Config.yaml"))
          and os.path.isfile(os.path.join(data_root, "bin", "ip.txt"))
          and os.path.isfile(os.path.join(data_root, "cidr_score_history.json")))
    check("旧目录文件保持原样（未被移动/删除）",
          all(os.path.isfile(p) and sha(p) == h for p, h in legacy_before.items()))

    # Existing user config must win over old/default sources.
    before_hash = sha(new_cfg_path)
    second = path_utils.ensure_user_data(
        data_root=data_root, legacy_roots=[legacy_release, legacy_dist])
    check("已有有效用户配置时不再迁移", second["status"] == "existing"
          and sha(new_cfg_path) == before_hash)

    # Fresh install: no legacy config -> nothing invented.
    fresh_root = os.path.join(base, "fresh-appdata")
    fresh = path_utils.ensure_user_data(data_root=fresh_root,
                                       legacy_roots=[os.path.join(base, "nope")])
    check("全新安装不凭空生成配置", fresh["status"] == "fresh"
          and not os.path.isfile(os.path.join(fresh_root, "config.json")))
    check("全新安装仍创建运行目录",
          all(os.path.isdir(os.path.join(fresh_root, d)) for d in ("bin", "backups", "exports")))

    # cfst lookup order: user data first, shipped package bin as fallback.
    check("cfst 搜索顺序为 数据目录 优先",
          path_utils.cfst_candidates()[0].lower().endswith("cfst.exe")
          and path_utils.CFST_EXE.lower().endswith("cfst.exe"))
    check("开发目录中的 cfst.exe 可被解析",
          os.path.isfile(path_utils.CFST_EXE) or not os.path.isdir(
              os.path.join(path_utils.APP_ROOT, "bin")))


def test_firewall_cleanup_safety(tmp):
    print("\n📋 7. 防火墙清理安全（不删正在监听的端口）")
    removed = []

    def fake_remove(port, allow_uac=False):
        removed.append(int(port))
        return True

    with mock.patch.object(lan_server, "list_own_firewall_ports",
                           return_value=[8686, 8687, 9999]), \
            mock.patch.object(lan_server, "_port_in_use",
                              side_effect=lambda p: p in (8686,)), \
            mock.patch.object(lan_server, "remove_firewall_rule", side_effect=fake_remove):
        result = lan_server.remove_stale_firewall_rules(keep_port=8687)
    check("正在监听的端口规则不会被清理", result == [9999], str(result))
    check("清理只跳过在用的端口", removed == [9999], str(removed))

    # A busy port must be detected as in-use (real bind probe).
    listener = None
    try:
        import socket as _socket
        listener = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        listener.bind(("0.0.0.0", 0))
        listener.listen(1)
        busy = listener.getsockname()[1]
        check("真实监听端口被判定为占用", lan_server._port_in_use(busy) is True)
        check("未监听端口被判定为空闲", lan_server._port_in_use(busy + 1) is False)
    finally:
        if listener is not None:
            listener.close()


def test_lan_self_check(tmp):
    print("\n📋 5. 局域网自检（真实 HTTP）")
    root = os.path.join(tmp, "selfcheck")
    os.makedirs(root, exist_ok=True)
    exports = os.path.join(root, "exports")
    os.makedirs(exports, exist_ok=True)
    profile_path, airport_path, opts = workspace(root, "sc")
    pm = ProfileManager(profile_path, os.path.join(root, "b"), CF_NAMES, options=opts)
    pm.apply_optimized_topology()
    pm.generate_all_exports(exports)

    token = generate_token()
    worker = LANServerWorker(exports, 0, profile_mgr=pm, profile_path=profile_path,
                             host="0.0.0.0", port_fallback=20, ensure_firewall=False,
                             token_provider=lambda: token)
    worker.start()
    deadline = time.time() + 25
    while time.time() < deadline and not worker.actual_port:
        time.sleep(0.1)
    port = worker.actual_port
    # v1.3.1: the self-check requests the REAL LAN IP, so the test serves on
    # 0.0.0.0 and uses the detected address (loopback machines fall back).
    detected = lan_server.detect_lan_ip_details()
    lan_ip = str(detected.get("ip") or "")
    usable_lan = bool(lan_ip) and lan_ip not in ("127.0.0.1", "0.0.0.0")
    fake_lan = {"ip": lan_ip or "127.0.0.1", "source": "test", "alias": "WLAN",
                "candidates": [{"ip": lan_ip or "127.0.0.1", "alias": "WLAN",
                                "physical": True}]}
    good_fw = {"rule": "CF-FlClash-LAN-%d" % port, "exists": True,
               "applies": True, "profile": "private,public",
               "remote": "LocalSubnet", "detail": "ok",
               "active_profiles": ["public"]}
    try:
        check("自检前服务已启动", bool(port), str(port))
        with mock.patch.object(lan_server, "detect_lan_ip_details", return_value=dict(fake_lan)):
            report = lan_self_check(port, token, exports, lan_ip=lan_ip, firewall=good_fw)
        keys = [item["key"] for item in report["items"]]
        check("自检覆盖全部检查项",
              all(k in keys for k in ("listen", "lan_ip", "token", "firewall",
                                      "get:flclash.yaml", "get:ios.yaml",
                                      "get:tv_happ.txt", "get:happ.json",
                                      "head", "bad_token")), str(keys))
        check("自检整体通过", report["ok"] is True,
              "; ".join(i["label"] for i in report["items"] if not i["ok"]))
        check("自检请求地址使用真实局域网 IP",
              report["request_host"] == (lan_ip if usable_lan else "127.0.0.1"),
              report["request_host"])
        check("两种 YAML 均可解析", report["yaml_ok"].get("flclash.yaml") is True
              and report["yaml_ok"].get("ios.yaml") is True)
        check("自检不泄露 Token", token not in json.dumps(report, ensure_ascii=False))
        check("自检返回打码后的订阅地址",
              bool(report["urls_masked"]) and all("•" in u for u in report["urls_masked"]))

        # Firewall not applicable to the current network -> reported as failure.
        bad_fw = dict(good_fw, applies=False, profile="private",
                      detail="规则仅对 private 生效")
        with mock.patch.object(lan_server, "detect_lan_ip_details", return_value=dict(fake_lan)):
            bad_report = lan_self_check(port, token, exports, firewall=bad_fw)
        fw_item = next(i for i in bad_report["items"] if i["key"] == "firewall")
        check("规则不覆盖当前网络时自检报警", fw_item["ok"] is False
              and "public" in fw_item["detail"].lower())

        # Invalid/missing token -> token item fails and endpoints are skipped.
        with mock.patch.object(lan_server, "detect_lan_ip_details", return_value=dict(fake_lan)):
            no_token = lan_self_check(port, "short", exports, firewall=good_fw)
        token_item = next(i for i in no_token["items"] if i["key"] == "token")
        check("Token 未配置时自检报警", token_item["ok"] is False)
        check("无 Token 时不会尝试下载配置",
              not any(i["key"].startswith("get:") for i in no_token["items"]))

        # A loopback-only advertised address must never be called usable.
        with mock.patch.object(lan_server, "detect_lan_ip_details",
                               return_value=dict(fake_lan, ip="127.0.0.1")):
            loop_report = lan_self_check(port, token, exports, lan_ip="127.0.0.1",
                                         firewall=good_fw)
        ip_item = next(i for i in loop_report["items"] if i["key"] == "lan_ip")
        check("127.0.0.1 不被称为可用局域网地址", ip_item["ok"] is False)
    finally:
        worker.stop()


def test_lan_ip_detection(tmp):
    print("\n📋 6. 局域网地址探测（排除虚拟网卡）")
    details = lan_server.detect_lan_ip_details()
    check("探测结果包含候选网卡列表", isinstance(details.get("candidates"), list),
          f"{len(details.get('candidates') or [])} 个")
    check("不会把 TUN/198.18 地址当作局域网 IP",
          not str(details.get("ip", "")).startswith(("198.18.", "198.19.")),
          str(details.get("ip")))
    fake_rows = [
        {"ip": "198.18.0.1", "alias": "FlClash", "description": "TUN", "status": "Up",
         "gateway": "0.0.0.0"},
        {"ip": "192.168.9.20", "alias": "WLAN", "description": "Intel Wi-Fi", "status": "Up",
         "gateway": "192.168.9.1"},
    ]
    with mock.patch.object(lan_server, "_adapter_addresses", return_value=fake_rows), \
            mock.patch.object(lan_server.socket, "socket", side_effect=OSError("no probe")):
        picked = lan_server.detect_lan_ip_details()
    check("虚拟网卡被跳过，选中物理网卡", picked["ip"] == "192.168.9.20", str(picked))


def main():
    print("=" * 74)
    print("CF-FlClash-Optimizer v1.3 稳定性测试（落地识别 / 防误写 / 迁移 / LAN 自检）")
    print("=" * 74)
    tmp = tempfile.mkdtemp(prefix="cffo-v13-")
    try:
        test_landing_identification(tmp)
        test_topology_guards(tmp)
        test_landing_then_build_on_copy(tmp)
        test_user_data_migration(tmp)
        test_firewall_cleanup_safety(tmp)
        test_lan_self_check(tmp)
        test_lan_ip_detection(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 74)
    total = PASS + FAIL
    print(f"结果: {PASS}/{total} 通过, {FAIL} 失败")
    if FAIL:
        print("失败项: " + "; ".join(FAILURES))
    else:
        print("🎉 v1.3 稳定性测试全部通过")
    print("=" * 74)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
