# -*- coding: utf-8 -*-
"""VPS VLESS 直连节点（direct landing）拓扑回归测试。

覆盖 ``build_optimized_profile()`` 新增的直连节点及其策略组改动：

* 链式节点带 ``dialer-proxy``，直连节点不带，其余参数完全一致；
* ``🤖 AI-链式落地`` = select，成员顺序为 链式 → 直连；
* ``PROXY`` = 日常 → 流媒体 → AI链式 → VPS直连 → DIRECT；
* 重复构建幂等、同名用户节点不被覆盖、VPS 缺失/非 VLESS/参数缺失安全降级；
* Auto-Guard、CIDR 评分、CF 换 IP 流程与新增节点完全隔离；
* FlClash / iOS 导出与 8686 局域网 Token 订阅都拿到新拓扑。

全部使用模拟的机场订阅与 VPS 落地节点（TEST-NET 地址、假 UUID），不读取
本机 config.json，不涉及真实订阅链接、Token 或 VPS 凭据。Happ 明文 / Xray
JSON 走独立生成逻辑，本文件只锁定它们没有被改动。
"""

import json
import os
import shutil
import socket
import sys
import tempfile
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import yaml as pyyaml

import config_templates as ct
from auto_guard import AutoGuardian
from cidr_pool import SubnetScoreStore, subnet_of
from config_templates import (
    build_optimized_profile, dump_yaml_text, strip_for_ios,
    validate_ios_profile, validate_rule_targets,
)
from profile_manager import ProfileManager

# ── fixtures ─────────────────────────────────────────────────────────────
CF_NAMES = ["🇺🇸 洛杉矶-CF优选1", "🇺🇸 洛杉矶-CF优选2", "🇺🇸 洛杉矶-CF优选3"]
CF_IPS = ["162.159.160.217", "104.17.135.99", "104.29.125.38"]
VPS_NAME = "TEST-VPS-Reality-203.0.113.45"
VPS_IP = "203.0.113.45"
CHAIN = ct.DEFAULT_OPTIONS["ai_chain_node_name"]
DIRECT = ct.DEFAULT_OPTIONS["direct_landing_node_name"]
AI_GROUP = ct.DEFAULT_OPTIONS["ai_chain_group_name"]
FRONT = ct.DEFAULT_OPTIONS["front_group_name"]
DAILY = ct.DEFAULT_OPTIONS["daily_group_name"]
STREAM = ct.DEFAULT_OPTIONS["stream_group_name"]

VPS_BLOCK = """- name: "TEST-VPS-Reality-203.0.113.45"
  type: vless
  server: 203.0.113.45
  port: 443
  uuid: "44444444-4444-4444-4444-444444444444"
  network: tcp
  tls: true
  servername: vps.example.com
  flow: xtls-rprx-vision
  reality-opts:
    public-key: pubkey-vps-test
    short-id: "a1b2c3d4"
  client-fingerprint: chrome
  udp: true
"""

CF_BLOCKS = "".join(
    f"""- name: "{name}"
  type: vless
  server: {ip}
  port: 8443
  uuid: "55555555-5555-5555-5555-555555555555"
  network: ws
  tls: true
  servername: cf.example.com
  ws-opts: {{path: /ws, headers: {{Host: cf.example.com}}}}
""" for name, ip in zip(CF_NAMES, CF_IPS))


def profile_yaml(extra_nodes: str = "", vps_block: str = VPS_BLOCK) -> str:
    return (
        "mixed-port: 7890\n"
        "ipv6: true\n"
        "proxies:\n" + CF_BLOCKS + vps_block + extra_nodes +
        "proxy-groups:\n"
        "- name: PROXY\n"
        "  type: select\n"
        "  proxies: [DIRECT]\n"
        "dns:\n"
        "  enable: true\n"
        "rules:\n"
        "- MATCH,PROXY\n"
    )


AIRPORT_YAML = """\
proxies:
- name: "🇺🇸United States 01"
  type: vless
  server: us1.airport.example
  port: 443
  uuid: "11111111-1111-1111-1111-111111111111"
  network: tcp
  tls: true
  servername: www.apple.com
  flow: xtls-rprx-vision
  reality-opts:
    public-key: pubkey-us-1
    short-id: "abcd1234"
- name: "🇺🇸United States 02"
  type: vless
  server: us2.airport.example
  port: 443
  uuid: "22222222-2222-2222-2222-222222222222"
  network: tcp
  tls: true
  servername: www.apple.com
  flow: xtls-rprx-vision
  reality-opts:
    public-key: pubkey-us-2
    short-id: "abcd1234"
- name: "🇯🇵Japan 01"
  type: vless
  server: jp1.airport.example
  port: 443
  uuid: "22222222-2222-2222-2222-222222222222"
  network: tcp
  tls: true
  servername: www.apple.com
  flow: xtls-rprx-vision
  reality-opts:
    public-key: pubkey-jp-1
    short-id: "abcd1234"
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

PASS = 0
FAIL = 0
FAILURES = []


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ {name}" + (f"  [{detail}]" if detail else ""))
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  ❌ {name}" + (f"  [{detail}]" if detail else ""))


# ── helpers ──────────────────────────────────────────────────────────────
def write_text(path: str, text: str) -> str:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return path


def load_yaml(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return ct.new_yaml().load(f)


def conn_params(node) -> dict:
    """Connection parameters of a node; ``name`` / ``dialer-proxy`` excluded."""
    data = json.loads(json.dumps(ct.to_builtin(dict(node)), default=str))
    for key in ("name", "dialer-proxy"):
        data.pop(key, None)
    return data


def proxy_map(profile) -> dict:
    return {str(p.get("name")): p for p in profile.get("proxies") or []}


def group_map(profile) -> dict:
    return {str(g.get("name")): g for g in profile.get("proxy-groups") or []}


def names_of(profile) -> list:
    return [str(p.get("name")) for p in profile.get("proxies") or []]


def make_options(tmp: str, profile_path: str, airport_path: str, **over) -> dict:
    opts = dict(ct.DEFAULT_OPTIONS)
    opts.update({
        "cf_node_names": list(CF_NAMES),
        "cf_node_name_prefix": ct.DEFAULT_OPTIONS["cf_node_name_prefix"],
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


def workspace(tmp: str, tag: str, profile_text: str = "", airport_text: str = AIRPORT_YAML,
              **over):
    """Create an isolated mock profile + airport; return (profile_path, opts)."""
    root = os.path.join(tmp, tag)
    os.makedirs(root, exist_ok=True)
    profile_path = write_text(os.path.join(root, "profile.yaml"),
                              profile_text or profile_yaml())
    airport_path = write_text(os.path.join(root, "airport.yaml"), airport_text)
    return profile_path, make_options(root, profile_path, airport_path, **over)


def build(profile_path: str, options: dict):
    """Build from the file on disk; returns (original_data, profile, summary)."""
    data = load_yaml(profile_path)
    profile, summary = build_optimized_profile(data, options)
    return data, profile, summary


# ══════════════════════════════════════════════════════════════════
def test_topology(tmp: str):
    print("\n📋 1. 直连节点生成与策略组拓扑")
    profile_path, options = workspace(tmp, "topology")
    data, profile, summary = build(profile_path, options)
    proxies, groups = proxy_map(profile), group_map(profile)
    chain, direct = proxies.get(CHAIN), proxies.get(DIRECT)

    check("链式节点已生成", chain is not None)
    check("链式节点带 dialer-proxy", chain is not None
          and chain.get("dialer-proxy") == FRONT, str(chain.get("dialer-proxy")))
    check("直连节点已生成", direct is not None, summary.get("direct_node", ""))
    check("直连节点无 dialer-proxy", direct is not None and "dialer-proxy" not in direct)
    check("两个节点均为 VLESS",
          str((chain or {}).get("type")) == "vless" and str((direct or {}).get("type")) == "vless")
    check("除 name / dialer-proxy 外连接参数完全一致",
          chain is not None and direct is not None and conn_params(chain) == conn_params(direct))
    check("直连节点保留 mux=false / udp / ip-version",
          direct is not None and (direct.get("mux") or {}).get("enabled") is False
          and direct.get("udp") is True and direct.get("ip-version") == "ipv4")
    check("直连节点保留 tls / servername / flow / reality-opts / client-fingerprint",
          direct is not None
          and direct.get("tls") is True
          and direct.get("servername") == "vps.example.com"
          and direct.get("flow") == "xtls-rprx-vision"
          and dict(direct.get("reality-opts") or {}) == {
              "public-key": "pubkey-vps-test", "short-id": "a1b2c3d4"}
          and direct.get("client-fingerprint") == "chrome")
    check("直连节点端口/地址与原始 VPS 一致",
          direct is not None and str(direct.get("server")) == VPS_IP
          and int(direct.get("port")) == 443)
    check("原始 VPS 落地节点未被改写",
          "dialer-proxy" not in proxies[VPS_NAME]
          and str(proxies[VPS_NAME].get("name")) == VPS_NAME)
    check("AI 组为 select", groups.get(AI_GROUP, {}).get("type") == "select")
    check("AI 组成员顺序为 链式 → 直连",
          groups.get(AI_GROUP, {}).get("proxies") == [CHAIN, DIRECT],
          str(groups.get(AI_GROUP, {}).get("proxies")))
    check("PROXY 顺序 日常 → 流媒体 → AI链式 → VPS直连 → DIRECT",
          groups.get("PROXY", {}).get("proxies") == [DAILY, STREAM, AI_GROUP, DIRECT, "DIRECT"],
          str(groups.get("PROXY", {}).get("proxies")))
    expected = [DAILY, STREAM, AI_GROUP, DIRECT, "DIRECT"]
    members = [str(m) for m in groups.get("PROXY", {}).get("proxies") or []]
    check("PROXY 无重复成员", len(members) == len(dict.fromkeys(members)), str(members))
    check("PROXY 成员可解析（无悬空引用）",
          all(m in proxy_map(profile) or m in groups or m == "DIRECT" for m in expected))
    check("规则无孤儿目标", validate_rule_targets(profile) == [],
          str(validate_rule_targets(profile)[:2]))
    check("无警告", summary["warnings"] == [], "; ".join(summary["warnings"]))
    check("原始 profile 未被修改（dump 一致）",
          dump_yaml_text(data) == dump_yaml_text(load_yaml(profile_path)))


def test_idempotency(tmp: str):
    print("\n📋 2. 重复构建幂等")
    profile_path, options = workspace(tmp, "idempotent")
    _data, first, first_summary = build(profile_path, options)
    _data2, second, _s2 = build(profile_path, options)
    check("两次构建节点名序列一致", names_of(first) == names_of(second))
    check("两次构建 PROXY/AI 组成员一致",
          group_map(first)["PROXY"].get("proxies") == group_map(second)["PROXY"].get("proxies")
          and group_map(first)[AI_GROUP].get("proxies") == group_map(second)[AI_GROUP].get("proxies"))

    # Rebuild on an already-optimized tree (apply topology -> export -> export).
    third, _s3 = ct.build_optimized_profile(load_yaml_text(dump_yaml_text(first)), options)
    fourth, _s4 = ct.build_optimized_profile(load_yaml_text(dump_yaml_text(third)), options)
    for label, prof in (("二次", third), ("三次", fourth)):
        seq = names_of(prof)
        check(f"{label}构建后直连节点只有一份", seq.count(DIRECT) == 1,
              f"{seq.count(DIRECT)} 份")
        check(f"{label}构建后链式节点只有一份", seq.count(CHAIN) == 1)
        check(f"{label}构建后策略组仍正确",
              group_map(prof)["PROXY"].get("proxies") == [DAILY, STREAM, AI_GROUP, DIRECT, "DIRECT"]
              and group_map(prof)[AI_GROUP].get("proxies") == [CHAIN, DIRECT])
    check("二次/三次构建节点序列稳定", names_of(third) == names_of(fourth))


def load_yaml_text(text: str):
    import io
    return ct.new_yaml().load(io.StringIO(text))


def test_user_name_conflict(tmp: str):
    print("\n📋 3. 同名用户节点不被覆盖")
    user_node = """- name: "🇺🇸 洛杉矶-VPS-直连(AI)"
  type: ss
  server: 198.51.100.7
  port: 8388
  cipher: aes-256-gcm
  password: test-only-password
"""
    profile_path, options = workspace(tmp, "conflict", profile_yaml(extra_nodes=user_node))
    original_user = proxy_map(load_yaml(profile_path))[DIRECT]
    _data, profile, summary = build(profile_path, options)
    proxies, groups = proxy_map(profile), group_map(profile)
    check("用户同名节点被原样保留",
          conn_params(proxies[DIRECT]) == conn_params(original_user)
          and str(proxies[DIRECT].get("type")) == "ss"
          and str(proxies[DIRECT].get("server")) == "198.51.100.7")
    check("冲突时不生成直连节点", summary.get("direct_node", "") == ""
          and summary.get("direct_node_skipped") == "name-conflict")
    check("冲突写入 warning",
          any("已被占用且连接参数与当前 VPS 不一致" in w for w in summary["warnings"]),
          "; ".join(summary["warnings"]))
    check("冲突时 AI 组只含链式节点", groups.get(AI_GROUP, {}).get("proxies") == [CHAIN])
    check("冲突时 PROXY 保持原结构",
          groups.get("PROXY", {}).get("proxies") == [DAILY, STREAM, AI_GROUP, "DIRECT"],
          str(groups.get("PROXY", {}).get("proxies")))
    check("冲突时规则无悬空目标", validate_rule_targets(profile) == [])


def test_airport_name_conflict(tmp: str):
    print("\n📋 4. 机场同名节点不被覆盖")
    airport = AIRPORT_YAML.replace(
        "proxies:\n",
        "proxies:\n"
        "- name: \"🇺🇸 洛杉矶-VPS-直连(AI)\"\n"
        "  type: vless\n"
        "  server: 198.51.100.8\n"
        "  port: 443\n"
        "  uuid: \"66666666-6666-6666-6666-666666666666\"\n"
        "  network: tcp\n"
        "  tls: true\n", 1)
    profile_path, options = workspace(tmp, "airport-conflict", airport_text=airport)
    _data, profile, summary = build(profile_path, options)
    node = proxy_map(profile)[DIRECT]
    check("机场同名节点未被改写",
          str(node.get("server")) == "198.51.100.8"
          and str(node.get("uuid")) == "66666666-6666-6666-6666-666666666666")
    check("机场同名冲突时不生成直连节点", summary.get("direct_node", "") == "")
    check("机场同名冲突写入 warning",
          any("已被占用且连接参数与当前 VPS 不一致" in w for w in summary["warnings"]))
    check("机场同名冲突时 AI 组/ PROXY 无直连引用",
          group_map(profile)[AI_GROUP].get("proxies") == [CHAIN]
          and DIRECT not in [str(m) for m in group_map(profile)["PROXY"].get("proxies") or []])


def test_missing_vps(tmp: str):
    print("\n📋 5. VPS 落地节点缺失 → 安全降级")
    profile_path, options = workspace(tmp, "no-vps", profile_yaml(vps_block=""),
                                      chain_landing_node_name="")
    _data, profile, summary = build(profile_path, options)
    proxies, groups = proxy_map(profile), group_map(profile)
    check("未生成链式节点", summary.get("chain_node", "") == "" and CHAIN not in proxies)
    check("未生成直连节点", summary.get("direct_node", "") == "" and DIRECT not in proxies)
    check("未伪造 AI 组成员", AI_GROUP not in groups)
    check("PROXY 保持原有结构",
          groups.get("PROXY", {}).get("proxies") == [DAILY, STREAM, "DIRECT"],
          str(groups.get("PROXY", {}).get("proxies")))
    check("降级原因写入 warning",
          any("未找到洛杉矶 VPS 落地节点" in w for w in summary["warnings"]),
          "; ".join(summary["warnings"]))
    check("降级后规则无悬空目标", validate_rule_targets(profile) == [])
    check("降级后 iOS 结构自检通过",
          validate_ios_profile(pyyaml.safe_load(dump_yaml_text(strip_for_ios(profile))),
                               options) == [])
    check("CF 测速组/流媒体组不受影响",
          groups.get(STREAM, {}).get("proxies") == CF_NAMES)


def test_ambiguous_vps(tmp: str):
    print("\n📋 6. 名称兜底命中多个候选 → 不猜、安全跳过")
    ambiguous = (
        "- name: \"TEST-VPS-a-198.51.100.11\"\n"
        "  type: vless\n"
        "  server: 198.51.100.11\n"
        "  port: 443\n"
        "  uuid: \"77777777-7777-7777-7777-777777777777\"\n"
        "  network: tcp\n"
        "  tls: true\n"
        "- name: \"TEST-VPS-b-198.51.100.12\"\n"
        "  type: vless\n"
        "  server: 198.51.100.12\n"
        "  port: 443\n"
        "  uuid: \"88888888-8888-8888-8888-888888888888\"\n"
        "  network: tcp\n"
        "  tls: true\n"
    )
    profile_path, options = workspace(tmp, "ambiguous", profile_yaml(vps_block=ambiguous),
                                      chain_landing_node_name="")
    _data, profile, summary = build(profile_path, options)
    check("多候选时不生成链式/直连节点",
          summary.get("chain_node", "") == "" and summary.get("direct_node", "") == "")
    check("多候选写入歧义 warning",
          any("无法确定唯一落地节点" in w for w in summary["warnings"]),
          "; ".join(summary["warnings"]))
    check("多候选时 PROXY 无悬空项",
          group_map(profile)["PROXY"].get("proxies") == [DAILY, STREAM, "DIRECT"])
    check("候选节点本身未被修改",
          "dialer-proxy" not in proxy_map(profile)["TEST-VPS-a-198.51.100.11"])


def test_non_vless_vps(tmp: str):
    print("\n📋 7. VPS 节点非 VLESS → 不生成错误的 VLESS 直连节点")
    ss_vps = """- name: "TEST-VPS-Reality-203.0.113.45"
  type: ss
  server: 203.0.113.45
  port: 8388
  cipher: aes-256-gcm
  password: test-only-password
"""
    profile_path, options = workspace(tmp, "non-vless", profile_yaml(vps_block=ss_vps))
    _data, profile, summary = build(profile_path, options)
    proxies, groups = proxy_map(profile), group_map(profile)
    check("直连节点未生成", summary.get("direct_node", "") == "" and DIRECT not in proxies)
    check("非 VLESS 原因写入 warning",
          any("不是有效 VLESS" in w for w in summary["warnings"]),
          "; ".join(summary["warnings"]))
    check("原有链式功能不受影响（仍生成链式节点）", CHAIN in proxies
          and proxies[CHAIN].get("dialer-proxy") == FRONT)
    check("AI 组只含链式节点", groups.get(AI_GROUP, {}).get("proxies") == [CHAIN])
    check("PROXY 保持 4 项", groups.get("PROXY", {}).get("proxies")
          == [DAILY, STREAM, AI_GROUP, "DIRECT"])
    check("非 VLESS 落地节点未被改写",
          proxies[VPS_NAME].get("type") == "ss" and "dialer-proxy" not in proxies[VPS_NAME])


def test_missing_fields(tmp: str):
    print("\n📋 8. VLESS 节点缺少必要连接参数 → 安全跳过")
    no_uuid = VPS_BLOCK.replace(
        '  uuid: "44444444-4444-4444-4444-444444444444"\n', "")
    profile_path, options = workspace(tmp, "no-uuid", profile_yaml(vps_block=no_uuid))
    _data, profile, summary = build(profile_path, options)
    check("缺 uuid 时不生成直连节点", summary.get("direct_node", "") == "")
    check("缺字段原因写入 warning",
          any("uuid" in w for w in summary["warnings"]), "; ".join(summary["warnings"]))
    check("缺字段时规则无悬空目标", validate_rule_targets(profile) == [])


def test_stale_identity_change(tmp: str):
    print("\n📋 9. 落地节点连接身份变化 → 不覆盖旧节点并告警")
    profile_path, options = workspace(tmp, "stale")
    _data, first, _s = build(profile_path, options)
    check("首次构建生成了直连节点", DIRECT in proxy_map(first))
    data2 = load_yaml_text(dump_yaml_text(first))
    landing2 = next(p for p in data2["proxies"] if str(p.get("name")) == VPS_NAME)
    landing2["server"] = "203.0.113.99"
    profile2, summary2 = build_optimized_profile(data2, options)
    proxies2 = proxy_map(profile2)
    check("身份变化时保留旧直连节点（不被静默覆盖）",
          str(proxies2[DIRECT].get("server")) == VPS_IP
          and summary2.get("direct_node", "") == ""
          and summary2.get("direct_node_skipped") == "name-conflict",
          str(proxies2[DIRECT].get("server")))
    check("旧直连节点只有一份",
          names_of(profile2).count(DIRECT) == 1)
    check("身份变化后策略组无悬空引用",
          group_map(profile2)[AI_GROUP].get("proxies") == [CHAIN]
          and group_map(profile2)["PROXY"].get("proxies")
          == [DAILY, STREAM, AI_GROUP, "DIRECT"]
          and validate_rule_targets(profile2) == [])


def test_nonidentity_refresh(tmp: str):
    print("\n📋 10. 落地节点非身份参数变化 → 直连节点原地刷新")
    profile_path, options = workspace(tmp, "refresh")
    _data, first, _s = build(profile_path, options)
    data2 = load_yaml_text(dump_yaml_text(first))
    landing2 = next(p for p in data2["proxies"] if str(p.get("name")) == VPS_NAME)
    landing2["client-fingerprint"] = "firefox"
    profile2, summary2 = build_optimized_profile(data2, options)
    proxies2 = proxy_map(profile2)
    check("刷新后直连节点仍是唯一一份", names_of(profile2).count(DIRECT) == 1)
    check("直连节点跟随落地节点参数刷新",
          proxies2[DIRECT].get("client-fingerprint") == "firefox"
          and proxies2[CHAIN].get("client-fingerprint") == "firefox",
          str(proxies2[DIRECT].get("client-fingerprint")))
    check("刷新后无冲突告警",
          summary2.get("direct_node_skipped") is None
          and summary2.get("direct_node") == DIRECT,
          f"{summary2.get('direct_node')!r} / {summary2.get('direct_node_skipped')!r}")
    check("刷新后锚点仍一致（除 name/dialer-proxy）",
          conn_params(proxies2[CHAIN]) == conn_params(proxies2[DIRECT]))


def test_exports_and_isolated_formats(tmp: str):
    print("\n📋 11. FlClash / iOS 导出与 Happ·Xray 隔离")
    profile_path, options = workspace(tmp, "exports")
    pm = ProfileManager(profile_path, os.path.join(tmp, "exports_backups"),
                        CF_NAMES, options=options)
    pm.apply_optimized_topology()
    paths = pm.generate_all_exports(os.path.join(tmp, "exports_out"))

    flclash = pyyaml.safe_load(open(paths["flclash"], encoding="utf-8"))
    ios = pyyaml.safe_load(open(paths["ios"], encoding="utf-8"))
    for label, parsed in (("FlClash", flclash), ("iOS", ios)):
        nodes = {str(p.get("name")): p for p in parsed["proxies"]}
        groups = {str(g.get("name")): g for g in parsed["proxy-groups"]}
        check(f"{label} YAML 含直连节点且无 dialer-proxy",
              DIRECT in nodes and "dialer-proxy" not in nodes[DIRECT])
        check(f"{label} YAML 含链式节点 dialer-proxy",
              nodes[CHAIN].get("dialer-proxy") == FRONT)
        check(f"{label} YAML 中两者除 name/dialer-proxy 外一致",
              conn_params(nodes[CHAIN]) == conn_params(nodes[DIRECT]))
        check(f"{label} YAML PROXY 顺序正确",
              groups["PROXY"].get("proxies") == [DAILY, STREAM, AI_GROUP, DIRECT, "DIRECT"],
              str(groups["PROXY"].get("proxies")))
        check(f"{label} YAML AI 组顺序正确",
              groups[AI_GROUP].get("proxies") == [CHAIN, DIRECT]
              and groups[AI_GROUP].get("type") == "select")
    check("iOS 结构自检通过", validate_ios_profile(ios, options) == [],
          "; ".join(validate_ios_profile(ios, options)))

    happ_text = open(paths["happ"], encoding="utf-8").read()
    xray = json.load(open(paths["happ_xray"], encoding="utf-8"))
    check("Happ 明文订阅未加入直连节点（独立生成逻辑）", DIRECT not in happ_text)
    check("Happ 明文订阅仍保留原有链式落地条目",
          VPS_IP in happ_text and happ_text.count("vless://") >= 3)
    check("Xray JSON 未加入直连出站",
          "ai-chain" in {o.get("tag") for o in xray.get("outbounds", [])}
          and all(DIRECT not in json.dumps(o, ensure_ascii=False)
                  for o in xray.get("outbounds", [])))
    check("Xray AI 路由仍指向链式出站",
          any(r.get("outboundTag") == "ai-chain"
              for r in xray.get("routing", {}).get("rules", [])))


def test_guard_and_cidr_isolation(tmp: str):
    print("\n📋 12. Auto-Guard / CIDR / CF 换 IP 与新增节点隔离")
    profile_path, options = workspace(tmp, "guard")
    pm = ProfileManager(profile_path, os.path.join(tmp, "guard_backups"),
                        CF_NAMES, options=options)
    pm.apply_optimized_topology()
    after = pm.load()
    nodes = {str(p.get("name")): p for p in after["proxies"]}
    check("直连节点已写入 profile", DIRECT in nodes and CHAIN in nodes)

    info = pm.get_node_full_info()
    check("get_node_full_info 仍只返回 3 个 CF 优选节点",
          [n["name"] for n in info] == CF_NAMES,
          str([n["name"] for n in info]))
    check("CF 节点 IP 只有 3 个 CF 地址",
          [n["server"] for n in info] == [str(nodes[n]["server"]) for n in CF_NAMES]
          and VPS_IP not in [n["server"] for n in info],
          str([n["server"] for n in info]))
    check("Auto-Guard 候选不含 VPS 直连/链式节点",
          DIRECT not in [n["name"] for n in info] and CHAIN not in [n["name"] for n in info])

    store = SubnetScoreStore(os.path.join(tmp, "guard_scores.json"))
    rows = [{"name": n["name"], "ip": n["server"], "speed": 9.0,
             "proxy_delay": 120, "cf_latency": 100, "loss": 0.0} for n in info]
    guard = AutoGuardian(
        profile_factory=lambda: pm, clash_api=None, cfst_exe="",
        bin_dir=os.path.join(tmp, "guard_bin"), exports_dir=os.path.join(tmp, "guard_exports"),
        config=dict(options, auto_guard_max_loss=5.0, cfst_sl=5.0, cfst_tl=400),
        store=store,
        health_runner=lambda node_info, log, is_stopped: rows,
        scan_runner=lambda ip_file, log, is_stopped: [])
    summary = guard.cycle()
    check("健康巡检判定无需换血", summary.get("status") == "healthy", str(summary.get("status")))
    scored = {row["subnet"] for row in store.all_scores()}
    expected = {subnet_of(n["server"]) for n in info}
    check("CIDR 评分只记录 3 个 CF 节点所在子网", scored == expected,
          f"{sorted(scored)} vs {sorted(expected)}")
    check("CIDR 评分未记录 VPS 直连节点子网",
          subnet_of(VPS_IP) not in scored, str(subnet_of(VPS_IP)))

    before = {str(p.get("name")): str(p.get("server")) for p in pm.load()["proxies"]}
    pm.update_node_ips_by_index(["104.20.1.1", "104.21.2.2", "104.22.3.3"])
    after = {str(p.get("name")): str(p.get("server")) for p in pm.load()["proxies"]}
    check("换 IP 只改写 3 个 CF 节点",
          after[CF_NAMES[0]] == "104.20.1.1" and after[CF_NAMES[2]] == "104.22.3.3")
    check("换 IP 不改动 VPS 直连/链式节点",
          after[DIRECT] == before[DIRECT] and after[CHAIN] == before[CHAIN]
          and after[DIRECT] == VPS_IP, f"{before[DIRECT]} -> {after[DIRECT]}")
    check("换 IP 后直连节点仍无 dialer-proxy",
          "dialer-proxy" not in {str(p.get("name")): p
                                 for p in pm.load()["proxies"]}[DIRECT])


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_lan_token_subscription(tmp: str):
    print("\n📋 13. 8686 局域网 Token 订阅（真实鉴权路径）")
    import requests
    from lan_server import LANServerWorker, generate_token

    profile_path, options = workspace(tmp, "lan")
    exports = os.path.join(tmp, "lan_exports")
    os.makedirs(exports, exist_ok=True)
    token = generate_token()

    def factory():
        return ProfileManager(profile_path, os.path.join(tmp, "lan_backups"),
                              CF_NAMES, options=options)

    worker = LANServerWorker(
        exports, free_port(), profile_mgr=None, profile_factory=factory,
        profile_path=profile_path, host="127.0.0.1", port_fallback=3,
        ensure_firewall=False, token_provider=lambda: token)
    worker.start()
    deadline = time.time() + 20
    while time.time() < deadline and not worker.actual_port:
        time.sleep(0.1)
    base = f"http://127.0.0.1:{worker.actual_port}/s/{token}"
    root = f"http://127.0.0.1:{worker.actual_port}"
    try:
        check("Token 认证服务已启动", bool(worker.actual_port), str(worker.actual_port))
        unauth = requests.get(f"{root}/flclash.yaml", timeout=15)
        check("无 Token 仍返回 404", unauth.status_code == 404
              and "proxies:" not in unauth.text)
        wrong = generate_token()
        while wrong == token:
            wrong = generate_token()
        bad = requests.get(f"{root}/s/{wrong}/flclash.yaml", timeout=15)
        check("错误 Token 仍返回 404", bad.status_code == 404 and "proxies:" not in bad.text)

        flclash_resp = requests.get(f"{base}/flclash.yaml", timeout=30)
        ios_resp = requests.get(f"{base}/ios.yaml", timeout=30)
        check("FlClash 订阅返回 200", flclash_resp.status_code == 200,
              str(flclash_resp.status_code))
        check("iOS 订阅返回 200", ios_resp.status_code == 200, str(ios_resp.status_code))
        for label, resp in (("FlClash", flclash_resp), ("iOS", ios_resp)):
            parsed = pyyaml.safe_load(resp.text)
            nodes = {str(p.get("name")): p for p in parsed["proxies"]}
            groups = {str(g.get("name")): g for g in parsed["proxy-groups"]}
            check(f"局域网 {label} 订阅可解析且含直连节点",
                  DIRECT in nodes and "dialer-proxy" not in nodes[DIRECT])
            check(f"局域网 {label} 订阅策略组已更新",
                  groups["PROXY"].get("proxies")
                  == [DAILY, STREAM, AI_GROUP, DIRECT, "DIRECT"]
                  and groups[AI_GROUP].get("proxies") == [CHAIN, DIRECT])
        check("响应不回显 Token", token not in flclash_resp.text)
        check("响应不带 CORS 通配符",
              "Access-Control-Allow-Origin" not in flclash_resp.headers)
    finally:
        worker.stop()


# ══════════════════════════════════════════════════════════════════
def main():
    print("=" * 66)
    print("VPS VLESS 直连节点拓扑回归（全模拟配置）")
    print("=" * 66)
    tmp = tempfile.mkdtemp(prefix="cffo-direct-")
    try:
        test_topology(tmp)
        test_idempotency(tmp)
        test_user_name_conflict(tmp)
        test_airport_name_conflict(tmp)
        test_missing_vps(tmp)
        test_ambiguous_vps(tmp)
        test_non_vless_vps(tmp)
        test_missing_fields(tmp)
        test_stale_identity_change(tmp)
        test_nonidentity_refresh(tmp)
        test_exports_and_isolated_formats(tmp)
        test_guard_and_cidr_isolation(tmp)
        test_lan_token_subscription(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 66)
    total = PASS + FAIL
    print(f"结果: {PASS}/{total} 通过, {FAIL} 失败")
    if FAIL:
        print("失败项: " + "; ".join(FAILURES))
    else:
        print("🎉 直连节点拓扑全部验证通过")
    print("=" * 66)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
