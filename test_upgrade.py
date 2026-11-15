# -*- coding: utf-8 -*-
"""Independent verification suite for the CF-FlClash-Optimizer upgrade.

Covers:
  1. /24 score persistence (read/write/decay/corrupt recovery)
  2. 70/30 Exploit-Explore sampling and cross-/24 Top-3 selection
  3. FlClash / iOS YAML topology (ipv6, fake-ip, mux, url-test, dialer-proxy)
  4. Happ subscription text + Xray JSON (UseIPv4, mux off, latest IPs)
  5. LAN HTTP subscription endpoints (200/HEAD/404, freshness)
  6. Auto-guardian decision + one-shot cycle + daemon thread lifecycle
  7. Windows autostart registry (HKCU Run: enable / verify / delete / restore)
  8. Forced working-directory switch (System32 autostart CWD fix)
  9. System tray icon + menu, closeEvent interception, forced full quit

Run:  python test_upgrade.py
"""

import base64
import copy
import json
import os
import random
import shutil
import socket
import sys
import tempfile
import threading
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import yaml as pyyaml
from ruamel.yaml import YAML

import cidr_pool as cp
import config_templates as ct
import core_test
from auto_guard import AutoGuardian, evaluate_health
from cidr_pool import SubnetScoreStore, sample_candidates, select_top_ips, subnet_of
from config_templates import (
    build_happ_subscription, build_happ_xray_json, build_optimized_profile,
    dump_yaml_text, strip_for_ios, validate_ios_profile, validate_rule_targets,
)
from path_utils import BACKUPS_DIR, load_config
from profile_manager import ProfileManager

PASS = 0
FAIL = 0
FAILURES = []


def conn_params(node):
    """Connection parameters only: ``name`` / ``dialer-proxy`` excluded."""
    data = json.loads(json.dumps(ct.to_builtin(dict(node)), default=str))
    for key in ("name", "dialer-proxy"):
        data.pop(key, None)
    return data


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ {name}" + (f"  [{detail}]" if detail else ""))
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  ❌ {name}" + (f"  [{detail}]" if detail else ""))


CF_NAMES = ["🇺🇸 洛杉矶-CF优选1", "🇺🇸 洛杉矶-CF优选2", "🇺🇸 洛杉矶-CF优选3"]
AIRPORT_YAML = """\
mixed-port: 7890
mode: rule
proxies:
- name: "🇦🇱 剩余流量：99 GB"
  type: vless
  server: info.airport.example
  port: 443
  uuid: "11111111-1111-1111-1111-111111111111"
  network: tcp
  tls: true
- name: "🇺🇸United States 01"
  type: vless
  server: us1.airport.example
  port: 443
  uuid: "22222222-2222-2222-2222-222222222222"
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
- name: "🇺🇸United States 03"
  type: vless
  server: us3.airport.example
  port: 443
  uuid: "22222222-2222-2222-2222-222222222222"
  network: tcp
  tls: true
  servername: www.apple.com
  flow: xtls-rprx-vision
  reality-opts:
    public-key: pubkey-us-3
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
proxy-groups:
- name: PROXY
  type: select
  proxies: [DIRECT]
"""


def make_workspace(tmp: str):
    """Create a temp profile + airport fixture; return (profile_path, airport_path, options)."""
    live = load_config()["flclash_profile_path"]
    profile_path = os.path.join(tmp, "profile.yaml")
    shutil.copy2(live, profile_path)
    airport_path = os.path.join(tmp, "airport.yaml")
    with open(airport_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(AIRPORT_YAML)
    options = dict(load_config())
    # Pick the chained landing node from the copied profile instead of
    # hard-coding somebody's VPS name/IP.
    landing_name = ""
    try:
        live_data = load_profile(profile_path)
        for node in live_data.get("proxies", []):
            name = str(node.get("name", ""))
            if "reality" in name.lower() or "vps" in name.lower():
                landing_name = name
                break
    except Exception:
        pass
    options.update({
        "airport_profile_path": airport_path,
        "airport_profile_name": "",          # use the fixture, not the live app metadata
        "airport_exclude_paths": [],
        "airport_managed_nodes": [],
        "cf_node_names": CF_NAMES,
        "cf_node_name_prefix": "🇺🇸 洛杉矶-CF优选",
        "chain_landing_node_name": landing_name,
    })
    return profile_path, airport_path, options


def load_profile(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return ct.new_yaml().load(f)


# ══════════════════════════════════════════════════════════════════
def test_cidr_pool(tmp: str):
    print("\n📋 1. /24 评分池、CIDR 库与动态抽样")
    old_ip_txt = os.path.join(tmp, "ip_old.txt")
    with open(old_ip_txt, "w", encoding="utf-8", newline="\n") as f:
        f.write("173.245.48.0/20\n104.16.0.0/12\n162.159.0.0/16\n104.29.0.0/16\n"
                "172.64.0.0/17\n172.64.229.0/24\n")
    rewritten = cp.ensure_cidr_file(old_ip_txt)
    content = open(old_ip_txt, encoding="utf-8").read()
    import ipaddress
    file_nets = [ipaddress.IPv4Network(line.strip()) for line in content.splitlines()
                 if line.strip() and not line.strip().startswith("#")]
    covered = lambda cidr: any(ipaddress.IPv4Network(cidr).subnet_of(n) for n in file_nets)
    check("CIDR 库自动补全", rewritten and covered("104.24.0.0/14"))
    check("保留 104.16.0.0/12 大网段", "104.16.0.0/12" in content)
    check("保留 104.29.0.0/16 / 162.159.0.0/16",
          "104.29.0.0/16" in content and "162.159.0.0/16" in content)
    check("官方大网段 172.64/13 与既有 172.64.* 子段并存",
          "172.64.0.0/13" in content and "172.64.229.0/24" in content)
    check("官方 CIDR 全量覆盖", all(covered(c) for c in cp.OFFICIAL_CF_IPV4_CIDRS),
          f"{len(cp.CF_CIDRS)} collapsed")
    check("in_library 识别 CF 段",
          cp.in_library("162.159.160.217") and cp.in_library("104.29.125.38")
          and not cp.in_library("8.8.8.8"))

    score_path = os.path.join(tmp, "scores.json")
    store = SubnetScoreStore(score_path).load()
    now = 1_800_000_000.0
    rows = [
        {"IP地址": "104.17.140.10", "下载速度(MB/s)": "12.5", "平均延迟": "150", "丢包率": "0%"},
        {"IP地址": "104.17.140.11", "下载速度(MB/s)": "10.2", "平均延迟": "160", "丢包率": "0%"},
        {"IP地址": "162.159.20.5", "下载速度(MB/s)": "8.0", "平均延迟": "180", "丢包率": "0%"},
        {"IP地址": "104.29.125.38", "下载速度(MB/s)": "1.0", "平均延迟": "900", "丢包率": "20%"},
    ]
    stats = store.record_results(rows, speed_floor=5.0, max_latency=400.0, now=now)
    store.save()
    check("评分写入样本数", stats["recorded"] == 4 and stats["subnets"] == 3, str(stats))

    reloaded = SubnetScoreStore(score_path).load()
    top = reloaded.top_subnets(5, now=now)
    check("评分持久化 & Top 排序", top and top[0]["subnet"] == "104.17.140.0/24",
          ", ".join(t["subnet"] for t in top))
    entry = reloaded.score_entry("104.17.140.0/24", now=now)
    check("评分包含连通率/速度/延迟",
          entry["connect_rate"] > 0 and entry["avg_speed"] > 5 and entry["avg_latency"] > 0,
          f"score={entry['score']:.3f}")
    check("劣质子网得分低于优质子网",
          reloaded.score_entry("104.29.125.0/24", now=now)["score"] < entry["score"])
    decayed = reloaded.score_entry("104.17.140.0/24", now=now + 30 * 86400)
    check("指数时间衰减生效", decayed["score"] < entry["score"] * 0.5,
          f"{entry['score']:.3f} -> {decayed['score']:.4f} after 30d")

    # corrupt file recovery
    corrupt_path = os.path.join(tmp, "corrupt.json")
    with open(corrupt_path, "w", encoding="utf-8") as f:
        f.write("{ this is not json ")
    recovered = SubnetScoreStore(corrupt_path).load()
    check("损坏评分文件自动重建",
          recovered.top_subnets(3) == [] and any(".corrupt-" in n for n in os.listdir(tmp)))
    check("重建后可继续写入", recovered.record_results(rows, now=now)["recorded"] == 4)

    # 100% explore when history empty
    empty = SubnetScoreStore(os.path.join(tmp, "empty.json")).load()
    explore = sample_candidates(empty, total=1500, exploit_ratio=0.7, rng=random.Random(1))
    check("空历史执行 100% 全网随机", len(explore) == 1500 and len(set(explore)) == 1500)
    check("抽样 IP 全部在官方 CIDR 库内", all(cp.in_library(ip) for ip in explore))
    check("全网抽样分散度高", len({subnet_of(ip) for ip in explore}) > 500,
          f"{len({subnet_of(ip) for ip in explore})} subnets")

    # 70/30 ratio (seed enough historical /24s so the exploit pool is not exhausted)
    more_rows = []
    for net in range(8):
        for host in range(6):
            more_rows.append({
                "IP地址": f"104.{16 + net}.{10 + host}.{host + 1}",
                "下载速度(MB/s)": str(8 + host * 0.5),
                "平均延迟": str(120 + host * 5),
                "丢包率": "0%",
            })
    reloaded.record_results(more_rows, now=now)
    reloaded.save()
    top_subnets = {t["subnet"] for t in reloaded.top_subnets(40, now=now)}
    sampled = sample_candidates(reloaded, total=2000, exploit_ratio=0.7, top_n=40,
                                rng=random.Random(7), now=now)
    exploit_hits = sum(1 for ip in sampled if subnet_of(ip) in top_subnets)
    ratio = exploit_hits / len(sampled)
    check("70/30 抽样比例", 0.64 <= ratio <= 0.76, f"history-hit={ratio:.1%}")
    check("抽样仍全部合法", len(sampled) == 2000 and len(set(sampled)) > 1950
          and all(cp.in_library(ip) for ip in sampled))

    # cross-subnet selection
    cluster = [
        {"IP地址": "104.17.140.10", "下载速度(MB/s)": "20"},
        {"IP地址": "104.17.140.11", "下载速度(MB/s)": "19"},
        {"IP地址": "104.17.140.12", "下载速度(MB/s)": "18"},
        {"IP地址": "162.159.20.5", "下载速度(MB/s)": "10"},
        {"IP地址": "104.29.125.38", "下载速度(MB/s)": "9"},
    ]
    picked = select_top_ips(cluster, count=3)
    check("Top3 跨 /24 去重", len({r["subnet"] for r in picked}) == 3,
          ", ".join(f"{r['ip']}({r['subnet']})" for r in picked))
    check("不被同网段次优挤占", picked[0]["ip"] == "104.17.140.10" and
          picked[1]["ip"] == "162.159.20.5")
    fallback = select_top_ips(cluster[:3], count=3)
    check("候选子网不足时同网段替补",
          len(fallback) == 3 and all(r["same_subnet_fallback"] for r in fallback[1:]),
          ", ".join(r["ip"] for r in fallback))
    avoided = select_top_ips(cluster, count=2, avoid_subnets=["104.17.140.0/24"])
    check("避开保留节点所在子网", all(r["subnet"] != "104.17.140.0/24" for r in avoided),
          ", ".join(r["ip"] for r in avoided))


# ══════════════════════════════════════════════════════════════════
def test_profile_resolver(tmp: str):
    print("\n📋 1.5 FlClash 显示名称 → YAML 路径解析")
    import sqlite3
    from path_utils import list_flclash_profiles, resolve_flclash_profile_by_label

    cfgdir = os.path.join(tmp, "flclash_meta")
    profiles = os.path.join(cfgdir, "profiles")
    os.makedirs(profiles, exist_ok=True)
    with open(os.path.join(cfgdir, "shared_preferences.json"), "w", encoding="utf-8") as f:
        json.dump({"flutter.config": json.dumps({"currentProfileId": 111})}, f)
    con = sqlite3.connect(os.path.join(cfgdir, "database.sqlite"))
    con.execute("create table profiles (id integer primary key, label text, url text, last_update_date integer)")
    con.execute("insert into profiles values (111,'Test Network','https://example.invalid/sub',0)")
    con.execute("insert into profiles values (222,'clash-config.yaml(1)','',0)")
    con.commit(); con.close()
    for pid, name in ((111, "🇺🇸United States 01"), (222, "TEST-Reality-203.0.113.45")):
        path = os.path.join(profiles, f"{pid}.yaml")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(f"proxies:\n- name: \"{name}\"\n  type: vless\n  server: 1.1.1.1\n  port: 443\n  uuid: test\n")

    rows = list_flclash_profiles(cfgdir)
    check("扫描出全部 FlClash profile", len(rows) == 2, str([r["label"] for r in rows]))
    resolved = resolve_flclash_profile_by_label("test NETWORK", cfgdir)
    check("大小写不敏感按名称解析", resolved.get("id") == 111
          and os.path.basename(resolved.get("path", "")) == "111.yaml")
    check("解析结果带显示名称/当前标记",
          resolved.get("label") == "Test Network" and resolved.get("current") is True)
    check("未知名返回空", resolve_flclash_profile_by_label("nope", cfgdir) == {})


def test_firewall_helpers():
    print("\n📋 1.6 防火墙规则辅助函数")
    from lan_server import (ensure_firewall_rule_detailed, firewall_rule_exists,
                            firewall_rule_name)
    check("规则名绑定端口", firewall_rule_name(8686) == "CF-FlClash-LAN-8686"
          and firewall_rule_name(9999) == "CF-FlClash-LAN-9999")
    check("规则存在性检查返回布尔", isinstance(firewall_rule_exists(59999), bool))
    info = ensure_firewall_rule_detailed(59999, allow_uac=False, dry_run=True)
    check("dry-run 不修改系统", info.get("status") == "missing"
          and not firewall_rule_exists(59999), str(info))
    info8686 = ensure_firewall_rule_detailed(8686, allow_uac=False, dry_run=True)
    check("8686 规则状态可查询", info8686.get("status") in ("exists", "missing"), str(info8686))


# ══════════════════════════════════════════════════════════════════
def test_configs(tmp: str, profile_path: str, options: dict):
    print("\n📋 2. 多端配置模板 / 链式代理 / IPv6 加固")
    pm = ProfileManager(profile_path, os.path.join(tmp, "backups"), CF_NAMES, options=options)
    data = pm.load()
    snapshot = dump_yaml_text(data)

    optimized, summary = build_optimized_profile(data, options)
    check("机场节点合并（排除广告节点）", summary["airport_nodes"] == 4,
          f"{summary['airport_nodes']} nodes")
    check("找到洛杉矶 VPS 落地节点", summary["chain_node"] != "", summary["chain_node"])
    check("未产生警告", summary["warnings"] == [], "; ".join(summary["warnings"]))

    proxies = {str(p.get("name")): p for p in optimized["proxies"]}
    groups = {str(g.get("name")): g for g in optimized["proxy-groups"]}
    chain = proxies.get(ct.DEFAULT_OPTIONS["ai_chain_node_name"])
    check("链式节点 dialer-proxy 指向机场前置组",
          chain is not None and chain.get("dialer-proxy") == ct.DEFAULT_OPTIONS["front_group_name"],
          str(chain.get("dialer-proxy") if chain else None))
    direct = proxies.get(ct.DEFAULT_OPTIONS["direct_landing_node_name"])
    check("直连节点已生成且无 dialer-proxy",
          direct is not None and "dialer-proxy" not in direct,
          str(direct.get("name") if direct else None))
    check("链式/直连均为 VLESS",
          str((chain or {}).get("type")) == "vless" and str((direct or {}).get("type")) == "vless")
    check("直连与链式仅差 name / dialer-proxy",
          direct is not None and chain is not None and conn_params(chain) == conn_params(direct))
    original_landing = next((p for p in data["proxies"]
                             if str(p.get("name")) == options.get("chain_landing_node_name")), None)
    check("原始 profile 未被 build_optimized_profile 修改",
          (original_landing is None or "dialer-proxy" not in original_landing)
          and dump_yaml_text(data) == snapshot)
    front = groups.get(ct.DEFAULT_OPTIONS["front_group_name"], {})
    check("机场前置优选为 url-test 且含美西节点",
          front.get("type") == "url-test"
          and all("United States" in str(n) or "🇺🇸" in str(n) for n in front.get("proxies", [])),
          ", ".join(front.get("proxies", [])))
    check("日常流量默认机场节点组",
          groups.get("PROXY", {}).get("proxies", [None])[0] == ct.DEFAULT_OPTIONS["daily_group_name"])
    stream = groups.get(ct.DEFAULT_OPTIONS["stream_group_name"], {})
    check("流媒体 url-test 参数",
          stream.get("type") == "url-test"
          and stream.get("url") == "http://www.gstatic.com/generate_204"
          and int(stream.get("interval", 0)) == 180
          and int(stream.get("tolerance", 0)) == 50,
          str({k: stream.get(k) for k in ("type", "url", "interval", "tolerance")}))
    check("流媒体组仅含 3 个 CF 节点", stream.get("proxies") == CF_NAMES)
    daily = groups.get(ct.DEFAULT_OPTIONS["daily_group_name"], {})
    auto = groups.get(ct.DEFAULT_OPTIONS["auto_airport_group_name"], {})
    check("日常组为手动 select 且首选自动优选",
          daily.get("type") == "select"
          and (daily.get("proxies") or [None])[0] == ct.DEFAULT_OPTIONS["auto_airport_group_name"],
          f"{daily.get('type')} / {(daily.get('proxies') or [])[:2]}")
    check("⚡ 机场自动优选为隐藏 url-test(300/50)",
          auto.get("type") == "url-test" and auto.get("hidden") is True
          and auto.get("url") == "http://www.gstatic.com/generate_204"
          and int(auto.get("interval", 0)) == 300
          and int(auto.get("tolerance", 0)) == 50,
          str({k: auto.get(k) for k in ("type", "hidden", "interval", "tolerance")}))
    check("机场前置优选隐藏",
          groups.get(ct.DEFAULT_OPTIONS["front_group_name"], {}).get("hidden") is True)
    check("AI 链式组为 select，成员顺序为链式 → 直连",
          groups.get(ct.DEFAULT_OPTIONS["ai_chain_group_name"], {}).get("type") == "select"
          and groups.get(ct.DEFAULT_OPTIONS["ai_chain_group_name"], {}).get("proxies") == [
              ct.DEFAULT_OPTIONS["ai_chain_node_name"],
              ct.DEFAULT_OPTIONS["direct_landing_node_name"]],
          str(groups.get(ct.DEFAULT_OPTIONS["ai_chain_group_name"], {}).get("proxies")))
    check("PROXY 顺序为 日常 → 流媒体 → AI链式 → VPS直连 → DIRECT",
          groups.get("PROXY", {}).get("proxies") == [
              ct.DEFAULT_OPTIONS["daily_group_name"],
              ct.DEFAULT_OPTIONS["stream_group_name"],
              ct.DEFAULT_OPTIONS["ai_chain_group_name"],
              ct.DEFAULT_OPTIONS["direct_landing_node_name"],
              "DIRECT",
          ],
          str(groups.get("PROXY", {}).get("proxies")))
    twice, _twice_summary = build_optimized_profile(optimized, options)
    twice_names = [str(p.get("name")) for p in twice["proxies"]]
    twice_groups = {str(g.get("name")): g for g in twice["proxy-groups"]}
    check("重复构建不重复生成节点",
          twice_names.count(ct.DEFAULT_OPTIONS["ai_chain_node_name"]) == 1
          and twice_names.count(ct.DEFAULT_OPTIONS["direct_landing_node_name"]) == 1,
          f"{twice_names.count(ct.DEFAULT_OPTIONS['direct_landing_node_name'])} direct copies")
    check("重复构建策略组成员不变",
          twice_groups["PROXY"].get("proxies") == groups["PROXY"].get("proxies")
          and twice_groups[ct.DEFAULT_OPTIONS["ai_chain_group_name"]].get("proxies")
          == groups[ct.DEFAULT_OPTIONS["ai_chain_group_name"]].get("proxies"))
    check("废节点 CF-保底 已彻底删除",
          "CF-保底" not in {str(p.get("name")) for p in optimized["proxies"]}
          and all("CF-保底" not in [str(m) for m in (g.get("proxies") or [])]
                  for g in optimized["proxy-groups"]))
    check("旧僵尸策略组已删除",
          "自动（直连优先）" not in groups and "🇺🇸 洛杉矶-CF优选" not in groups)
    check("无孤儿规则目标", validate_rule_targets(optimized) == [],
          str(validate_rule_targets(optimized)[:2]))
    pikpak = groups.get("PikPak")
    check("PikPak 成员已净化",
          pikpak is None or not ({"CF-保底", "自动（直连优先）", "🇺🇸 洛杉矶-CF优选"}
                                 & {str(m) for m in (pikpak.get("proxies") or [])}))

    ios = strip_for_ios(optimized)
    text = dump_yaml_text(ios)
    parsed = pyyaml.safe_load(text)
    check("iOS YAML 可被严格解析", isinstance(parsed, dict) and "proxies" in parsed)
    check("顶层 ipv6: false", parsed.get("ipv6") is False)
    check("dns.ipv6: false", parsed.get("dns", {}).get("ipv6") is False)
    check("DNS fake-ip 模式", parsed.get("dns", {}).get("enhanced-mode") == "fake-ip")
    check("iOS 不含 external-controller / tun",
          "external-controller" not in parsed and "tun" not in parsed)
    check("iOS 规则去除 PROCESS-NAME",
          not any("PROCESS-NAME" in str(r) for r in parsed.get("rules", [])))
    check("IPv6 阻断规则存在", "IP-CIDR6,::/0,REJECT,no-resolve" in [str(r) for r in parsed.get("rules", [])])
    check("结构自检无问题", validate_ios_profile(parsed, options) == [],
          "; ".join(validate_ios_profile(parsed, options)))

    chain_parsed = [p for p in parsed["proxies"]
                    if p.get("name") == ct.DEFAULT_OPTIONS["ai_chain_node_name"]]
    check("iOS YAML 含 dialer-proxy", chain_parsed and chain_parsed[0].get("dialer-proxy")
          == ct.DEFAULT_OPTIONS["front_group_name"])
    direct_parsed = [p for p in parsed["proxies"]
                     if p.get("name") == ct.DEFAULT_OPTIONS["direct_landing_node_name"]]
    check("iOS YAML 含 VPS 直连节点且无 dialer-proxy",
          len(direct_parsed) == 1 and "dialer-proxy" not in direct_parsed[0],
          str(len(direct_parsed)))
    ios_groups = {str(g.get("name")): g for g in parsed.get("proxy-groups") or []}
    check("iOS YAML 策略组顺序正确",
          ios_groups.get("PROXY", {}).get("proxies") == groups["PROXY"].get("proxies")
          and ios_groups.get(ct.DEFAULT_OPTIONS["ai_chain_group_name"], {}).get("proxies")
          == groups[ct.DEFAULT_OPTIONS["ai_chain_group_name"]].get("proxies"))
    cf_parsed = [p for p in parsed["proxies"] if p.get("name") in CF_NAMES]
    check("全部 CF 节点 mux 关闭",
          len(cf_parsed) == 3 and all((p.get("mux") or {}).get("enabled") is False for p in cf_parsed))
    check("CF 节点 ip-version=ipv4", all(p.get("ip-version") == "ipv4" for p in cf_parsed))

    rules = [str(r) for r in parsed["rules"]]
    check("AI 规则指向链式组",
          any(r.startswith("DOMAIN-SUFFIX,claude.ai,")
              and r.endswith(ct.DEFAULT_OPTIONS["ai_chain_group_name"]) for r in rules)
          and any(r.startswith("DOMAIN-SUFFIX,openai.com,")
                  and r.endswith(ct.DEFAULT_OPTIONS["ai_chain_group_name"]) for r in rules))
    check("流媒体规则指向 CF url-test 组",
          any(r.startswith("DOMAIN-SUFFIX,netflix.com,")
              and r.endswith(ct.DEFAULT_OPTIONS["stream_group_name"]) for r in rules)
          and any(r.startswith("DOMAIN-SUFFIX,tiktok.com,")
                  and r.endswith(ct.DEFAULT_OPTIONS["stream_group_name"]) for r in rules))
    check("国内直连规则仍保留", any(r == "GEOSITE,cn,DIRECT" for r in rules))

    # No-airport fallback must not break generation.
    fallback_options = dict(options, airport_profile_path="", airport_profile_name="")
    fb_profile, fb_summary = build_optimized_profile(data, fallback_options)
    fb_groups = {g.get("name") for g in fb_profile["proxy-groups"]}
    check("无机场时安全降级", ct.DEFAULT_OPTIONS["stream_group_name"] in fb_groups
          and fb_summary["airport_nodes"] == 0 and fb_summary["warnings"])
    check("无机场时 iOS 仍然合法",
          validate_ios_profile(pyyaml.safe_load(dump_yaml_text(strip_for_ios(fb_profile))), fallback_options) == [])

    # Commented rules must still serialise to valid YAML (ruamel comment tables).
    commented = ct.new_yaml().load("""\
mixed-port: 7890
proxies:
- name: "TEST-Reality-203.0.113.45"
  type: vless
  server: 203.0.113.45
  port: 443
  uuid: "33333333-3333-3333-3333-333333333333"
  network: tcp
  tls: true
- name: "🇺🇸 洛杉矶-CF优选1"
  type: vless
  server: 162.159.160.217
  port: 8443
  uuid: "33333333-3333-3333-3333-333333333333"
  network: ws
  tls: true
  servername: us.example.com
  ws-opts: {path: /ws, headers: {Host: us.example.com}}
- name: "🇺🇸 洛杉矶-CF优选2"
  type: vless
  server: 104.17.135.99
  port: 8443
  uuid: "33333333-3333-3333-3333-333333333333"
  network: ws
  tls: true
  servername: us.example.com
  ws-opts: {path: /ws, headers: {Host: us.example.com}}
- name: "🇺🇸 洛杉矶-CF优选3"
  type: vless
  server: 104.29.125.38
  port: 8443
  uuid: "33333333-3333-3333-3333-333333333333"
  network: ws
  tls: true
  servername: us.example.com
  ws-opts: {path: /ws, headers: {Host: us.example.com}}
proxy-groups:
- name: PROXY
  type: select
  proxies: [DIRECT]
rules:
  # ===== 规则段注释 =====
  # 第二行注释
- "DOMAIN-SUFFIX,netflix.com,🇺🇸 洛杉矶-CF优选"
- "MATCH,PROXY"
""")
    cprof, _ = build_optimized_profile(commented, dict(options, airport_profile_name=""))
    ctext = dump_yaml_text(strip_for_ios(cprof))
    try:
        cparsed = pyyaml.safe_load(ctext)
        check("带注释规则导出为合法 YAML", isinstance(cparsed, dict)
              and "rules" in cparsed and isinstance(cparsed["rules"], list))
    except Exception as exc:
        check("带注释规则导出为合法 YAML", False, str(exc)[:120])

    # Live-profile application path (the GUI button uses this).
    topo_path = os.path.join(tmp, "topo_profile.yaml")
    shutil.copy2(profile_path, topo_path)
    topo_pm = ProfileManager(topo_path, os.path.join(tmp, "topo_backups"), CF_NAMES, options=options)
    topo_pm.load()
    tsummary = topo_pm.apply_optimized_topology()
    check("应用拓扑自动备份", os.path.exists(tsummary.get("backup", "")))
    tdata = topo_pm.load()
    tgroups = {str(g.get("name")): g for g in tdata["proxy-groups"]}
    tproxies = {str(p.get("name")): p for p in tdata["proxies"]}
    check("拓扑写入 FlClash 策略组",
          all(name in tgroups for name in (
              ct.DEFAULT_OPTIONS["stream_group_name"], ct.DEFAULT_OPTIONS["front_group_name"],
              ct.DEFAULT_OPTIONS["ai_chain_group_name"], ct.DEFAULT_OPTIONS["daily_group_name"])))
    check("拓扑写入链式节点",
          tproxies.get(ct.DEFAULT_OPTIONS["ai_chain_node_name"], {}).get("dialer-proxy")
          == ct.DEFAULT_OPTIONS["front_group_name"])
    check("拓扑写入 VPS 直连节点（无 dialer-proxy）",
          ct.DEFAULT_OPTIONS["direct_landing_node_name"] in tproxies
          and "dialer-proxy" not in tproxies[ct.DEFAULT_OPTIONS["direct_landing_node_name"]])
    check("Auto-Guard 节点范围仍只含 3 个 CF 优选",
          [n["name"] for n in topo_pm.get_node_full_info()] == CF_NAMES,
          str(len(topo_pm.get_node_full_info())))
    check("拓扑加固 DNS/IPv6/mux",
          tdata.get("ipv6") is False and tdata["dns"].get("ipv6") is False
          and tdata["dns"].get("enhanced-mode") == "fake-ip"
          and all((tproxies[n].get("mux") or {}).get("enabled") is False for n in CF_NAMES))
    check("拓扑改写 AI/流媒体规则",
          any(str(r).startswith("DOMAIN-SUFFIX,openai.com,")
              and str(r).endswith(ct.DEFAULT_OPTIONS["ai_chain_group_name"])
              for r in tdata["rules"]))

    proxy_count = len(tdata["proxies"])
    group_count = len(tdata["proxy-groups"])
    topo_pm.apply_optimized_topology()
    tdata2 = topo_pm.load()
    check("重复应用拓扑幂等",
          len(tdata2["proxies"]) == proxy_count and len(tdata2["proxy-groups"]) == group_count,
          f"{proxy_count} proxies / {group_count} groups")
    topo_exports = os.path.join(tmp, "topo_exports")
    tpaths = topo_pm.generate_all_exports(topo_exports)
    try:
        for key in ("flclash", "ios"):
            parsed_export = pyyaml.safe_load(open(tpaths[key], encoding="utf-8"))
            assert isinstance(parsed_export, dict) and parsed_export.get("rules")
        check("应用拓扑后多端 YAML 合法", True)
    except Exception as exc:
        check("应用拓扑后多端 YAML 合法", False, str(exc)[:120])
    check("导出不含非法 rules 序列",
          "rules: -\n" not in open(tpaths["flclash"], encoding="utf-8").read()
          and "rules: -\n" not in open(tpaths["ios"], encoding="utf-8").read())

    direct_server_before = str(tproxies.get(
        ct.DEFAULT_OPTIONS["direct_landing_node_name"], {}).get("server"))
    topo_pm.update_node_ips_by_index(["104.20.1.1", "104.21.2.2", "104.22.3.3"])
    tdata3 = topo_pm.load()
    tproxies3 = {str(p.get("name")): p for p in tdata3["proxies"]}
    check("换 IP 后拓扑与加固保持",
          str(tproxies3[CF_NAMES[0]].get("server")) == "104.20.1.1"
          and ct.DEFAULT_OPTIONS["ai_chain_node_name"] in tproxies3
          and all((tproxies3[n].get("mux") or {}).get("enabled") is False for n in CF_NAMES))
    check("换 IP 不修改 VPS 直连/链式节点",
          str(tproxies3.get(ct.DEFAULT_OPTIONS["direct_landing_node_name"], {})
              .get("server")) == direct_server_before
          and str(tproxies3.get(ct.DEFAULT_OPTIONS["ai_chain_node_name"], {})
                  .get("server")) == direct_server_before,
          f"{direct_server_before} vs 104.20.1.1")
    return pm


# ══════════════════════════════════════════════════════════════════
def test_exports(tmp: str, pm: ProfileManager, options: dict):
    print("\n📋 3. Happ 电视端导出与最新 IP 同步")
    new_ips = ["104.17.140.11", "104.18.32.7", "162.159.20.5"]
    pm.update_node_ips_by_index(new_ips)

    exports = os.path.join(tmp, "exports")
    paths = pm.generate_all_exports(exports)
    check("generate_all_exports 输出齐全",
          all(os.path.exists(paths[k]) for k in
              ("flclash", "ios", "happ", "happ_xray", "tv", "tv_sub")),
          ", ".join(os.path.basename(p) for p in paths.values()))

    flclash_text = open(paths["flclash"], encoding="utf-8").read()
    ios_text = open(paths["ios"], encoding="utf-8").read()
    happ_text = open(paths["happ"], encoding="utf-8").read()
    xray = json.load(open(paths["happ_xray"], encoding="utf-8"))
    check("FlClash 桌面端导出含链式代理与最新 IP",
          "dialer-proxy" in flclash_text and "ipv6: false" in flclash_text
          and all(ip in flclash_text for ip in new_ips))
    check("FlClash/iOS 导出均含 VPS 直连节点",
          ct.DEFAULT_OPTIONS["direct_landing_node_name"] in flclash_text
          and ct.DEFAULT_OPTIONS["direct_landing_node_name"] in ios_text)
    check("iOS 导出含最新替换 IP", all(ip in ios_text for ip in new_ips))
    check("Happ 订阅含最新替换 IP", all(ip in happ_text for ip in new_ips))
    check("Happ 自动更新/自动连接指令",
          "#subscription-auto-update-open-enable: 1" in happ_text
          and "#subscription-autoconnect: 1" in happ_text
          and "#subscription-autoconnect-type: lowestdelay" in happ_text)
    links = [line for line in happ_text.splitlines() if line.startswith("vless://")]
    check("Happ 订阅链接数量 >= 3", len(links) >= 3, f"{len(links)} links")
    check("Happ 链接显式关闭 mux", all("mux=0" in link for link in links))
    check("Happ 链接使用 xudp/packetEncoding", all("packetEncoding=xudp" in link for link in links))
    check("Happ 链接指向最新 IP", sum(1 for link in links if any(ip in link for ip in new_ips)) >= 3)

    check("Xray DNS queryStrategy=UseIPv4", xray.get("dns", {}).get("queryStrategy") == "UseIPv4")
    vless_outs = [o for o in xray.get("outbounds", []) if o.get("protocol") == "vless"]
    check("Xray 所有 VLESS 出站 mux 关闭",
          vless_outs and all((o.get("mux") or {}).get("enabled") is False for o in vless_outs),
          f"{len(vless_outs)} vless outbounds")
    tags = {o["tag"]: o for o in xray.get("outbounds", [])}
    addrs = [o.get("settings", {}).get("vnext", [{}])[0].get("address")
             for tag, o in tags.items() if tag.startswith("cf-")]
    check("Xray CF 出站使用最新 IP", all(ip in addrs for ip in new_ips), str(addrs))
    chain_out = tags.get("ai-chain")
    check("Xray 链式落地 proxySettings",
          chain_out is not None and chain_out.get("proxySettings", {}).get("tag") == "airport-front")
    check("Xray AI 路由指向链式出站",
          any(r.get("outboundTag") == "ai-chain" for r in xray.get("routing", {}).get("rules", [])))
    check("Xray 流媒体走 leastPing 负载均衡",
          any(r.get("balancerTag") == "cf-auto" for r in xray.get("routing", {}).get("rules", []))
          and xray["routing"].get("balancers"))

    tv_text = open(paths["tv_sub"], encoding="utf-8").read()
    decoded = base64.b64decode(tv_text).decode("utf-8")
    check("Base64 订阅可解码且含最新 IP",
          decoded.count("vless://") >= 3 and any(ip in decoded for ip in new_ips))
    return happ_text


# ══════════════════════════════════════════════════════════════════
def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_lan_server(tmp: str, profile_path: str, options: dict):
    print("\n📋 4. 局域网 HTTP 订阅服务（Token 认证）")
    import requests
    from lan_server import LANServerWorker, generate_token

    exports = os.path.join(tmp, "lan_exports")
    os.makedirs(exports, exist_ok=True)
    port = free_port()
    token = generate_token()

    def token_provider():
        return token

    def factory():
        return ProfileManager(profile_path, os.path.join(tmp, "lan_backups"),
                              CF_NAMES, options=options)

    worker = LANServerWorker(exports, port, profile_mgr=None, profile_factory=factory,
                             profile_path=profile_path, host="127.0.0.1", port_fallback=3,
                             ensure_firewall=False, token_provider=token_provider)
    worker.start()
    deadline = time.time() + 15
    while time.time() < deadline and not worker.actual_port:
        time.sleep(0.1)
    check("服务在独立线程监听", worker.actual_port == port, f"port={worker.actual_port}")

    root = f"http://127.0.0.1:{worker.actual_port}"
    base = f"{root}/s/{token}"
    try:
        check("访问 Token 为高强度 URL-safe 字符串",
              len(token) >= 43 and all(c.isalnum() or c in "-_" for c in token))

        unauth = requests.get(f"{root}/ios.yaml", timeout=10)
        check("旧的无认证订阅路径已停用",
              unauth.status_code == 404 and "proxies:" not in unauth.text)
        check("404 响应不泄露 Token", token not in unauth.text)
        wrong_token = generate_token()
        while wrong_token == token:
            wrong_token = generate_token()
        wrong = requests.get(f"{root}/s/{wrong_token}/ios.yaml", timeout=10)
        check("错误 Token 无法获取配置",
              wrong.status_code == 404 and "proxies:" not in wrong.text)
        check("根路径不再提供无认证仪表盘",
              requests.get(f"{root}/", timeout=10).status_code == 404)

        resp = requests.get(f"{base}/ios.yaml", timeout=10)
        check("GET /s/<token>/ios.yaml 返回 200", resp.status_code == 200,
              resp.headers.get("Content-Type", ""))
        check("/ios.yaml 内容为可订阅 YAML",
              "proxies:" in resp.text and "ipv6: false" in resp.text
              and ct.DEFAULT_OPTIONS["stream_group_name"] in resp.text)
        check("订阅响应不含 CORS 通配符",
              "Access-Control-Allow-Origin" not in resp.headers)
        check("订阅响应带 nosniff", resp.headers.get("X-Content-Type-Options") == "nosniff")

        resp_flclash = requests.get(f"{base}/flclash.yaml", timeout=10)
        check("GET /s/<token>/flclash.yaml 返回 200", resp_flclash.status_code == 200)
        check("/flclash.yaml 含链式代理与 url-test",
              "dialer-proxy" in resp_flclash.text
              and ct.DEFAULT_OPTIONS["stream_group_name"] in resp_flclash.text)
        check("/flclash.yaml 含 VPS 直连节点与更新后的策略组",
              resp_flclash.text.count(ct.DEFAULT_OPTIONS["direct_landing_node_name"]) >= 2
              and ct.DEFAULT_OPTIONS["ai_chain_group_name"] in resp_flclash.text)
        check("/ios.yaml 含 VPS 直连节点",
              ct.DEFAULT_OPTIONS["direct_landing_node_name"] in resp.text)

        resp_happ = requests.get(f"{base}/tv_happ.txt", timeout=10)
        check("GET /s/<token>/tv_happ.txt 返回 200", resp_happ.status_code == 200)
        check("/tv_happ.txt 含 Happ 头与 mux=0",
              "#subscription-autoconnect-type: lowestdelay" in resp_happ.text
              and "mux=0" in resp_happ.text)
        check("/tv_happ.txt 返回最新 IP",
              all(ip in resp_happ.text for ip in ["104.17.140.11", "104.18.32.7", "162.159.20.5"]))

        resp_json = requests.get(f"{base}/happ.json", timeout=10)
        check("GET /s/<token>/happ.json 返回 200", resp_json.status_code == 200)
        check("/happ.json queryStrategy=UseIPv4",
              json.loads(resp_json.text)["dns"]["queryStrategy"] == "UseIPv4")

        head = requests.head(f"{base}/ios.yaml", timeout=10)
        check("HEAD /ios.yaml 返回 200 且无 body",
              head.status_code == 200 and head.content == b"" and int(head.headers.get("Content-Length", 0)) > 0,
              f"len={head.headers.get('Content-Length')}")
        check("订阅响应头含更新间隔",
              head.headers.get("Profile-Update-Interval") == "24")

        resp_404 = requests.get(f"{base}/nope", timeout=10)
        check("Token 下未知端点返回 404", resp_404.status_code == 404)
        dash = requests.get(f"{base}/", timeout=10)
        check("Token 下仪表盘 200 且列出端点",
              dash.status_code == 200 and "tv_happ.txt" in dash.text and "ios.yaml" in dash.text)

        # Freshness: a newer profile must be picked up on the next request.
        later = time.time() + 120
        os.utime(profile_path, (later, later))
        pm = ProfileManager(profile_path, os.path.join(tmp, "lan_backups"), CF_NAMES, options=options)
        pm.update_node_ips_by_index(["104.19.10.20", "104.20.30.40", "104.21.50.60"])
        refreshed = requests.get(f"{base}/ios.yaml", timeout=10)
        check("按 profile mtime 自动刷新订阅",
              "104.19.10.20" in refreshed.text and "104.21.50.60" in refreshed.text)
    finally:
        worker.stop()
    time.sleep(0.3)
    try:
        requests.get(f"{base}/ios.yaml", timeout=2)
        down = False
    except Exception:
        down = True
    check("stop() 正常关闭监听端口", down)

    # Port fallback: occupy a port, the worker must move to the next free one.
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    busy_port = blocker.getsockname()[1]
    worker2 = LANServerWorker(exports, busy_port, profile_mgr=None, profile_factory=factory,
                              profile_path=profile_path, host="127.0.0.1", port_fallback=5,
                              ensure_firewall=False, token_provider=token_provider)
    try:
        worker2.start()
        deadline = time.time() + 15
        while time.time() < deadline and not worker2.actual_port:
            time.sleep(0.1)
        check("端口占用自动回退", busy_port < worker2.actual_port <= busy_port + 5,
              f"{busy_port} -> {worker2.actual_port}")
        check("回退后仍可响应订阅",
              requests.get(
                  f"http://127.0.0.1:{worker2.actual_port}/s/{token}/tv_happ.txt",
                  timeout=10).status_code == 200)
    finally:
        worker2.stop()
        blocker.close()


# ══════════════════════════════════════════════════════════════════
def test_auto_guard(tmp: str, profile_path: str, options: dict):
    print("\n📋 5. 后台巡检决策与自动换血")
    good = {"name": "n1", "ip": "104.17.140.11", "speed": 9.0, "proxy_delay": 120,
            "cf_latency": 100, "loss": 0.0}
    degraded1 = {"name": "n2", "ip": "104.18.32.7", "speed": 0.4, "proxy_delay": 800,
                 "cf_latency": 600, "loss": 10.0}
    degraded2 = {"name": "n3", "ip": "162.159.20.5", "speed": 0.0, "proxy_delay": -1,
                 "cf_latency": 0, "loss": 0.0}

    healthy = evaluate_health([good, good, good], 5.0, 400, 5, 3)
    check("3/3 达标时不换血", healthy["requires_replace"] is False and healthy["good_count"] == 3)
    two_good = evaluate_health([good, dict(good, ip="1.1.1.1"), degraded1], 5.0, 400, 5, 3)
    check("2/3 达标时跳过全网扫描", two_good["requires_replace"] is False
          and two_good["degraded_count"] == 1)
    one_good = evaluate_health([good, degraded1, degraded2], 5.0, 400, 5, 3)
    check("2 个劣化时触发换血", one_good["requires_replace"] is True
          and one_good["degraded_count"] == 2)
    missing = evaluate_health([good], 5.0, 400, 5, 3)
    check("结果缺失按劣化处理", missing["requires_replace"] is True and missing["degraded_count"] == 2)

    guard_profile = os.path.join(tmp, "guard_profile.yaml")
    shutil.copy2(profile_path, guard_profile)
    # Pin the three IPs so the fake health rows line up with the profile.
    ProfileManager(guard_profile, os.path.join(tmp, "guard_seed"), CF_NAMES,
                   options=options).update_node_ips_by_index(
        ["104.17.140.11", "104.18.32.7", "162.159.20.5"])
    guard_backups = os.path.join(tmp, "guard_backups")
    guard_exports = os.path.join(tmp, "guard_exports")
    scan_rows = [
        {"IP地址": "104.17.140.11", "下载速度(MB/s)": "9.0", "平均延迟": "120", "丢包率": "0%"},
        {"IP地址": "104.18.50.9", "下载速度(MB/s)": "15.0", "平均延迟": "110", "丢包率": "0%"},
        {"IP地址": "162.159.30.8", "下载速度(MB/s)": "14.0", "平均延迟": "130", "丢包率": "0%"},
        {"IP地址": "104.19.60.7", "下载速度(MB/s)": "13.0", "平均延迟": "140", "丢包率": "0%"},
    ]
    calls = {"scan": 0, "health": 0}

    def health_runner(node_info, log, is_stopped):
        calls["health"] += 1
        return [good, degraded1, degraded2]

    def scan_runner(ip_file, log, is_stopped):
        calls["scan"] += 1
        assert os.path.exists(ip_file) and open(ip_file).read().strip()
        return scan_rows

    store = SubnetScoreStore(os.path.join(tmp, "guard_scores.json"))
    guard = AutoGuardian(
        profile_factory=lambda: ProfileManager(guard_profile, guard_backups, CF_NAMES, options=options),
        clash_api=None, cfst_exe="cfst.exe", bin_dir=os.path.join(tmp, "bin"),
        exports_dir=guard_exports, config=dict(options, cfst_sl=5.0, cfst_tl=400),
        store=store, health_runner=health_runner, scan_runner=scan_runner,
    )
    os.makedirs(os.path.join(tmp, "bin"), exist_ok=True)
    summary = guard.cycle()
    check("巡检触发全网扫描", calls["scan"] == 1 and summary.get("status") == "replaced", str(summary.get("status")))
    pm = ProfileManager(guard_profile, guard_backups, CF_NAMES, options=options)
    ips = [ip for _n, ip in pm.get_current_ips()]
    check("保留健康节点并换掉 2 个劣化节点",
          ips[0] == "104.17.140.11" and ips[1] != "104.18.32.7" and ips[2] != "162.159.20.5", str(ips))
    check("换血结果跨 /24 分散", len({subnet_of(ip) for ip in ips}) >= 2, str(ips))
    check("自动生成多端导出",
          os.path.exists(os.path.join(guard_exports, "tv_happ.txt"))
          and all(ip in open(os.path.join(guard_exports, "tv_happ.txt"), encoding="utf-8").read()
                  for ip in ips))
    check("自动创建备份", any(n.startswith("profile_backup_") for n in os.listdir(guard_backups))
          if os.path.isdir(guard_backups) else False)
    check("评分池记录本轮结果", store.top_subnets(3, now=time.time()) != [])

    # second cycle: all healthy -> no scan
    def healthy_health_runner(node_info, log, is_stopped):
        current = ProfileManager(guard_profile, guard_backups, CF_NAMES, options=options)
        result = []
        for node in current.get_node_full_info():
            result.append({"name": node["name"], "ip": node["server"], "speed": 9.0,
                           "proxy_delay": 100, "cf_latency": 90, "loss": 0.0})
        return result

    guard2 = AutoGuardian(
        profile_factory=lambda: ProfileManager(guard_profile, guard_backups, CF_NAMES, options=options),
        clash_api=None, cfst_exe="cfst.exe", bin_dir=os.path.join(tmp, "bin"),
        exports_dir=guard_exports, config=dict(options, cfst_sl=5.0, cfst_tl=400),
        store=store, health_runner=healthy_health_runner, scan_runner=scan_runner,
    )
    before = calls["scan"]
    summary2 = guard2.cycle()
    check("健康时跳过全网扫描", calls["scan"] == before and summary2.get("status") == "healthy")

    # daemon thread lifecycle
    guard3 = AutoGuardian(
        profile_factory=lambda: ProfileManager(guard_profile, guard_backups, CF_NAMES, options=options),
        clash_api=None, cfst_exe="cfst.exe", bin_dir=os.path.join(tmp, "bin"),
        exports_dir=guard_exports, config=dict(options, cfst_sl=5.0, cfst_tl=400),
        store=store, health_runner=healthy_health_runner, scan_runner=scan_runner,
    )
    guard3.start(1)
    check("守护线程已启动", guard3.is_running())
    guard3._wake.set()
    time.sleep(0.4)
    guard3.stop(timeout=5)
    check("守护线程安全退出", not guard3.is_running())
    guard3.stop()  # idempotent
    check("重复 stop 不报错", True)


# ══════════════════════════════════════════════════════════════════
def test_gui_headless(tmp: str):
    print("\n📋 6. GUI 无头冒烟（离屏实例化）")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
        import main_gui
    except Exception as exc:
        check("GUI 模块导入", False, str(exc))
        return
    app = QApplication.instance() or QApplication(sys.argv)
    try:
        window = main_gui.MainWindow()
        check("MainWindow 可离屏实例化", window is not None)
        check("自动巡检控件存在",
              window.guard_chk is not None and window.guard_interval_spin.value() >= 5)

        # The LAN subscription service starts on a daemon thread; its "started"
        # signal is queued to this thread, so pump the event loop until it lands.
        deadline = time.time() + 15
        while time.time() < deadline and "http://" not in window.lan_info_lbl.text():
            app.processEvents()
            time.sleep(0.05)
        check("局域网地址标签已填充",
              "http://" in window.lan_info_lbl.text() and "/tv_happ.txt" in window.lan_info_lbl.text(),
              window.lan_info_lbl.text()[:120])
        check("跨网段排序辅助函数", main_gui.order_for_subnet_diversity(
            ["104.17.140.1", "104.17.140.2", "162.159.20.3"])[1] == "162.159.20.3")
        window._force_quit = True  # bypass the tray interception for teardown
        window.close()
        for _ in range(20):
            app.processEvents()
            time.sleep(0.02)
        check("关闭时停止后台服务",
              window._lan_server is None and window._guard is None
              and window._tray_icon is None)
    except Exception as exc:
        import traceback
        traceback.print_exc()
        check("MainWindow 可离屏实例化", False, str(exc))


# ══════════════════════════════════════════════════════════════════
# 7. Windows autostart (HKCU Run) — real registry read/write
# ══════════════════════════════════════════════════════════════════
def _read_run_value() -> str:
    import winreg
    from path_utils import AUTO_START_KEY_NAME, AUTO_START_REG_PATH
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTO_START_REG_PATH) as key:
            value, _type = winreg.QueryValueEx(key, AUTO_START_KEY_NAME)
            return str(value or "")
    except (FileNotFoundError, OSError):
        return ""


def _restore_run_value(value: str):
    """Put the registry back exactly as it was before the test (raw value)."""
    import winreg
    from path_utils import AUTO_START_KEY_NAME, AUTO_START_REG_PATH
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, AUTO_START_REG_PATH, 0,
                                winreg.KEY_SET_VALUE) as key:
            if value:
                winreg.SetValueEx(key, AUTO_START_KEY_NAME, 0, winreg.REG_SZ, value)
            else:
                try:
                    winreg.DeleteValue(key, AUTO_START_KEY_NAME)
                except FileNotFoundError:
                    pass
    except OSError as exc:
        print(f"  ! 恢复注册表失败: {exc}")


def test_autostart_registry():
    print("\n📋 7. Windows 开机自启注册表（HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run）")
    if os.name != "nt":
        check("Windows 平台注册表自启（非 Windows 跳过）", True, "skipped")
        return
    from path_utils import (_split_command, build_auto_start_command,
                            is_auto_start_enabled, set_auto_start)

    initial = _read_run_value()
    try:
        command = build_auto_start_command(minimized=True)
        check("自启命令以引号包裹绝对路径",
              command.startswith('"') and '"' in command[1:], command[:100])
        check("自启命令以 --minimized 结尾", command.endswith("--minimized"),
              command[-32:])
        tokens = _split_command(command)
        if getattr(sys, "frozen", False):
            check("打包环境自启命令指向 exe 自身",
                  os.path.normcase(os.path.abspath(tokens[0])) ==
                  os.path.normcase(os.path.abspath(sys.executable)), tokens[0])
        else:
            check("源码环境自启命令为 pythonw/python + main_gui.py",
                  len(tokens) >= 2 and tokens[0].lower().endswith(("pythonw.exe", "python.exe"))
                  and tokens[1].lower().endswith("main_gui.py"),
                  " | ".join(tokens[:2]))
        check("源码环境优先使用 pythonw.exe（无控制台窗口）",
              getattr(sys, "frozen", False) or tokens[0].lower().endswith("pythonw.exe"),
              tokens[0])

        if initial:
            check("已存在的注册表项可被读取", True, initial[:80])
        else:
            check("注册表初始无自启项 -> is_auto_start_enabled() 为 False",
                  not is_auto_start_enabled())

        ok, msg = set_auto_start(True, minimized=True)
        check("开启开机自启返回成功", ok, msg)
        check("开启后 is_auto_start_enabled() 核验为 True", is_auto_start_enabled(), msg)
        stored = _read_run_value()
        check("注册表值等于 build_auto_start_command() 输出", stored == command, stored[:100])
        check("注册表值携带 --minimized", "--minimized" in stored)

        ok, msg = set_auto_start(False)
        check("关闭开机自启返回成功", ok, msg)
        check("关闭后 is_auto_start_enabled() 为 False", not is_auto_start_enabled())
        check("关闭后注册表键值已删除", _read_run_value() == "", msg)
        ok, msg = set_auto_start(False)
        check("重复关闭仍视为成功（幂等）", ok, msg)
    finally:
        _restore_run_value(initial)
        check("测试后注册表恢复初始状态", _read_run_value() == initial,
              _read_run_value()[:80])


# ══════════════════════════════════════════════════════════════════
# 8. Working-directory fix (explorer starts us in System32)
# ══════════════════════════════════════════════════════════════════
def test_cwd_switch():
    print("\n📋 8. 启动目录强制切换（防 System32 相对路径失效）")
    from path_utils import ensure_app_cwd, get_app_dir

    original = os.getcwd()
    fake_system32 = tempfile.mkdtemp(prefix="cffo-system32-")
    try:
        os.chdir(fake_system32)
        check("已模拟 explorer 拉起时的错误工作目录",
              os.path.normcase(os.getcwd()) != os.path.normcase(get_app_dir()),
              os.getcwd())
        root = ensure_app_cwd()
        check("ensure_app_cwd() 后 CWD == 程序目录",
              os.path.normcase(os.getcwd()) == os.path.normcase(get_app_dir()),
              os.getcwd())
        check("ensure_app_cwd() 返回程序目录",
              os.path.normcase(root) == os.path.normcase(get_app_dir()))
        check("切换后 main_gui.py 可相对访问",
              os.path.exists(os.path.join(root, "main_gui.py")))
        check("切换后 config.json 可相对访问",
              os.path.exists(os.path.join(root, "config.json")))
        with open(os.path.join(root, "main_gui.py"), "r", encoding="utf-8") as f:
            source = f.read()
        check("main() 入口调用了 ensure_app_cwd()", "ensure_app_cwd()" in source)
        check("托盘/自启相关实现已落地",
              "QSystemTrayIcon" in source and "set_auto_start(" in source
              and "setQuitOnLastWindowClosed(False)" in source)
    finally:
        os.chdir(original)
        shutil.rmtree(fake_system32, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════
# 9. System tray + closeEvent interception + full quit
# ══════════════════════════════════════════════════════════════════
def test_tray_and_close(tmp: str):
    print("\n📋 9. 系统托盘 / closeEvent 拦截 / 完全退出")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtGui import QCloseEvent
        import main_gui
        from path_utils import save_config
    except Exception as exc:
        check("托盘模块导入", False, str(exc))
        return

    app = QApplication.instance() or QApplication(sys.argv)
    window = main_gui.MainWindow()
    cfg_snapshot = copy.deepcopy(window.cfg)
    # Never let the real guardian / LAN server start from the toggles here:
    # the real ones (started by __init__) are torn down in the finally block.
    window._start_guard = lambda: None
    window._stop_guard = lambda: None
    window._start_lan_server = lambda: None
    window._stop_lan_server = lambda: None
    try:
        tray = getattr(window, "_tray_icon", None)
        check("QSystemTrayIcon 已创建", tray is not None)
        check("托盘图标非空 (not icon().isNull())",
              tray is not None and not tray.icon().isNull())
        check("窗口图标非空（窗口与托盘共用）", not window.windowIcon().isNull())

        actions = [a for a in window._tray_menu.actions() if a.text().strip()]
        labels = [a.text() for a in actions]
        joined = " | ".join(labels)
        for needed in ("🖥️ 显示主界面", "⚡ 立即执行一次巡检",
                       "🔄 开启后台自动巡检", "🌐 开启局域网订阅服务",
                       "❌ 完全退出程序"):
            check(f"托盘菜单包含「{needed}」", needed in labels, joined)
        check("托盘菜单含分隔线",
              any(a.isSeparator() for a in window._tray_menu.actions()))
        check("「开启后台自动巡检」为 Checkable",
              window._tray_guard_action.isCheckable())
        check("「开启局域网订阅服务」为 Checkable",
              window._tray_lan_action.isCheckable())

        # --- bidirectional sync (start/stop stubbed above) ---
        window.guard_chk.setChecked(True)
        check("主界面勾选巡检 -> 托盘菜单同步勾选",
              window._tray_guard_action.isChecked())
        window._tray_guard_action.trigger()
        check("托盘菜单取消巡检 -> 主界面同步取消",
              not window.guard_chk.isChecked())
        lan_before = window.lan_chk.isChecked()
        window.lan_chk.setChecked(not lan_before)
        check("主界面切换局域网 -> 托盘菜单同步",
              window._tray_lan_action.isChecked() == (not lan_before))
        window._tray_lan_action.trigger()
        check("托盘菜单切换局域网 -> 主界面同步",
              window.lan_chk.isChecked() == lan_before)

        # --- close-to-tray interception ---
        check("「关闭窗口时最小化到系统托盘」默认勾选",
              window.close_to_tray_chk.isChecked())
        window.show()
        event = QCloseEvent()
        window.closeEvent(event)
        check("close_to_tray=True 时拦截关闭 (event.ignore)",
              not event.isAccepted())
        check("close_to_tray=True 时窗口隐藏到托盘", window.isHidden())
        check("首次隐藏弹出托盘气泡提示（仅一次）", window._tray_hint_shown is True)
        hidden_once = window._tray_hint_shown
        window.closeEvent(QCloseEvent())
        check("再次隐藏不重复弹气泡", window._tray_hint_shown is hidden_once)

        # --- true quit path (tray "完全退出程序") ---
        window.show()
        window._force_quit = True
        quit_event = QCloseEvent()
        window.closeEvent(quit_event)
        check("_force_quit=True 时接受关闭", quit_event.isAccepted())
        check("_force_quit: auto_guard 守护线程已停止", window._guard is None)
        check("_force_quit: lan_server 已停止", window._lan_server is None)
        check("_force_quit: 托盘图标已清理", window._tray_icon is None)

        # --- --minimized parsing ---
        check("--minimized 参数解析为静默启动",
              main_gui.parse_start_minimized(["--minimized"], {}))
        check("配置 start_minimized=True 也静默启动",
              main_gui.parse_start_minimized([], {"start_minimized": True}))
        check("默认（无参数/无配置）正常显示窗口",
              not main_gui.parse_start_minimized([], {"start_minimized": False}))
    finally:
        for key, value in cfg_snapshot.items():
            window.cfg[key] = value
        try:
            save_config(window.cfg)
        except Exception:
            pass
        try:
            window._force_quit = True
            window._shutdown_background()
            window._cleanup_tray()
            window.close()
        except Exception:
            pass
        for _ in range(20):
            app.processEvents()
            time.sleep(0.02)


# ══════════════════════════════════════════════════════════════════
# 10. --minimized start restores the saved background services
# ══════════════════════════════════════════════════════════════════
def test_minimized_service_restore():
    print("\n📋 10. --minimized 静默启动按 config.json 恢复后台服务")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
        import main_gui
        from path_utils import load_config
    except Exception as exc:
        check("静默启动测试导入", False, str(exc))
        return

    app = QApplication.instance() or QApplication(sys.argv)
    silent_cfg = dict(copy.deepcopy(load_config()),
                      auto_guard_enabled=True, lan_server_enabled=True,
                      close_to_tray=True)
    calls = []
    originals = {}
    try:
        # Stub the two service starters so no real thread / port is used here;
        # the point is that __init__ *asks* for them when config.json says so.
        for name, stub in (
            ("_start_guard", lambda self: calls.append("guard")),
            ("_stop_guard", lambda self: None),
            ("_build_guard", lambda self: None),
            ("_start_lan_server", lambda self: calls.append("lan")),
            ("_stop_lan_server", lambda self: None),
        ):
            originals[name] = getattr(main_gui.MainWindow, name)
            setattr(main_gui.MainWindow, name, stub)
        originals["load_config"] = main_gui.load_config
        originals["save_config"] = main_gui.save_config
        main_gui.load_config = lambda: dict(silent_cfg)
        main_gui.save_config = lambda cfg: None

        window = main_gui.MainWindow()
        try:
            check("静默起点: 窗口默认不可见（驻留托盘）", not window.isVisible())
            check("auto_guard_enabled=True -> 自动拉起守护线程", "guard" in calls, str(calls))
            check("lan_server_enabled=True -> 自动拉起局域网订阅服务", "lan" in calls, str(calls))
            check("巡检复选框与配置一致", window.guard_chk.isChecked())
            check("局域网复选框与配置一致", window.lan_chk.isChecked())
            check("托盘已就绪", window._tray_icon is not None
                  and not window._tray_icon.icon().isNull())
        finally:
            window._force_quit = True
            window._shutdown_background()
            window._cleanup_tray()
            window.close()
            for _ in range(10):
                app.processEvents()
                time.sleep(0.02)
    finally:
        for name, original in originals.items():
            if name in ("load_config", "save_config"):
                setattr(main_gui, name, original)
            else:
                setattr(main_gui.MainWindow, name, original)


# ══════════════════════════════════════════════════════════════════
# 11. Single-instance lock + second-launch wake-up
# ══════════════════════════════════════════════════════════════════
def test_single_instance(tmp: str):
    print("\n📋 11. 单实例互斥与二次启动唤醒（QLocalServer/QLocalSocket）")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtNetwork import QLocalSocket
        import main_gui
    except Exception as exc:
        check("单实例测试导入", False, str(exc))
        return

    app = QApplication.instance() or QApplication(sys.argv)
    pipe_name = "CFFO-SingleInstance-test-%d" % os.getpid()
    old_name = os.environ.get("CFFO_SINGLE_INSTANCE_NAME")
    old_multi = os.environ.get("CFFO_ALLOW_MULTI_INSTANCE")
    server = None
    server2 = None
    try:
        os.environ["CFFO_SINGLE_INSTANCE_NAME"] = pipe_name
        os.environ.pop("CFFO_ALLOW_MULTI_INSTANCE", None)

        check("无实例时 connect 失败 -> 不拦截启动",
              main_gui.notify_existing_instance(200) is False)

        server = main_gui.SingleInstanceServer(pipe_name)
        check("首实例 QLocalServer 已监听", bool(server._listening), pipe_name)

        hits = {"n": 0}
        server.activated.connect(lambda: hits.__setitem__("n", hits["n"] + 1))

        sock = QLocalSocket()
        sock.connectToServer(pipe_name)
        connected = sock.waitForConnected(800)
        sock.write(b"SHOW")
        sock.flush()
        sock.waitForBytesWritten(800)
        deadline = time.time() + 2.0
        while time.time() < deadline and hits["n"] == 0:
            app.processEvents()
            time.sleep(0.02)
        sock.disconnectFromServer()
        sock.abort()
        check("二次启动发送 SHOW -> 旧实例收到唤醒信号",
              connected and hits["n"] >= 1, f"connected={connected} hits={hits['n']}")

        os.environ["CFFO_ALLOW_MULTI_INSTANCE"] = "1"
        check("CFFO_ALLOW_MULTI_INSTANCE=1 时绕过互斥（并行测试用）",
              main_gui.notify_existing_instance(300) is False)
        os.environ.pop("CFFO_ALLOW_MULTI_INSTANCE", None)

        # A crashed process can leave the pipe behind: removeServer() must let
        # the next owner listen on the same name.
        server2 = main_gui.SingleInstanceServer(pipe_name)
        check("残留管道被 removeServer 清理后仍可监听", bool(server2._listening))
        check("唤醒信号仍可送达（新 owner）", main_gui.notify_existing_instance(800) is True)
        for _ in range(10):
            app.processEvents()
            time.sleep(0.01)

        src = open(os.path.join(HERE, "main_gui.py"), encoding="utf-8").read()
        check("main() 在创建窗口前检查既有实例",
              "if notify_existing_instance():" in src
              and "SHOW sent, new process exits 0" in src)
        check("退出清理关闭 QLocalServer",
              "server.close()" in src and "_instance_server" in src)
    finally:
        if server2 is not None:
            server2.close()
        if server is not None:
            server.close()
        if old_name is None:
            os.environ.pop("CFFO_SINGLE_INSTANCE_NAME", None)
        else:
            os.environ["CFFO_SINGLE_INSTANCE_NAME"] = old_name
        if old_multi is None:
            os.environ.pop("CFFO_ALLOW_MULTI_INSTANCE", None)
        else:
            os.environ["CFFO_ALLOW_MULTI_INSTANCE"] = old_multi


# ══════════════════════════════════════════════════════════════════
# 12. Multi-client discovery (FlClash / Verge / Mihomo Party / manual YAML)
# ══════════════════════════════════════════════════════════════════
def test_client_discovery(tmp: str):
    print("\n📋 12. 多客户端发现 / 手动 YAML / 自定义 API")
    try:
        import clients
    except Exception as exc:
        check("客户端发现模块导入", False, str(exc))
        return

    root = os.path.join(tmp, "verge_profile")
    profiles = os.path.join(root, "profiles")
    os.makedirs(profiles, exist_ok=True)
    good = os.path.join(profiles, "abc123.yaml")
    with open(good, "w", encoding="utf-8", newline="\n") as f:
        f.write("mixed-port: 7897\nproxies:\n- name: n1\n  type: vless\n"
                "  server: 203.0.113.10\n  port: 443\n  uuid: test\n")
    bad = os.path.join(root, "not_a_profile.yaml")
    with open(bad, "w", encoding="utf-8", newline="\n") as f:
        f.write("hello: world\n")
    with open(os.path.join(root, "config.yaml"), "w", encoding="utf-8", newline="\n") as f:
        f.write('external-controller: 127.0.0.1:9097\nsecret: s3cr3t\n')

    check("YAML 有效性判定", clients.looks_like_profile(good)
          and not clients.looks_like_profile(bad))
    check("API 地址归一化",
          clients.normalize_api("http://127.0.0.1:9097/") == "127.0.0.1:9097"
          and clients.normalize_api(" 127.0.0.1:9090 ") == "127.0.0.1:9090")

    rows = clients.discover(root)
    mine = [r for r in rows if os.path.normcase(r["dir"]) == os.path.normcase(os.path.abspath(root))]
    check("发现客户端目录并列出可用配置",
          bool(mine) and len(mine[0]["profiles"]) == 1
          and mine[0]["profiles"][0]["path"] == os.path.abspath(good),
          str([r["dir"] for r in rows]))
    check("从客户端 config.yaml 读取 external-controller",
          mine[0]["api"] == "127.0.0.1:9097", mine[0]["api"])
    check("从客户端 config.yaml 读取 secret", mine[0]["secret"] == "s3cr3t")
    first = clients.first_profile(root)
    check("first_profile 返回第一份配置与 API",
          first and first["path"] == os.path.abspath(good)
          and first["api"] == "127.0.0.1:9097")
    check("客户端进程名映射",
          clients.restart_hint("verge") == "clash-verge.exe"
          and clients.restart_hint("mihomo") == "Mihomo Party.exe"
          and clients.restart_hint("manual") == "")


# ══════════════════════════════════════════════════════════════════
# 13. Single tab + client panel widgets
# ══════════════════════════════════════════════════════════════════
def test_gui_single_tab(tmp: str):
    print("\n📋 13. 单标签页与客户端配置面板")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    try:
        from PySide6.QtWidgets import QApplication
        import main_gui
        from path_utils import load_config
    except Exception as exc:
        check("单标签页测试导入", False, str(exc))
        return

    app = QApplication.instance() or QApplication(sys.argv)
    cfg = dict(copy.deepcopy(load_config()))
    originals = {}
    window = None
    try:
        for name, stub in (
            ("_start_guard", lambda self: None),
            ("_stop_guard", lambda self: None),
            ("_build_guard", lambda self: None),
            ("_start_lan_server", lambda self: None),
            ("_stop_lan_server", lambda self: None),
        ):
            originals[name] = getattr(main_gui.MainWindow, name)
            setattr(main_gui.MainWindow, name, stub)
        originals["load_config"] = main_gui.load_config
        originals["save_config"] = main_gui.save_config
        main_gui.load_config = lambda: dict(cfg)
        main_gui.save_config = lambda c: None

        window = main_gui.MainWindow()
        check("主界面只有 1 个标签页", window.tabs.count() == 1, f"{window.tabs.count()} tabs")
        check("国际网站/流媒体实测页已移除",
              not hasattr(window, "site_table") and not hasattr(window, "probe_log"))
        check("窗口标题不再含「国际网站」", "国际网站" not in window.windowTitle())

        check("客户端下拉框含自动/三家客户端/手动",
              window.client_combo.count() == 5,
              str([window.client_combo.itemText(i) for i in range(window.client_combo.count())]))
        check("YAML 路径 / API URL / Secret 输入框存在",
              all(hasattr(window, n) for n in
                  ("client_path_edit", "api_url_edit", "api_secret_edit")))
        check("浏览与应用按钮存在",
              hasattr(window, "browse_btn") and hasattr(window, "client_apply_btn"))
        check("空路径被拒绝", window._validate_client_settings("")[0] is False)
        check("不存在的路径被拒绝",
              window._validate_client_settings(os.path.join(tmp, "nope.yaml"))[0] is False)
        ok, resolved = window._validate_client_settings(window.profile_path)
        check("当前配置路径校验通过", ok and os.path.isfile(resolved), resolved)
        check("配置下拉框已填充",
              window.profile_combo.count() >= 1 and window.profile_combo.itemData(0) is not None)
    finally:
        if window is not None:
            window._force_quit = True
            window._shutdown_background()
            window._cleanup_tray()
            window.close()
            for _ in range(10):
                app.processEvents()
                time.sleep(0.01)
        for name, original in originals.items():
            if name in ("load_config", "save_config"):
                setattr(main_gui, name, original)
            else:
                setattr(main_gui.MainWindow, name, original)


# ══════════════════════════════════════════════════════════════════
def main():
    print("=" * 66)
    print("CF-FlClash-Optimizer 升级验证套件")
    print("=" * 66)
    tmp = tempfile.mkdtemp(prefix="cffo-test-")
    try:
        test_cidr_pool(tmp)
        test_profile_resolver(tmp)
        test_firewall_helpers()
        profile_path, airport_path, options = make_workspace(tmp)
        pm = test_configs(tmp, profile_path, options)
        test_exports(tmp, pm, options)
        test_lan_server(tmp, profile_path, options)
        test_auto_guard(tmp, profile_path, options)
        test_autostart_registry()
        test_cwd_switch()
        if os.environ.get("CFFO_GUI_TEST", "1") == "1":
            test_gui_headless(tmp)
            test_tray_and_close(tmp)
            test_minimized_service_restore()
            test_gui_single_tab(tmp)
        test_single_instance(tmp)
        test_client_discovery(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 66)
    total = PASS + FAIL
    print(f"结果: {PASS}/{total} 通过, {FAIL} 失败")
    if FAIL:
        print("失败项: " + "; ".join(FAILURES))
    else:
        print("🎉 全部验证通过")
    print("=" * 66)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
