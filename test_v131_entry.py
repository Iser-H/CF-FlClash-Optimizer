# -*- coding: utf-8 -*-
"""v1.3.1 tests: cfst.exe resolution/execution, AI chain-entry selection and
LAN self-check over the real LAN IP.

All fixtures are throw-away copies under %TEMP%; the real profiles and the real
user config are only ever read (or not touched at all).
"""

import json
import os
import shutil
import sys
import tempfile
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import config_templates as ct
import core_test
import lan_server
import path_utils
from config_templates import (
    build_optimized_profile, chain_entry_candidates, resolve_chain_entry,
)
from lan_server import LANServerWorker, generate_token, lan_self_check
from profile_manager import ProfileManager

CF_NAMES = ["🇺🇸 洛杉矶-CF优选1", "🇺🇸 洛杉矶-CF优选2", "🇺🇸 洛杉矶-CF优选3"]
CF_IPS = ["162.159.160.217", "104.17.135.99", "104.29.125.38"]
VPS_NAME = "TEST-VPS-Reality-203.0.113.45"
CHAIN = ct.DEFAULT_OPTIONS["ai_chain_node_name"]
DIRECT = ct.DEFAULT_OPTIONS["direct_landing_node_name"]
AI_GROUP = ct.DEFAULT_OPTIONS["ai_chain_group_name"]
FRONT = ct.DEFAULT_OPTIONS["front_group_name"]
DAILY = ct.DEFAULT_OPTIONS["daily_group_name"]

PASS = 0
FAIL = 0
FAILURES = []


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ✅ " + name + (f"  [{detail}]" if detail else ""))
    else:
        FAIL += 1
        FAILURES.append(name)
        print("  ❌ " + name + (f"  [{detail}]" if detail else ""))


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


AIRPORT_YAML = """\
proxies:
- name: "🇺🇸United States 01"
  type: vless
  server: us1.airport.example
  port: 443
  uuid: "11111111-1111-1111-1111-111111111111"
  network: tcp
  tls: true
- name: "🇺🇸United States 02"
  type: vless
  server: us2.airport.example
  port: 443
  uuid: "22222222-2222-2222-2222-222222222222"
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


def profile_yaml():
    cf = "".join(
        "- name: \"%s\"\n  type: vless\n  server: %s\n  port: 8443\n"
        "  uuid: \"55555555-5555-5555-5555-555555555555\"\n  network: ws\n"
        "  tls: true\n  servername: cf.example.com\n"
        "  ws-opts: {path: /ws, headers: {Host: cf.example.com}}\n" % (n, ip)
        for n, ip in zip(CF_NAMES, CF_IPS))
    vps = ("- name: \"%s\"\n  type: vless\n  server: 203.0.113.45\n  port: 443\n"
           "  uuid: \"44444444-4444-4444-4444-444444444444\"\n  network: tcp\n"
           "  tls: true\n  servername: vps.example.com\n  flow: xtls-rprx-vision\n"
           "  reality-opts:\n    public-key: pubkey-test\n    short-id: \"a1b2c3d4\"\n"
           "  client-fingerprint: chrome\n" % VPS_NAME)
    return ("mixed-port: 7890\nipv6: true\nproxies:\n" + cf + vps +
            "proxy-groups:\n- name: PROXY\n  type: select\n  proxies: [DIRECT]\n"
            "dns:\n  enable: true\nrules:\n- MATCH,PROXY\n")


def workspace(tmp, tag, **over):
    root = os.path.join(tmp, tag)
    os.makedirs(root, exist_ok=True)
    profile = write(os.path.join(root, "profile.yaml"), profile_yaml())
    airport = write(os.path.join(root, "airport.yaml"), AIRPORT_YAML)
    opts = dict(ct.DEFAULT_OPTIONS)
    opts.update({
        "cf_node_names": list(CF_NAMES),
        "airport_profile_path": airport,
        "airport_profile_name": "",
        "airport_exclude_paths": [],
        "airport_managed_nodes": [],
        "chain_landing_node_name": VPS_NAME,
        "flclash_profile_path": profile,
        "flclash_config_dir": root,
        "chain_entry_node": "",
    })
    opts.update(over)
    return profile, airport, opts


def build(profile, opts):
    data = ct.new_yaml().load(open(profile, encoding="utf-8"))
    return build_optimized_profile(data, opts)


# ══════════════════════════════════════════════════════════════════
def test_cfst_resolution(tmp):
    print("\n📋 1. cfst.exe 路径解析（frozen onefile 优先 EXE 目录）")
    exe_dir = os.path.join(tmp, "frozen_exe")
    data_bin = os.path.join(tmp, "appdata", "bin")
    shipped = write(os.path.join(exe_dir, "bin", "cfst.exe"), "shipped-binary" * 10)
    user_copy = write(os.path.join(data_bin, "cfst.exe"), "user-binary" * 10)

    paths = path_utils.cfst_lookup_paths(frozen=True, exe_dir=exe_dir, data_bin=data_bin)
    check("frozen 模式首选 EXE 目录 bin", paths[0] == shipped, paths[0])
    check("frozen 模式第二候选为数据目录 bin", paths[1] == user_copy, paths[1])
    check("frozen 解析结果来自 EXE 目录",
          path_utils.resolve_cfst_exe(frozen=True, exe_dir=exe_dir,
                                      data_bin=data_bin) == shipped)
    check("不会使用 _MEIPASS 临时目录",
          "MEIPASS" not in " ".join(paths) and "_MEI" not in " ".join(paths))

    missing_exe_bin = os.path.join(tmp, "frozen2")
    os.makedirs(missing_exe_bin, exist_ok=True)
    check("EXE 目录缺失时回退数据目录",
          path_utils.resolve_cfst_exe(frozen=True, exe_dir=missing_exe_bin,
                                      data_bin=data_bin) == user_copy)

    source_paths = path_utils.cfst_lookup_paths(frozen=False, exe_dir=exe_dir,
                                                data_bin=data_bin)
    check("源码模式优先数据目录", source_paths[0] == user_copy, source_paths[0])

    empty_root = os.path.join(tmp, "nothing")
    os.makedirs(empty_root, exist_ok=True)
    diag = path_utils.cfst_diagnostics(frozen=True, exe_dir=empty_root,
                                       data_bin=os.path.join(empty_root, "bin"))
    check("缺失时诊断 exists=False 并列出候选",
          diag["exists"] is False and len(diag["candidates"]) >= 1
          and any(c["exists"] is False for c in diag["candidates"]), str(diag))

    # Real shipped binary verification (repo dev build has bin/cfst.exe).
    real = path_utils.resolve_cfst_exe()
    info = core_test.verify_cfst_binary(real)
    if os.path.isfile(real) and os.path.getsize(real) > 1_000_000:
        check("真实 cfst.exe 校验通过（x64）", info["ok"] is True, info["arch"])
        check("真实 cfst.exe 大小正确", info["size"] > 1_000_000, f"{info['size']:,}")
    else:
        check("真实 cfst.exe 校验通过（x64）", False, f"未找到: {real}")
    bad = core_test.verify_cfst_binary(os.path.join(tmp, "nope.exe"))
    check("缺失二进制校验失败并给出原因", bad["ok"] is False and bad["error"], bad["error"])
    tiny = write(os.path.join(tmp, "tiny.exe"), "MZ")
    check("过小文件校验失败", core_test.verify_cfst_binary(tiny)["ok"] is False)


def test_cfst_execution(tmp):
    print("\n📋 2. cfst 子进程调用（stdin/cwd/退出码/stderr）")
    workdir = os.path.join(tmp, "cfst-run")
    os.makedirs(workdir, exist_ok=True)
    logs = []

    def log(line):
        logs.append(str(line))

    rc = core_test._run_cfst([os.path.join(tmp, "missing.exe"), "-h"],
                             workdir, log, lambda: False)
    check("缺失二进制直接返回错误码", rc == -2, str(rc))
    check("缺失二进制给出可操作提示",
          any("找不到测速核心" in line for line in logs), str(logs[-2:]))

    logs.clear()
    cmd = [sys.executable, "-c",
           "import sys; print('boom-line'); sys.stderr.write('err-line\\n'); sys.exit(3)"]
    rc = core_test._run_cfst(cmd, workdir, log, lambda: False)
    check("非零退出码被捕获", rc == 3, str(rc))
    check("退出码写入日志", any("退出码 3" in line for line in logs), str(logs))
    check("stderr 输出被合并记录",
          any("err-line" in line or "boom-line" in line for line in logs), str(logs))

    logs.clear()
    cmd = [sys.executable, "-c",
           "import os,sys; data=sys.stdin.read(); print('stdin_len=' + str(len(data)));"
           " print('cwd=' + os.getcwd())"]
    rc = core_test._run_cfst(cmd, workdir, log, lambda: False)
    joined = "\n".join(logs)
    check("stdin 为 DEVNULL（不会等待回车）", rc == 0 and "stdin_len=0" in joined, joined[-200:])
    check("cwd 传递正确", os.path.normcase(workdir) in os.path.normcase(joined), joined[-200:])


def test_chain_entry(tmp):
    print("\n📋 3. AI 链路入口（dialer-proxy）选择")
    profile, airport, opts = workspace(tmp, "entry_auto")
    _p, summary = build(profile, opts)
    nodes = {str(p.get("name")): p for p in _p["proxies"]}
    check("默认自动 = 机场前置优选组",
          nodes[CHAIN].get("dialer-proxy") == FRONT and summary["chain_entry"] == FRONT,
          str(nodes[CHAIN].get("dialer-proxy")))
    check("默认不产生入口问题", summary["chain_entry_problem"] == "")

    entry = "🇺🇸United States 01"
    profile2, _airport2, opts2 = workspace(tmp, "entry_node", chain_entry_node=entry)
    built, summary2 = build(profile2, opts2)
    nodes2 = {str(p.get("name")): p for p in built["proxies"]}
    check("指定机场节点后 dialer-proxy = 该节点",
          nodes2[CHAIN].get("dialer-proxy") == entry,
          str(nodes2[CHAIN].get("dialer-proxy")))
    check("指定节点仍在 proxies 列表中", entry in nodes2)
    check("直连节点仍无 dialer-proxy", "dialer-proxy" not in nodes2[DIRECT])
    check("除 name/dialer-proxy 外两者仍一致",
          {k: v for k, v in ct.to_builtin(dict(nodes2[CHAIN])).items()
           if k not in ("name", "dialer-proxy")}
          == {k: v for k, v in ct.to_builtin(dict(nodes2[DIRECT])).items()
              if k not in ("name", "dialer-proxy")})
    groups2 = {str(g.get("name")): g for g in built["proxy-groups"]}
    check("AI 组顺序不受影响", groups2[AI_GROUP]["proxies"] == [CHAIN, DIRECT])
    check("PROXY 顺序不受影响",
          groups2["PROXY"]["proxies"] == [DAILY, ct.DEFAULT_OPTIONS["stream_group_name"],
                                          AI_GROUP, DIRECT, "DIRECT"])

    profile3, _a3, opts3 = workspace(tmp, "entry_group", chain_entry_node=DAILY)
    built3, summary3 = build(profile3, opts3)
    nodes3 = {str(p.get("name")): p for p in built3["proxies"]}
    check("可直接选用 日常-机场节点 策略组作为入口",
          nodes3[CHAIN].get("dialer-proxy") == DAILY, str(nodes3[CHAIN].get("dialer-proxy")))
    check("策略组入口无问题", summary3["chain_entry_problem"] == "")

    profile4, _a4, opts4 = workspace(tmp, "entry_bad", chain_entry_node="不存在的节点")
    built4, summary4 = build(profile4, opts4)
    nodes4 = {str(p.get("name")): p for p in built4["proxies"]}
    check("未知入口安全回退到前置组",
          nodes4[CHAIN].get("dialer-proxy") == FRONT, str(nodes4[CHAIN].get("dialer-proxy")))
    check("未知入口记录问题",
          "不在目标配置" in summary4["chain_entry_problem"], summary4["chain_entry_problem"])
    check("未知入口写入 warning",
          any("AI 链路入口" in str(w) for w in summary4["warnings"]))

    profile5, _a5, opts5 = workspace(tmp, "entry_generated", chain_entry_node=CHAIN)
    _b5, summary5 = build(profile5, opts5)
    check("不允许把生成节点当入口",
          "生成的节点" in summary5["chain_entry_problem"], summary5["chain_entry_problem"])

    # Preflight blocks a bad entry, allows the good one.
    pm_bad = ProfileManager(profile4, os.path.join(tmp, "b_bad"), CF_NAMES, options=opts4)
    pre_bad = pm_bad.topology_preflight()
    check("入口无效时预检查阻止写入", pre_bad["ok"] is False
          and any("AI 链路入口" in p for p in pre_bad["problems"]), str(pre_bad["problems"]))
    pm_ok = ProfileManager(profile2, os.path.join(tmp, "b_ok"), CF_NAMES, options=opts2)
    pre_ok = pm_ok.topology_preflight()
    check("入口有效时预检查通过且显示入口", pre_ok["ok"] is True
          and pre_ok["chain_entry"] == entry, pre_ok["chain_entry"])

    # Candidate list: airport nodes only, no info/ad nodes, no generated ones.
    names = chain_entry_candidates(airport, opts)
    check("候选包含机场节点", "🇺🇸United States 01" in names
          and "🇺🇸United States 02" in names, str(names))
    check("候选排除信息节点", all("剩余流量" not in n for n in names), str(names))
    check("候选排除程序生成节点", CHAIN not in names and DIRECT not in names)
    check("候选无重复", len(names) == len(dict.fromkeys(names)))

    # resolve_chain_entry contract
    target, problem = resolve_chain_entry("", [], opts)
    check("空值返回前置组且无问题", target == FRONT and problem == "")
    target2, problem2 = resolve_chain_entry(entry, [{"name": entry}], opts)
    check("存在节点直接采用", target2 == entry and problem2 == "")


def test_lan_self_check_real_ip(tmp):
    print("\n📋 4. 局域网自检走真实 LAN IP（非仅 127.0.0.1）")
    root = os.path.join(tmp, "lan_real")
    os.makedirs(root, exist_ok=True)
    profile, airport, opts = workspace(root, "sc")
    pm = ProfileManager(profile, os.path.join(root, "b"), CF_NAMES, options=opts)
    pm.apply_optimized_topology()
    exports = os.path.join(root, "exports")
    pm.generate_all_exports(exports)

    token = generate_token()
    worker = LANServerWorker(exports, 0, profile_mgr=pm, profile_path=profile,
                             host="0.0.0.0", port_fallback=20, ensure_firewall=False,
                             token_provider=lambda: token)
    worker.start()
    deadline = time.time() + 25
    while time.time() < deadline and not worker.actual_port:
        time.sleep(0.1)
    port = worker.actual_port
    try:
        details = lan_server.detect_lan_ip_details()
        lan_ip = str(details.get("ip") or "")
        usable = bool(lan_ip) and lan_ip not in ("127.0.0.1", "0.0.0.0")
        report = lan_self_check(port, token, exports, lan_ip=lan_ip,
                                firewall={"rule": f"CF-FlClash-LAN-{port}", "exists": True,
                                          "applies": True, "profile": "private,public",
                                          "remote": "LocalSubnet", "detail": "ok",
                                          "active_profiles": ["public"]})
        check("自检服务已启动", bool(port), str(port))
        check("自检请求使用真实局域网 IP",
              report["request_host"] == (lan_ip if usable else "127.0.0.1"),
              f"{report['request_host']} / lan={lan_ip}")
        if usable:
            get_items = [i for i in report["items"] if i["key"].startswith("get:")]
            check("全部订阅接口经真实 LAN IP 请求",
                  get_items and all(f"经 {lan_ip}" in i["detail"] for i in get_items),
                  get_items[0]["detail"] if get_items else "")
        check("自检全部通过", report["ok"] is True,
              "; ".join(i["label"] for i in report["items"] if not i["ok"]))
        check("两种 YAML 均可解析", report["yaml_ok"].get("flclash.yaml") is True
              and report["yaml_ok"].get("ios.yaml") is True)
        check("内容类型为 text/yaml; charset=utf-8",
              any("text/yaml; charset=utf-8" in i["detail"]
                  for i in report["items"] if i["key"] in ("get:flclash.yaml", "get:ios.yaml")))
        check("手机提示包含关闭手机代理",
              any("关闭手机端代理" in t for t in report.get("tips") or []),
              str(report.get("tips")))
        check("自检不泄露 Token", token not in json.dumps(report, ensure_ascii=False))
    finally:
        worker.stop()


def test_config_schema(tmp):
    print("\n📋 5. 配置 Schema（chain_entry_node 默认值与示例配置）")
    defaults = path_utils.load_config.__globals__  # noqa: F841  (documentation only)
    import inspect
    src = inspect.getsource(path_utils.load_config)
    check("默认配置包含 chain_entry_node", '"chain_entry_node": ""' in src)
    example = os.path.join(path_utils.APP_ROOT, "config.example.json")
    if os.path.isfile(example):
        cfg = json.load(open(example, encoding="utf-8"))
        check("config.example.json 包含 chain_entry_node",
              "chain_entry_node" in cfg and cfg["chain_entry_node"] == "",
              str(cfg.get("chain_entry_node")))
    else:
        check("config.example.json 包含 chain_entry_node", False, "文件缺失")


def main():
    print("=" * 74)
    print("CF-FlClash-Optimizer v1.3.1 测试（cfst 解析/执行 · 链路入口 · LAN 真实 IP）")
    print("=" * 74)
    tmp = tempfile.mkdtemp(prefix="cffo-v131-")
    try:
        test_cfst_resolution(tmp)
        test_cfst_execution(tmp)
        test_chain_entry(tmp)
        test_lan_self_check_real_ip(tmp)
        test_config_schema(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n" + "=" * 74)
    total = PASS + FAIL
    print(f"结果: {PASS}/{total} 通过, {FAIL} 失败")
    if FAIL:
        print("失败项: " + "; ".join(FAILURES))
    else:
        print("🎉 v1.3.1 测试全部通过")
    print("=" * 74)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
