# -*- coding: utf-8 -*-
"""Multi-client configuration templates.

One builder feeds every consumer:

* FlClash / Clash for iOS  -> ``build_optimized_profile`` + ``strip_for_ios``
* TV / Happ                -> ``build_happ_subscription`` + ``build_happ_xray_json``
* LAN subscription server  -> the same exported files, served read-only

The generated topology contains:
  * ``🎬 流媒体-CF自动优选``   url-test over the three CF nodes (client-side auto
    failover, interval 180 s, tolerance 50 ms);
  * ``✈️ 机场前置优选``        url-test over the airport's US / low-latency nodes;
  * ``🇺🇸 洛杉矶-VPS-链式落地(AI)`` a copy of the Los Angeles VPS node carrying
    ``dialer-proxy: "✈️ 机场前置优选"``, i.e. local -> airport front -> LA VPS;
  * ``🇺🇸 洛杉矶-VPS-直连(AI)``  the same VPS copy with ``dialer-proxy`` removed,
    i.e. local -> LA VPS directly (manual choice, not failover);
  * ``🤖 AI-链式落地``         selector exposing chain node (1st) and direct node
    (2nd), both optional when the VPS landing cannot be built;
  * ``🚀 日常-机场节点``       default airport group for ordinary overseas traffic;
  * hardened DNS/transport: ``ipv6: false``, ``dns.ipv6: false``,
    ``dns.enhanced-mode: fake-ip`` and ``mux.enabled: false`` on every CF node,
    which removes AAAA lookups / second-connection stalls without touching the
    operating system's IPv6 setting.
"""

import copy
import datetime
import ipaddress
import json
import os
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

# --------------------------------------------------------------------------
# Options
# --------------------------------------------------------------------------
DEFAULT_OPTIONS: Dict[str, Any] = {
    "cf_node_names": [
        "🇺🇸 洛杉矶-CF优选1",
        "🇺🇸 洛杉矶-CF优选2",
        "🇺🇸 洛杉矶-CF优选3",
    ],
    "cf_node_name_prefix": "🇺🇸 洛杉矶-CF优选",
    "stream_group_name": "🎬 流媒体-CF自动优选",
    "front_group_name": "✈️ 机场前置优选",
    "daily_group_name": "🚀 日常-机场节点",
    "auto_airport_group_name": "⚡ 机场自动优选",
    "excluded_node_names": ["CF-保底"],
    "obsolete_group_names": ["自动（直连优先）", "🇺🇸 洛杉矶-CF优选"],
    "ai_chain_group_name": "🤖 AI-链式落地",
    "ai_chain_node_name": "🇺🇸 洛杉矶-VPS-链式落地(AI)",
    # Twin of the chain node without dialer-proxy: same VPS, no airport front.
    "direct_landing_node_name": "🇺🇸 洛杉矶-VPS-直连(AI)",
    "legacy_cf_group": "🇺🇸 洛杉矶-CF优选",
    "main_group_name": "PROXY",
    "chain_landing_node_name": "",
    "airport_profile_path": "",
    "airport_profile_name": "",
    "airport_exclude_paths": [],
    "airport_managed_nodes": [],
    "airport_exclude_keywords": ["流量", "到期", "重置", "官网", "剩余", "套餐"],
    "airport_us_keywords": ["united states", "美国", "美西", "los angeles", "洛杉矶"],
    "airport_max_nodes": 80,
    "test_url": "http://www.gstatic.com/generate_204",
    "group_interval": 180,
    "group_tolerance": 50,
    "happ_subscription_url": "",
    "happ_include_landing": True,
}

# Streaming domains routed to the CF url-test group.
STREAM_DOMAINS: List[str] = [
    "youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
    "netflix.com", "netflix.net", "nflximg.net", "nflxvideo.net",
    "nflxso.net", "nflxext.com",
    "disneyplus.com", "disney-plus.net", "bamgrid.com", "dssott.com",
    "disneystreaming.com", "disney-portal.my.onetrust.com",
    "tiktok.com", "tiktokcdn.com", "ttvnw.net", "tiktokv.com",
    "hulu.com", "hulustream.com",
    "max.com", "hbomax.com", "hbomaxcdn.com",
    "primevideo.com", "amazonvideo.com", "aiv-cdn.net",
    "twitch.tv", "ttvnw.net", "spotify.com", "scdn.co",
]

# High-risk AI endpoints routed through the chained landing node.
AI_DOMAINS: List[str] = [
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
    "anthropic.com", "claude.ai",
    "gemini.google.com", "generativelanguage.googleapis.com",
    "makersuite.google.com", "aistudio.google.com", "bard.google.com",
    "copilot.microsoft.com", "openrouter.ai", "perplexity.ai",
    "grok.com", "x.ai", "api.x.ai", "poe.com",
]


def merged_options(options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    merged = dict(DEFAULT_OPTIONS)
    if options:
        for key, value in options.items():
            if value is not None:
                merged[key] = value
    return merged


# --------------------------------------------------------------------------
# YAML helpers
# --------------------------------------------------------------------------
def new_yaml() -> YAML:
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096
    yaml.allow_unicode = True
    return yaml


def cmap(**kwargs) -> CommentedMap:
    result = CommentedMap()
    for key, value in kwargs.items():
        result[key] = value
    return result


def cseq(items: Optional[Iterable[Any]] = None) -> CommentedSeq:
    result = CommentedSeq()
    for item in items or []:
        result.append(item)
    return result


def _as_map(value: Any) -> CommentedMap:
    if isinstance(value, CommentedMap):
        return value
    result = CommentedMap()
    if isinstance(value, dict):
        for key, val in value.items():
            result[key] = val
    return result


def _as_seq(value: Any) -> CommentedSeq:
    if isinstance(value, CommentedSeq):
        return value
    result = CommentedSeq()
    if isinstance(value, (list, tuple)):
        for item in value:
            result.append(item)
    return result


def _setdefault(mapping: Any, key: str, value: Any) -> Any:
    """dict.setdefault replacement that also works on ruamel CommentedMap."""
    if key in mapping and mapping.get(key) is not None:
        return mapping[key]
    mapping[key] = value
    return value


def _names(items: Any) -> List[str]:
    names: List[str] = []
    for item in items or []:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            name = item.get("name")
            if name:
                names.append(str(name))
    return names


def find_proxy(proxies: Any, name: str) -> Optional[Any]:
    if not name:
        return None
    for proxy in proxies or []:
        if isinstance(proxy, dict) and str(proxy.get("name", "")) == name:
            return proxy
    return None


def find_group(groups: Any, name: str) -> Optional[Any]:
    if not name:
        return None
    for group in groups or []:
        if isinstance(group, dict) and str(group.get("name", "")) == name:
            return group
    return None


def _matches_any(name: str, keywords: Sequence[str]) -> bool:
    lowered = str(name).lower()
    return any(str(kw).lower() in lowered for kw in keywords if kw)


# --------------------------------------------------------------------------
# Airport provider (node-list merge)
# --------------------------------------------------------------------------
def load_airport_nodes(path: str, options: Optional[Dict[str, Any]] = None,
                       existing_names: Optional[Iterable[str]] = None) -> List[Any]:
    """Load airport nodes from a local Clash/Mihomo profile.

    A node-list merge is used instead of ``proxy-providers`` on purpose: the
    generated profile must be fully self-contained after export (iOS / TV
    clients cannot always reach the subscription URL the desktop uses), and it
    keeps the airport credential inside the user's local profile instead of
    the repository.  A subscription URL can still be placed in the airport
    profile, which is refreshed by the client itself.
    """
    opts = merged_options(options)
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = new_yaml().load(f)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []

    exclude = opts["airport_exclude_keywords"]
    known = {str(n) for n in (existing_names or [])}
    result: List[Any] = []
    for proxy in data.get("proxies", []) or []:
        if not isinstance(proxy, dict):
            continue
        name = str(proxy.get("name", "")).strip()
        if not name or name in known:
            continue
        if _matches_any(name, exclude):
            continue  # traffic / expiry / website placeholder nodes
        if not proxy.get("server") or not proxy.get("type"):
            continue
        known.add(name)
        result.append(copy.deepcopy(proxy))
        if len(result) >= int(opts["airport_max_nodes"]):
            break
    return result


def airport_front_nodes(airport_nodes: Sequence[Any], options: Optional[Dict[str, Any]] = None) -> List[str]:
    """Names of airport nodes used in the front url-test group."""
    opts = merged_options(options)
    us = [str(n.get("name")) for n in airport_nodes
          if isinstance(n, dict) and _matches_any(str(n.get("name", "")), opts["airport_us_keywords"])]
    if us:
        return us
    # No US tag found: use every airport node as the front pool rather than
    # silently dropping the chain feature.
    return [str(n.get("name")) for n in airport_nodes if isinstance(n, dict)]


# --------------------------------------------------------------------------
# Hardening
# --------------------------------------------------------------------------
def _cf_node_names(data: Dict[str, Any], options: Dict[str, Any]) -> List[str]:
    configured = [str(n) for n in options["cf_node_names"]]
    present = set(_names(data.get("proxies", [])))
    found = [n for n in configured if n in present]
    prefix = str(options.get("cf_node_name_prefix") or "")
    if not found and prefix:
        found = [n for n in present if n.startswith(prefix)]
        found.sort()
    return found


def harden_cf_nodes(proxies: Any, node_names: Sequence[str]) -> int:
    """Force mux off + IPv4-only resolution on every CF node. Returns count."""
    changed = 0
    names = set(node_names)
    for proxy in proxies or []:
        if not isinstance(proxy, dict) or str(proxy.get("name", "")) not in names:
            continue
        mux = _as_map(proxy.get("mux"))
        if mux.get("enabled") is not False:
            mux["enabled"] = False
            proxy["mux"] = mux
            changed += 1
        else:
            proxy["mux"] = mux
        if proxy.get("ip-version") != "ipv4":
            proxy["ip-version"] = "ipv4"
            changed += 1
    return changed


def ensure_dns_hardening(data: Dict[str, Any]) -> None:
    """Disable IPv6 at the proxy/DNS layer (system IPv6 stays untouched)."""
    data["ipv6"] = False
    dns = _as_map(data.get("dns"))
    dns["enable"] = True
    dns["ipv6"] = False
    dns["enhanced-mode"] = "fake-ip"
    _setdefault(dns, "fake-ip-range", "198.18.0.1/16")
    _setdefault(dns, "default-nameserver", cseq(["223.5.5.5", "119.29.29.29"]))
    _setdefault(dns, "nameserver", cseq([
        "https://dns.alidns.com/dns-query",
        "https://doh.pub/dns-query",
    ]))
    _setdefault(dns, "proxy-server-nameserver", cseq([
        "https://dns.alidns.com/dns-query",
        "223.5.5.5",
    ]))
    filters = _as_seq(dns.get("fake-ip-filter"))
    for entry in ("*.lan", "+.msftconnecttest.com", "+.msftncsi.com", "+.stun.*.*"):
        if entry not in filters:
            filters.append(entry)
    dns["fake-ip-filter"] = filters
    data["dns"] = dns


def ensure_ipv6_block_rule(rules: CommentedSeq) -> None:
    block_rule = "IP-CIDR6,::/0,REJECT,no-resolve"
    if block_rule in [str(r) for r in rules]:
        return
    insert_at = 0
    for idx, rule in enumerate(rules):
        if str(rule).startswith("MATCH,"):
            insert_at = idx
            break
    else:
        insert_at = len(rules)
    rules.insert(insert_at, block_rule)


# --------------------------------------------------------------------------
# Groups / rules
# --------------------------------------------------------------------------
def _url_test_group(name: str, members: Sequence[str], options: Dict[str, Any],
                    interval: Optional[int] = None, hidden: bool = False) -> CommentedMap:
    group = cmap(name=name, type="url-test")
    group["proxies"] = cseq(members)
    group["url"] = str(options["test_url"])
    group["interval"] = int(interval if interval is not None else options["group_interval"])
    group["tolerance"] = int(options["group_tolerance"])
    group["lazy"] = False
    if hidden:
        group["hidden"] = True
    return group


def _select_group(name: str, members: Sequence[str]) -> CommentedMap:
    group = cmap(name=name, type="select")
    group["proxies"] = cseq(members)
    return group


def _upsert_group(groups: CommentedSeq, group: CommentedMap) -> str:
    name = str(group.get("name"))
    for idx, existing in enumerate(groups):
        if isinstance(existing, dict) and str(existing.get("name", "")) == name:
            groups[idx] = group
            return "updated"
    groups.insert(0, group)
    return "added"


def resolve_airport_profile_path(options: Dict[str, Any],
                                 summary: Optional[Dict[str, Any]] = None) -> str:
    """Resolve the airport YAML from FlClash metadata by display name.

    ``airport_profile_name`` (case-insensitive) wins over the static
    ``airport_profile_path``; explicit exclusions are honoured.  Returns the
    path actually used (empty when excluded/missing).
    """
    summary = summary if summary is not None else {}
    path = str(options.get("airport_profile_path") or "")
    label = str(options.get("airport_profile_name") or "").strip()
    summary["airport_label"] = label
    if label:
        try:
            from path_utils import resolve_flclash_profile_by_label
            info = resolve_flclash_profile_by_label(
                label, str(options.get("flclash_config_dir") or ""))
        except Exception:
            info = {}
        if info and info.get("path") and os.path.exists(info["path"]):
            path = str(info["path"])
            summary["airport_profile"] = {
                "id": info.get("id"), "label": info.get("label"),
                "path": path, "current": info.get("current", False),
            }
        else:
            summary.setdefault("warnings", []).append(
                f"未能按名称 {label!r} 解析 FlClash 机场配置，回退静态路径 {path or '(空)'}")
    excluded = set()
    for item in options.get("airport_exclude_paths") or []:
        try:
            excluded.add(os.path.normcase(os.path.abspath(str(item))))
        except Exception:
            continue
    if path and os.path.normcase(os.path.abspath(path)) in excluded:
        summary.setdefault("warnings", []).append(
            f"机场配置 {path} 命中排除列表，已跳过")
        summary["airport_path"] = ""
        return ""
    summary["airport_path"] = path
    return path


def cleanup_managed_airport_nodes(proxies: Any, managed_old: Sequence[str],
                                  allowed_names: Sequence[str]) -> List[str]:
    """Remove airport nodes merged by a previous run but absent from the current airport.

    Only nodes recorded in ``airport_managed_nodes`` are eligible, so self-built
    nodes, the LA VPS and the chain copy can never be removed by mistake.
    """
    managed = {str(n) for n in (managed_old or [])}
    allowed = {str(n) for n in (allowed_names or [])}
    removed: List[str] = []
    for idx in range(len(proxies) - 1, -1, -1):
        node = proxies[idx]
        if not isinstance(node, dict):
            continue
        name = str(node.get("name", ""))
        if name in managed and name not in allowed:
            removed.append(name)
            del proxies[idx]
    return removed


def _build_chain_node(landing: Dict[str, Any], options: Dict[str, Any],
                      front_group: str) -> CommentedMap:
    node = copy.deepcopy(landing)
    node["name"] = options["ai_chain_node_name"]
    node["dialer-proxy"] = front_group
    node["mux"] = cmap(enabled=False)
    node["ip-version"] = "ipv4"
    node["udp"] = True
    return node


# Built-in policy targets: a proxy must never be named like one of these.
RESERVED_TARGET_NAMES = frozenset({
    "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL", "PROXY"})


def _blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def vless_node_problem(node: Any) -> str:
    """Return why *node* cannot be used as a VLESS landing ("" when valid)."""
    if not isinstance(node, dict):
        return "节点不存在"
    kind = str(node.get("type") or "").strip().lower()
    if kind != "vless":
        return f"type={kind or '(空)'} 不是 vless"
    for key in ("server", "uuid"):
        if _blank(node.get(key)):
            return f"缺少必要字段 {key}"
    port = node.get("port")
    if _blank(port):
        return "缺少必要字段 port"
    try:
        if not 0 < int(port) < 65536:
            return f"port 越界: {port!r}"
    except (TypeError, ValueError):
        return f"port 非整数: {port!r}"
    return ""


def _node_signature(node: Any) -> str:
    """Canonical signature of the parts that define a connection.

    ``name`` and ``dialer-proxy`` are excluded on purpose: they are the only two
    keys allowed to differ between the chain node and its direct twin.
    """
    if not isinstance(node, dict):
        return ""
    try:
        data = to_builtin(copy.deepcopy(dict(node)))
    except Exception:
        return ""
    data.pop("name", None)
    data.pop("dialer-proxy", None)
    return json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)


def _derived_from(node: Any, expected: Dict[str, Any]) -> bool:
    """True when *node* is a copy of the same VPS the direct node derives from.

    A name-only marker is deliberately not written into the YAML (the spec
    requires the twin to differ from the chain node in ``name`` /
    ``dialer-proxy`` alone), so ownership is proved by the connection identity
    instead: identical parameters, or the same type/server/port/uuid.
    """
    if not isinstance(node, dict):
        return False
    if _node_signature(node) == _node_signature(expected):
        return True
    for key in ("type", "server", "port", "uuid"):
        left, right = node.get(key), expected.get(key)
        if _blank(left) or str(left).strip().lower() != str(right).strip().lower():
            return False
    return True


def generated_node_names(options: Dict[str, Any]) -> set:
    """Names this program creates itself (never valid landing candidates)."""
    return {str(options.get(key) or "").strip()
            for key in ("ai_chain_node_name", "direct_landing_node_name")
            if str(options.get(key) or "").strip()}


def landing_candidates(proxies: Any, options: Dict[str, Any]) -> List[Any]:
    """Nodes that could be the original VPS landing (keyword scan, no guessing).

    Program-generated nodes (chain / direct twin) are excluded: a previous run
    writes them into the profile, and their names contain "VPS" too, so keeping
    them would make every later run ambiguous.
    """
    skip = generated_node_names(options)
    return [p for p in (proxies or [])
            if isinstance(p, dict)
            and str(p.get("name", "")).strip() not in skip
            and _matches_any(str(p.get("name", "")), ("reality", "vps"))]


def chain_entry_candidates(airport_path: str, options: Optional[Dict[str, Any]] = None) -> List[str]:
    """Airport node names usable as the AI chain dialer-proxy entry.

    Info/ad nodes (traffic, expiry, website …) and program-generated nodes are
    filtered out; the order of the airport file is preserved and duplicates are
    collapsed.
    """
    opts = merged_options(options)
    skip = generated_node_names(opts)
    names: List[str] = []
    for node in load_airport_nodes(str(airport_path or ""), opts, []):
        if not isinstance(node, dict):
            continue
        name = str(node.get("name", "")).strip()
        if not name or name in skip:
            continue
        if _matches_any(name, opts.get("airport_exclude_keywords") or []):
            continue
        names.append(name)
    return list(dict.fromkeys(names))


def resolve_chain_entry(requested: Any, proxies: Any, options: Dict[str, Any],
                        summary: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
    """Resolve ``chain_entry_node`` to the dialer-proxy target.

    ``""`` (automatic) keeps the validated behaviour: the airport front group.
    A configured value must be an existing proxy name or one of the program's
    policy groups; otherwise the front group is used as a safe fallback and the
    reason is reported (the GUI preflight blocks the write in that case).
    Returns ``(target, problem)`` where ``problem`` is ``""`` when everything is
    in order.
    """
    opts = merged_options(options)
    summary = summary if summary is not None else {}
    warnings = summary.setdefault("warnings", [])
    requested = str(requested or "").strip()
    fallback = str(opts["front_group_name"])
    if not requested:
        return fallback, ""
    skip = generated_node_names(opts)
    if requested in skip:
        problem = (f"AI 链路入口 {requested!r} 是本程序生成的节点，不能作为前置跳板，"
                   f"已回退到 {fallback}")
        warnings.append(problem)
        return fallback, problem
    group_targets = {str(opts[key]) for key in
                     ("front_group_name", "daily_group_name",
                      "auto_airport_group_name", "main_group_name")}
    proxy_names = {str(p.get("name")) for p in (proxies or []) if isinstance(p, dict)}
    if requested in proxy_names or requested in group_targets:
        return requested, ""
    problem = (f"AI 链路入口 {requested!r} 不在目标配置的节点/策略组中，"
               f"已回退到 {fallback}；请重新选择入口节点后再写入")
    warnings.append(problem)
    return fallback, problem


def resolve_landing_node(proxies: Any, options: Dict[str, Any],
                         summary: Optional[Dict[str, Any]] = None) -> Optional[Any]:
    """Locate the original VPS landing node.

    ``chain_landing_node_name`` is authoritative.  The legacy keyword scan
    (``reality`` / ``vps`` in the name) stays as a fallback only, and refuses to
    guess when several candidates match: promoting an airport node to "the VPS"
    would silently build a wrong chain.
    """
    summary = summary if summary is not None else {}
    warnings = summary.setdefault("warnings", [])
    skip = generated_node_names(options)
    configured = str(options.get("chain_landing_node_name") or "").strip()
    if configured and configured in skip:
        warnings.append(
            f"chain_landing_node_name={configured!r} 是本程序生成的节点，不能当作原始 VPS 落地节点，"
            "改用名称兜底识别")
        configured = ""
    if configured:
        node = find_proxy(proxies, configured)
        if node is not None:
            return node
        warnings.append(f"配置的 VPS 落地节点 {configured!r} 不在当前配置中，改用名称兜底识别")
    candidates = landing_candidates(proxies, options)
    if not candidates:
        return None
    if len(candidates) > 1:
        preferred = [p for p in candidates if not vless_node_problem(p)]
        if len(preferred) != 1:
            warnings.append(
                "名称兜底识别命中 %d 个候选 VPS 节点（%s），无法确定唯一落地节点，"
                "已跳过链式/直连节点生成"
                % (len(candidates),
                   ", ".join(str(p.get("name")) for p in candidates[:4])))
            return None
        candidates = preferred
    return candidates[0]


def _upsert_direct_node(proxies: CommentedSeq, chain_node: Dict[str, Any],
                        options: Dict[str, Any],
                        summary: Dict[str, Any]) -> str:
    """Install the no-dialer-proxy twin of *chain_node*; idempotent.

    Returns the name actually installed, or "" when it was skipped (reserved
    name, or a foreign node already owning that name).  Never touches the
    landing node, the chain node, or a user node.
    """
    direct_name = str(options.get("direct_landing_node_name") or "").strip()
    if not direct_name:
        summary["warnings"].append("direct_landing_node_name 为空，跳过 VPS 直连节点")
        return ""
    if direct_name in RESERVED_TARGET_NAMES:
        summary["warnings"].append(
            f"direct_landing_node_name={direct_name!r} 与内置策略目标同名，跳过 VPS 直连节点")
        return ""

    expected = copy.deepcopy(chain_node)
    expected.pop("dialer-proxy", None)
    expected["name"] = direct_name

    existing = [idx for idx, proxy in enumerate(proxies)
                if isinstance(proxy, dict) and str(proxy.get("name", "")) == direct_name]
    if any(not _derived_from(proxies[idx], expected) for idx in existing):
        # Same name, different connection: somebody else's node (a user node or a
        # leftover from an earlier VPS identity).  Leave it alone and report; a
        # silent overwrite would destroy a node the user created.
        summary["warnings"].append(
            f"节点名称 {direct_name!r} 已被占用且连接参数与当前 VPS 不一致，"
            "已保留原节点并跳过 VPS 直连节点生成（若是旧配置残留，请手动删除该节点）")
        summary["direct_node_skipped"] = "name-conflict"
        return ""

    if existing:
        keep = existing[0]
        for idx in reversed(existing[1:]):      # collapse older duplicates
            del proxies[idx]
        proxies[keep] = expected
    else:
        chain_name = str(options.get("ai_chain_node_name") or "")
        chain_idx = next((idx for idx, proxy in enumerate(proxies)
                          if isinstance(proxy, dict)
                          and str(proxy.get("name", "")) == chain_name), None)
        if chain_idx is None:
            proxies.append(expected)
        else:
            proxies.insert(chain_idx + 1, expected)   # sits right after the chain
    summary["direct_node"] = direct_name
    return direct_name


def update_rules(rules: CommentedSeq, options: Dict[str, Any],
                 stream_group: Optional[str],
                 ai_chain_group: Optional[str]) -> Tuple[CommentedSeq, int]:
    """Rewrite streaming/AI rules to the new groups and add missing ones."""
    old_group = str(options["legacy_cf_group"])
    stream_set = set(STREAM_DOMAINS)
    ai_set = set(AI_DOMAINS)
    new_rules = CommentedSeq()
    seen = set()
    rewritten = 0

    for raw in rules:
        rule = str(raw)
        if rule in seen:
            continue
        parts = rule.split(",")
        if len(parts) >= 3:
            kind, value = parts[0].strip().upper(), parts[1].strip()
            target_idx = len(parts) - 1
            if parts[-1].strip() == "no-resolve" and len(parts) >= 4:
                target_idx = len(parts) - 2
            target = parts[target_idx].strip()
            if kind in ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD") and target == old_group:
                if value in stream_set and stream_group:
                    parts[target_idx] = stream_group
                    rule = ",".join(parts)
                    rewritten += 1
                elif value in ai_set and ai_chain_group:
                    parts[target_idx] = ai_chain_group
                    rule = ",".join(parts)
                    rewritten += 1
        if rule not in seen:
            seen.add(rule)
            new_rules.append(rule)

    # Add any domain that is not covered yet, right before MATCH.
    additions: List[str] = []
    if stream_group:
        for domain in STREAM_DOMAINS:
            rule = f"DOMAIN-SUFFIX,{domain},{stream_group}"
            if rule not in seen:
                additions.append(rule)
                seen.add(rule)
    if ai_chain_group:
        for domain in AI_DOMAINS:
            rule = f"DOMAIN-SUFFIX,{domain},{ai_chain_group}"
            if rule not in seen:
                additions.append(rule)
                seen.add(rule)

    if additions:
        insert_at = len(new_rules)
        for idx, rule in enumerate(new_rules):
            if str(rule).startswith("MATCH,"):
                insert_at = idx
                break
        for offset, rule in enumerate(additions):
            new_rules.insert(insert_at + offset, rule)

    # Return a brand-new sequence instead of clearing/reusing the original one:
    # ruamel keeps per-index comment tables, and dumping a cleared CommentedSeq
    # can emit "rules: -" (invalid YAML) when the source profile had comments.
    return new_rules, rewritten + len(additions)


def _rule_target_index(parts: List[str]) -> Optional[int]:
    if not parts:
        return None
    kind = parts[0].strip().upper()
    if kind in ("MATCH", "FINAL"):
        return len(parts) - 1 if len(parts) >= 2 else None
    if len(parts) < 3:
        return None
    idx = len(parts) - 1
    if parts[idx].strip().lower() == "no-resolve":
        idx -= 1
    if idx < 2:
        return None
    return idx


def rewrite_rule_targets(rules: Any, mapping: Dict[str, str],
                         valid_targets: Sequence[str], fallback: str) -> Tuple[Any, int]:
    """Rewrite rule targets to surviving groups/nodes.

    Mapping wins, then unknown targets fall back to ``fallback`` (PROXY), so a
    deleted group can never make the mihomo core fail with "proxy not found".
    """
    valid = set(valid_targets)
    new_rules = CommentedSeq()
    changed = 0
    for raw in rules:
        rule = str(raw)
        parts = rule.split(",")
        idx = _rule_target_index(parts)
        if idx is None:
            new_rules.append(rule)
            continue
        target = parts[idx].strip()
        replacement = mapping.get(target)
        if replacement is None and target not in valid:
            replacement = fallback
        if replacement and replacement != target:
            parts[idx] = replacement
            rule = ",".join(parts)
            changed += 1
        new_rules.append(rule)
    return new_rules, changed


def validate_rule_targets(profile: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Return [(rule, missing_target)] for rules pointing at nothing."""
    groups = {str(g.get("name")) for g in profile.get("proxy-groups") or []}
    proxies = {str(p.get("name")) for p in profile.get("proxies") or []}
    builtins = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}
    missing: List[Tuple[str, str]] = []
    for raw in profile.get("rules") or []:
        parts = str(raw).split(",")
        idx = _rule_target_index(parts)
        if idx is None:
            continue
        target = parts[idx].strip()
        if target not in groups and target not in proxies and target not in builtins:
            missing.append((str(raw), target))
    return missing


# --------------------------------------------------------------------------
# Main topology builder
# --------------------------------------------------------------------------
def build_optimized_profile(data: Dict[str, Any],
                            options: Optional[Dict[str, Any]] = None) -> Tuple[Any, Dict[str, Any]]:
    """Return (optimized deep copy of *data*, summary dict).

    ``data`` may be a ruamel CommentedMap loaded from FlClash; comments and
    unrelated keys are preserved because everything happens on a deep copy.
    """
    opts = merged_options(options)
    profile = copy.deepcopy(data)
    summary: Dict[str, Any] = {
        "cf_nodes": [],
        "airport_nodes": 0,
        "front_group": "",
        "stream_group": "",
        "ai_group": "",
        "ai_group_members": [],
        "chain_node": "",
        "chain_entry": "",
        "chain_entry_requested": "",
        "chain_entry_problem": "",
        "direct_node": "",
        "landing_node": "",
        "groups_added": [],
        "rules_touched": 0,
        "warnings": [],
    }

    proxies = _as_seq(profile.get("proxies"))
    profile["proxies"] = proxies
    groups = _as_seq(profile.get("proxy-groups"))
    profile["proxy-groups"] = groups
    rules = _as_seq(profile.get("rules"))
    profile["rules"] = rules

    cf_names = _cf_node_names(profile, opts)
    summary["cf_nodes"] = cf_names
    if len(cf_names) < 3:
        summary["warnings"].append(f"仅找到 {len(cf_names)} 个 CF 优选节点（期望 3 个）")
    harden_cf_nodes(proxies, cf_names)

    # 1. Remove blacklisted nodes (e.g. the retired CF-保底) everywhere.
    excluded_nodes = {str(n) for n in (opts.get("excluded_node_names") or []) if n}
    removed_blacklisted: List[str] = []
    for idx in range(len(proxies) - 1, -1, -1):
        node = proxies[idx]
        if isinstance(node, dict) and str(node.get("name", "")) in excluded_nodes:
            removed_blacklisted.append(str(node.get("name")))
            del proxies[idx]

    # 2. Airport nodes, resolved by the FlClash display name (case-insensitive).
    airport_path = resolve_airport_profile_path(opts, summary)
    airport_nodes = load_airport_nodes(airport_path, opts, [])
    allowed_names = [str(n.get("name")) for n in airport_nodes
                     if isinstance(n, dict) and str(n.get("name")) not in excluded_nodes]
    airport_nodes = [n for n in airport_nodes if str(n.get("name")) in allowed_names]
    removed = cleanup_managed_airport_nodes(
        proxies, opts.get("airport_managed_nodes") or [], allowed_names)
    existing_names = set(_names(proxies))
    for node in airport_nodes:
        name = str(node.get("name"))
        if name not in existing_names:
            proxies.append(node)
            existing_names.add(name)
    summary["airport_nodes"] = len(airport_nodes)
    summary["airport_first_nodes"] = allowed_names[:10]
    summary["managed_nodes"] = allowed_names
    if not airport_nodes:
        summary["warnings"].append("未加载到机场节点（airport_profile_name/path 为空或不可读），"
                                   "链式代理组将回退为 CF 直连组")
    if removed_blacklisted:
        summary["removed_blacklisted"] = removed_blacklisted
    if removed:
        summary.setdefault("removed_nodes", []).extend(removed)
        summary.setdefault("warnings", []).append(
            f"已清理 {len(removed)} 个过期机场节点: {', '.join(removed[:8])}"
            + (" ..." if len(removed) > 8 else ""))

    # 3. Los Angeles VPS landing node (exact name first, keyword scan fallback).
    landing = resolve_landing_node(proxies, opts, summary)
    summary["landing_node"] = str(landing.get("name", "")) if isinstance(landing, dict) else ""

    front_names = airport_front_nodes(airport_nodes, opts)
    front_group_name = str(opts["front_group_name"])
    auto_group_name = str(opts["auto_airport_group_name"])
    daily_group_name = str(opts["daily_group_name"])
    stream_group_name = str(opts["stream_group_name"])
    main_name = str(opts["main_group_name"])
    ai_chain_group: Optional[str] = None
    groups_added: List[str] = []
    summary["front_group"] = front_group_name
    summary["auto_airport_group"] = auto_group_name
    summary["daily_group"] = daily_group_name

    # 3a. Hidden airport auto-test group + visible manual selector.
    if airport_nodes and front_names:
        front_group = _url_test_group(front_group_name, front_names, opts, hidden=True)
        groups_added.append(f"{_upsert_group(groups, front_group)}:{front_group_name}")

    if airport_nodes:
        auto_members = [str(n.get("name")) for n in airport_nodes if isinstance(n, dict)]
        auto_group = _url_test_group(auto_group_name, auto_members, opts,
                                     interval=300, hidden=True)
        groups_added.append(f"{_upsert_group(groups, auto_group)}:{auto_group_name}")
        daily_members = [auto_group_name] + auto_members
        daily_group = _select_group(daily_group_name, daily_members)
        groups_added.append(f"{_upsert_group(groups, daily_group)}:{daily_group_name}")

    # 3b. Chained AI landing + its direct twin.
    # The chain node stays the only member that carries dialer-proxy; the direct
    # twin is derived from it, never from the landing node itself.
    direct_name = ""
    if airport_nodes and front_names and landing is not None:
        chain_name = str(opts["ai_chain_node_name"])
        # Manual "chain entry" (dialer-proxy) selection; "" keeps the verified
        # airport front group. An unknown/stale value falls back safely and is
        # reported so the write preflight can block it.
        chain_entry_target, chain_entry_problem = resolve_chain_entry(
            opts.get("chain_entry_node"), proxies, opts, summary)
        summary["chain_entry"] = chain_entry_target
        summary["chain_entry_requested"] = str(opts.get("chain_entry_node") or "")
        summary["chain_entry_problem"] = chain_entry_problem
        chain_node = _build_chain_node(landing, opts, chain_entry_target)
        for idx, proxy in enumerate(proxies):
            if isinstance(proxy, dict) and str(proxy.get("name", "")) == chain_name:
                proxies[idx] = chain_node
                break
        else:
            proxies.append(chain_node)
        summary["chain_node"] = chain_name

        landing_problem = vless_node_problem(landing)
        if landing_problem:
            summary["warnings"].append(
                f"VPS 落地节点不是有效 VLESS 节点（{landing_problem}），跳过直连节点生成")
        else:
            direct_name = _upsert_direct_node(proxies, chain_node, opts, summary)

        ai_group_name = str(opts["ai_chain_group_name"])
        # Order is fixed: chain first (manual default), direct second.
        ai_members = [chain_name] + ([direct_name] if direct_name else [])
        ai_group = _select_group(ai_group_name, ai_members)
        groups_added.append(f"{_upsert_group(groups, ai_group)}:{ai_group_name}")
        ai_chain_group = ai_group_name
        summary["ai_group"] = ai_group_name
        summary["ai_group_members"] = list(ai_members)
    elif airport_nodes and front_names:
        summary["warnings"].append("未找到洛杉矶 VPS 落地节点，无法创建 dialer-proxy 链式节点")

    # 3c. Streaming url-test over the CF nodes.
    if cf_names:
        stream_group = _url_test_group(stream_group_name, cf_names, opts)
        groups_added.append(f"{_upsert_group(groups, stream_group)}:{stream_group_name}")
        summary["stream_group"] = stream_group_name

    # 4. PROXY: clean top-level entry only (no single nodes).
    main_group = find_group(groups, main_name)
    if main_group is None:
        main_group = _select_group(main_name, [])
        groups.append(main_group)
        summary["warnings"].append(f"主策略组 {main_name} 缺失，已新建")
    top_members = [daily_group_name, stream_group_name, ai_chain_group or "",
                   direct_name, "DIRECT"]
    top_members = [m for m in dict.fromkeys(top_members) if m]
    main_group["proxies"] = cseq(top_members)
    main_group["type"] = "select"
    summary["proxy_members"] = list(top_members)

    # 5. Drop obsolete/zombie groups and sanitise every member list.
    obsolete = {str(n) for n in (opts.get("obsolete_group_names") or []) if n}
    kept_groups = CommentedSeq()
    removed_groups: List[str] = []
    for group in groups:
        if not isinstance(group, dict):
            continue
        name = str(group.get("name", ""))
        if name in obsolete:
            removed_groups.append(name)
            continue
        kept_groups.append(group)
    summary["removed_groups"] = removed_groups

    proxy_names = {str(p.get("name")) for p in proxies if isinstance(p, dict)}
    valid_members = proxy_names | {str(g.get("name")) for g in kept_groups} | {
        "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}
    for group in kept_groups:
        members = [str(m) for m in (group.get("proxies") or [])]
        cleaned = [m for m in dict.fromkeys(members) if m in valid_members]
        if str(group.get("name")) == main_name:
            cleaned = [m for m in (group.get("proxies") or []) if m in valid_members]
        if not cleaned:
            cleaned = ["DIRECT"]
        group["proxies"] = cseq(cleaned)

    # Stable UI order: hidden backing groups first, then user-facing entries.
    preferred_order = [front_group_name, auto_group_name, daily_group_name,
                       stream_group_name, opts["ai_chain_group_name"], main_name]
    ordered = CommentedSeq()
    for name in preferred_order:
        for group in kept_groups:
            if str(group.get("name")) == name and group not in ordered:
                ordered.append(group)
    for group in kept_groups:
        if group not in ordered:
            ordered.append(group)
    profile["proxy-groups"] = ordered

    # 6. Rules: domain mapping first, then orphan-target repair.
    new_rules, touched = update_rules(
        rules, opts, stream_group_name if cf_names else None, ai_chain_group)
    mapping: Dict[str, str] = {
        "自动（直连优先）": main_name,
        str(opts["legacy_cf_group"]): stream_group_name if cf_names else main_name,
    }
    for name in removed_groups:
        mapping.setdefault(name, main_name)
    for name in excluded_nodes:
        mapping[name] = main_name
    valid_targets = proxy_names | {str(g.get("name")) for g in ordered} | {
        "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}
    final_rules, rewritten = rewrite_rule_targets(new_rules, mapping, valid_targets, main_name)
    profile["rules"] = final_rules
    summary["rules_touched"] = touched + rewritten
    summary["rules_rewritten_targets"] = rewritten
    ensure_ipv6_block_rule(profile["rules"])
    orphan = validate_rule_targets(profile)
    if orphan:
        summary["warnings"].append(
            f"{len(orphan)} 条规则指向不存在的目标，已兜底为 {main_name}: "
            + ", ".join(sorted({t for _r, t in orphan})[:5]))

    ensure_dns_hardening(profile)
    profile["ipv6"] = False
    if "allow-lan" not in profile:
        profile["allow-lan"] = False
    summary["groups_added"] = groups_added
    return profile, summary


def strip_for_ios(profile: Dict[str, Any]) -> Any:
    """Remove desktop-only keys and rules so the YAML works on Clash for iOS."""
    ios = copy.deepcopy(profile)
    for key in [
        "tun", "external-controller", "external-controller-tls",
        "external-controller-pipe", "external-controller-unix",
        "global-ua", "find-process-mode", "interface-name",
        "bind-address", "profile", "geodata-mode", "geo-auto-update",
    ]:
        if key in ios:
            del ios[key]
    if "rules" in ios:
        cleaned = CommentedSeq()
        for rule in ios["rules"]:
            text = str(rule)
            if "PROCESS-NAME" in text:
                continue
            if text.startswith("MATCH,") or text.startswith("IP-CIDR") or "," in text:
                cleaned.append(text)
        ios["rules"] = cleaned
    ios["allow-lan"] = False
    ios["ipv6"] = False
    ensure_dns_hardening(ios)
    return to_builtin(ios)


# --------------------------------------------------------------------------
# Happ (TV) exports
# --------------------------------------------------------------------------
def _vless_link(node: Dict[str, Any], mux: bool = False,
                packet_encoding: str = "xudp", name_suffix: str = "") -> Optional[str]:
    from urllib.parse import quote

    if not isinstance(node, dict) or str(node.get("type", "")).lower() != "vless":
        return None
    server = str(node.get("server", "")).strip()
    uuid = str(node.get("uuid", "")).strip()
    if not server or not uuid:
        return None
    port = node.get("port", 443)
    network = str(node.get("network", "tcp") or "tcp")
    tls = bool(node.get("tls", False))
    reality = node.get("reality-opts") or {}
    ws_opts = node.get("ws-opts") or {}
    headers = ws_opts.get("headers") or {}
    host = str(headers.get("Host") or node.get("servername") or server)
    path = str(ws_opts.get("path") or "/")
    sni = str(node.get("servername") or host)
    fingerprint = str(node.get("client-fingerprint") or "chrome")
    name = str(node.get("name", "node")) + name_suffix

    security = "reality" if (tls and reality.get("public-key")) else ("tls" if tls else "none")
    params = [
        "encryption=none",
        f"security={security}",
        f"sni={sni}",
        f"fp={fingerprint}",
        f"type={network}",
        f"packetEncoding={packet_encoding}",
        f"mux={'1' if mux else '0'}",
    ]
    if network == "ws":
        params.extend([f"host={host}", f"path={quote(path, safe='')}"])
    if node.get("flow"):
        params.append(f"flow={node['flow']}")
    if security == "reality":
        if reality.get("public-key"):
            params.append(f"pbk={reality['public-key']}")
        if reality.get("short-id"):
            params.append(f"sid={reality['short-id']}")
    return f"vless://{uuid}@{server}:{port}?{'&'.join(params)}#{quote(name, safe='')}"


def happ_nodes(profile: Dict[str, Any], options: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Nodes worth putting into the Happ TV subscription (CF first)."""
    opts = merged_options(options)
    proxies = [p for p in (profile.get("proxies") or []) if isinstance(p, dict)]
    names: List[str] = []
    for node in proxies:
        if str(node.get("name")) in opts["cf_node_names"]:
            names.append(str(node.get("name")))
    landing = find_proxy(proxies, str(opts.get("chain_landing_node_name") or ""))
    if landing is not None and opts.get("happ_include_landing"):
        names.append(str(landing.get("name")))
    result: List[Dict[str, Any]] = []
    for name in dict.fromkeys(names):
        node = find_proxy(proxies, name)
        if node is not None and _vless_link(node) is not None:
            result.append(node)
    # Fallback: any VLESS node at all (never emit an empty subscription).
    if not result:
        for node in proxies:
            if _vless_link(node) is not None:
                result.append(node)
            if len(result) >= 3:
                break
    return result


def build_happ_subscription(profile: Dict[str, Any],
                            options: Optional[Dict[str, Any]] = None,
                            generated_at: Optional[datetime.datetime] = None) -> str:
    """Plain-text Happ subscription with the TV-specific auto-update headers."""
    opts = merged_options(options)
    nodes = happ_nodes(profile, opts)
    stamp = (generated_at or datetime.datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# CF-FlClash-Optimizer · Happ 电视端订阅 (自动生成)",
        f"# generated: {stamp}",
        "#subscription-auto-update-open-enable: 1",
        "#subscription-autoconnect: 1",
        "#subscription-autoconnect-type: lowestdelay",
        "# ipv6: disabled | mux: disabled | packetEncoding: xudp | dns queryStrategy: UseIPv4",
    ]
    for node in nodes:
        link = _vless_link(node, mux=False, packet_encoding="xudp")
        if link:
            lines.append(link)
    return "\n".join(lines) + "\n"


def _vless_xray_outbound(node: Dict[str, Any], tag: str,
                         extra: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    if not isinstance(node, dict) or str(node.get("type", "")).lower() != "vless":
        return None
    if not node.get("uuid") or not node.get("server"):
        return None
    server = str(node["server"])
    port = int(node.get("port", 443) or 443)
    network = str(node.get("network", "tcp") or "tcp")
    ws_opts = node.get("ws-opts") or {}
    headers = ws_opts.get("headers") or {}
    host = str(headers.get("Host") or node.get("servername") or server)
    path = str(ws_opts.get("path") or "/")
    sni = str(node.get("servername") or host)
    reality = node.get("reality-opts") or {}

    stream: Dict[str, Any] = {"network": network}
    if node.get("tls"):
        if reality.get("public-key"):
            stream.update({
                "security": "reality",
                "realitySettings": {
                    "serverName": sni,
                    "fingerprint": str(node.get("client-fingerprint") or "chrome"),
                    "publicKey": str(reality.get("public-key")),
                    "shortId": str(reality.get("short-id") or ""),
                    "spiderX": "/",
                },
            })
        else:
            stream.update({
                "security": "tls",
                "tlsSettings": {
                    "serverName": sni,
                    "fingerprint": str(node.get("client-fingerprint") or "chrome"),
                    "allowInsecure": bool(node.get("skip-cert-verify", False)),
                },
            })
    if network == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host}}

    outbound: Dict[str, Any] = {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": server,
                "port": port,
                "users": [{
                    "id": str(node["uuid"]),
                    "encryption": "none",
                    "flow": str(node.get("flow") or ""),
                }],
            }],
            # TV-friendly: no multiplexing (weak CPU), XUDP for UDP streams.
            "packetEncoding": "xudp",
        },
        # Explicitly disabled on every outbound, per the TV low-latency profile.
        "mux": {"enabled": False, "concurrency": 1},
        "streamSettings": stream,
    }
    if extra:
        outbound.update(extra)
    return outbound


def build_happ_xray_json(profile: Dict[str, Any],
                         options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Xray JSON for Happ: IPv4-only DNS, no mux, AI chained via proxySettings."""
    opts = merged_options(options)
    nodes = happ_nodes(profile, opts)
    proxies = [p for p in (profile.get("proxies") or []) if isinstance(p, dict)]

    cf_nodes = [p for p in proxies if str(p.get("name")) in opts["cf_node_names"]]
    if not cf_nodes:
        cf_nodes = [n for n in nodes if _vless_xray_outbound(n, "x") is not None][:3]

    outbounds: List[Dict[str, Any]] = []
    cf_tags: List[str] = []
    for idx, node in enumerate(cf_nodes[:3], start=1):
        tag = f"cf-{idx}"
        outbound = _vless_xray_outbound(node, tag)
        if outbound:
            outbounds.append(outbound)
            cf_tags.append(tag)

    # Airport front + LA landing chain (best effort; requires VLESS nodes).
    landing = find_proxy(proxies, str(opts.get("chain_landing_node_name") or ""))
    front = None
    for node in proxies:
        if not isinstance(node, dict):
            continue
        if str(node.get("name")) == str(opts.get("chain_landing_node_name")):
            continue
        if str(node.get("name")) in opts["cf_node_names"]:
            continue
        if str(node.get("type", "")).lower() != "vless" or not node.get("tls"):
            continue
        if "reality-opts" not in node:
            continue
        front = node
        break

    chain_tag = ""
    if front is not None and landing is not None:
        front_out = _vless_xray_outbound(front, "airport-front")
        landing_out = _vless_xray_outbound(landing, "ai-chain",
                                           {"proxySettings": {"tag": "airport-front"}})
        if front_out and landing_out:
            outbounds.extend([front_out, landing_out])
            chain_tag = "ai-chain"

    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})

    rules: List[Dict[str, Any]] = []
    if chain_tag:
        rules.append({"type": "field", "domain": [f"domain:{d}" for d in AI_DOMAINS],
                      "outboundTag": chain_tag})
    balancer_tag = "cf-auto"
    if cf_tags:
        rules.append({"type": "field", "domain": [f"domain:{d}" for d in STREAM_DOMAINS],
                      "balancerTag": balancer_tag})
    if cf_tags:
        rules.append({"type": "field", "network": "tcp,udp", "balancerTag": balancer_tag})
    else:
        rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "direct"})

    config: Dict[str, Any] = {
        "log": {"loglevel": "warning"},
        "dns": {
            "tag": "dns-in",
            "servers": ["https://1.1.1.1/dns-query", "8.8.8.8"],
            # IPv4-only DNS: no AAAA lookups, no IPv6 first-hop stall on TV.
            "queryStrategy": "UseIPv4",
            "disableCache": False,
            "disableFallback": False,
        },
        "inbounds": [
            {
                "tag": "socks-in", "listen": "127.0.0.1", "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"],
                             "routeOnly": True},
            },
            {
                "tag": "http-in", "listen": "127.0.0.1", "port": 10809,
                "protocol": "http",
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"],
                             "routeOnly": True},
            },
        ],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": rules,
        },
    }
    if cf_tags:
        config["routing"]["balancers"] = [{
            "tag": balancer_tag,
            "selector": cf_tags,
            "strategy": {"type": "leastPing"},
        }]
        config["observatory"] = {
            "subjectSelector": cf_tags,
            "probeUrl": "http://www.gstatic.com/generate_204",
            "probeInterval": "3m",
            "enableConcurrency": True,
        }
    return config


def to_builtin(value: Any) -> Any:
    """Deep-convert ruamel CommentedMap/CommentedSeq to plain dict/list.

    Generated client configs do not need comments; dropping them also avoids
    stale per-key comment tables that can serialise ``rules: -`` (invalid YAML).
    """
    if isinstance(value, dict):
        return {str(k): to_builtin(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_builtin(v) for v in value]
    return value


def dump_yaml_text(data: Any) -> str:
    """Serialise to YAML text (UTF-8, LF). Used for atomic writes/tests."""
    import io
    buf = io.StringIO()
    new_yaml().dump(data, buf)
    return buf.getvalue()


def validate_ios_profile(profile: Any, options: Optional[Dict[str, Any]] = None) -> List[str]:
    """Cheap structural self-check used by tests and before writing."""
    opts = merged_options(options)
    problems: List[str] = []
    if profile.get("ipv6") is not False:
        problems.append("top-level ipv6 is not false")
    dns = profile.get("dns") or {}
    if dns.get("ipv6") is not False:
        problems.append("dns.ipv6 is not false")
    if dns.get("enhanced-mode") != "fake-ip":
        problems.append("dns.enhanced-mode is not fake-ip")
    groups = {str(g.get("name")): g for g in profile.get("proxy-groups") or []}
    stream = groups.get(str(opts["stream_group_name"]))
    if stream is None:
        problems.append("streaming url-test group missing")
    elif stream.get("type") != "url-test":
        problems.append("streaming group is not url-test")
    elif stream.get("url") != "http://www.gstatic.com/generate_204":
        problems.append("streaming group url mismatch")
    elif int(stream.get("interval", 0)) != 180 or int(stream.get("tolerance", 0)) != 50:
        problems.append("streaming group interval/tolerance mismatch")
    for proxy in profile.get("proxies") or []:
        name = str(proxy.get("name", ""))
        if name in opts["cf_node_names"]:
            if (proxy.get("mux") or {}).get("enabled") is not False:
                problems.append(f"{name} mux not disabled")
    return problems
