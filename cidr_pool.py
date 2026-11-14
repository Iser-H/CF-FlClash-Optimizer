# -*- coding: utf-8 -*-
"""Cloudflare CIDR pool, /24 subnet score history and Exploit-Explore sampling.

Design notes
------------
* The full Cloudflare IPv4 CIDR library is kept in code (and synchronised into
  ``bin/ip.txt``).  No big segment is ever dropped: small per-/24 ranges that
  used to live in ``ip.txt`` (104.29.0.0/16, 162.159.0.0/16, ...) are retained
  as an explicit *legacy* layer and collapsed together with the official list,
  so overlapping ranges are only weighted once.
* After every speed test the caller records the rows.  Rows are aggregated per
  /24 subnet (connectivity rate, pass rate, average speed, average latency,
  last pass timestamp).  Old aggregates are exponentially decayed, so a subnet
  that was fast three weeks ago cannot permanently dominate the ranking.
* Candidate generation is 70 % exploit (random hosts inside the best scoring
  /24 subnets) and 30 % explore (uniform random hosts over the whole official
  library).  With no history it is 100 % explore.
* Final Top-N selection enforces distinct /24 subnets when possible, so a
  single subnet that collapses during prime time cannot take all three slots.
"""

import ipaddress
import json
import math
import os
import random
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from storage_utils import atomic_write_text, get_file_lock, read_json

# --------------------------------------------------------------------------
# CIDR library
# --------------------------------------------------------------------------
# https://www.cloudflare.com/ips-v4 (canonical, current)
OFFICIAL_CF_IPV4_CIDRS: List[str] = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

# Historical / expanded ranges that the tool shipped with.  They are kept on
# purpose: 162.159.0.0/16 and 104.29.0.0/16 are reachable anycast blocks that
# the old random scan could hit, and users may already have them in ip.txt.
LEGACY_EXPANDED_CIDRS: List[str] = [
    "104.16.0.0/12",
    "162.158.0.0/15",
    "162.159.0.0/16",
    "104.29.0.0/16",
    "172.64.0.0/16",
    "172.65.0.0/16",
    "172.66.0.0/16",
    "172.67.0.0/16",
    "104.17.0.0/16",
    "104.18.0.0/16",
    "104.19.0.0/16",
    "104.20.0.0/16",
    "104.21.0.0/16",
    "104.22.0.0/16",
    "104.23.0.0/16",
    "104.24.0.0/16",
    "104.25.0.0/16",
    "104.26.0.0/16",
    "104.27.0.0/16",
    "104.28.0.0/16",
    "104.29.0.0/16",
    "104.30.0.0/16",
    "104.31.0.0/16",
]


# Ranges the operator explicitly wants visible in the base library even though
# they are already covered by a larger collapsed block.  They are appended to
# ip.txt (never replacing existing lines) and are part of the sampling library.
PINNED_EXPLICIT_CIDRS: List[str] = ["162.159.0.0/16", "104.29.0.0/16"]


def _parse_networks(cidrs: Iterable[str]) -> List[ipaddress.IPv4Network]:
    nets: List[ipaddress.IPv4Network] = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.IPv4Network(str(cidr).strip(), strict=False))
        except ValueError:
            continue
    return nets


def _collapse(nets: Sequence[ipaddress.IPv4Network]) -> List[ipaddress.IPv4Network]:
    return list(ipaddress.collapse_addresses(nets))


# Collapsed minimal cover of official + legacy ranges (weighting-correct).
CF_NETWORKS: List[ipaddress.IPv4Network] = _collapse(
    _parse_networks(list(OFFICIAL_CF_IPV4_CIDRS) + LEGACY_EXPANDED_CIDRS)
)
CF_CIDRS: List[str] = [str(n) for n in CF_NETWORKS]
_TOTAL_ADDRESSES: int = sum(n.num_addresses for n in CF_NETWORKS)


def in_library(ip: str) -> bool:
    """True when the IP belongs to the Cloudflare library."""
    try:
        addr = ipaddress.IPv4Address(str(ip).strip())
    except ValueError:
        return False
    return any(addr in net for net in CF_NETWORKS)


def subnet_of(ip: str) -> Optional[str]:
    """Return the /24 subnet string of an IPv4 address (None if invalid)."""
    try:
        return str(ipaddress.IPv4Network(f"{ipaddress.IPv4Address(str(ip).strip())}/24", strict=False))
    except ValueError:
        return None


def ensure_cidr_file(path: str) -> bool:
    """Ensure ``path`` (bin/ip.txt) contains the whole library.

    Existing lines are never removed or reordered - missing networks are only
    appended.  Returns True when the file was rewritten.
    """
    existing: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    existing.append(line)
    except OSError:
        existing = []

    existing_nets = _parse_networks(existing)
    missing: List[ipaddress.IPv4Network] = []
    for net in CF_NETWORKS:
        if not any(net.subnet_of(have) for have in existing_nets if have.version == 4):
            missing.append(net)

    pinned_missing = [cidr for cidr in PINNED_EXPLICIT_CIDRS if cidr not in existing]

    if not missing and not pinned_missing and existing:
        return False

    # Existing lines are preserved verbatim; only additional networks are
    # appended, so no previously deployed big range can ever disappear.
    lines = list(existing)
    for net in _collapse(missing):
        if str(net) not in lines:
            lines.append(str(net))
    for cidr in pinned_missing:
        lines.append(cidr)
    header = "# Cloudflare IPv4 CIDR library (auto-synced, do not delete big ranges)\n"
    atomic_write_text(path, header + "\n".join(lines) + "\n")
    return True


# --------------------------------------------------------------------------
# Score history
# --------------------------------------------------------------------------
DEFAULT_SCORE_FILENAME = "cidr_score_history.json"
HALF_LIFE_DAYS = 7.0
LATENCY_REF_MS = 200.0


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if isinstance(value, str):
            value = value.strip().replace("%", "").replace("ms", "").strip()
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_result(row: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise one cfst CSV row (or a dict built by the GUI) to numbers."""
    ip = str(row.get("IP地址", row.get("ip", row.get("server", "")))).strip()
    speed = _as_float(row.get("下载速度(MB/s)", row.get("download_speed", row.get("speed", row.get("speed_num", 0.0)))))
    latency = _as_float(row.get("平均延迟", row.get("avg_latency", row.get("latency", row.get("cf_latency", 0.0)))))
    loss = _as_float(row.get("丢包率", row.get("loss", 0.0)))
    return {"ip": ip, "speed": speed, "latency": latency, "loss": loss}


class SubnetScoreStore:
    """/24 health scores persisted as JSON, with exponential time decay."""

    def __init__(self, path: str, half_life_days: float = HALF_LIFE_DAYS):
        self.path = path
        self.half_life_days = max(0.1, float(half_life_days))
        self._lock = get_file_lock(path)
        self._subnets: Dict[str, Dict[str, float]] = {}
        self._updated_at: float = 0.0
        self._loaded = False

    # ── persistence ──────────────────────────────────────────────
    def load(self) -> "SubnetScoreStore":
        with self._lock:
            data, error = read_json(self.path, default=None)
            if error:
                # Corrupt history must never block a speed test: quarantine
                # the damaged file and start from an empty (100 % explore) pool.
                self._quarantine_corrupt()
                self._subnets = {}
                self._loaded = True
                return self

            if not isinstance(data, dict):
                self._subnets = {}
                self._updated_at = 0.0
                self._loaded = True
                return self

            subnets = data.get("subnets")
            clean: Dict[str, Dict[str, float]] = {}
            if isinstance(subnets, dict):
                for key, value in subnets.items():
                    entry = self._sanitize_entry(key, value)
                    if entry is not None:
                        clean[key] = entry
            self._subnets = clean
            self._updated_at = _as_float(data.get("updated_at", 0.0), 0.0)
            self._loaded = True
            return self

    def _quarantine_corrupt(self) -> None:
        try:
            if os.path.exists(self.path):
                os.replace(self.path, f"{self.path}.corrupt-{int(time.time())}")
        except OSError:
            pass

    @staticmethod
    def _sanitize_entry(key: str, value: Any) -> Optional[Dict[str, float]]:
        if not isinstance(value, dict):
            return None
        try:
            net = ipaddress.IPv4Network(str(key), strict=False)
        except ValueError:
            return None
        if net.prefixlen != 24:
            return None
        samples = _as_float(value.get("samples", 0.0))
        if samples <= 0:
            return None
        entry = {
            "samples": samples,
            "connected": max(0.0, _as_float(value.get("connected", 0.0))),
            "passed": max(0.0, _as_float(value.get("passed", 0.0))),
            "sum_speed": max(0.0, _as_float(value.get("sum_speed", 0.0))),
            "sum_latency": max(0.0, _as_float(value.get("sum_latency", 0.0))),
            "latency_samples": max(0.0, _as_float(value.get("latency_samples", 0.0))),
            "best_speed": max(0.0, _as_float(value.get("best_speed", 0.0))),
            "last_pass_ts": _as_float(value.get("last_pass_ts", 0.0)),
            "last_seen_ts": _as_float(value.get("last_seen_ts", 0.0)),
        }
        if entry["connected"] > entry["samples"]:
            entry["connected"] = entry["samples"]
        if entry["passed"] > entry["samples"]:
            entry["passed"] = entry["samples"]
        return entry

    def save(self) -> str:
        with self._lock:
            payload = {
                "version": 1,
                "half_life_days": self.half_life_days,
                "updated_at": time.time(),
                "subnets": self._subnets,
            }
            return atomic_write_text(self.path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

    # ── recording ────────────────────────────────────────────────
    def record_results(self, rows: Iterable[Dict[str, Any]], speed_floor: float = 5.0,
                       max_latency: float = 400.0, now: Optional[float] = None) -> Dict[str, int]:
        """Merge one speed-test batch into the /24 history.

        Returns {"recorded": n, "subnets": n}.
        """
        now = float(now if now is not None else time.time())
        speed_floor = max(0.0, float(speed_floor))
        max_latency = max(0.0, float(max_latency))

        with self._lock:
            if not self._loaded:
                # load() re-enters the RLock, that is fine.
                self.load()

            recorded = 0
            touched = set()
            for raw in rows:
                row = normalize_result(raw if isinstance(raw, dict) else {})
                ip = row["ip"]
                subnet = subnet_of(ip)
                if not subnet or not in_library(ip):
                    continue
                entry = self._get_entry(subnet)
                last_seen = entry["last_seen_ts"] or now
                decay = self._decay(last_seen, now)
                for key in ("samples", "connected", "passed", "sum_speed",
                            "sum_latency", "latency_samples"):
                    entry[key] = entry.get(key, 0.0) * decay

                speed = max(0.0, row["speed"])
                latency = max(0.0, row["latency"])
                connected = 1.0 if (speed > 0.0 or latency > 0.0) else 0.0
                passed = 1.0 if (
                    speed >= speed_floor
                    and (latency <= 0.0 or latency <= max_latency)
                    and connected > 0
                ) else 0.0

                entry["samples"] += 1.0
                entry["connected"] += connected
                entry["passed"] += passed
                entry["sum_speed"] += speed
                entry["best_speed"] = max(entry["best_speed"], speed)
                if latency > 0:
                    entry["sum_latency"] += latency
                    entry["latency_samples"] += 1.0
                if passed > 0:
                    entry["last_pass_ts"] = now
                entry["last_seen_ts"] = now
                recorded += 1
                touched.add(subnet)

            self._updated_at = now
            return {"recorded": recorded, "subnets": len(touched)}

    def _get_entry(self, subnet: str) -> Dict[str, float]:
        entry = self._subnets.get(subnet)
        if entry is None:
            entry = {
                "samples": 0.0,
                "connected": 0.0,
                "passed": 0.0,
                "sum_speed": 0.0,
                "sum_latency": 0.0,
                "latency_samples": 0.0,
                "best_speed": 0.0,
                "last_pass_ts": 0.0,
                "last_seen_ts": 0.0,
            }
            self._subnets[subnet] = entry
        return entry

    def _decay(self, last_seen: float, now: float) -> float:
        if last_seen <= 0:
            return 0.0
        age_days = max(0.0, (now - last_seen) / 86400.0)
        return 0.5 ** (age_days / self.half_life_days) if age_days > 0 else 1.0

    # ── scoring ──────────────────────────────────────────────────
    def score_entry(self, key: str, now: Optional[float] = None) -> Dict[str, float]:
        now = float(now if now is not None else time.time())
        entry = self._subnets.get(key)
        if not entry or entry["samples"] <= 0:
            return {"subnet": key, "score": 0.0, "samples": 0.0, "connect_rate": 0.0,
                    "pass_rate": 0.0, "avg_speed": 0.0, "avg_latency": 0.0,
                    "last_pass_ts": 0.0, "last_seen_ts": 0.0, "age_days": 0.0}
        samples = max(1e-9, entry["samples"])
        connect_rate = min(1.0, entry["connected"] / samples)
        pass_rate = min(1.0, entry["passed"] / samples)
        avg_speed = entry["sum_speed"] / samples
        latency_samples = max(1e-9, entry["latency_samples"])
        avg_latency = entry["sum_latency"] / latency_samples if entry["latency_samples"] > 0 else 0.0

        speed_component = min(1.0, avg_speed / 10.0)
        latency_component = 1.0 / (1.0 + (avg_latency / LATENCY_REF_MS) ** 2) if avg_latency > 0 else 0.0
        base = (0.30 * connect_rate + 0.30 * pass_rate
                + 0.28 * speed_component + 0.12 * latency_component)
        confidence = samples / (samples + 1.0)
        decay = self._decay(entry["last_seen_ts"], now)
        score = max(0.0, min(1.0, base * confidence * decay))
        age_days = max(0.0, (now - entry["last_seen_ts"]) / 86400.0) if entry["last_seen_ts"] else 0.0
        return {
            "subnet": key,
            "score": score,
            "samples": samples,
            "connect_rate": connect_rate,
            "pass_rate": pass_rate,
            "avg_speed": avg_speed,
            "avg_latency": avg_latency,
            "last_pass_ts": entry["last_pass_ts"],
            "last_seen_ts": entry["last_seen_ts"],
            "age_days": age_days,
        }

    def all_scores(self, now: Optional[float] = None) -> List[Dict[str, float]]:
        with self._lock:
            if not self._loaded:
                self.load()
            return [self.score_entry(key, now) for key in self._subnets]

    def top_subnets(self, limit: int = 40, now: Optional[float] = None) -> List[Dict[str, float]]:
        scored = [s for s in self.all_scores(now=now) if s["score"] > 0]
        scored.sort(key=lambda s: (s["score"], s["last_pass_ts"]), reverse=True)
        return scored[: max(0, int(limit))]

    def summary(self, top: int = 5) -> str:
        tops = self.top_subnets(top)
        if not tops:
            return "历史评分为空（首次运行，将执行 100% 全网随机抽样）"
        parts = []
        for item in tops:
            parts.append(f"{item['subnet']} score={item['score']:.3f} "
                         f"speed={item['avg_speed']:.1f}MB/s lat={item['avg_latency']:.0f}ms")
        return " | ".join(parts)


# --------------------------------------------------------------------------
# Sampling
# --------------------------------------------------------------------------
def _pick_ip_in_network(net: ipaddress.IPv4Network, rng: random.Random) -> str:
    """Random usable-ish host inside a network."""
    if net.num_addresses <= 2:
        return str(net.network_address)
    offset = rng.randrange(1, net.num_addresses - 1)
    return str(net.network_address + offset)


def sample_candidates(store: Optional[SubnetScoreStore], total: int = 2000,
                      exploit_ratio: float = 0.7, top_n: int = 40,
                      rng: Optional[random.Random] = None,
                      networks: Optional[Sequence[ipaddress.IPv4Network]] = None,
                      now: Optional[float] = None) -> List[str]:
    """Generate the IP list handed to cfst.

    ``exploit_ratio`` of the samples come from the best scoring /24 subnets
    (weighted by score), the remainder is uniform over the whole library.
    With no usable history every sample is explore.
    """
    rng = rng or random.Random()
    total = max(1, int(total))
    ratio = max(0.0, min(1.0, float(exploit_ratio)))
    nets = list(networks) if networks else list(CF_NETWORKS)

    tops: List[Dict[str, float]] = []
    if store is not None:
        try:
            tops = store.top_subnets(limit=top_n, now=now)
        except Exception:
            tops = []

    exploit_ratio = ratio if tops else 0.0
    exploit_count = int(round(total * exploit_ratio))
    ips: List[str] = []
    seen = set()
    attempts = 0
    max_attempts = total * 40 + 1000

    if tops and exploit_count > 0:
        weights = [max(1e-6, float(t.get("score", 0.0))) for t in tops]
        subnets = [ipaddress.IPv4Network(t["subnet"]) for t in tops]
        while len(ips) < exploit_count and attempts < max_attempts:
            attempts += 1
            subnet = rng.choices(subnets, weights=weights, k=1)[0]
            ip = _pick_ip_in_network(subnet, rng)
            if ip not in seen and in_library(ip):
                seen.add(ip)
                ips.append(ip)

    # Uniform explore over the collapsed library (weighted by size).
    attempts = 0
    while len(ips) < total and attempts < max_attempts:
        attempts += 1
        net = rng.choices(nets, weights=[n.num_addresses for n in nets], k=1)[0]
        ip = _pick_ip_in_network(net, rng)
        if ip not in seen and in_library(ip):
            seen.add(ip)
            ips.append(ip)

    # Extremely unlikely, but never return fewer than requested if possible.
    if len(ips) < total:
        for net in nets:
            if len(ips) >= total:
                break
            for host_offset in range(1, min(net.num_addresses - 1, 256)):
                ip = str(net.network_address + host_offset)
                if ip not in seen:
                    seen.add(ip)
                    ips.append(ip)
                    if len(ips) >= total:
                        break
    return ips


# --------------------------------------------------------------------------
# Top-N selection with cross-/24 diversity
# --------------------------------------------------------------------------
def select_top_ips(results: Iterable[Dict[str, Any]], count: int = 3,
                   exclude_ips: Optional[Iterable[str]] = None,
                   avoid_subnets: Optional[Iterable[str]] = None,
                   require_distinct_subnet: bool = True,
                   min_speed: float = 0.0) -> List[Dict[str, Any]]:
    """Pick the best rows, preferring one IP per /24 subnet.

    The same-subnet fallback is only used when the candidate pool simply does
    not contain enough distinct subnets (never to pad a healthy pool).
    """
    excluded = {str(ip).strip() for ip in (exclude_ips or []) if ip}
    blocked_subnets = {str(s) for s in (avoid_subnets or []) if s}
    rows: List[Dict[str, Any]] = []
    seen_ips = set()
    for raw in results:
        row = normalize_result(raw if isinstance(raw, dict) else {})
        ip = row["ip"]
        if not ip or ip in excluded or ip in seen_ips or ip == "N/A":
            continue
        if row["speed"] < float(min_speed):
            continue
        subnet = subnet_of(ip)
        if not subnet:
            continue
        seen_ips.add(ip)
        row["subnet"] = subnet
        rows.append(row)

    rows.sort(key=lambda r: (r["speed"], -r["latency"]), reverse=True)
    chosen: List[Dict[str, Any]] = []
    chosen_subnets = set()

    if require_distinct_subnet:
        for row in rows:
            if len(chosen) >= count:
                break
            if row["subnet"] in chosen_subnets or row["subnet"] in blocked_subnets:
                continue
            row["same_subnet_fallback"] = False
            chosen.append(row)
            chosen_subnets.add(row["subnet"])
        if len(chosen) < count:
            # Prefer other subnets that are only blocked by a retained node's
            # subnet; blocked subnets are the very last resort.
            for allow_blocked in (False, True):
                for row in rows:
                    if len(chosen) >= count:
                        break
                    if any(c["ip"] == row["ip"] for c in chosen):
                        continue
                    subnet_blocked = row["subnet"] in blocked_subnets
                    if subnet_blocked and not allow_blocked:
                        continue
                    row["same_subnet_fallback"] = True
                    chosen.append(row)
    else:
        for row in rows[:count]:
            row["same_subnet_fallback"] = False
            chosen.append(row)
    return chosen
