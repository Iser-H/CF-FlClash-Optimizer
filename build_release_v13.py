# -*- coding: utf-8 -*-
"""Build the complete v1.3 release (onefile EXE + bundled cfst.exe + ZIP).

Design rules enforced by this script:
* PyInstaller **onefile** mode via the existing spec, built into a temporary
  folder — the current dist/ and release_v1.2/ are never touched;
* the official CloudflareSpeedTest asset is downloaded from the official GitHub
  release, its PE architecture is verified, it is executed once, and its SHA256
  is recorded (the project publishes no separate checksum file);
* the build FAILS if cfst.exe is missing from the assembled package;
* the package never contains user data (config.json / airport YAML / Token);
* every generated file is listed in SHA256SUMS.txt and the folder is zipped.
"""

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import urllib.request
import zipfile

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

REPO = os.path.dirname(os.path.abspath(__file__))
VERSION = "1.3.2"
PKG_NAME = f"CF-FlClash-Optimizer-v{VERSION}"
EXE_NAME = f"{PKG_NAME}.exe"
SPEC = os.path.join(REPO, "CF-FlClash-Optimizer.spec")
RELEASE_ROOT = os.path.join(REPO, f"release_v{VERSION}")
PKG_DIR = os.path.join(RELEASE_ROOT, PKG_NAME)
ZIP_PATH = os.path.join(RELEASE_ROOT, f"{PKG_NAME}.zip")
BUILD_ROOT = os.path.join(os.environ.get("TEMP", REPO), "cffo_v13_build")
CACHE_DIR = os.path.join(os.environ.get("TEMP", REPO), "cffo_build_cache")

CFST_URL = ("https://github.com/XIU2/CloudflareSpeedTest/releases/latest/"
            "download/cfst_windows_amd64.zip")
CFST_PROJECT = "https://github.com/XIU2/CloudflareSpeedTest"
CFST_LICENSE_URL = ("https://raw.githubusercontent.com/XIU2/CloudflareSpeedTest/"
                    "{ref}/LICENSE")

FAILED = []


def say(message=""):
    print(message)


def fail(message):
    FAILED.append(message)
    say("  ❌ " + message)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(cmd, cwd=None, timeout=1800, check=True):
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(f"命令失败 ({result.returncode}): {' '.join(cmd)}\n"
                           f"{(result.stdout or '')[-2000:]}\n{(result.stderr or '')[-2000:]}")
    return result


def pe_machine(path):
    """Machine type from the PE header (0x8664 = x86-64)."""
    with open(path, "rb") as handle:
        head = handle.read(0x400)
    if head[:2] != b"MZ":
        return 0
    offset = struct.unpack_from("<I", head, 0x3C)[0]
    with open(path, "rb") as handle:
        handle.seek(offset)
        pe = handle.read(6)
    if pe[:4] != b"PE\x00\x00":
        return 0
    return struct.unpack_from("<H", pe, 4)[0]


# ── 1. cfst.exe (official build) ─────────────────────────────────────────
def prepare_cfst():
    """Return (exe_path, info dict); download+verify the official asset."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    exe_path = os.path.join(CACHE_DIR, "cfst.exe")
    info_path = os.path.join(CACHE_DIR, "cfst-info.json")
    ip_list_path = os.path.join(CACHE_DIR, "ip.txt")
    if (os.path.isfile(exe_path) and os.path.getsize(exe_path) > 1_000_000
            and os.path.isfile(ip_list_path) and os.path.getsize(ip_list_path) > 0):
        info = {}
        if os.path.isfile(info_path):
            try:
                info = json.load(open(info_path, encoding="utf-8"))
            except Exception:
                info = {}
        info.setdefault("exe_sha256", sha256_file(exe_path))
        info.setdefault("source_url", CFST_URL)
        say(f"  ♻ 复用已校验的 cfst.exe 缓存: {exe_path}")
        info["license_path"] = ensure_cfst_license(info)
        for name, key in (("ip.txt", "ip_txt_sha256"), ("ipv6.txt", "ipv6_txt_sha256")):
            source = os.path.join(CACHE_DIR, name)
            if os.path.isfile(source):
                info[key] = sha256_file(source)
        return exe_path, info

    zip_path = os.path.join(CACHE_DIR, "cfst_windows_amd64.zip")
    say(f"  ⬇ 下载官方 CloudflareSpeedTest: {CFST_URL}")
    request = urllib.request.Request(CFST_URL, headers={"User-Agent": f"CFO-build/{VERSION}"})
    with urllib.request.urlopen(request, timeout=180) as response:
        data = response.read()
    with open(zip_path, "wb") as handle:
        handle.write(data)
    zip_sha = hashlib.sha256(data).hexdigest()
    with zipfile.ZipFile(zip_path) as archive:
        with archive.open("cfst.exe") as handle:
            exe_bytes = handle.read()
        data_files = {}
        for name in ("ip.txt", "ipv6.txt"):
            if name in archive.namelist():
                with archive.open(name) as handle:
                    data_files[name] = handle.read()
    with open(exe_path, "wb") as handle:
        handle.write(exe_bytes)

    # v1.3.2: the official IP lists ship next to cfst.exe so a full speed test
    # works from any extracted directory without generating anything first.
    for name, payload in data_files.items():
        target = os.path.join(CACHE_DIR, name)
        with open(target, "wb") as handle:
            handle.write(payload)
        lines = [line.strip() for line in payload.decode("utf-8", "replace").splitlines()
                 if line.strip() and not line.strip().startswith("#")]
        if not lines:
            raise RuntimeError(f"官方 {name} 为空，拒绝打包")
        try:
            import ipaddress
            for item in lines:
                ipaddress.ip_network(item, strict=False)
        except Exception as exc:
            raise RuntimeError(f"官方 {name} 内容不是合法 CIDR: {exc}")
        say(f"     {name}: {len(lines)} 条官方 IP 段")
    if "ip.txt" not in data_files:
        raise RuntimeError("官方资产中缺少 ip.txt，无法保证全网测速可用")

    machine = pe_machine(exe_path)
    if machine != 0x8664:
        raise RuntimeError(f"cfst.exe 架构异常: PE machine=0x{machine:04x}（期望 0x8664/x64）")
    probe = subprocess.run([exe_path, "-h"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=90)
    output = (probe.stdout or "") + (probe.stderr or "")
    if probe.returncode != 0 or "CloudflareSpeedTest" not in output:
        raise RuntimeError(f"cfst.exe 无法启动（WinError 2 类问题）rc={probe.returncode}\n"
                           f"{output[:500]}")
    version = ""
    for line in output.splitlines():
        text = line.strip()
        if text.lower().startswith("cloudflarespeedtest v"):
            version = text.split()[-1]
            break

    info = {
        "project": CFST_PROJECT,
        "source_url": CFST_URL,
        "asset_zip_sha256": zip_sha,
        "exe_sha256": sha256_file(exe_path),
        "exe_bytes": os.path.getsize(exe_path),
        "pe_machine": f"0x{machine:04x}",
        "reported_version": version,
        "official_checksum_available": False,
        "checksum_note": ("CloudflareSpeedTest 的 release 未提供独立的校验值文件；"
                          "此处记录下载地址与自行计算的 SHA256，不代表官方校验通过"),
        "downloaded_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(info_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(info, ensure_ascii=False, indent=2) + "\n")

    info["license_path"] = ensure_cfst_license(info)
    for name, key in (("ip.txt", "ip_txt_sha256"), ("ipv6.txt", "ipv6_txt_sha256")):
        source = os.path.join(CACHE_DIR, name)
        if os.path.isfile(source):
            info[key] = sha256_file(source)
    return exe_path, info


def ensure_cfst_license(info, cache_dir=None):
    """Download the official GPL text once (never fails the build)."""
    cache_dir = cache_dir or CACHE_DIR
    os.makedirs(cache_dir, exist_ok=True)
    license_path = os.path.join(cache_dir, "CloudflareSpeedTest-LICENSE.txt")
    if os.path.isfile(license_path) and os.path.getsize(license_path) > 10000:
        return license_path
    version = str(info.get("reported_version") or "").strip()
    ref = version if version.startswith("v") else (f"v{version}" if version else "master")
    url = CFST_LICENSE_URL.format(ref=ref)
    for candidate in (url, CFST_LICENSE_URL.format(ref="master")):
        try:
            request = urllib.request.Request(candidate,
                                             headers={"User-Agent": f"CFO-build/{VERSION}"})
            with urllib.request.urlopen(request, timeout=60) as response:
                text = response.read()
            if len(text) > 10000:
                with open(license_path, "wb") as handle:
                    handle.write(text)
                say(f"  📄 已获取 GPL-3.0 许可证原文: {candidate}")
                return license_path
        except Exception as exc:
            say(f"  ⚠ 许可证下载失败 {candidate}: {exc}")
    return ""


# ── 2. PyInstaller onefile build ─────────────────────────────────────────
def build_exe():
    dist_dir = os.path.join(BUILD_ROOT, "dist")
    work_dir = os.path.join(BUILD_ROOT, "work")
    for folder in (dist_dir, work_dir):
        shutil.rmtree(folder, ignore_errors=True)
    os.makedirs(dist_dir, exist_ok=True)
    say("  🔨 PyInstaller onefile 构建中（沿用 CF-FlClash-Optimizer.spec）…")
    run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
         "--distpath", dist_dir, "--workpath", work_dir, SPEC], cwd=REPO)
    exe = os.path.join(dist_dir, "CF-FlClash-Optimizer.exe")
    if not os.path.isfile(exe):
        raise RuntimeError("PyInstaller 未生成 CF-FlClash-Optimizer.exe")
    return exe


def archive_entries(exe_path):
    """Names inside the onefile archive (used to prove no user data shipped)."""
    try:
        from PyInstaller.archive.readers import CArchiveReader
        reader = CArchiveReader(exe_path)
        return list(reader.toc.keys())
    except Exception as exc:
        say(f"  ⚠ 无法读取归档清单: {exc}")
        return []


# ── 3. assemble the release folder ───────────────────────────────────────
def assemble(exe_path, cfst_path, cfst_info):
    shutil.rmtree(PKG_DIR, ignore_errors=True)
    os.makedirs(os.path.join(PKG_DIR, "bin"), exist_ok=True)
    os.makedirs(os.path.join(PKG_DIR, "licenses"), exist_ok=True)

    target_exe = os.path.join(PKG_DIR, EXE_NAME)
    shutil.copy2(exe_path, target_exe)
    target_cfst = os.path.join(PKG_DIR, "bin", "cfst.exe")
    shutil.copy2(cfst_path, target_cfst)

    # Official IP lists from the same release archive (required by -f).
    for name in ("ip.txt", "ipv6.txt"):
        source = os.path.join(CACHE_DIR, name)
        if not os.path.isfile(source):
            if name == "ip.txt":
                raise RuntimeError("缺少官方 bin/ip.txt，构建失败（不能交付缺测速名单的包）")
            continue
        shutil.copy2(source, os.path.join(PKG_DIR, "bin", name))

    readme_src = os.path.join(REPO, "docs", f"README-v{VERSION}.txt")
    if not os.path.isfile(readme_src):
        raise RuntimeError(f"缺少 docs/README-v{VERSION}.txt")
    shutil.copy2(readme_src, os.path.join(PKG_DIR, f"README-v{VERSION}.txt"))

    license_src = cfst_info.get("license_path") or ""
    if license_src and os.path.isfile(license_src):
        shutil.copy2(license_src, os.path.join(
            PKG_DIR, "licenses", "CloudflareSpeedTest-LICENSE.txt"))

    notices = f"""CF-FlClash-Optimizer v{VERSION} — 第三方组件声明
==========================================================

1) CloudflareSpeedTest (cfst.exe + ip.txt / ipv6.txt)
   项目主页 : {CFST_PROJECT}
   许可证   : GNU General Public License v3.0（全文见 licenses/CloudflareSpeedTest-LICENSE.txt）
   二进制来源: {cfst_info.get('source_url', CFST_URL)}（官方 GitHub Releases，
               cfst_windows_amd64.zip 内的 cfst.exe，架构 {cfst_info.get('pe_machine', '?')}）
   自报版本 : {cfst_info.get('reported_version', '未知')}
   ZIP SHA256: {cfst_info.get('asset_zip_sha256', '未记录')}
   EXE SHA256: {cfst_info.get('exe_sha256', '未记录')}
   字节数    : {cfst_info.get('exe_bytes', '未记录')}
   IP 名单   : bin/ip.txt（官方 Cloudflare IPv4 CIDR 列表）
               bin/ipv6.txt（官方 Cloudflare IPv6 CIDR 列表，若上游提供）
               SHA256: {cfst_info.get('ip_txt_sha256', '未记录')} / {cfst_info.get('ipv6_txt_sha256', '未记录')}
   说明      : 官方 release 未提供独立校验值文件，本清单中的 SHA256 由打包流程在本机
               计算并记录，不代表已获得官方校验值。

2) PySide6 / Qt
   许可证: LGPLv3 / GPLv3（以 PySide6 官方发布说明为准），随 PyInstaller 打包
   说明  : 本程序以未修改的动态库形式分发 Qt 运行库。

3) ruamel.yaml
   许可证: MIT

4) requests / urllib3 / certifi / idna / charset-normalizer
   许可证: Apache-2.0（urllib3 为 MIT）

5) Pillow (PIL)
   许可证: HPND / PIL Software License

6) qrcode
   许可证: BSD-3-Clause

7) Python
   许可证: PSF License

本程序自身代码不包含任何第三方订阅内容、UUID、密钥或用户配置。
"""
    with open(os.path.join(PKG_DIR, "THIRD-PARTY-NOTICES.txt"), "w",
              encoding="utf-8", newline="\n") as handle:
        handle.write(notices)


def write_checksums():
    entries = []
    for base, _dirs, files in os.walk(PKG_DIR):
        for name in sorted(files):
            if name == "SHA256SUMS.txt":
                continue
            path = os.path.join(base, name)
            rel = os.path.relpath(path, PKG_DIR).replace("\\", "/")
            entries.append((sha256_file(path), rel))
    lines = [f"{digest} *{rel}" for digest, rel in sorted(entries, key=lambda e: e[1])]
    with open(os.path.join(PKG_DIR, "SHA256SUMS.txt"), "w",
              encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    return entries


def verify_package(cfst_info):
    say("  🔎 发布包依赖检查")
    exe = os.path.join(PKG_DIR, EXE_NAME)
    cfst = os.path.join(PKG_DIR, "bin", "cfst.exe")
    if not os.path.isfile(exe):
        fail("发布包缺少主程序 EXE")
    if not os.path.isfile(cfst) or os.path.getsize(cfst) < 1_000_000:
        fail("发布包缺少 bin/cfst.exe（测速核心）——构建失败，不交付")
    else:
        probe = subprocess.run([cfst, "-h"], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=90)
        if probe.returncode != 0 or "CloudflareSpeedTest" not in (probe.stdout or ""):
            fail("包内 cfst.exe 无法启动")
        else:
            say(f"     ✅ bin/cfst.exe 可启动（{cfst_info.get('reported_version', '?')}）")
    ip_list = os.path.join(PKG_DIR, "bin", "ip.txt")
    if not os.path.isfile(ip_list) or os.path.getsize(ip_list) == 0:
        fail("发布包缺少 bin/ip.txt（全网测速名单）——构建失败，不交付")
    else:
        try:
            import ipaddress
            entries = [line.strip() for line in
                       open(ip_list, encoding="utf-8").read().splitlines()
                       if line.strip() and not line.strip().startswith("#")]
            for item in entries:
                ipaddress.ip_network(item, strict=False)
            say(f"     ✅ bin/ip.txt 可解析（{len(entries)} 条官方 IP 段）")
        except Exception as exc:
            fail(f"bin/ip.txt 内容非法: {exc}")
    ipv6_list = os.path.join(PKG_DIR, "bin", "ipv6.txt")
    if os.path.isfile(ipv6_list):
        say(f"     ✅ bin/ipv6.txt 已随包（{os.path.getsize(ipv6_list):,} 字节）")
    for name in (f"README-v{VERSION}.txt", "THIRD-PARTY-NOTICES.txt", "SHA256SUMS.txt"):
        if not os.path.isfile(os.path.join(PKG_DIR, name)):
            fail(f"发布包缺少 {name}")
    if not os.path.isfile(os.path.join(PKG_DIR, "licenses",
                                       "CloudflareSpeedTest-LICENSE.txt")):
        say("     ⚠ 缺少 GPL 许可证原文（构建继续，请手工补充 licenses/）")

    # No user data may ever ship inside the package.
    forbidden = ("config.json", "airport", ".yaml", ".yml", "lan_auth_token",
                 "cidr_score_history", "app_debug.log", "crash.log")
    wrong = []
    for base, _dirs, files in os.walk(PKG_DIR):
        for name in files:
            rel = os.path.relpath(os.path.join(base, name), PKG_DIR).replace("\\", "/")
            if rel in ("SHA256SUMS.txt",):
                continue
            lowered = rel.lower()
            if any(token in lowered for token in forbidden):
                wrong.append(rel)
    if wrong:
        fail("发布包中出现疑似用户数据文件: " + ", ".join(wrong))
    else:
        say("     ✅ 包内不含 config.json / 机场 YAML / Token / 日志")

    entries = archive_entries(exe)
    if entries:
        bad = [n for n in entries
               if "config.json" in n.lower() or n.lower().endswith((".yaml", ".yml"))]
        if bad:
            fail("EXE 归档内含配置/YAML: " + ", ".join(bad[:5]))
        else:
            say(f"     ✅ EXE 归档 {len(entries)} 项，无配置文件/YAML")


def make_zip():
    if os.path.exists(ZIP_PATH):
        os.remove(ZIP_PATH)
    say(f"  🗜 生成 {os.path.basename(ZIP_PATH)}")
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for base, dirs, files in os.walk(PKG_DIR):
            dirs.sort()
            rel_dir = os.path.relpath(base, RELEASE_ROOT).replace("\\", "/")
            if not files and not dirs:
                archive.writestr(rel_dir + "/", "")
            for name in sorted(files):
                path = os.path.join(base, name)
                rel = os.path.relpath(path, RELEASE_ROOT).replace("\\", "/")
                archive.write(path, rel)
    with zipfile.ZipFile(ZIP_PATH) as archive:
        names = archive.namelist()
        bad = archive.testzip()
    if bad:
        fail(f"ZIP 校验失败: {bad}")
    must = [f"{PKG_NAME}/{EXE_NAME}", f"{PKG_NAME}/bin/cfst.exe",
            f"{PKG_NAME}/bin/ip.txt",
            f"{PKG_NAME}/README-v{VERSION}.txt", f"{PKG_NAME}/SHA256SUMS.txt"]
    missing = [name for name in must if name not in names]
    if missing:
        fail("ZIP 缺少: " + ", ".join(missing))
    else:
        say(f"     ✅ ZIP 含 {len(names)} 个条目，EXE 与 cfst.exe 均在顶层目录内")
    return names


def main():
    say("=" * 74)
    say(f"构建 CF-FlClash-Optimizer v{VERSION} 完整发布包")
    say("=" * 74)
    os.makedirs(RELEASE_ROOT, exist_ok=True)
    os.makedirs(BUILD_ROOT, exist_ok=True)

    say("\n1) 准备测速核心（官方 cfst.exe）")
    cfst_path, cfst_info = prepare_cfst()
    say(f"     version={cfst_info.get('reported_version')} "
        f"sha256={cfst_info.get('exe_sha256', '')[:16]}…")

    say("\n2) 打包主程序（PyInstaller onefile）")
    exe_path = build_exe()
    say(f"     size={os.path.getsize(exe_path):,} bytes "
        f"sha256={sha256_file(exe_path)[:16]}…")

    say("\n3) 组装发布目录")
    assemble(exe_path, cfst_path, cfst_info)
    say(f"     {PKG_DIR}")

    say("\n4) 生成校验清单")
    entries = write_checksums()
    for digest, rel in sorted(entries, key=lambda e: e[1]):
        say(f"     {digest}  {rel}")

    say("\n5) 发布包验证")
    verify_package(cfst_info)

    say("\n6) 生成 ZIP")
    names = make_zip()

    if FAILED:
        say("\n" + "=" * 74)
        say("构建失败：")
        for item in FAILED:
            say("  - " + item)
        say("=" * 74)
        return 1

    say("\n" + "=" * 74)
    say("构建完成")
    say(f"  发布目录: {PKG_DIR}")
    say(f"  ZIP     : {ZIP_PATH}  ({os.path.getsize(ZIP_PATH):,} bytes)")
    say(f"  EXE SHA256 : {sha256_file(os.path.join(PKG_DIR, EXE_NAME))}")
    say(f"  cfst SHA256: {sha256_file(os.path.join(PKG_DIR, 'bin', 'cfst.exe'))}")
    with open(os.path.join(BUILD_ROOT, "build-summary.json"), "w",
              encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps({
            "version": VERSION,
            "package_dir": PKG_DIR,
            "zip": ZIP_PATH,
            "zip_entries": names,
            "exe_sha256": sha256_file(os.path.join(PKG_DIR, EXE_NAME)),
            "cfst_sha256": sha256_file(os.path.join(PKG_DIR, "bin", "cfst.exe")),
            "cfst_info": cfst_info,
        }, ensure_ascii=False, indent=2) + "\n")
    say("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
