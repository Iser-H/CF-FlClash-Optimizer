# -*- coding: utf-8 -*-
"""Create clean desktop shortcuts and remove garbled files."""

import os
import shutil
import subprocess

from path_utils import get_desktop_dir

def create_shortcuts():
    base = os.path.dirname(os.path.abspath(__file__))
    target_exe = os.path.join(base, "dist", "CF-FlClash-Optimizer.exe")
    working_dir = os.path.dirname(target_exe)
    desktops = [get_desktop_dir()]

    for d in desktops:
        if not os.path.exists(d):
            continue

        # Clean up any malformed / garbled entries
        for fname in os.listdir(d):
            if "CF" in fname:
                full = os.path.join(d, fname)
                try:
                    if os.path.isdir(full) and ("瀵" in fname or "" in fname):
                        shutil.rmtree(full, ignore_errors=True)
                    elif os.path.isfile(full) and ("浼" in fname or "" in fname):
                        os.remove(full)
                except Exception:
                    pass

        # Create properly encoded shortcut using Windows Script Host via PowerShell with proper string
        shortcut_names = ["CF-FlClash-Optimizer.lnk", "CF优选与多端同步工具.lnk"]
        for sname in shortcut_names:
            s_path = os.path.join(d, sname)
            ps_script = f'''
$wsh = New-Object -ComObject WScript.Shell
$sc = $wsh.CreateShortcut('{s_path}')
$sc.TargetPath = '{target_exe}'
$sc.WorkingDirectory = '{working_dir}'
$sc.Description = 'Cloudflare 优选 IP 体检与多端配置导出工具'
$sc.Save()
'''
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            print(f"Created shortcut: {s_path}")

        export_dir = os.path.join(d, "CF导出配置")
        os.makedirs(export_dir, exist_ok=True)
        print(f"Created clean export folder: {export_dir}")

if __name__ == "__main__":
    create_shortcuts()
