$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$desktops = @("E:\desktop", "C:\Users\iser\Desktop")
$targetExe = "C:\Users\iser\.gemini\antigravity\scratch\CF-FlClash-Optimizer\dist\CF-FlClash-Optimizer.exe"
$workingDir = "C:\Users\iser\.gemini\antigravity\scratch\CF-FlClash-Optimizer\dist"

$wsh = New-Object -ComObject WScript.Shell

foreach ($d in $desktops) {
    if (Test-Path $d) {
        # Clean up any malformed shortcuts
        Get-ChildItem $d -Filter "*CF*.lnk" | Remove-Item -Force -ErrorAction SilentlyContinue

        $shortcutName = [System.Text.Encoding]::UTF8.GetString([System.Text.Encoding]::UTF8.GetBytes("CF优选与多端同步工具.lnk"))
        $shortcutPath = Join-Path $d $shortcutName
        $shortcut = $wsh.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $targetExe
        $shortcut.WorkingDirectory = $workingDir
        $shortcut.Description = "Cloudflare 优选 IP 体检、多端配置导出与国际网站实测工具"
        $shortcut.Save()

        $folderName = [System.Text.Encoding]::UTF8.GetString([System.Text.Encoding]::UTF8.GetBytes("CF导出配置"))
        $exportPath = Join-Path $d $folderName
        if (-not (Test-Path $exportPath)) {
            New-Item -ItemType Directory -Path $exportPath -Force | Out-Null
        }
        Write-Host "Created shortcut: $shortcutPath"
        Write-Host "Created folder: $exportPath"
    }
}
