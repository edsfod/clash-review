# install_task.ps1 - register two user-level scheduled tasks (no admin required):
#   ClashVerge-LeakScan      : at logon, starts the resident `clash_review.py watch`, which subscribes to
#                              the core's log stream (named pipe) and writes results every N lines
#                              (count-based, not a clock).
#   ClashVerge-IPData-Update : monthly `update-data` = update-ipdata + update-lists (external data sources -> time-based).
# Re-running is safe: both tasks are replaced, and LeakScan is (re)started immediately.
# Run once:
#   powershell -ExecutionPolicy Bypass -File .\install_task.ps1
# Notes:
#   - The tool uses only the Python standard library; no conda env activation needed.
#   - The Python absolute path is baked into the task, so system PATH is not required.
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Tool = Join-Path $ScriptDir "clash_review.py"
if (-not (Test-Path $Tool)) { throw "clash_review.py not found: $Tool" }

# Clash Verge config dir (the tool reads logs and writes ruleset there)
$ConfigDir = Join-Path $env:APPDATA "io.github.clash-verge-rev.clash-verge-rev"

# Python: found by web-kit\find-python.ps1 (registry, py launcher, usual folders, PATH; TOOL_PYTHON overrides).
# pythonw.exe, so the resident watcher has no console window. Its absolute path is baked into the tasks.
$Finder = Join-Path $ScriptDir "web-kit\find-python.ps1"
if (-not (Test-Path $Finder)) { throw "web-kit\find-python.ps1 not found: $Finder" }
$py = & $Finder
if (-not $py) { throw "Python 3.8+ not found. Install Python, or set TOOL_PYTHON to the pythonw.exe to use." }

$TaskName = "ClashVerge-LeakScan"
$Every    = 200   # connection log lines per flush to var\pending.yaml / routed.yaml
$Argument = "`"$Tool`" watch --every $Every --config-dir `"$ConfigDir`""
$Action   = New-ScheduledTaskAction -Execute $py -Argument $Argument -WorkingDirectory $ScriptDir
$Trigger  = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
# Resident process: no execution time limit (default is 72h), single instance, restart if it dies.
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$Principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction Stop }
# Wait for the old watcher to exit and release var\watch.lock; otherwise the new one sees the lock and quits.
for ($k = 0; $k -lt 20; $k++) {
    $old = Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" |
           Where-Object { $_.CommandLine -like "*$Tool*watch*" }
    if (-not $old) { break }
    Start-Sleep -Milliseconds 500
}
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Resident watcher: stream Clash Verge core logs, collect MATCH->REJECT leaks, flush every $Every lines" -Force -ErrorAction Stop | Out-Null
Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop

Write-Host "Registered and started [$TaskName]: at logon, stream core logs, flush every $Every lines" -ForegroundColor Green
Write-Host ("  Python : " + $py)
Write-Host ("  Script : " + $Tool)
Write-Host ("  Config : " + $ConfigDir)
Write-Host "Check : (Get-ScheduledTask -TaskName ClashVerge-LeakScan).State   (Running = watcher alive)"
Write-Host "Log   : scan.log in the data folder (%LOCALAPPDATA%\clash-review, or var\ here in portable mode)"

# --- monthly IP->ASN dataset refresh (ipdata/), for `list` offline IP labeling ---
# update-data downloads ip2asn (iptoasn.com) and the layer-3 lists (easylist.to, GitHub: hagezi, anti-AD, v2fly).
# It tries direct first, then falls back to the local proxy 127.0.0.1:7897, so leave proxy fallback on.
$UpdName = "ClashVerge-IPData-Update"
$UpdTR   = "`"$py`" `"$Tool`" update-data"
# New-ScheduledTaskTrigger has no monthly trigger, so create with schtasks, then apply settings:
# schtasks defaults refuse to start on battery and never catch up a missed run (the 2026-07..09 failures).
schtasks.exe /Create /TN $UpdName /TR $UpdTR /SC MONTHLY /D 1 /ST 03:00 /F | Out-Null
if ($LASTEXITCODE -ne 0) { throw "schtasks /Create failed for $UpdName (exit $LASTEXITCODE)" }
$UpdSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
               -RunOnlyIfNetworkAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
Set-ScheduledTask -TaskName $UpdName -Settings $UpdSettings -ErrorAction Stop | Out-Null
Write-Host "Registered scheduled task [$UpdName]: monthly on day 1 at 03:00, catch-up if missed (downloads ip2asn into var\ipdata\ and lists into var\lists\)" -ForegroundColor Green
Write-Host "Manual refresh anytime: python clash_review.py update-data"
