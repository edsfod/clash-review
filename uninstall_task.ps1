# uninstall_task.ps1 - stop the resident watcher and remove both scheduled tasks
$ErrorActionPreference = "Stop"
if (Get-ScheduledTask -TaskName "ClashVerge-LeakScan" -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName "ClashVerge-LeakScan"
    Unregister-ScheduledTask -TaskName "ClashVerge-LeakScan" -Confirm:$false
    Write-Host "Removed scheduled task ClashVerge-LeakScan (watcher stopped)" -ForegroundColor Green
}
# monthly ip2asn refresh task (registered via schtasks)
schtasks.exe /Delete /TN "ClashVerge-IPData-Update" /F 2>$null | Out-Null
Write-Host "Removed scheduled task ClashVerge-IPData-Update" -ForegroundColor Green
