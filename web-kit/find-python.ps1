# find-python.ps1 - print the path of a usable Python 3.8+ interpreter (pythonw.exe by default).
# Used by each tool's launcher (.bat) and scheduled-task installer, so no machine path is hard-coded.
#   powershell -NoProfile -ExecutionPolicy Bypass -File find-python.ps1            -> pythonw.exe (no console)
#   powershell -NoProfile -ExecutionPolicy Bypass -File find-python.ps1 -Console   -> python.exe
# Exit code 1 and a message on stderr when nothing is found.
#
# Search order (first hit wins):
#   1. $env:TOOL_PYTHON: a python(w).exe, or the folder that holds it (manual override)
#   1b. <tool>\python\: the embeddable Python shipped in the release zip (see pack.py)
#   2. Registered installs (PEP 514: HKCU / HKLM \Software\Python\<company>\<version>\InstallPath),
#      newest version first. python.org and Miniforge/Anaconda installers register here.
#   3. The py launcher (py -3)
#   4. Usual install folders: %LOCALAPPDATA%\Programs\Python\Python3*, %USERPROFILE%\{miniforge3,miniconda3,anaconda3}
#   5. python.exe on PATH, skipping the Microsoft Store stub (WindowsApps)
# PATH comes last on purpose: programs such as Inkscape put their own bundled python on PATH.
param([switch]$Console)
$ErrorActionPreference = 'SilentlyContinue'
$exe = if ($Console) { 'python.exe' } else { 'pythonw.exe' }

function Test-Py([string]$dir) {
    if (-not $dir) { return $null }
    $p = Join-Path $dir $exe
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $null }
    $console = Join-Path $dir 'python.exe'
    if (Test-Path -LiteralPath $console -PathType Leaf) {
        & $console -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { return $null }
    }
    return $p
}

function Out-Found([string]$p) { Write-Output $p; exit 0 }

# 1. manual override
if ($env:TOOL_PYTHON) {
    $o = $env:TOOL_PYTHON.Trim('"')
    $dir = if (Test-Path -LiteralPath $o -PathType Leaf) { Split-Path -Parent $o } else { $o }
    $p = Test-Py $dir; if ($p) { Out-Found $p }
    [Console]::Error.WriteLine("TOOL_PYTHON=$($env:TOOL_PYTHON) has no usable $exe (Python 3.8+); searching elsewhere")
}

# 1b. bundled: this script lives in <tool>\web-kit\, the release zip puts Python in <tool>\python\
$p = Test-Py (Join-Path (Split-Path -Parent $PSScriptRoot) 'python'); if ($p) { Out-Found $p }

# 2. PEP 514 registry
$found = @()
foreach ($root in 'HKCU:\Software\Python', 'HKLM:\Software\Python', 'HKLM:\Software\WOW6432Node\Python') {
    foreach ($company in Get-ChildItem -LiteralPath $root) {
        if ($company.PSChildName -eq 'PyLauncher') { continue }
        foreach ($tag in Get-ChildItem -LiteralPath $company.PSPath) {
            $ip = Get-ItemProperty -LiteralPath (Join-Path $tag.PSPath 'InstallPath')
            if (-not $ip) { continue }
            $dir = $ip.'(default)'
            if (-not $dir -and $ip.ExecutablePath) { $dir = Split-Path -Parent $ip.ExecutablePath }
            $v = [version]'0.0'
            if ($tag.PSChildName -match '^(\d+)\.(\d+)') { $v = [version]"$($Matches[1]).$($Matches[2])" }
            $found += [pscustomobject]@{ dir = $dir; ver = $v }
        }
    }
}
foreach ($f in $found | Sort-Object ver -Descending) { $p = Test-Py $f.dir; if ($p) { Out-Found $p } }

# 3. py launcher
$py = Get-Command py.exe -CommandType Application | Select-Object -First 1
if ($py) {
    $pe = & $py.Source -3 -c "import sys; print(sys.executable)" 2>$null
    if ($LASTEXITCODE -eq 0 -and $pe) { $p = Test-Py (Split-Path -Parent ($pe | Select-Object -First 1)); if ($p) { Out-Found $p } }
}

# 4. usual folders
$dirs = @()
$dirs += Get-ChildItem -Directory -Path (Join-Path $env:LOCALAPPDATA 'Programs\Python') -Filter 'Python3*' |
         Sort-Object Name -Descending | ForEach-Object { $_.FullName }
$dirs += 'miniforge3', 'miniconda3', 'anaconda3' | ForEach-Object { Join-Path $env:USERPROFILE $_ }
foreach ($d in $dirs) { $p = Test-Py $d; if ($p) { Out-Found $p } }

# 5. PATH, without the Store stub
foreach ($c in Get-Command python.exe -CommandType Application -All) {
    if ($c.Source -like '*\WindowsApps\*') { continue }
    $p = Test-Py (Split-Path -Parent $c.Source); if ($p) { Out-Found $p }
}

[Console]::Error.WriteLine("No Python 3.8+ found. Install Python, or set TOOL_PYTHON to the python.exe to use.")
exit 1
