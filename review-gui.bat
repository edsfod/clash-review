@echo off
rem Start the web UI in the background (pythonw, no console window); this window closes at once.
rem Stop: pythonw clash_review_web.py --stop. It also exits by itself after 30 idle minutes.
rem Startup errors show a dialog; log: var\web.log.
rem Python is found by web-kit\find-python.ps1 (registry, py launcher, usual folders, PATH);
rem to force one, set TOOL_PYTHON to its python.exe / pythonw.exe.
setlocal
set "HERE=%~dp0"
set "PYW="
for /f "usebackq delims=" %%P in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%web-kit\find-python.ps1"`) do set "PYW=%%P"
if not defined PYW (
    echo [!] No Python 3.8+ found. Install Python, or set TOOL_PYTHON to the pythonw.exe to use.
    pause
    exit /b 1
)
start "" "%PYW%" "%HERE%clash_review_web.py" %*
