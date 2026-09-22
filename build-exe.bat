@echo off
REM Build e01-check.exe (Windows). Must be run on Windows.
REM Produces dist\e01-check.exe

setlocal
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
    echo Python not found on PATH. Install Python 3.10+ from python.org first.
    exit /b 1
)

if not exist ".venv-build" (
    echo Creating build virtualenv...
    python -m venv .venv-build
)

call .venv-build\Scripts\activate.bat

echo Installing build dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements-build.txt

echo Building e01-check.exe...
python -m PyInstaller --noconfirm --clean e01-check.spec

echo.
echo Done. Binary at: dist\e01-check.exe
endlocal