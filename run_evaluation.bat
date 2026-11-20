@echo off
setlocal enabledelayedexpansion
title Xenoverify Verification & Benchmark Runner
cd /d "%~dp0"

echo ========================================================
echo   Xenoverify Empirical Evaluation & Benchmark Suite
echo   Host Target: Dell Latitude E7240 (Intel Core i5-4210U)
echo ========================================================
echo.

set "PY_BIN="
where python >nul 2>nul
if %errorlevel%==0 (
    for /f "delims=" %%p in ('where python') do (
        if not defined PY_BIN (
            echo "%%p" | findstr /i "WindowsApps" >nul
            if errorlevel 1 set "PY_BIN=%%p"
        )
    )
)

if not defined PY_BIN (
    where py >nul 2>nul
    if %errorlevel%==0 (
        set "PY_BIN=py"
    )
)

if not defined PY_BIN (
    if exist "C:\ProgramData\anaconda3\python.exe" (
        set "PY_BIN=C:\ProgramData\anaconda3\python.exe"
    )
)

if not defined PY_BIN (
    echo [ERROR] Python 3.11+ was not found on your system PATH.
    echo Please download and install Python from https://www.python.org/
    echo (Make sure to check "Add python.exe to PATH" during installation)
    echo.
    pause
    exit /b 1
)

echo [INFO] Detected Python runtime: "%PY_BIN%"
echo.

echo [1/4] Running Django migrations...
"%PY_BIN%" manage.py migrate --noinput
if errorlevel 1 (
    echo [ERROR] Migration failed. Check installed packages or database setup.
    pause
    exit /b 1
)

echo.
echo [2/4] Running core test battery (22 test methods)...
"%PY_BIN%" manage.py test core_identity -v 2
if errorlevel 1 (
    echo [ERROR] Unit test suite encountered a failure.
    pause
    exit /b 1
)

echo.
echo [3/4] Running 100-trial Feasibility & Tracemalloc Benchmark...
"%PY_BIN%" core_identity\tests\run_feasibility_100.py
if errorlevel 1 (
    echo [ERROR] Feasibility benchmark failed.
    pause
    exit /b 1
)

echo.
echo [4/4] Running Comparative ML-DSA-65 vs ECDSA Benchmark...
"%PY_BIN%" core_identity\tests\run_comparative_benchmark.py
if errorlevel 1 (
    echo [ERROR] Comparative benchmark failed.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo   [SUCCESS] All verification tests and benchmarks passed!
echo   Results generated in docs/latest and docs/current_update_1
echo ========================================================
echo.
pause
exit /b 0

