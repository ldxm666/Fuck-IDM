@echo off
chcp 65001 >nul
setlocal
title IDM-Unlock

set "HERE=%~dp0"
set "PY="

rem --- locate a usable Python 3 ---
for %%P in (python.exe py.exe) do (
    if not defined PY (
        where %%P >nul 2>nul && set "PY=%%P"
    )
)
if not defined PY (
    if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
)
if not defined PY (
    echo [X] Python 3 not found. Install Python 3 and make sure it is on PATH.
    echo.
    pause
    exit /b 1
)

rem --- no arguments: safe default = analyse only ---
if "%~1"=="" (
    echo.
    echo   IDM-Unlock  -  analyse only ^(no changes^)
    echo   To actually apply:  run  IDM-Unlock.cmd --apply
    echo.
    "%PY%" "%HERE%IDM-Unlock.py" --scan
) else (
    "%PY%" "%HERE%IDM-Unlock.py" %*
)

echo.
echo ================================================================
echo   Done.  Exit code: %ERRORLEVEL%
echo   scan = analyse only   /   apply = patch   /   restore = revert
echo ================================================================
pause
endlocal
