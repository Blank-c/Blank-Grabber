@echo off
cd /d %~dp0

:: Check for Python
where python > nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed! (Go to https://www.python.org/downloads and install the latest version.^)
    goto ERROR
)

:: Check for libraries
title Checking for libraries...
pip show customtkinter > nul 2>&1
if %errorlevel% neq 0 (
    title Installing missing libraries...
    pip install customtkinter
)

pip show pillow > nul 2>&1
if %errorlevel% neq 0 (
    title Installing missing libraries...
    pip install pillow
)

cls
:: Run the builder
title Starting builder...
python gui.py
if %errorlevel% neq 0 goto ERROR
exit

:ERROR
color 4 && title [Error]
pause > nul