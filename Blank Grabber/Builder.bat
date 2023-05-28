@echo off
cd /d %~dp0

title Checking Python installation...
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed! (Go to https://www.python.org/downloads and install the latest version.^)
    goto ERROR
)

title Checking libraries...
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
title Starting builder...
python gui.py
if %errorlevel% neq 0 goto ERROR
exit

:ERROR
color 4 && title [Error]
pause > nul