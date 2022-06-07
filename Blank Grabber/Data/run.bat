@echo off
if not exist activate.bat exit
call activate
cls
if exist pyinstaller.zip title Unpacking Files...
if exist pyinstaller.zip call python unpack.py
if exist pyinstaller.zip del unpack.py
if exist pyinstaller.zip del pyinstaller.zip
if exist dep.bat call dep
if exist dep.bat del dep.bat
cls
call convert
