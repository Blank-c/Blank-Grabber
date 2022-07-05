@echo off
if not exist activate.bat exit
call activate
cls
if exist unpack.py title Unpacking Files...
if exist unpack.py call python unpack.py
if exist unpack.py del pyaes.zip
if exist unpack.py del unpack.py
if exist dep.bat call dep
if exist dep.bat del dep.bat
cls
call convert
