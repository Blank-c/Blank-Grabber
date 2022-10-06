@echo off
if not exist activate.bat exit
call activate
cls
if exist dep.bat call dep
if exist dep.bat del dep.bat
cls
call convert
exit
