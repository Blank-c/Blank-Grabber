@echo off
cd /d %~dp0
python gui.py
if not %errorlevel%==0 (
    color 4 && title Error
    pause > NUL
)