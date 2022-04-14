@echo off
title Installing requirements...
pip install --upgrade requests
pip install --upgrade pyinstaller
pip install --upgrade pypiwin32
pip install --upgrade virtualenv
pip install --upgrade pycryptodome
pip install --upgrade pillow
cls
echo Done! (press any key to exit)
pause >> NUL
