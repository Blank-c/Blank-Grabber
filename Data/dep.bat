@echo off
if not exist activate.bat exit
title Installing dependencies...
python -m pip install --upgrade pip
python -m pip install --upgrade requests
python -m pip install --upgrade pypiwin32
python -m pip install --upgrade pycryptodome
python -m pip install --upgrade pillow
cd pyinstaller
python setup.py install
cd ..