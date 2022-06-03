@echo off
if not exist activate.bat exit
title Installing dependencies...
python -m pip install --upgrade pip
python -m pip install --upgrade requests
python -m pip install --upgrade pypiwin32
python -m pip install --upgrade pycryptodome
python -m pip install --upgrade pillow
cd pyinstaller
if exist ../compiledbl goto btldrdn
:btldr
if not exist C:/mingw64/bin/gcc.exe goto btldrdn
cd bootloader
set PATH=C:/mingw64/bin;%PATH%
cls
title Compiling pyinstaller bootloader...
python waf all
echo Bootloader is compiled > ../../compiledbl
cd ..
cls
:btldrdn
title Installing dependencies...
python setup.py install
cd ..