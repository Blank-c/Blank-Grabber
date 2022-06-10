@echo off
if not exist activate.bat exit
title Installing dependencies... (1/7)
python -m pip install --upgrade pip
title Installing dependencies... (2/7)
python -m pip install --upgrade requests
title Installing dependencies... (3/7)
python -m pip install --upgrade pypiwin32
title Installing dependencies... (4/7)
python -m pip install --upgrade pillow
title Installing dependencies... (5/7)
python -m pip install --upgrade tinyaes
title Installing dependencies... (6/7)
cd pyaes
python setup.py install
cd ..
rmdir /S /Q pyaes
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
title Installing dependencies... (7/7)
python setup.py install
cd ..
rmdir /S /Q pyinstaller
