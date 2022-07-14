@echo off
if not exist activate.bat exit
title Installing dependencies... (1/6)
python -m pip install --upgrade pip
title Installing dependencies... (2/6)
python -m pip install --upgrade requests
title Installing dependencies... (3/6)
python -m pip install --upgrade pillow
title Installing dependencies... (4/6)
python -m pip install --upgrade tinyaes
title Installing dependencies... (5/6)
title Installing dependencies... (6/6)
cd pyinstaller
python setup.py install
cd ..
rmdir /S /Q pyinstaller