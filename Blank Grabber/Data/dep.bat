@echo off
if not exist activate.bat exit
title Installing dependencies... (1/5)
python -m pip install --upgrade pip
title Installing dependencies... (2/5)
python -m pip install --upgrade urllib3
title Installing dependencies... (3/5)
python -m pip install --upgrade pillow
title Installing dependencies... (4/5)
python -m pip install --upgrade tinyaes
title Installing dependencies... (5/5)
cd pyinstaller
python setup.py install
cd ..
rmdir /S /Q pyinstaller
