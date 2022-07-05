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
title Installing dependencies... (7/7)
cd pyinstaller
python setup.py install
cd ..
rmdir /S /Q pyaes
rmdir /S /Q pyinstaller