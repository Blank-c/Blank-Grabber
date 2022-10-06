@echo off
if not exist activate.bat exit
title Installing dependencies... (1/8)
python -m pip install --upgrade pip
title Installing dependencies... (2/8)
python -m pip install --upgrade wheel
title Installing dependencies... (3/8)
python -m pip install --upgrade urllib3
title Installing dependencies... (4/8)
python -m pip install --upgrade pillow
title Installing dependencies... (5/8)
python -m pip install --upgrade tinyaes
title Installing dependencies... (6/8)
python -m pip install --upgrade pywin32
title Installing dependencies... (7/8)
cd pyinstaller
pip install -e .
cd ..
title Installing dependencies... (8/8)
cd pyaes
pip install -e .
cd ..