@echo off
cd /d %~dp0

title Checking Python installation...
python --version > nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo *** Python is not installed! ***
    echo Please follow the instructions below to install Python:
    echo.
    echo 1. Go to https://www.python.org/downloads and download the latest version.
    echo 2. Run the installer and make sure to select the option to add Python to the system's PATH.
    echo 3. Once installation is complete, re-run this script.
    echo.
    pause > nul
    goto ERROR
)

title Checking libraries...
echo.
echo *** Checking required libraries ***

echo.
echo [1/4] Checking 'customtkinter'...
python -c "import customtkinter" > nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo 'customtkinter' library not found.
    echo Installing 'customtkinter'...
    title Installing customtkinter...
    python -m pip install customtkinter > nul
) else (
    echo 'customtkinter' library is installed.
)

echo.
echo [2/4] Checking 'Pillow'...
python -c "import PIL" > nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo 'Pillow' library not found.
    echo Installing 'Pillow'...
    title Installing Pillow...
    python -m pip install pillow > nul
) else (
    echo 'Pillow' library is installed.
)

echo.
echo [3/4] Checking 'pyaes'...
python -c "import pyaes" > nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo 'pyaes' library not found.
    echo Installing 'pyaes'...
    title Installing pyaes...
    python -m pip install pyaes > nul
) else (
    echo 'pyaes' library is installed.
)

echo.
echo [4/4] Checking 'urllib3'...
python -c "import urllib3" > nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo 'urllib3' library not found.
    echo Installing 'urllib3'...
    title Installing urllib3...
    python -m pip install urllib3 > nul
) else (
    echo 'urllib3' library is installed.
)

cls
title Starting builder...
echo.
echo *** All required libraries are installed! ***
echo.
echo Starting the application...
python gui.py

if %errorlevel% neq 0 goto ERROR
exit

:ERROR
color 4D
title [Error]
echo.
echo *** An error occurred while running the application! ***
echo.
echo Please make sure all the dependencies are installed correctly.
echo If the issue persists, Make an issue on github (https://github.com/Blank-c/Blank-Grabber/issues)
echo.
pause > nul
