from zipfile import ZipFile
with ZipFile("pyinstaller.zip") as file:
    file.extractall()

with ZipFile("pyaes.zip") as file:
    file.extractall()