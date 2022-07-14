from zipfile import ZipFile
with ZipFile("pyinstaller.zip") as file:
    file.extractall()