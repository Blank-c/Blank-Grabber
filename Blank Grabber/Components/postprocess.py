import os
from sigthief import signfile

def RemovePyinstallerStrings(path: str):
    with open(path, "rb") as file:
        data = file.read()
        
    data = data.replace(b"PyInstaller:", b"PyInstallem:")
    data = data.replace(b"pyi-runtime-tmpdir", b"bye-runtime-tmpdir")
    data = data.replace(b"pyi-windows-manifest-filename", b"bye-windows-manifest-filename")
    
    with open(path, "wb") as file:
        file.write(data)

def AddCertificate(path: str):
    certFile = "cert"
    if os.path.isfile(certFile):
        signfile(path, certFile, path)

if __name__ == "__main__":
    builtFile = os.path.join("dist", "Built.exe")
    if os.path.isfile(builtFile):
        RemovePyinstallerStrings(builtFile)
        AddCertificate(builtFile)
    else:
        print("Not Found")