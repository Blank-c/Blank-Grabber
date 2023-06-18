import os
from sigthief import signfile

def RemoveMetaData(path: str):
    with open(path, "rb") as file:
        data = file.read()
    
    # Remove pyInstaller strings
    data = data.replace(b"PyInstaller:", b"PyInstallem:")
    data = data.replace(b"pyi-runtime-tmpdir", b"bye-runtime-tmpdir")
    data = data.replace(b"pyi-windows-manifest-filename", b"bye-windows-manifest-filename")

    # Remove linker information
    start_index = data.find(b"$") + 1
    end_index = data.find(b"PE\x00\x00", start_index) - 1
    data = data[:start_index] + bytes([0] * (end_index - start_index))  + data[end_index:]

    # Remove compilation timestamp
    start_index = data.find(b"PE\x00\x00") + 8
    end_index = start_index + 4
    data = data[:start_index] + bytes([0] * (end_index - start_index))  + data[end_index:]
    
    with open(path, "wb") as file:
        file.write(data)

def AddCertificate(path: str):
    certFile = "cert"
    if os.path.isfile(certFile):
        signfile(path, certFile, path)

if __name__ == "__main__":
    builtFile = os.path.join("dist", "Built.exe")
    if os.path.isfile(builtFile):
        RemoveMetaData(builtFile)
        AddCertificate(builtFile)
    else:
        print("Not Found")