import os

def RemovePyinstallerStrings(path: str):
    with open(path, "rb") as file:
        data = file.read()
        
    data = data.replace(b"PyInstaller:", b"PyInstallem:")
    
    with open(path, "wb") as file:
        file.write(data)

if __name__ == "__main__":
    builtFile = os.path.join("dist", "Built.exe")
    if os.path.isfile(builtFile):
        RemovePyinstallerStrings(builtFile)
    else:
        print("Not Found")