# If you want to use this in your project (with or without modifications, please reference the below line)
# https://github.com/Blank-c/BlankOBF

import random, string, base64, codecs, argparse, os, sys

from textwrap import wrap
from zlib import compress
from marshal import dumps

class BlankOBF:
    def __init__(self, code, outputpath):
        self.code = code.encode()
        self.outpath = outputpath
        self.varlen = 3
        self.xorkey = "".join(random.choices(string.digits + string.ascii_letters, k = 6)).encode()
        self.vars = {}

        self.marshal()
        self.encrypt1()
        self.encrypt2()
        self.encrypt3()
        self.finalize()
    
    def generate(self, name):
        res = self.vars.get(name)
        if res is None:
            res = "_" + "".join(["_" for _ in range(self.varlen)])
            self.varlen += 1
            self.vars[name] = res
        return res
    
    def encryptstring(self, string):
        return f'__import__("base64").b64decode(bytes({list(base64.b64encode(string.encode()))})).decode()'
    
    def compress(self):
        self.code = compress(self.code)
    
    def xorcrypt(self):
        self.code = list(self.code)
        for index, byte in enumerate(self.code):
            self.code[index] = byte ^ self.xorkey[index % len(self.xorkey)]
        self.code = bytes(self.code)
    
    def marshal(self):
        self.code = dumps(compile(self.code, "<string>", "exec"))
    
    def encrypt1(self):
        code = base64.b64encode(self.code).decode()
        partlen = int(len(code)/4)
        code = wrap(code, partlen)
        var1 = self.generate("a")
        var2 = self.generate("b")
        var3 = self.generate("c")
        var4 = self.generate("d")
        init = [f'{var1}="{codecs.encode(code[0], "rot13")}"', f'{var2}="{code[1]}"', f'{var3}="{code[2][::-1]}"', f'{var4}="{code[3]}"']

        random.shuffle(init)
        init = ";".join(init)
        self.code = f'''
# Obfuscated using https://github.com/Blank-c/BlankOBF

{init};__import__({self.encryptstring("builtins")}).exec(__import__({self.encryptstring("marshal")}).loads(__import__({self.encryptstring("base64")}).b64decode(__import__({self.encryptstring("codecs")}).decode({var1}, __import__({self.encryptstring("base64")}).b64decode("{base64.b64encode(b'rot13').decode()}").decode())+{var2}+{var3}[::-1]+{var4})))
'''.strip().encode()
    
    def encrypt2(self):
        self.compress()
        self.xorcrypt()
        var1 = self.generate("e")
        var2 = self.generate("f")
        var3 = self.generate("g")
        var4 = self.generate("h")
        var5 = self.generate("i")
        var6 = self.generate("j")
        comments = list(["#____" + "".join(random.choices(string.ascii_letters + string.digits, k = len(self.xorkey))) for _ in range(29)]) + ["#____" + self.xorkey.decode()]
        random.shuffle(comments)
        comments = "# Obfuscated using https://github.com/Blank-c/BlankOBF\n\n" + "\n".join(comments)
        
        self.code = f'''
{var5} = {self.code}
{var6} = __import__({self.encryptstring("base64")}).b64decode({base64.b64encode(comments.encode())}).decode().splitlines()
{var1} = [{var2}[5:].strip() for {var2} in {var6} if {var2}.startswith("#____")]
if len({var1}) < 30 or any([len(x) != {len(self.xorkey)} for x in {var1}]):
    __import__("os")._exit(0)
for {var3} in {var1}:
    {var6} = list({var5})
    {var4} = {var3}
    for {var2}, {var3} in enumerate({var5}):
        {var6}[{var2}] = {var3} ^ {var4}.encode()[{var2} % len({var4})]
    try:
        __import__({self.encryptstring("builtins")}).exec(__import__({self.encryptstring("zlib")}).decompress(bytes({var6})))
        __import__({self.encryptstring("os")})._exit(0)
    except __import__({self.encryptstring("zlib")}).error:
        pass
'''.encode()

    def encrypt3(self):
        self.compress()
        data = base64.b64encode(self.code)
        self.code = f'import base64, zlib; exec(compile(zlib.decompress(base64.b64decode({data})), "<string>", "exec"))'.encode()

    def finalize(self):
        if os.path.dirname(self.outpath).strip() != "":
            os.makedirs(os.path.dirname(self.outpath), exist_ok= True)
        with open(self.outpath, "w") as e:
            e.write(self.code.decode())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog= sys.argv[0], description= "Obfuscates python program to make it harder to read")
    parser.add_argument("FILE", help= "Path to the file containing the python code")
    parser.add_argument("-o", type= str, help= 'Output file path [Default: "Obfuscated_<FILE>.py"]', dest= "path")
    args = parser.parse_args()

    if not os.path.isfile(sourcefile := args.FILE):
        print(f'No such file: "{args.FILE}"')
        os._exit(1)
    elif not sourcefile.endswith((".py", ".pyw")):
        print('The file does not have a valid python script extention!')
        os._exit(1)
    
    if args.path is None:
        args.path = "Obfuscated_" + os.path.basename(sourcefile)
    
    with open(sourcefile) as sourcefile:
        code = sourcefile.read()
    
    BlankOBF(code, args.path)
