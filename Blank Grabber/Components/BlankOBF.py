# If you want to use this in your project (with or without modifications, please give credits)
# https://github.com/Blank-c/BlankOBF

import random, string, base64, codecs, argparse, os, sys

from textwrap import wrap
from lzma import compress
from marshal import dumps

def printerr(data):
    print(data, file= sys.stderr)

class BlankOBF:
    def __init__(self, code, outputpath):
        self.code = code.encode()
        self.outpath = outputpath
        self.varlen = 3
        self.vars = {}

        self.marshal()
        self.encrypt1()
        self.encrypt2()
        # self.encrypt3() # This one increases detections
        self.finalize()
    
    def generate(self, name):
        res = self.vars.get(name)
        if res is None:
            res = "_" + "".join(["_" for _ in range(self.varlen)])
            self.varlen += 1
            self.vars[name] = res
        return res
    
    def encryptstring(self, string, config= {}, func= False):
        b64 = list(b"base64")
        b64decode = list(b"b64decode")
        __import__ = config.get("__import__", "__import__")
        getattr = config.get("getattr", "getattr")
        bytes = config.get("bytes", "bytes")
        eval = config.get("eval", "eval")
        if not func:
            return f'{getattr}({__import__}({bytes}({b64}).decode()), {bytes}({b64decode}).decode())({bytes}({list(base64.b64encode(string.encode()))})).decode()'
        else:
            attrs = string.split(".")
            base = self.encryptstring(attrs[0], config)
            attrs = list(map(lambda x: self.encryptstring(x, config, False), attrs[1:]))
            newattr = ""
            for i, val in enumerate(attrs):
                if i == 0:
                    newattr = f'{getattr}({eval}({base}), {val})'
                else:
                    newattr = f'{getattr}({newattr}, {val})'
            return newattr
            
    def encryptor(self, config):
        def func_(string, func= False):
            return self.encryptstring(string, config, func)
        return func_
    
    def compress(self):
        self.code = compress(self.code)
    
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
        var1 = self.generate("e")
        var2 = self.generate("f")
        var3 = self.generate("g")
        var4 = self.generate("h")
        var5 = self.generate("i")
        var6 = self.generate("j")
        var7 = self.generate("k")
        var8 = self.generate("l")
        var9 = self.generate("m")

        conf = {
            "getattr" : var4,
            "eval" : var3,
            "__import__" : var8,
            "bytes" : var9
        }
        encryptstring = self.encryptor(conf)
        
        self.code = f'''# Obfuscated using https://github.com/Blank-c/BlankOBF
{var3} = eval({self.encryptstring("eval")});{var4} = {var3}({self.encryptstring("getattr")});{var8} = {var3}({self.encryptstring("__import__")});{var9} = {var3}({self.encryptstring("bytes")});{var5} = lambda {var7}: {var3}({encryptstring("compile")})({var7}, {encryptstring("<string>")}, {encryptstring("exec")});{var1} = {self.code}
{var2} = {encryptstring('__import__("builtins").list', func= True)}({var1})
try:
    {encryptstring('__import__("builtins").exec', func= True)}({var5}({encryptstring('__import__("lzma").decompress', func= True)}({var9}({var2})))) or {encryptstring('__import__("os")._exit', func= True)}(0)
except {encryptstring('__import__("lzma").LZMAError', func= True)}:...
'''.strip().encode()

    def encrypt3(self):
        self.compress()
        data = base64.b64encode(self.code)
        self.code = f'# Obfuscated using https://github.com/Blank-c/BlankOBF\n\nimport base64, lzma; exec(compile(lzma.decompress(base64.b64decode({data})), "<string>", "exec"))'.encode()

    def finalize(self):
        if os.path.dirname(self.outpath).strip() != "":
            os.makedirs(os.path.dirname(self.outpath), exist_ok= True)
        with open(self.outpath, "w") as e:
            e.write(self.code.decode())
        # print("Saved as --> " + os.path.realpath(self.outpath))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog= sys.argv[0], description= "Obfuscates python program to make it harder to read")
    parser.add_argument("FILE", help= "Path to the file containing the python code")
    parser.add_argument("-o", type= str, help= 'Output file path [Default: "Obfuscated_<FILE>.py"]', dest= "path")
    args = parser.parse_args()

    if not os.path.isfile(sourcefile := args.FILE):
        printerr(f'No such file: "{args.FILE}"')
        os._exit(1)
    elif not sourcefile.endswith((".py", ".pyw")):
        printerr('The file does not have a valid python script extention!')
        os._exit(1)
    
    if args.path is None:
        args.path = "Obfuscated_" + os.path.basename(sourcefile)
    
    with open(sourcefile) as sourcefile:
        code = sourcefile.read()
    
    BlankOBF(code, args.path)