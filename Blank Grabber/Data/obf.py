# https://github.com/Blank-c/BlankOBF

import os, base64, argparse, codecs, random, string

class Obfuscator:
    def __init__(self, code, level):
        self.code = code
        if level < 1:
            level = 1
        for _ in range(level):
            self.__obfuscate()
    
    def __xorED(self, text, key = None):
        newstring = ""
        if key is None:
            key = "".join(random.choices(string.digits + string.ascii_letters, k= random.randint(4, 8)))
        if not key[0] == " ":
            key = " " + key
        for i in range(len(text)):
            newstring += chr(ord(text[i]) ^ ord(key[(len(key) - 2) + 1]))
        return (newstring, key)

    def __encodestring(self, string):
        newstring = ''
        for i in string:
            if random.choice([True, False]):
                newstring += '\\x' + codecs.encode(i.encode(), 'hex').decode()
            else:
                newstring += '\\' + oct(ord(i))[2:]
        return newstring

    def __obfuscate(self):
        xorcod = self.__xorED(self.code)
        self.code = xorcod[0]
        encoded_code = base64.b64encode(codecs.encode(codecs.encode(self.code.encode(), 'bz2'), 'uu')).decode()
        encoded_code = [encoded_code[i:i + int(len(encoded_code) / 4)] for i in range(0, len(encoded_code), int(len(encoded_code) / 4))]
        new_encoded_code = []
        for i in range(4):
            new_encoded_code.append(codecs.encode(encoded_code[0].encode(), 'uu').decode() + 'u')
            new_encoded_code.append(codecs.encode(encoded_code[1], 'rot13') + 'r')
            new_encoded_code.append(codecs.encode(encoded_code[2].encode(), 'hex').decode() + 'h')
            new_encoded_code.append(base64.b85encode(codecs.encode(encoded_code[3].encode(), 'hex')).decode() + 'x')
        self.code = f"""# Obfuscated with BlankOBF
# https://github.com/Blank-c/BlankOBF

_____=eval("{self.__encodestring('eval')}");_______=_____("{self.__encodestring('compile')}");______,____=_____(_______("{self.__encodestring("__import__('base64')")}","",_____.__name__)),_____(_______("{self.__encodestring("__import__('codecs')")}","",_____.__name__));____________________=_____("'{self.__encodestring(xorcod[True])}'");________,_________,__________,___________=_____(_______("{self.__encodestring('exec')}","",_____.__name__)),_____(_______("{self.__encodestring('str.encode')}","",_____.__name__)),_____(_______("{self.__encodestring('isinstance')}","",_____.__name__)),_____(_______("{self.__encodestring('bytes')}","",_____.__name__))
def ___________________(__________, ___________):
    __________=__________.decode()
    _________=""
    if not ___________[False]=="{self.__encodestring(' ')}":
        ___________="{self.__encodestring(' ')}"+___________
    for _ in range(_____("{self.__encodestring('len(__________)')}")):
        _________+=_____("{self.__encodestring('chr(ord(__________[_])^ord(___________[(len(___________) - True*2) + True]))')}")
    return (_________,___________)
def ____________(_____________):
    if(_____________[-True]!=_____(_______("'{self.__encodestring('c________________6s5________________6ardv8')}'[-True*4]","",_____.__name__))):_____________ = _________(_____________)
    if not(__________(_____________, ___________)):_____________ = _____(_______("{self.__encodestring('____.decode(_____________[:-True]')},'{self.__encodestring('rot13')}')","",_____.__name__))
    else:
        if(_____________[-True]==_____(_______("b'{self.__encodestring('f5sfsdfauf85')}'[-True*4]","", _____.__name__))):
            _____________=_____(_______("{self.__encodestring('____.decode(_____________[:-True]')},'{self.__encodestring('uu')}')","",_____.__name__))
        elif (_____________[-True] ==_____(_______("b'{self.__encodestring('d5sfs1dffhsd8')}'[-True*4]","", _____.__name__))):_____________=_____(_______("{self.__encodestring('____.decode(_____________[:-True]')},'{self.__encodestring('hex')}')","",_____.__name__))
        else:_____________=_____(_______("{self.__encodestring('______.b85decode(_____________[:-True])')}","",_____.__name__));_____________=_____(_______("{self.__encodestring('____.decode(_____________')}, '{self.__encodestring('hex')}')","",_____.__name__))
        _____________=_____(_______("{self.__encodestring('___________.decode(_____________)')}","",_____.__name__))
    return _____________
_________________=_____(_______("{self.__encodestring('___________.decode')}({self.__encodestring(new_encoded_code[True*3]).encode()})","",_____.__name__));________________ = _____(_______("{self.__encodestring('___________.decode')}({self.__encodestring(new_encoded_code[1]).encode()})","",_____.__name__));__________________=_____(_______("{self.__encodestring('___________.decode')}({self.__encodestring(new_encoded_code[True*2]).encode()})","",_____.__name__));______________=_____(_______("{self.__encodestring('___________.decode')}({self.__encodestring(new_encoded_code[False]).encode()})","",_____.__name__));_______________=_____(_______("{self.__encodestring('str.join')}('', {self.__encodestring('[____________(x) for x in [______________,________________,__________________,_________________]]')})","", _____.__name__));________(___________________(____.decode(____.decode(______.b64decode(_________(_______________)), "{self.__encodestring("uu")}"),"{self.__encodestring("bz2")}"),____________________)[_____("{self.__encodestring('False')}")])"""

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('FILE', help='the target file', metavar= 'SOURCE')
    parser.add_argument('-l', metavar='level', help='level of obfuscation', type=int, default=1)
    parser.add_argument('-o', metavar='path', help='custom output file path')
    args = parser.parse_args()
    if args.o is None:
        args.o = f'obfuscated_{os.path.basename(args.FILE)}'
    if not os.path.isfile(args.FILE):
        print(f'File "{os.path.basename(args.FILE)}" is not found')
        exit()
    elif not 'py' in os.path.basename(args.FILE).split('.')[-1]:
        print(f'''File "{os.path.basename(args.FILE)}" is not a '.py' file''')
        exit()
    with open(args.FILE, encoding='utf-8') as file:
        CODE = file.read()
    obfuscator = Obfuscator(CODE, args.l)
    with open(args.o, 'w', encoding='utf-8') as output_file:
        output_file.write(obfuscator.code)
    print(f"Saved as '{os.path.abspath(f'{os.path.basename(args.o)}')}'")

if __name__ == '__main__':
    main()
