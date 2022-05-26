#! /usr/bin/env python
# encoding: utf-8
# WARNING! Do not edit! https://waf.io/book/index.html#_obtaining_the_waf_file

import re, string, traceback
from waflib import Logs, Utils, Errors


class PreprocError(Errors.WafError):
    pass


FILE_CACHE_SIZE = 100000
LINE_CACHE_SIZE = 100000
POPFILE = '-'
recursion_limit = 150
go_absolute = False
standard_includes = ['/usr/local/include', '/usr/include']
if Utils.is_win32:
    standard_includes = []
use_trigraphs = 0
strict_quotes = 0
g_optrans = {
    'not': '!',
    'not_eq': '!',
    'and': '&&',
    'and_eq': '&=',
    'or': '||',
    'or_eq': '|=',
    'xor': '^',
    'xor_eq': '^=',
    'bitand': '&',
    'bitor': '|',
    'compl': '~',
}
re_lines = re.compile(
    '^[ \t]*(?:#|%:)[ \t]*(ifdef|ifndef|if|else|elif|endif|include|import|define|undef|pragma)[ \t]*(.*)\r*$',
    re.IGNORECASE | re.MULTILINE
)
re_mac = re.compile(r"^[a-zA-Z_]\w*")
re_fun = re.compile('^[a-zA-Z_][a-zA-Z0-9_]*[(]')
re_pragma_once = re.compile(r'^\s*once\s*', re.IGNORECASE)
re_nl = re.compile('\\\\\r*\n', re.MULTILINE)
re_cpp = re.compile(r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"', re.DOTALL | re.MULTILINE)
trig_def = [('??' + a, b) for a, b in zip("=-/!'()<>", r'#~\|^[]{}')]
chr_esc = {'0': 0, 'a': 7, 'b': 8, 't': 9, 'n': 10, 'f': 11, 'v': 12, 'r': 13, '\\': 92, "'": 39}
NUM = 'i'
OP = 'O'
IDENT = 'T'
STR = 's'
CHAR = 'c'
tok_types = [NUM, STR, IDENT, OP]
exp_types = [
    r"""0[xX](?P<hex>[a-fA-F0-9]+)(?P<qual1>[uUlL]*)|L*?'(?P<char>(\\.|[^\\'])+)'|(?P<n1>\d+)[Ee](?P<exp0>[+-]*?\d+)(?P<float0>[fFlL]*)|(?P<n2>\d*\.\d+)([Ee](?P<exp1>[+-]*?\d+))?(?P<float1>[fFlL]*)|(?P<n4>\d+\.\d*)([Ee](?P<exp2>[+-]*?\d+))?(?P<float2>[fFlL]*)|(?P<oct>0*)(?P<n0>\d+)(?P<qual2>[uUlL]*)""",
    r'L?"([^"\\]|\\.)*"',
    r'[a-zA-Z_]\w*',
    r'%:%:|<<=|>>=|\.\.\.|<<|<%|<:|<=|>>|>=|\+\+|\+=|--|->|-=|\*=|/=|%:|%=|%>|==|&&|&=|\|\||\|=|\^=|:>|!=|##|[\(\)\{\}\[\]<>\?\|\^\*\+&=:!#;,%/\-\?\~\.]',
]
re_clexer = re.compile('|'.join(["(?P<%s>%s)" % (name, part) for name, part in zip(tok_types, exp_types)]), re.M)
accepted = 'a'
ignored = 'i'
undefined = 'u'
skipped = 's'


def repl(m):
    s = m.group()
    if s[0] == '/':
        return ' '
    return s


prec = {}
ops = ['* / %', '+ -', '<< >>', '< <= >= >', '== !=', '& | ^', '&& ||', ',']
for x, syms in enumerate(ops):
    for u in syms.split():
        prec[u] = x


def reduce_nums(val_1, val_2, val_op):
    try:
        a = 0 + val_1
    except TypeError:
        a = int(val_1)
    try:
        b = 0 + val_2
    except TypeError:
        b = int(val_2)
    d = val_op
    if d == '%':
        c = a % b
    elif d == '+':
        c = a + b
    elif d == '-':
        c = a - b
    elif d == '*':
        c = a * b
    elif d == '/':
        c = a / b
    elif d == '^':
        c = a ^ b
    elif d == '==':
        c = int(a == b)
    elif d == '|' or d == 'bitor':
        c = a | b
    elif d == '||' or d == 'or':
        c = int(a or b)
    elif d == '&' or d == 'bitand':
        c = a & b
    elif d == '&&' or d == 'and':
        c = int(a and b)
    elif d == '!=' or d == 'not_eq':
        c = int(a != b)
    elif d == '^' or d == 'xor':
        c = int(a ^ b)
    elif d == '<=':
        c = int(a <= b)
    elif d == '<':
        c = int(a < b)
    elif d == '>':
        c = int(a > b)
    elif d == '>=':
        c = int(a >= b)
    elif d == '<<':
        c = a << b
    elif d == '>>':
        c = a >> b
    else:
        c = 0
    return c


def get_num(lst):
    if not lst:
        raise PreprocError('empty list for get_num')
    (p, v) = lst[0]
    if p == OP:
        if v == '(':
            count_par = 1
            i = 1
            while i < len(lst):
                (p, v) = lst[i]
                if p == OP:
                    if v == ')':
                        count_par -= 1
                        if count_par == 0:
                            break
                    elif v == '(':
                        count_par += 1
                i += 1
            else:
                raise PreprocError('rparen expected %r' % lst)
            (num, _) = get_term(lst[1:i])
            return (num, lst[i + 1:])
        elif v == '+':
            return get_num(lst[1:])
        elif v == '-':
            num, lst = get_num(lst[1:])
            return (reduce_nums('-1', num, '*'), lst)
        elif v == '!':
            num, lst = get_num(lst[1:])
            return (int(not int(num)), lst)
        elif v == '~':
            num, lst = get_num(lst[1:])
            return (~int(num), lst)
        else:
            raise PreprocError('Invalid op token %r for get_num' % lst)
    elif p == NUM:
        return v, lst[1:]
    elif p == IDENT:
        return 0, lst[1:]
    else:
        raise PreprocError('Invalid token %r for get_num' % lst)


def get_term(lst):
    if not lst:
        raise PreprocError('empty list for get_term')
    num, lst = get_num(lst)
    if not lst:
        return (num, [])
    (p, v) = lst[0]
    if p == OP:
        if v == ',':
            return get_term(lst[1:])
        elif v == '?':
            count_par = 0
            i = 1
            while i < len(lst):
                (p, v) = lst[i]
                if p == OP:
                    if v == ')':
                        count_par -= 1
                    elif v == '(':
                        count_par += 1
                    elif v == ':':
                        if count_par == 0:
                            break
                i += 1
            else:
                raise PreprocError('rparen expected %r' % lst)
            if int(num):
                return get_term(lst[1:i])
            else:
                return get_term(lst[i + 1:])
        else:
            num2, lst = get_num(lst[1:])
            if not lst:
                num2 = reduce_nums(num, num2, v)
                return get_term([(NUM, num2)] + lst)
            p2, v2 = lst[0]
            if p2 != OP:
                raise PreprocError('op expected %r' % lst)
            if prec[v2] >= prec[v]:
                num2 = reduce_nums(num, num2, v)
                return get_term([(NUM, num2)] + lst)
            else:
                num3, lst = get_num(lst[1:])
                num3 = reduce_nums(num2, num3, v2)
                return get_term([(NUM, num), (p, v), (NUM, num3)] + lst)
    raise PreprocError('cannot reduce %r' % lst)


def reduce_eval(lst):
    num, lst = get_term(lst)
    return (NUM, num)


def stringize(lst):
    lst = [str(v2) for (p2, v2) in lst]
    return "".join(lst)


def paste_tokens(t1, t2):
    p1 = None
    if t1[0] == OP and t2[0] == OP:
        p1 = OP
    elif t1[0] == IDENT and (t2[0] == IDENT or t2[0] == NUM):
        p1 = IDENT
    elif t1[0] == NUM and t2[0] == NUM:
        p1 = NUM
    if not p1:
        raise PreprocError('tokens do not make a valid paste %r and %r' % (t1, t2))
    return (p1, t1[1] + t2[1])


def reduce_tokens(lst, defs, ban=[]):
    i = 0
    while i < len(lst):
        (p, v) = lst[i]
        if p == IDENT and v == "defined":
            del lst[i]
            if i < len(lst):
                (p2, v2) = lst[i]
                if p2 == IDENT:
                    if v2 in defs:
                        lst[i] = (NUM, 1)
                    else:
                        lst[i] = (NUM, 0)
                elif p2 == OP and v2 == '(':
                    del lst[i]
                    (p2, v2) = lst[i]
                    del lst[i]
                    if v2 in defs:
                        lst[i] = (NUM, 1)
                    else:
                        lst[i] = (NUM, 0)
                else:
                    raise PreprocError('Invalid define expression %r' % lst)
        elif p == IDENT and v in defs:
            if isinstance(defs[v], str):
                a, b = extract_macro(defs[v])
                defs[v] = b
            macro_def = defs[v]
            to_add = macro_def[1]
            if isinstance(macro_def[0], list):
                del lst[i]
                accu = to_add[:]
                reduce_tokens(accu, defs, ban + [v])
                for tmp in accu:
                    lst.insert(i, tmp)
                    i += 1
            else:
                args = []
                del lst[i]
                if i >= len(lst):
                    raise PreprocError('expected ( after %r (got nothing)' % v)
                (p2, v2) = lst[i]
                if p2 != OP or v2 != '(':
                    raise PreprocError('expected ( after %r' % v)
                del lst[i]
                one_param = []
                count_paren = 0
                while i < len(lst):
                    p2, v2 = lst[i]
                    del lst[i]
                    if p2 == OP and count_paren == 0:
                        if v2 == '(':
                            one_param.append((p2, v2))
                            count_paren += 1
                        elif v2 == ')':
                            if one_param:
                                args.append(one_param)
                            break
                        elif v2 == ',':
                            if not one_param:
                                raise PreprocError('empty param in funcall %r' % v)
                            args.append(one_param)
                            one_param = []
                        else:
                            one_param.append((p2, v2))
                    else:
                        one_param.append((p2, v2))
                        if v2 == '(':
                            count_paren += 1
                        elif v2 == ')':
                            count_paren -= 1
                else:
                    raise PreprocError('malformed macro')
                accu = []
                arg_table = macro_def[0]
                j = 0
                while j < len(to_add):
                    (p2, v2) = to_add[j]
                    if p2 == OP and v2 == '#':
                        if j + 1 < len(to_add) and to_add[j + 1][0] == IDENT and to_add[j + 1][1] in arg_table:
                            toks = args[arg_table[to_add[j + 1][1]]]
                            accu.append((STR, stringize(toks)))
                            j += 1
                        else:
                            accu.append((p2, v2))
                    elif p2 == OP and v2 == '##':
                        if accu and j + 1 < len(to_add):
                            t1 = accu[-1]
                            if to_add[j + 1][0] == IDENT and to_add[j + 1][1] in arg_table:
                                toks = args[arg_table[to_add[j + 1][1]]]
                                if toks:
                                    accu[-1] = paste_tokens(t1, toks[0])
                                    accu.extend(toks[1:])
                                else:
                                    accu.append((p2, v2))
                                    accu.extend(toks)
                            elif to_add[j + 1][0] == IDENT and to_add[j + 1][1] == '__VA_ARGS__':
                                va_toks = []
                                st = len(macro_def[0])
                                pt = len(args)
                                for x in args[pt - st + 1:]:
                                    va_toks.extend(x)
                                    va_toks.append((OP, ','))
                                if va_toks:
                                    va_toks.pop()
                                if len(accu) > 1:
                                    (p3, v3) = accu[-1]
                                    (p4, v4) = accu[-2]
                                    if v3 == '##':
                                        accu.pop()
                                        if v4 == ',' and pt < st:
                                            accu.pop()
                                accu += va_toks
                            else:
                                accu[-1] = paste_tokens(t1, to_add[j + 1])
                            j += 1
                        else:
                            accu.append((p2, v2))
                    elif p2 == IDENT and v2 in arg_table:
                        toks = args[arg_table[v2]]
                        reduce_tokens(toks, defs, ban + [v])
                        accu.extend(toks)
                    else:
                        accu.append((p2, v2))
                    j += 1
                reduce_tokens(accu, defs, ban + [v])
                for x in range(len(accu) - 1, -1, -1):
                    lst.insert(i, accu[x])
        i += 1


def eval_macro(lst, defs):
    reduce_tokens(lst, defs, [])
    if not lst:
        raise PreprocError('missing tokens to evaluate')
    if lst:
        p, v = lst[0]
        if p == IDENT and v not in defs:
            raise PreprocError('missing macro %r' % lst)
    p, v = reduce_eval(lst)
    return int(v) != 0


def extract_macro(txt):
    t = tokenize(txt)
    if re_fun.search(txt):
        p, name = t[0]
        p, v = t[1]
        if p != OP:
            raise PreprocError('expected (')
        i = 1
        pindex = 0
        params = {}
        prev = '('
        while 1:
            i += 1
            p, v = t[i]
            if prev == '(':
                if p == IDENT:
                    params[v] = pindex
                    pindex += 1
                    prev = p
                elif p == OP and v == ')':
                    break
                else:
                    raise PreprocError('unexpected token (3)')
            elif prev == IDENT:
                if p == OP and v == ',':
                    prev = v
                elif p == OP and v == ')':
                    break
                else:
                    raise PreprocError('comma or ... expected')
            elif prev == ',':
                if p == IDENT:
                    params[v] = pindex
                    pindex += 1
                    prev = p
                elif p == OP and v == '...':
                    raise PreprocError('not implemented (1)')
                else:
                    raise PreprocError('comma or ... expected (2)')
            elif prev == '...':
                raise PreprocError('not implemented (2)')
            else:
                raise PreprocError('unexpected else')
        return (name, [params, t[i + 1:]])
    else:
        (p, v) = t[0]
        if len(t) > 1:
            return (v, [[], t[1:]])
        else:
            return (v, [[], [('T', '')]])


re_include = re.compile(r'^\s*(<(?:.*)>|"(?:.*)")')


def extract_include(txt, defs):
    m = re_include.search(txt)
    if m:
        txt = m.group(1)
        return txt[0], txt[1:-1]
    toks = tokenize(txt)
    reduce_tokens(toks, defs, ['waf_include'])
    if not toks:
        raise PreprocError('could not parse include %r' % txt)
    if len(toks) == 1:
        if toks[0][0] == STR:
            return '"', toks[0][1]
    else:
        if toks[0][1] == '<' and toks[-1][1] == '>':
            ret = '<', stringize(toks).lstrip('<').rstrip('>')
            return ret
    raise PreprocError('could not parse include %r' % txt)


def parse_char(txt):
    if not txt:
        raise PreprocError('attempted to parse a null char')
    if txt[0] != '\\':
        return ord(txt)
    c = txt[1]
    if c == 'x':
        if len(txt) == 4 and txt[3] in string.hexdigits:
            return int(txt[2:], 16)
        return int(txt[2:], 16)
    elif c.isdigit():
        if c == '0' and len(txt) == 2:
            return 0
        for i in 3, 2, 1:
            if len(txt) > i and txt[1:1 + i].isdigit():
                return (1 + i, int(txt[1:1 + i], 8))
    else:
        try:
            return chr_esc[c]
        except KeyError:
            raise PreprocError('could not parse char literal %r' % txt)


def tokenize(s):
    return tokenize_private(s)[:]


def tokenize_private(s):
    ret = []
    for match in re_clexer.finditer(s):
        m = match.group
        for name in tok_types:
            v = m(name)
            if v:
                if name == IDENT:
                    if v in g_optrans:
                        name = OP
                    elif v.lower() == "true":
                        v = 1
                        name = NUM
                    elif v.lower() == "false":
                        v = 0
                        name = NUM
                elif name == NUM:
                    if m('oct'):
                        v = int(v, 8)
                    elif m('hex'):
                        v = int(m('hex'), 16)
                    elif m('n0'):
                        v = m('n0')
                    else:
                        v = m('char')
                        if v:
                            v = parse_char(v)
                        else:
                            v = m('n2') or m('n4')
                elif name == OP:
                    if v == '%:':
                        v = '#'
                    elif v == '%:%:':
                        v = '##'
                elif name == STR:
                    v = v[1:-1]
                ret.append((name, v))
                break
    return ret


def format_defines(lst):
    ret = []
    for y in lst:
        if y:
            pos = y.find('=')
            if pos == -1:
                ret.append(y)
            elif pos > 0:
                ret.append('%s %s' % (y[:pos], y[pos + 1:]))
            else:
                raise ValueError('Invalid define expression %r' % y)
    return ret


class c_parser(object):
    def __init__(self, nodepaths=None, defines=None):
        self.lines = []
        if defines is None:
            self.defs = {}
        else:
            self.defs = dict(defines)
        self.state = []
        self.count_files = 0
        self.currentnode_stack = []
        self.nodepaths = nodepaths or []
        self.nodes = []
        self.names = []
        self.curfile = ''
        self.ban_includes = set()
        self.listed = set()

    def cached_find_resource(self, node, filename):
        try:
            cache = node.ctx.preproc_cache_node
        except AttributeError:
            cache = node.ctx.preproc_cache_node = Utils.lru_cache(FILE_CACHE_SIZE)
        key = (node, filename)
        try:
            return cache[key]
        except KeyError:
            ret = node.find_resource(filename)
            if ret:
                if getattr(ret, 'children', None):
                    ret = None
                elif ret.is_child_of(node.ctx.bldnode):
                    tmp = node.ctx.srcnode.search_node(ret.path_from(node.ctx.bldnode))
                    if tmp and getattr(tmp, 'children', None):
                        ret = None
            cache[key] = ret
            return ret

    def tryfind(self, filename, kind='"', env=None):
        if filename.endswith('.moc'):
            self.names.append(filename)
            return None
        self.curfile = filename
        found = None
        if kind == '"':
            if env.MSVC_VERSION:
                for n in reversed(self.currentnode_stack):
                    found = self.cached_find_resource(n, filename)
                    if found:
                        break
            else:
                found = self.cached_find_resource(self.currentnode_stack[-1], filename)
        if not found:
            for n in self.nodepaths:
                found = self.cached_find_resource(n, filename)
                if found:
                    break
        listed = self.listed
        if found and not found in self.ban_includes:
            if found not in listed:
                listed.add(found)
                self.nodes.append(found)
            self.addlines(found)
        else:
            if filename not in listed:
                listed.add(filename)
                self.names.append(filename)
        return found

    def filter_comments(self, node):
        code = node.read()
        if use_trigraphs:
            for (a, b) in trig_def:
                code = code.split(a).join(b)
        code = re_nl.sub('', code)
        code = re_cpp.sub(repl, code)
        return re_lines.findall(code)

    def parse_lines(self, node):
        try:
            cache = node.ctx.preproc_cache_lines
        except AttributeError:
            cache = node.ctx.preproc_cache_lines = Utils.lru_cache(LINE_CACHE_SIZE)
        try:
            return cache[node]
        except KeyError:
            cache[node] = lines = self.filter_comments(node)
            lines.append((POPFILE, ''))
            lines.reverse()
            return lines

    def addlines(self, node):
        self.currentnode_stack.append(node.parent)
        self.count_files += 1
        if self.count_files > recursion_limit:
            raise PreprocError('recursion limit exceeded')
        if Logs.verbose:
            Logs.debug('preproc: reading file %r', node)
        try:
            lines = self.parse_lines(node)
        except EnvironmentError:
            raise PreprocError('could not read the file %r' % node)
        except Exception:
            if Logs.verbose > 0:
                Logs.error('parsing %r failed %s', node, traceback.format_exc())
        else:
            self.lines.extend(lines)

    def start(self, node, env):
        Logs.debug('preproc: scanning %s (in %s)', node.name, node.parent.name)
        self.current_file = node
        self.addlines(node)
        if env.DEFINES:
            lst = format_defines(env.DEFINES)
            lst.reverse()
            self.lines.extend([('define', x) for x in lst])
        while self.lines:
            (token, line) = self.lines.pop()
            if token == POPFILE:
                self.count_files -= 1
                self.currentnode_stack.pop()
                continue
            try:
                state = self.state
                if token[:2] == 'if':
                    state.append(undefined)
                elif token == 'endif':
                    state.pop()
                if token[0] != 'e':
                    if skipped in self.state or ignored in self.state:
                        continue
                if token == 'if':
                    ret = eval_macro(tokenize(line), self.defs)
                    if ret:
                        state[-1] = accepted
                    else:
                        state[-1] = ignored
                elif token == 'ifdef':
                    m = re_mac.match(line)
                    if m and m.group() in self.defs:
                        state[-1] = accepted
                    else:
                        state[-1] = ignored
                elif token == 'ifndef':
                    m = re_mac.match(line)
                    if m and m.group() in self.defs:
                        state[-1] = ignored
                    else:
                        state[-1] = accepted
                elif token == 'include' or token == 'import':
                    (kind, inc) = extract_include(line, self.defs)
                    self.current_file = self.tryfind(inc, kind, env)
                    if token == 'import':
                        self.ban_includes.add(self.current_file)
                elif token == 'elif':
                    if state[-1] == accepted:
                        state[-1] = skipped
                    elif state[-1] == ignored:
                        if eval_macro(tokenize(line), self.defs):
                            state[-1] = accepted
                elif token == 'else':
                    if state[-1] == accepted:
                        state[-1] = skipped
                    elif state[-1] == ignored:
                        state[-1] = accepted
                elif token == 'define':
                    try:
                        self.defs[self.define_name(line)] = line
                    except AttributeError:
                        raise PreprocError('Invalid define line %r' % line)
                elif token == 'undef':
                    m = re_mac.match(line)
                    if m and m.group() in self.defs:
                        self.defs.__delitem__(m.group())
                elif token == 'pragma':
                    if re_pragma_once.match(line.lower()):
                        self.ban_includes.add(self.current_file)
            except Exception as e:
                if Logs.verbose:
                    Logs.debug('preproc: line parsing failed (%s): %s %s', e, line, traceback.format_exc())

    def define_name(self, line):
        return re_mac.match(line).group()


def scan(task):
    try:
        incn = task.generator.includes_nodes
    except AttributeError:
        raise Errors.WafError('%r is missing a feature such as "c", "cxx" or "includes": ' % task.generator)
    if go_absolute:
        nodepaths = incn + [task.generator.bld.root.find_dir(x) for x in standard_includes]
    else:
        nodepaths = [x for x in incn if x.is_child_of(x.ctx.srcnode) or x.is_child_of(x.ctx.bldnode)]
    tmp = c_parser(nodepaths)
    tmp.start(task.inputs[0], task.env)
    return (tmp.nodes, tmp.names)
