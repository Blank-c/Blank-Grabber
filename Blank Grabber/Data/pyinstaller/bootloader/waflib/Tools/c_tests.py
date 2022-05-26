#! /usr/bin/env python
# encoding: utf-8
# WARNING! Do not edit! https://waf.io/book/index.html#_obtaining_the_waf_file

from waflib import Task
from waflib.Configure import conf
from waflib.TaskGen import feature, before_method, after_method

LIB_CODE = '''
#ifdef _MSC_VER
#define testEXPORT __declspec(dllexport)
#else
#define testEXPORT
#endif
testEXPORT int lib_func(void) { return 9; }
'''
MAIN_CODE = '''
#ifdef _MSC_VER
#define testEXPORT __declspec(dllimport)
#else
#define testEXPORT
#endif
testEXPORT int lib_func(void);
int main(int argc, char **argv) {
	(void)argc; (void)argv;
	return !(lib_func() == 9);
}
'''


@feature('link_lib_test')
@before_method('process_source')
def link_lib_test_fun(self):
    def write_test_file(task):
        task.outputs[0].write(task.generator.code)

    rpath = []
    if getattr(self, 'add_rpath', False):
        rpath = [self.bld.path.get_bld().abspath()]
    mode = self.mode
    m = '%s %s' % (mode, mode)
    ex = self.test_exec and 'test_exec' or ''
    bld = self.bld
    bld(rule=write_test_file, target='test.' + mode, code=LIB_CODE)
    bld(rule=write_test_file, target='main.' + mode, code=MAIN_CODE)
    bld(features='%sshlib' % m, source='test.' + mode, target='test')
    bld(features='%sprogram %s' % (m, ex), source='main.' + mode, target='app', use='test', rpath=rpath)


@conf
def check_library(self, mode=None, test_exec=True):
    if not mode:
        mode = 'c'
        if self.env.CXX:
            mode = 'cxx'
    self.check(
        compile_filename=[], features='link_lib_test', msg='Checking for libraries', mode=mode, test_exec=test_exec
    )


INLINE_CODE = '''
typedef int foo_t;
static %s foo_t static_foo () {return 0; }
%s foo_t foo () {
	return 0;
}
'''
INLINE_VALUES = ['inline', '__inline__', '__inline']


@conf
def check_inline(self, **kw):
    self.start_msg('Checking for inline')
    if not 'define_name' in kw:
        kw['define_name'] = 'INLINE_MACRO'
    if not 'features' in kw:
        if self.env.CXX:
            kw['features'] = ['cxx']
        else:
            kw['features'] = ['c']
    for x in INLINE_VALUES:
        kw['fragment'] = INLINE_CODE % (x, x)
        try:
            self.check(**kw)
        except self.errors.ConfigurationError:
            continue
        else:
            self.end_msg(x)
            if x != 'inline':
                self.define('inline', x, quote=False)
            return x
    self.fatal('could not use inline functions')


LARGE_FRAGMENT = '''#include <unistd.h>
int main(int argc, char **argv) {
	(void)argc; (void)argv;
	return !(sizeof(off_t) >= 8);
}
'''


@conf
def check_large_file(self, **kw):
    if not 'define_name' in kw:
        kw['define_name'] = 'HAVE_LARGEFILE'
    if not 'execute' in kw:
        kw['execute'] = True
    if not 'features' in kw:
        if self.env.CXX:
            kw['features'] = ['cxx', 'cxxprogram']
        else:
            kw['features'] = ['c', 'cprogram']
    kw['fragment'] = LARGE_FRAGMENT
    kw['msg'] = 'Checking for large file support'
    ret = True
    try:
        if self.env.DEST_BINFMT != 'pe':
            ret = self.check(**kw)
    except self.errors.ConfigurationError:
        pass
    else:
        if ret:
            return True
    kw['msg'] = 'Checking for -D_FILE_OFFSET_BITS=64'
    kw['defines'] = ['_FILE_OFFSET_BITS=64']
    try:
        ret = self.check(**kw)
    except self.errors.ConfigurationError:
        pass
    else:
        self.define('_FILE_OFFSET_BITS', 64)
        return ret
    self.fatal('There is no support for large files')


ENDIAN_FRAGMENT = '''
#ifdef _MSC_VER
#define testshlib_EXPORT __declspec(dllexport)
#else
#define testshlib_EXPORT
#endif

short int ascii_mm[] = { 0x4249, 0x4765, 0x6E44, 0x6961, 0x6E53, 0x7953, 0 };
short int ascii_ii[] = { 0x694C, 0x5454, 0x656C, 0x6E45, 0x6944, 0x6E61, 0 };
int testshlib_EXPORT use_ascii (int i) {
	return ascii_mm[i] + ascii_ii[i];
}
short int ebcdic_ii[] = { 0x89D3, 0xE3E3, 0x8593, 0x95C5, 0x89C4, 0x9581, 0 };
short int ebcdic_mm[] = { 0xC2C9, 0xC785, 0x95C4, 0x8981, 0x95E2, 0xA8E2, 0 };
int use_ebcdic (int i) {
	return ebcdic_mm[i] + ebcdic_ii[i];
}
extern int foo;
'''


class grep_for_endianness(Task.Task):
    color = 'PINK'

    def run(self):
        txt = self.inputs[0].read(flags='rb').decode('latin-1')
        if txt.find('LiTTleEnDian') > -1:
            self.generator.tmp.append('little')
        elif txt.find('BIGenDianSyS') > -1:
            self.generator.tmp.append('big')
        else:
            return -1


@feature('grep_for_endianness')
@after_method('apply_link')
def grep_for_endianness_fun(self):
    self.create_task('grep_for_endianness', self.link_task.outputs[0])


@conf
def check_endianness(self):
    tmp = []

    def check_msg(self):
        return tmp[0]

    self.check(
        fragment=ENDIAN_FRAGMENT,
        features='c cshlib grep_for_endianness',
        msg='Checking for endianness',
        define='ENDIANNESS',
        tmp=tmp,
        okmsg=check_msg,
        confcache=None
    )
    return tmp[0]
