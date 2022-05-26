AR = ['C:\\MinGw\\bin\\ar.exe']
ARCH_FLAGS_REQUIRED = False
ARFLAGS = ['rcs']
BINDIR = 'C:\\Users\\SAUHAR~1\\AppData\\Local\\Temp/bin'
CC = ['C:\\MinGw\\bin\\gcc.exe']
CCLNK_SRC_F = []
CCLNK_TGT_F = ['-o']
CC_NAME = 'gcc'
CC_SRC_F = []
CC_TGT_F = ['-c', '-o']
CC_VERSION = ('8', '1', '0')
CFLAGS = ['-m64', '-O2', '-Wall', '-Werror', '-Wno-error=unused-variable', '-Wno-error=unused-function', '-Wno-unused-variable', '-Wno-unused-function', '-mms-bitfields', '-municode', '-mwindows']
CFLAGS_MACBUNDLE = ['-fPIC']
CFLAGS_cshlib = []
COMPILER_CC = 'gcc'
CPPPATH = ['../zlib']
CPPPATH_ST = '-I%s'
DEFINES = ['WIN32', 'NTDDI_VERSION=0x06010000', '_WIN32_WINNT=0x0601', 'HAVE_DIRNAME=1', 'HAVE_BASENAME=1', 'HAVE_STRNLEN=1', 'LAUNCH_DEBUG', 'NDEBUG', 'WINDOWED']
DEFINES_ST = '-D%s'
DEFINE_COMMENTS = {'HAVE_UNSETENV': '', 'HAVE_MKDTEMP': '', 'HAVE_DIRNAME': '', 'HAVE_BASENAME': '', 'HAVE_STRNDUP': '', 'HAVE_STRNLEN': ''}
DEST_BINFMT = 'pe'
DEST_CPU = 'x86_64'
DEST_OS = 'win32'
HAVE_BASENAME = 1
HAVE_DIRNAME = 1
HAVE_STRNLEN = 1
IMPLIBDIR = 'C:\\Users\\SAUHAR~1\\AppData\\Local\\Temp/lib'
IMPLIB_ST = '-Wl,--out-implib,%s'
LIBDIR = 'C:\\Users\\SAUHAR~1\\AppData\\Local\\Temp/bin'
LIBPATH_ST = '-L%s'
LIB_ADVAPI32 = ['advapi32']
LIB_COMCTL32 = ['comctl32']
LIB_GDI32 = ['gdi32']
LIB_KERNEL32 = ['kernel32']
LIB_ST = '-l%s'
LIB_USER32 = ['user32']
LINKFLAGS = ['-Wl,--enable-auto-import', '-m64', '-municode', '-Wl,--stack,2000000', '-mwindows']
LINKFLAGS_MACBUNDLE = ['-bundle', '-undefined', 'dynamic_lookup']
LINKFLAGS_cshlib = ['-shared']
LINKFLAGS_cstlib = ['-Wl,-Bstatic']
LINK_CC = ['C:\\MinGw\\bin\\gcc.exe']
MSVC_MANIFEST = False
PREFIX = 'C:\\Users\\SAUHAR~1\\AppData\\Local\\Temp'
PYI_ARCH = '64bit'
PYI_SYSTEM = 'Windows'
RPATH_ST = '-Wl,-rpath,%s'
SHLIB_MARKER = '-Wl,-Bdynamic'
SONAME_ST = '-Wl,-h,%s'
STLIBPATH_ST = '-L%s'
STLIB_MARKER = '-Wl,-Bstatic'
STLIB_ST = '-l%s'
STRIP = ['C:\\MinGw\\bin\\strip.exe']
STRIPFLAGS = ['']
cprogram_PATTERN = '%s.exe'
cshlib_PATTERN = '%s.dll'
cstlib_PATTERN = 'lib%s.a'
define_key = ['HAVE_UNSETENV', 'HAVE_MKDTEMP', 'HAVE_DIRNAME', 'HAVE_BASENAME', 'HAVE_STRNDUP', 'HAVE_STRNLEN']
implib_PATTERN = '%s.dll.a'
macbundle_PATTERN = '%s.bundle'
