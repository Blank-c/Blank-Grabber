import basemod

import inspect
import sys


class _Popen(basemod.Popen):
    def __init__(self, *args, **kw):
        print(inspect.getfile(self.__init__))
        print(inspect.getfile(super().__init__))
        super().__init__(*args, **kw)


# Reduce recursion limit to shorten the traceback.
sys.setrecursionlimit(50)

basemod.Popen = _Popen
p = basemod.Popen()
