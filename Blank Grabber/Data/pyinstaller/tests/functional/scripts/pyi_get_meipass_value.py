#-----------------------------------------------------------------------------
# Copyright (c) 2005-2022, PyInstaller Development Team.
#
# Distributed under the terms of the GNU General Public License (version 2
# or later) with exception for distributing the bootloader.
#
# The full license is in the file COPYING.txt, distributed with this software.
#
# SPDX-License-Identifier: (GPL-2.0-or-later WITH Bootloader-exception)
#-----------------------------------------------------------------------------

# Bootloader unsets _MEIPASS2 for child processes so that if the program invokes another PyInstaller one-file program
# as subprocess, this subprocess will not fooled into thinking that it is already unpacked.
#
# This test checks if it is really unset in a subprocess.

import subprocess
import sys


def _get_meipass_value():
    if sys.platform.startswith('win'):
        command = 'echo %_MEIPASS2%'
    else:
        command = 'echo $_MEIPASS2'

    stdout = subprocess.check_output(command, shell=True)
    meipass = stdout.strip()

    # Win32 fix.
    if meipass.startswith(b'%'):
        meipass = ''

    return meipass


meipass = _get_meipass_value()

print(meipass)
print(('_MEIPASS2 value: %s' % sys._MEIPASS))

if meipass:
    raise SystemExit('Error: _MEIPASS2 env variable available in subprocess.')
