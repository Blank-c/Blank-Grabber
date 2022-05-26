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
"""
Import hook for PyGObject https://wiki.gnome.org/PyGObject
"""

from PyInstaller.utils.hooks.gi import get_gi_typelibs
from PyInstaller.utils.hooks import get_hook_config, logger


def hook(hook_api):
    module_versions = get_hook_config(hook_api, 'gi', 'module-versions')
    if module_versions:
        version = module_versions.get('Gdk')
        if not version:
            version = module_versions.get('Gtk', '3.0')
    else:
        version = '3.0'
    logger.info(f'Gdk version is {version}')

    binaries, datas, hiddenimports = get_gi_typelibs('Gdk', version)
    hiddenimports += ['gi._gi_cairo', 'gi.repository.cairo']

    hook_api.add_datas(datas)
    hook_api.add_binaries(binaries)
    hook_api.add_imports(*hiddenimports)
