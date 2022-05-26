#-----------------------------------------------------------------------------
# Copyright (c) 2013-2022, PyInstaller Development Team.
#
# Distributed under the terms of the GNU General Public License (version 2
# or later) with exception for distributing the bootloader.
#
# The full license is in the file COPYING.txt, distributed with this software.
#
# SPDX-License-Identifier: (GPL-2.0-or-later WITH Bootloader-exception)
#-----------------------------------------------------------------------------

from PyInstaller import isolated


@isolated.decorate
def mpl_data_dir():
    import matplotlib
    return matplotlib.get_data_path()


datas = [
    (mpl_data_dir(), "matplotlib/mpl-data"),
]
