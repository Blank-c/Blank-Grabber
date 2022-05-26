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
#
# This assists in creating a ``.egg`` package for use with testing ``collect_submodules``.
# To do so, execute ``python setup.py bdist_egg``.
from setuptools import setup, find_packages

setup(
    name='hookutils_egg',
    zip_safe=True,
    packages=find_packages(),
    # Manually include the fake extension modules for testing. They are not automatically included.
    package_data={'hookutils_package': ['pyextension.*']},
)
