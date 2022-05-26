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
Functional tests for the PyPubSub API bundled with wxPython.

Since wxPython is currently only stably supported under Python 2, these tests are implicitly skipped under Python 3.
"""

import pkg_resources
from PyInstaller.utils.tests import importorskip, xfail

try:
    # These tests fail under wxPython versions which support multiple pubsub APIs.
    # See https://github.com/pyinstaller/pyinstaller/issues/1704.
    wxPython_fail = (
        pkg_resources.parse_version('2.8.10') <= pkg_resources.get_distribution('wxPython').parsed_version <
        pkg_resources.parse_version('2.9')
    )
except pkg_resources.DistributionNotFound:
    # Linux wxPython installations don't provide distribution metadata, but pass all the tests below.
    wxPython_fail = False


@xfail
@xfail(wxPython_fail, reason='Unsupported wxPython version')
@importorskip('wx.lib.pubsub')
def test_wx_lib_pubsub_protocol_default(pyi_builder):
    """
    Functional test applicable to all PyPubSub versions.
    """
    pyi_builder.test_script('pyi_hooks/wx_lib_pubsub.py')


@xfail
# This test will pass when test_import.test_import_respects_path passes, since that test provides a simple example
# of what causes this wxPython version to fail.
@xfail(wxPython_fail, reason='PyInstaller does not support this wxPython version')
@importorskip('wx.lib.pubsub.core')
def test_wx_lib_pubsub_protocol_kwargs(pyi_builder):
    """
    Functional test specific to version 3 of the PyPubSub API.

    The `wx.lib.pubsub.core` package is specific to this version.
    """
    pyi_builder.test_script('pyi_hooks/wx_lib_pubsub_setupkwargs.py')


@xfail
@xfail(wxPython_fail, reason='Unsupported wxPython version')
@importorskip('wx.lib.pubsub.core')
def test_wx_lib_pubsub_protocol_arg1(pyi_builder):
    """
    Functional test specific to version 3 of the PyPubSub API.

    The `wx.lib.pubsub.core` package is specific to this version.
    """
    pyi_builder.test_script('pyi_hooks/wx_lib_pubsub_setuparg1.py')
