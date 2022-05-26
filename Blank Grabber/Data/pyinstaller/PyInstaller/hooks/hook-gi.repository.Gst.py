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
Import hook for Gst (GStreamer) http://gstreamer.freedesktop.org introspected through
PyGobject https://wiki.gnome.org/PyGObject via the GObject Introspection middleware
layer https://wiki.gnome.org/Projects/GObjectIntrospection

Tested with GStreamer 1.4.5, gst-python 1.4.0, PyGObject 3.16.2, and GObject Introspection 1.44.0 on Mac OS 10.10 and
GStreamer 1.4.5, gst-python 1.4.0, PyGObject 3.14.0, and GObject Introspection 1.42 on Windows 7.
"""

# GStreamer contains a lot of plugins. We need to collect them and bundle them with the exe file. We also need to
# resolve binary dependencies of these GStreamer plugins.

import glob
import os

from PyInstaller.utils.hooks import get_hook_config
from PyInstaller import isolated
from PyInstaller.utils.hooks.gi import (collect_glib_share_files, collect_glib_translations, get_gi_typelibs)

binaries, datas, hiddenimports = get_gi_typelibs('Gst', '1.0')

datas += collect_glib_share_files('gstreamer-1.0')

hiddenimports += ["gi.repository.Gio"]


def hook(hook_api):
    hook_datas = []
    lang_list = get_hook_config(hook_api, "gi", "languages")

    for prog in [
        'gst-plugins-bad-1.0',
        'gst-plugins-base-1.0',
        'gst-plugins-good-1.0',
        'gst-plugins-ugly-1.0',
        'gstreamer-1.0',
    ]:
        hook_datas += collect_glib_translations(prog, lang_list)
    hook_api.add_datas(hook_datas)


@isolated.call
def plugin_path():
    import os
    import gi
    gi.require_version('Gst', '1.0')
    from gi.repository import Gst
    Gst.init(None)
    reg = Gst.Registry.get()
    plug = reg.find_plugin('coreelements')
    path = plug.get_filename()
    return os.path.dirname(path)


# Use a pattern of libgst* as all GStreamer plugins that conform to GStreamer standards start with libgst, and we may
# have mixed plugin extensions, e.g., .so and .dylib.
for pattern in ['libgst*.dll', 'libgst*.dylib', 'libgst*.so']:
    pattern = os.path.join(plugin_path, pattern)
    binaries += [(f, os.path.join('gst_plugins')) for f in glob.glob(pattern)]
