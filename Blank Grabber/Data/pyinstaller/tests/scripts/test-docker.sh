#!/usr/bin/env bash
#-----------------------------------------------------------------------------
# Copyright (c) 2018-2022, PyInstaller Development Team.
#
# Distributed under the terms of the GNU General Public License (version 2
# or later) with exception for distributing the bootloader.
#
# The full license is in the file COPYING.txt, distributed with this software.
#
# SPDX-License-Identifier: (GPL-2.0-or-later WITH Bootloader-exception)
#-----------------------------------------------------------------------------

# Run commands (e.g. functional tests) in a Docker container.
#
# Usage: tests/scripts/test-docker.sh [args]
#
# Must be run from the PyInstaller project root. Any args
# will be passed on to `docker run`.
#
# This serves primarily to make it easier for e.g. macOS-based
# developers to run the tests in a Linux environment *before*
# opening a pull request.
#
# Note: this functionality is contributed and not maintained
# by the PyInstaller maintainers. If you find it useful,
# please consider contributing to its maintenance and improvement.

set -e
set -x

_args="py.test -n8 tests/functional"
if [[ -n $1 ]]; then
    _args=$@
fi

_image="pyinstaller-functional-tests"
docker build -t ${_image} -f "$(dirname $0)/Dockerfile" .
docker run -it --rm ${_image} ${_args}
