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

# --- functions for checking guts ---
# NOTE: by GUTS it is meant intermediate files and data structures that PyInstaller creates for bundling files and
# creating final executable.
import fnmatch
import glob
import hashlib
import os
import pathlib
import platform
import shutil
import struct
import subprocess
import sys

from PyInstaller import compat
from PyInstaller import log as logging
from PyInstaller.compat import (EXTENSION_SUFFIXES, is_cygwin, is_darwin, is_win)
from PyInstaller.config import CONF
from PyInstaller.depend import dylib
from PyInstaller.depend.bindepend import match_binding_redirect
from PyInstaller.utils import misc

if is_win or is_cygwin:
    from PyInstaller.utils.win32 import versioninfo, winmanifest, winresource

if is_darwin:
    import PyInstaller.utils.osx as osxutils

logger = logging.getLogger(__name__)

# -- Helpers for checking guts.
#
# NOTE: by _GUTS it is meant intermediate files and data structures that PyInstaller creates for bundling files and
# creating final executable.


def _check_guts_eq(attr, old, new, _last_build):
    """
    Rebuild is required if values differ.
    """
    if old != new:
        logger.info("Building because %s changed", attr)
        return True
    return False


def _check_guts_toc_mtime(_attr, old, _toc, last_build, pyc=0):
    """
    Rebuild is required if mtimes of files listed in old toc are newer than last_build.

    If pyc=1, check for .py files as well.

    Use this for calculated/analysed values read from cache.
    """
    for nm, fnm, typ in old:
        if misc.mtime(fnm) > last_build:
            logger.info("Building because %s changed", fnm)
            return True
        elif pyc and misc.mtime(fnm[:-1]) > last_build:
            logger.info("Building because %s changed", fnm[:-1])
            return True
    return False


def _check_guts_toc(attr, old, toc, last_build, pyc=0):
    """
    Rebuild is required if either toc content changed or mtimes of files listed in old toc are newer than last_build.

    If pyc=1, check for .py files as well.

    Use this for input parameters.
    """
    return _check_guts_eq(attr, old, toc, last_build) or _check_guts_toc_mtime(attr, old, toc, last_build, pyc=pyc)


def add_suffix_to_extension(inm, fnm, typ):
    """
    Take a TOC entry (inm, fnm, typ) and adjust the inm for EXTENSION or DEPENDENCY to include the full library suffix.
    """
    if typ == 'EXTENSION':
        if fnm.endswith(inm):
            # If inm completely fits into end of the fnm, it has already been processed.
            return inm, fnm, typ
        # Change the dotted name into a relative path. This places C extensions in the Python-standard location.
        inm = inm.replace('.', os.sep)
        # In some rare cases extension might already contain a suffix. Skip it in this case.
        if os.path.splitext(inm)[1] not in EXTENSION_SUFFIXES:
            # Determine the base name of the file.
            base_name = os.path.basename(inm)
            assert '.' not in base_name
            # Use this file's existing extension. For extensions such as ``libzmq.cp36-win_amd64.pyd``, we cannot use
            # ``os.path.splitext``, which would give only the ```.pyd`` part of the extension.
            inm = inm + os.path.basename(fnm)[len(base_name):]

    elif typ == 'DEPENDENCY':
        # Use the suffix from the filename.
        # TODO: verify what extensions are by DEPENDENCIES.
        binext = os.path.splitext(fnm)[1]
        if not os.path.splitext(inm)[1] == binext:
            inm = inm + binext

    return inm, fnm, typ


def applyRedirects(manifest, redirects):
    """
    Apply the binding redirects specified by 'redirects' to the dependent assemblies of 'manifest'.

    :param manifest:
    :type manifest:
    :param redirects:
    :type redirects:
    :return:
    :rtype:
    """
    redirecting = False
    for binding in redirects:
        for dep in manifest.dependentAssemblies:
            if match_binding_redirect(dep, binding):
                logger.info("Redirecting %s version %s -> %s", binding.name, dep.version, binding.newVersion)
                dep.version = binding.newVersion
                redirecting = True
    return redirecting


def checkCache(
    fnm,
    strip=False,
    upx=False,
    upx_exclude=None,
    dist_nm=None,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    strict_arch_validation=False
):
    """
    Cache prevents preprocessing binary files again and again.

    'dist_nm'  Filename relative to dist directory. We need it on Mac to determine level of paths for @loader_path like
               '@loader_path/../../' for qt4 plugins.
    """
    from PyInstaller.config import CONF

    # On Mac OS, a cache is required anyway to keep the libraries with relative install names.
    # Caching on Mac OS does not work since we need to modify binary headers to use relative paths to dll dependencies
    # and starting with '@loader_path'.
    if not strip and not upx and not is_darwin and not is_win:
        return fnm

    if dist_nm is not None and ":" in dist_nm:
        # A file embedded in another PyInstaller build via multipackage.
        # No actual file exists to process.
        return fnm

    if strip:
        strip = True
    else:
        strip = False

    # Disable UPX on non-Windows. Using UPX (3.96) on modern Linux shared libraries (for example, the python3.x.so
    # shared library) seems to result in segmentation fault when they are dlopen'd. This happens in recent versions
    # of Fedora and Ubuntu linux, as well as in Alpine containers. On Mac OS, UPX (3.96) fails with
    # UnknownExecutableFormatException on most .dylibs (and interferes with code signature on other occasions). And
    # even when it would succeed, compressed libraries cannot be (re)signed due to failed strict validation.
    upx = upx and (is_win or is_cygwin)

    # Match against provided UPX exclude patterns.
    upx_exclude = upx_exclude or []
    if upx:
        fnm_path = pathlib.PurePath(fnm)
        for upx_exclude_entry in upx_exclude:
            # pathlib.PurePath.match() matches from right to left, and supports * wildcard, but does not support the
            # "**" syntax for directory recursion. Case sensitivity follows the OS default.
            if fnm_path.match(upx_exclude_entry):
                logger.info("Disabling UPX for %s due to match in exclude pattern: %s", fnm, upx_exclude_entry)
                upx = False
                break

    # Load cache index.
    # Make cachedir per Python major/minor version.
    # This allows parallel building of executables with different Python versions as one user.
    pyver = 'py%d%s' % (sys.version_info[0], sys.version_info[1])
    arch = platform.architecture()[0]
    cachedir = os.path.join(CONF['cachedir'], 'bincache%d%d_%s_%s' % (strip, upx, pyver, arch))
    if target_arch:
        cachedir = os.path.join(cachedir, target_arch)
    if is_darwin:
        # Separate by codesign identity
        if codesign_identity:
            # Compute hex digest of codesign identity string to prevent issues with invalid characters.
            csi_hash = hashlib.sha256(codesign_identity.encode('utf-8'))
            cachedir = os.path.join(cachedir, csi_hash.hexdigest())
        else:
            cachedir = os.path.join(cachedir, 'adhoc')  # ad-hoc signing
        # Separate by entitlements
        if entitlements_file:
            # Compute hex digest of entitlements file contents
            with open(entitlements_file, 'rb') as fp:
                ef_hash = hashlib.sha256(fp.read())
            cachedir = os.path.join(cachedir, ef_hash.hexdigest())
        else:
            cachedir = os.path.join(cachedir, 'no-entitlements')
    if not os.path.exists(cachedir):
        os.makedirs(cachedir)
    cacheindexfn = os.path.join(cachedir, "index.dat")
    if os.path.exists(cacheindexfn):
        try:
            cache_index = misc.load_py_data_struct(cacheindexfn)
        except Exception:
            # Tell the user they may want to fix their cache... However, do not delete it for them; if it keeps getting
            # corrupted, we will never find out.
            logger.warning("PyInstaller bincache may be corrupted; use pyinstaller --clean to fix it.")
            raise
    else:
        cache_index = {}

    # Verify that the file we are looking for is present in the cache. Use the dist_mn if given to avoid different
    # extension modules sharing the same basename get corrupted.
    if dist_nm:
        basenm = os.path.normcase(dist_nm)
    else:
        basenm = os.path.normcase(os.path.basename(fnm))

    # Binding redirects should be taken into account to see if the file needs to be reprocessed. The redirects may
    # change if the versions of dependent manifests change due to system updates.
    redirects = CONF.get('binding_redirects', [])
    digest = cacheDigest(fnm, redirects)
    cachedfile = os.path.join(cachedir, basenm)
    cmd = None
    if basenm in cache_index:
        if digest != cache_index[basenm]:
            os.remove(cachedfile)
        else:
            return cachedfile

    # Optionally change manifest and its dependencies to private assemblies.
    if fnm.lower().endswith(".manifest") and (is_win or is_cygwin):
        manifest = winmanifest.Manifest()
        manifest.filename = fnm
        with open(fnm, "rb") as f:
            manifest.parse_string(f.read())
        if CONF.get('win_private_assemblies', False):
            if manifest.publicKeyToken:
                logger.info("Changing %s into private assembly", os.path.basename(fnm))
            manifest.publicKeyToken = None
            for dep in manifest.dependentAssemblies:
                # Exclude common-controls which is not bundled
                if dep.name != "Microsoft.Windows.Common-Controls":
                    dep.publicKeyToken = None

        applyRedirects(manifest, redirects)

        manifest.writeprettyxml(cachedfile)
        return cachedfile

    if upx:
        if strip:
            fnm = checkCache(
                fnm,
                strip=True,
                upx=False,
                dist_nm=dist_nm,
                target_arch=target_arch,
                codesign_identity=codesign_identity,
                entitlements_file=entitlements_file,
                strict_arch_validation=strict_arch_validation,
            )
        # We need to avoid using UPX with Windows DLLs that have Control Flow Guard enabled, as it breaks them.
        if (is_win or is_cygwin) and versioninfo.pefile_check_control_flow_guard(fnm):
            logger.info('Disabling UPX for %s due to CFG!', fnm)
        elif misc.is_file_qt_plugin(fnm):
            logger.info('Disabling UPX for %s due to it being a Qt plugin!', fnm)
        else:
            bestopt = "--best"
            # FIXME: Linux builds of UPX do not seem to contain LZMA (they assert out).
            # A better configure-time check is due.
            if CONF["hasUPX"] >= (3,) and os.name == "nt":
                bestopt = "--lzma"

            upx_executable = "upx"
            if CONF.get('upx_dir'):
                upx_executable = os.path.join(CONF['upx_dir'], upx_executable)
            cmd = [upx_executable, bestopt, "-q", cachedfile]
    else:
        if strip:
            strip_options = []
            if is_darwin:
                # The default strip behavior breaks some shared libraries under Mac OS.
                strip_options = ["-S"]  # -S = strip only debug symbols.
            cmd = ["strip"] + strip_options + [cachedfile]

    if not os.path.exists(os.path.dirname(cachedfile)):
        os.makedirs(os.path.dirname(cachedfile))
    # There are known some issues with 'shutil.copy2' on Mac OS 10.11 with copying st_flags. Issue #1650.
    # 'shutil.copy' copies also permission bits and it should be sufficient for PyInstaller's purposes.
    shutil.copy(fnm, cachedfile)
    # TODO: find out if this is still necessary when no longer using shutil.copy2()
    if hasattr(os, 'chflags'):
        # Some libraries on FreeBSD have immunable flag (libthr.so.3, for example). If this flag is preserved,
        # os.chmod() fails with: OSError: [Errno 1] Operation not permitted.
        try:
            os.chflags(cachedfile, 0)
        except OSError:
            pass
    os.chmod(cachedfile, 0o755)

    if os.path.splitext(fnm.lower())[1] in (".pyd", ".dll") and (is_win or is_cygwin):
        # When shared assemblies are bundled into the app, they may optionally be changed into private assemblies.
        try:
            res = winmanifest.GetManifestResources(os.path.abspath(cachedfile))
        except winresource.pywintypes.error as e:
            if e.args[0] == winresource.ERROR_BAD_EXE_FORMAT:
                # Not a win32 PE file
                pass
            else:
                logger.error(os.path.abspath(cachedfile))
                raise
        else:
            if winmanifest.RT_MANIFEST in res and len(res[winmanifest.RT_MANIFEST]):
                for name in res[winmanifest.RT_MANIFEST]:
                    for language in res[winmanifest.RT_MANIFEST][name]:
                        try:
                            manifest = winmanifest.Manifest()
                            manifest.filename = ":".join([
                                cachedfile, str(winmanifest.RT_MANIFEST),
                                str(name), str(language)
                            ])
                            manifest.parse_string(res[winmanifest.RT_MANIFEST][name][language], False)
                        except Exception:
                            logger.error("Cannot parse manifest resource %s, =%s", name, language)
                            logger.error("From file %s", cachedfile, exc_info=1)
                        else:
                            # optionally change manifest to private assembly
                            private = CONF.get('win_private_assemblies', False)
                            if private:
                                if manifest.publicKeyToken:
                                    logger.info("Changing %s into a private assembly", os.path.basename(fnm))
                                manifest.publicKeyToken = None

                                # Change dep to private assembly
                                for dep in manifest.dependentAssemblies:
                                    # Exclude common-controls which is not bundled
                                    if dep.name != "Microsoft.Windows.Common-Controls":
                                        dep.publicKeyToken = None
                            redirecting = applyRedirects(manifest, redirects)
                            if redirecting or private:
                                try:
                                    manifest.update_resources(os.path.abspath(cachedfile), [name], [language])
                                except Exception:
                                    logger.error(os.path.abspath(cachedfile))
                                    raise

    if cmd:
        logger.info("Executing - " + "".join(cmd))
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # update cache index
    cache_index[basenm] = digest
    misc.save_py_data_struct(cacheindexfn, cache_index)

    # On Mac OS we need relative paths to dll dependencies starting with @executable_path. While modifying
    # the headers invalidates existing signatures, we avoid removing them in order to speed things up (and
    # to avoid potential bugs in the codesign utility, like the one reported on Mac OS 10.13 in #6167).
    # The forced re-signing at the end should take care of the invalidated signatures.
    if is_darwin:
        try:
            osxutils.binary_to_target_arch(cachedfile, target_arch, display_name=fnm)
            #osxutils.remove_signature_from_binary(cachedfile)  # Disabled as per comment above.
            dylib.mac_set_relative_dylib_deps(cachedfile, dist_nm)
            osxutils.sign_binary(cachedfile, codesign_identity, entitlements_file)
        except osxutils.InvalidBinaryError:
            # Raised by osxutils.binary_to_target_arch when the given file is not a valid macOS binary (for example,
            # a linux .so file; see issue #6327). The error prevents any further processing, so just ignore it.
            pass
        except osxutils.IncompatibleBinaryArchError:
            # Raised by osxutils.binary_to_target_arch when the given file does not contain (all) required arch slices.
            # Depending on the strict validation mode, re-raise or swallow the error.
            #
            # Strict validation should be enabled only for binaries where the architecture *must* match the target one,
            # i.e., the extension modules. Everything else is pretty much a gray area, for example:
            #  * a universal2 extension may have its x86_64 and arm64 slices linked against distinct single-arch/thin
            #    shared libraries
            #  * a collected executable that is launched by python code via a subprocess can be x86_64-only, even though
            #    the actual python code is running on M1 in native arm64 mode.
            if strict_arch_validation:
                raise
            logger.debug("File %s failed optional architecture validation - collecting as-is!", fnm)

    return cachedfile


def cacheDigest(fnm, redirects):
    hasher = hashlib.md5()
    with open(fnm, "rb") as f:
        for chunk in iter(lambda: f.read(16 * 1024), b""):
            hasher.update(chunk)
    if redirects:
        redirects = str(redirects).encode('utf-8')
        hasher.update(redirects)
    digest = bytearray(hasher.digest())
    return digest


def _check_path_overlap(path):
    """
    Check that path does not overlap with WORKPATH or SPECPATH (i.e., WORKPATH and SPECPATH may not start with path,
    which could be caused by a faulty hand-edited specfile).

    Raise SystemExit if there is overlap, return True otherwise
    """
    from PyInstaller.config import CONF
    specerr = 0
    if CONF['workpath'].startswith(path):
        logger.error('Specfile error: The output path "%s" contains WORKPATH (%s)', path, CONF['workpath'])
        specerr += 1
    if CONF['specpath'].startswith(path):
        logger.error('Specfile error: The output path "%s" contains SPECPATH (%s)', path, CONF['specpath'])
        specerr += 1
    if specerr:
        raise SystemExit(
            'Error: Please edit/recreate the specfile (%s) and set a different output name (e.g. "dist").' %
            CONF['spec']
        )
    return True


def _make_clean_directory(path):
    """
    Create a clean directory from the given directory name.
    """
    if _check_path_overlap(path):
        if os.path.isdir(path) or os.path.isfile(path):
            try:
                os.remove(path)
            except OSError:
                _rmtree(path)

        os.makedirs(path, exist_ok=True)


def _rmtree(path):
    """
    Remove directory and all its contents, but only after user confirmation, or if the -y option is set.
    """
    from PyInstaller.config import CONF
    if CONF['noconfirm']:
        choice = 'y'
    elif sys.stdout.isatty():
        choice = compat.stdin_input(
            'WARNING: The output directory "%s" and ALL ITS CONTENTS will be REMOVED! Continue? (y/N)' % path
        )
    else:
        raise SystemExit(
            'Error: The output directory "%s" is not empty. Please remove all its contents or use the -y option (remove'
            ' output directory without confirmation).' % path
        )
    if choice.strip().lower() == 'y':
        if not CONF['noconfirm']:
            print("On your own risk, you can use the option `--noconfirm` to get rid of this question.")
        logger.info('Removing dir %s', path)
        shutil.rmtree(path)
    else:
        raise SystemExit('User aborted')


# TODO Refactor to prohibit empty target directories. As the docstring below documents, this function currently permits
# the second item of each 2-tuple in "hook.datas" to be the empty string, in which case the target directory defaults to
# the source directory's basename. However, this functionality is very fragile and hence bad. Instead:
#
# * An exception should be raised if such item is empty.
# * All hooks currently passing the empty string for such item (e.g.,
#   "hooks/hook-babel.py", "hooks/hook-matplotlib.py") should be refactored
#   to instead pass such basename.
def format_binaries_and_datas(binaries_or_datas, workingdir=None):
    """
    Convert the passed list of hook-style 2-tuples into a returned set of `TOC`-style 2-tuples.

    Elements of the passed list are 2-tuples `(source_dir_or_glob, target_dir)`.
    Elements of the returned set are 2-tuples `(target_file, source_file)`.
    For backwards compatibility, the order of elements in the former tuples are the reverse of the order of elements in
    the latter tuples!

    Parameters
    ----------
    binaries_or_datas : list
        List of hook-style 2-tuples (e.g., the top-level `binaries` and `datas` attributes defined by hooks) whose:
        * The first element is either:
          * A glob matching only the absolute or relative paths of source non-Python data files.
          * The absolute or relative path of a source directory containing only source non-Python data files.
        * The second element is the relative path of the target directory into which these source files will be
          recursively copied.

        If the optional `workingdir` parameter is passed, source paths may be either absolute or relative; else, source
        paths _must_ be absolute.
    workingdir : str
        Optional absolute path of the directory to which all relative source paths in the `binaries_or_datas`
        parameter will be prepended by (and hence converted into absolute paths) _or_ `None` if these paths are to be
        preserved as relative. Defaults to `None`.

    Returns
    ----------
    set
        Set of `TOC`-style 2-tuples whose:
        * First element is the absolute or relative path of a target file.
        * Second element is the absolute or relative path of the corresponding source file to be copied to this target
          file.
    """
    toc_datas = set()

    for src_root_path_or_glob, trg_root_dir in binaries_or_datas:
        if not trg_root_dir:
            raise SystemExit(
                "Empty DEST not allowed when adding binary and data files. Maybe you want to used %r.\nCaused by %r." %
                (os.curdir, src_root_path_or_glob)
            )
        # Convert relative to absolute paths if required.
        if workingdir and not os.path.isabs(src_root_path_or_glob):
            src_root_path_or_glob = os.path.join(workingdir, src_root_path_or_glob)

        # Normalize paths.
        src_root_path_or_glob = os.path.normpath(src_root_path_or_glob)
        if os.path.isfile(src_root_path_or_glob):
            src_root_paths = [src_root_path_or_glob]
        else:
            # List of the absolute paths of all source paths matching the current glob.
            src_root_paths = glob.glob(src_root_path_or_glob)

        if not src_root_paths:
            msg = 'Unable to find "%s" when adding binary and data files.' % src_root_path_or_glob
            # on Debian/Ubuntu, missing pyconfig.h files can be fixed with installing python-dev
            if src_root_path_or_glob.endswith("pyconfig.h"):
                msg += """This means your Python installation does not come with proper shared library files.
This usually happens due to missing development package, or unsuitable build parameters of the Python installation.

* On Debian/Ubuntu, you need to install Python development packages:
  * apt-get install python3-dev
  * apt-get install python-dev
* If you are building Python by yourself, rebuild with `--enable-shared` (or, `--enable-framework` on macOS).
"""
            raise SystemExit(msg)

        for src_root_path in src_root_paths:
            if os.path.isfile(src_root_path):
                # Normalizing the result to remove redundant relative paths (e.g., removing "./" from "trg/./file").
                toc_datas.add((
                    os.path.normpath(os.path.join(trg_root_dir, os.path.basename(src_root_path))),
                    os.path.normpath(src_root_path),
                ))
            elif os.path.isdir(src_root_path):
                for src_dir, src_subdir_basenames, src_file_basenames in os.walk(src_root_path):
                    # Ensure the current source directory is a subdirectory of the passed top-level source directory.
                    # Since os.walk() does *NOT* follow symlinks by default, this should be the case. (But let's make
                    # sure.)
                    assert src_dir.startswith(src_root_path)

                    # Relative path of the current target directory, obtained by:
                    #
                    # * Stripping the top-level source directory from the current source directory (e.g., removing
                    #   "/top" from "/top/dir").
                    # * Normalizing the result to remove redundant relative paths (e.g., removing "./" from
                    #   "trg/./file").
                    trg_dir = os.path.normpath(os.path.join(trg_root_dir, os.path.relpath(src_dir, src_root_path)))

                    for src_file_basename in src_file_basenames:
                        src_file = os.path.join(src_dir, src_file_basename)
                        if os.path.isfile(src_file):
                            # Normalize the result to remove redundant relative paths (e.g., removing "./" from
                            # "trg/./file").
                            toc_datas.add((
                                os.path.normpath(os.path.join(trg_dir, src_file_basename)), os.path.normpath(src_file)
                            ))

    return toc_datas


def get_code_object(modname, filename):
    """
    Get the code-object for a module.

    This is a simplifed non-performant version which circumvents __pycache__.
    """

    try:
        if filename in ('-', None):
            # This is a NamespacePackage, modulegraph marks them by using the filename '-'. (But wants to use None, so
            # check for None, too, to be forward-compatible.)
            logger.debug('Compiling namespace package %s', modname)
            txt = '#\n'
            return compile(txt, filename, 'exec')
        else:
            logger.debug('Compiling %s', filename)
            with open(filename, 'rb') as f:
                source = f.read()
            return compile(source, filename, 'exec')
    except SyntaxError as e:
        print("Syntax error in ", filename)
        print(e.args)
        raise


def strip_paths_in_code(co, new_filename=None):
    # Paths to remove from filenames embedded in code objects
    replace_paths = sys.path + CONF['pathex']
    # Make sure paths end with os.sep and the longest paths are first
    replace_paths = sorted((os.path.join(f, '') for f in replace_paths), key=len, reverse=True)

    if new_filename is None:
        original_filename = os.path.normpath(co.co_filename)
        for f in replace_paths:
            if original_filename.startswith(f):
                new_filename = original_filename[len(f):]
                break

        else:
            return co

    code_func = type(co)

    consts = tuple(
        strip_paths_in_code(const_co, new_filename) if isinstance(const_co, code_func) else const_co
        for const_co in co.co_consts
    )

    if hasattr(co, 'replace'):  # is_py38
        return co.replace(co_consts=consts, co_filename=new_filename)
    elif hasattr(co, 'co_kwonlyargcount'):
        # co_kwonlyargcount was added in some version of Python 3
        return code_func(
            co.co_argcount, co.co_kwonlyargcount, co.co_nlocals, co.co_stacksize, co.co_flags, co.co_code, consts,
            co.co_names, co.co_varnames, new_filename, co.co_name, co.co_firstlineno, co.co_lnotab, co.co_freevars,
            co.co_cellvars
        )
    else:
        return code_func(
            co.co_argcount, co.co_nlocals, co.co_stacksize, co.co_flags, co.co_code, consts, co.co_names,
            co.co_varnames, new_filename, co.co_name, co.co_firstlineno, co.co_lnotab, co.co_freevars, co.co_cellvars
        )


def fake_pyc_timestamp(buf):
    """
    Reset the timestamp from a .pyc-file header to a fixed value.

    This enables deterministic builds without having to set pyinstaller source metadata (mtime) since that changes the
    pyc-file contents.

    _buf_ must at least contain the full pyc-file header.
    """
    assert buf[:4] == compat.BYTECODE_MAGIC, \
        "Expected pyc magic {}, got {}".format(compat.BYTECODE_MAGIC, buf[:4])
    start, end = 4, 8
    # See https://www.python.org/dev/peps/pep-0552/
    (flags,) = struct.unpack_from(">I", buf, 4)
    if flags & 1:
        # We are in the future and hash-based pyc-files are used, so
        # clear "check_source" flag, since there is no source.
        buf[4:8] = struct.pack(">I", flags ^ 2)
        return buf
    else:
        # No hash-based pyc-file, timestamp is the next field.
        start, end = 8, 12

    ts = b'pyi0'  # So people know where this comes from
    return buf[:start] + ts + buf[end:]


def _should_include_system_binary(binary_tuple, exceptions):
    """
    Return True if the given binary_tuple describes a system binary that should be included.

    Exclude all system library binaries other than those with "lib-dynload" in the destination or "python" in the
    source, except for those matching the patterns in the exceptions list. Intended to be used from the Analysis
    exclude_system_libraries method.
    """
    dest = binary_tuple[0]
    if dest.startswith('lib-dynload'):
        return True
    src = binary_tuple[1]
    if fnmatch.fnmatch(src, '*python*'):
        return True
    if not src.startswith('/lib') and not src.startswith('/usr/lib'):
        return True
    for exception in exceptions:
        if fnmatch.fnmatch(dest, exception):
            return True
    return False
