from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
import os
import platform
import requests
import setuptools
import sys
from subprocess import check_call
from hashlib import sha256

__version__ = '0.0.3'


class get_pybind_include(object):
    """Helper class to determine the pybind11 include path

    The purpose of this class is to postpone importing pybind11
    until it is actually installed, so that the ``get_include()``
    method can be invoked. """

    def __str__(self):
        import pybind11
        return pybind11.get_include()


def verify_sha256sum(file_path, expected_sha256):
    with open(file_path, 'rb') as f:
        file_hash = sha256()
        chunk = f.read(8192)
        while chunk:
            file_hash.update(chunk)
            chunk = f.read(8192)

    return file_hash.hexdigest() == expected_sha256


def build_libsodium():
    libsodium_version = '1.0.18'
    install_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
    if platform.system() == "Windows":
        import zipfile
        # Download precompiled libsodium for Windows
        libsodium_url = f'https://download.libsodium.org/libsodium/releases/libsodium-{libsodium_version}-stable-msvc.zip'
        file_path = f'libsodium-{libsodium_version}-stable-msvc.zip'
        expected_sha256 = 'c1d48d85c9361e350931ffe5067559cd7405a697c655d26955fb568d1084a5f4'
        # Download libsodium
        response = requests.get(libsodium_url, stream=True)
        # Verify the sha256sum
        if not verify_sha256sum(file_path, expected_sha256):
            print("ERROR: The download's sha256sum does not match the expected one.")
            return
        with open(file_path, 'wb') as f:
            f.write(response.content)
        # Extract the zip file
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall()
        # todo : set or detect msvc version
        libsodium_lib = ""
        return libsodium_lib
    else:
        import tarfile
        libsodium_url = f'https://download.libsodium.org/libsodium/releases/libsodium-{libsodium_version}.tar.gz'
        expected_sha256 = '6f504490b342a4f8a4c4a02fc9b866cbef8622d5df4e5452b46be121e46636c1'
        file_path = f'libsodium-{libsodium_version}.tar.gz'
        # Download libsodium
        response = requests.get(libsodium_url, stream=True)
        with open(file_path, 'wb') as f:
            f.write(response.content)
        # Verify the sha256sum
        if not verify_sha256sum(file_path, expected_sha256):
            print("ERROR: The download's sha256sum does not match the expected one.")
            return
        # Extract the tar.gz file
        with tarfile.open(file_path, 'r:gz') as tar:
            tar.extractall()
        # Change the directory to the extracted libsodium directory
        os.chdir(f'libsodium-{libsodium_version}')
        # Run the configure script with the desired flags and then make and make install
        check_call(['./configure','--disable-static' ,'--enable-shared', f'--prefix={install_dir}'])
        check_call(['make'])
        check_call(['make', 'install'])
        os.chdir(os.path.dirname(__file__))
        libsodium_lib = os.path.join(install_dir, "lib")
        return libsodium_lib


ext_modules = [
    Extension(
        'verushash',
        sorted(['src/compat/glibc_compat.cpp',
                'src/compat/glibc_sanity.cpp',
                'src/compat/glibcxx_sanity.cpp',
                'src/compat/strnlen.cpp',
                'src/crypto/haraka.c',
                'src/crypto/haraka_portable.c',
                'src/crypto/ripemd160.cpp',
                'src/crypto/sha256.cpp',
                'src/crypto/uint256.cpp',
                'src/crypto/utilstrencodings.cpp',
                'src/crypto/verus_hash.cpp',
                'src/crypto/verus_clhash.cpp',
                'src/crypto/verus_clhash_portable.cpp',
                'src/support/cleanse.cpp',
                'src/blockhash.cpp',
                'src/main.cpp']),
        include_dirs=[
            # Path to pybind11 headers
            get_pybind_include(),
            'src/include',
            'src',
        ],
        libraries=['sodium'],
        library_dirs=[build_libsodium()],
        define_macros=[('VERSION_INFO', __version__)],
    ),
]


# cf http://bugs.python.org/issue26689
def has_flag(compiler, flagname):
    """Return a boolean indicating whether a flag name is supported on
    the specified compiler.
    """
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.cpp', delete=False) as f:
        f.write('int main (int argc, char **argv) { return 0; }')
        fname = f.name
        try:
            compiler.compile([fname], extra_postargs=[flagname])
        except setuptools.distutils.errors.CompileError:
            return False
        finally:
            try:
                os.remove(fname)
            except OSError:
                pass
    return True


def cpp_flag(compiler):
    """Return the -std=c++[11/14/17] compiler flag.

    The newer version is preferred over c++11 (when it is available).
    """
    flags = ['-std=c++17', '-std=c++14', '-std=c++11']

    for flag in flags:
        if has_flag(compiler, flag):
            return flag
    raise RuntimeError('Unsupported compiler -- at least C++11 support '
                       'is needed!')


class BuildExt(build_ext):
    """A custom build extension for adding compiler-specific options."""
    c_opts = {
        'msvc': ['/EHsc'],
        'unix': ['-Wl,--whole-archive',
                 '-fPIC',
                 '-fexceptions',
                 '-O3',
                 '-march=native',
                 '-Wno-reorder',
                 '-g'],
    }
    l_opts = {
        'msvc': [],
        'unix': [],
    }

    if sys.platform == 'darwin':
        darwin_opts = ['-stdlib=libc++', '-mmacosx-version-min=10.7']
        c_opts['unix'] += darwin_opts
        l_opts['unix'] += darwin_opts

    def build_extensions(self):
        if '-Wstrict-prototypes' in self.compiler.compiler_so:
            self.compiler.compiler_so.remove('-Wstrict-prototypes')
        ct = self.compiler.compiler_type
        opts = self.c_opts.get(ct, [])
        link_opts = self.l_opts.get(ct, [])
        if ct == 'unix':
            opts.append(cpp_flag(self.compiler))
            if has_flag(self.compiler, '-fvisibility=hidden'):
                opts.append('-fvisibility=hidden')
        for ext in self.extensions:
            ext.define_macros = [('VERSION_INFO', '"{}"'.format(self.distribution.get_version()))]
            ext.extra_compile_args = opts
            ext.extra_link_args = link_opts
        build_ext.build_extensions(self)


setup(
    name='verushash',
    version=__version__,
    author='Michael Toutonghi',
    author_email='',
    url='https://github.com/miketout/verushashpy',
    description='Native Verus Hash module for Python',
    long_description='A Verus Hash module supporting VerusHash 1.0 - 2.2, written in C++',
    ext_modules=ext_modules,
    setup_requires=['pybind11>=2.5'],
    cmdclass={'build_ext': BuildExt},
    zip_safe=False,
)