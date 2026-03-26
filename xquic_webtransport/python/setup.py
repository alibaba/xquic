from setuptools import setup, find_packages

setup(
    name="pyxquic-wt",
    cffi_modules=["pyxquic_wt/_ffi_build.py:ffi"],
    packages=find_packages(),
    package_data={
        "pyxquic_wt": [
            "libxquic.so*",
            "libxquic.dylib",
            "xquic.dll",
        ],
    },
    setup_requires=["cffi>=1.15"],
    install_requires=["cffi>=1.15"],
)
