import os
import subprocess
import sys

from setuptools import setup, find_packages
from setuptools.command.build_py import build_py


class BuildWithLib(build_py):
    """Custom build that compiles libxquic_wt_py if not present."""

    def run(self):
        pkg_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "pyxquic_wt"
        )
        has_lib = any(
            os.path.isfile(os.path.join(pkg_dir, n))
            for n in ("libxquic_wt_py.dylib", "libxquic_wt_py.so")
        )
        if not has_lib:
            script = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..", "..", "scripts", "build_wt_py.sh",
            )
            if os.path.isfile(script):
                print("Building libxquic_wt_py...")
                subprocess.check_call(["bash", script])
            else:
                print(
                    "WARNING: libxquic_wt_py not found and build script missing. "
                    "Set XQUIC_LIB_PATH or run scripts/build_wt_py.sh manually."
                )
        super().run()


def _read_version():
    init = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "pyxquic_wt", "__init__.py"
    )
    for line in open(init):
        if line.startswith("__version__"):
            return line.split("=")[1].strip().strip('"').strip("'")
    return "0.1.0"


setup(
    name="pyxquic-wt",
    version=_read_version(),
    description="WebTransport client/server powered by xquic QUIC/HTTP3 stack",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    license="Apache-2.0",
    python_requires=">=3.9",
    packages=find_packages(),
    package_data={
        "pyxquic_wt": [
            "libxquic_wt_py.so*",
            "libxquic_wt_py.dylib",
            "py.typed",
            "*.pyi",
        ],
    },
    install_requires=["cffi>=1.15"],
    extras_require={
        "cert": ["cryptography>=3.0"],
    },
    entry_points={
        "console_scripts": [
            "pyxquic-wt=pyxquic_wt.cli:main",
        ],
    },
    cmdclass={"build_py": BuildWithLib},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: C",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking",
        "Framework :: AsyncIO",
        "Development Status :: 3 - Alpha",
    ],
)
