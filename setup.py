import setuptools
import os
from subprocess import Popen, PIPE

# This will add the __version__ to the globals
with open("src/servenix/__init__.py") as f:
    exec(f.read())

setuptools.setup(
    name="servenix",
    version=__version__,
    package_dir={"": "src"},
    packages=setuptools.find_packages("src"),
    provides=setuptools.find_packages("src"),
    install_requires=open("requirements.txt").readlines(),
    entry_points={
        "console_scripts": [
            "servenix = servenix.server.servenix:main",
            "sendnix = servenix.client.sendnix:main"
        ]
    }
)
