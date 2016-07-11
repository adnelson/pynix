import setuptools
import os
from subprocess import Popen, PIPE
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "src"))
import servenix

setuptools.setup(
    name="servenix",
    version=servenix.__version__,
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
