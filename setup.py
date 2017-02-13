import setuptools
import os
from subprocess import Popen, PIPE
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "src"))
import pynix

setuptools.setup(
    name="pynix",
    version=pynix.__version__,
    package_dir={"": "src"},
    packages=setuptools.find_packages("src"),
    provides=setuptools.find_packages("src"),
    install_requires=open("requirements.txt").readlines(),
    test_suite="pynix.tests",
    entry_points={
        "console_scripts": [
            "servenix = pynix.binary_cache.server:main",
            "sendnix = pynix.binary_cache.client:main",
            "derivtool = pynix.derivtool:main"
        ]
    }
)
