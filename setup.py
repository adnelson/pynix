import setuptools
import os
from subprocess import Popen, PIPE

# # Get the nix store directory and drop it in __init__.py
# proc = Popen("nix-instantiate --eval -E builtins.storeDir",
#              shell=True, stdout=PIPE, stderr=PIPE)
# out, err = proc.communicate()
# if proc.returncode != 0:
#     exit("Couldn't get store directory: {}".format(err))

# with open("src/servenix/__init__.py", "a") as f:
#     f.write(

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
        "console_scripts": ["servenix = servenix.servenix:main"]
    }
)
