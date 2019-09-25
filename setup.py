import io
import os
import subprocess

from setuptools import setup, find_packages


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(filename):
    with io.open(os.path.join(os.path.dirname(__file__), filename)) as f:
        return f.read()


# Utility function to determine version using git in a PEP-440 compatible way, fallback to version.txt for releases
def determine_version():
    dir_path = os.path.dirname(os.path.realpath(__file__))
    ver_file = os.path.join(dir_path, "version.txt")
    version = "0.0.0"
    if os.path.exists(ver_file):
        version = read(ver_file)
    # If this is a release file and no git is found, use version.txt
    if not os.path.isdir(os.path.join(dir_path, ".git")):
        return version
    # Derive version from git
    try:
        output = subprocess.check_output(['git', 'describe', '--tags', '--dirty'], cwd=dir_path) \
            .decode('utf-8').strip().split('-')
        if len(output) == 1:
            return output[0]
        elif len(output) == 2:
            return "{}.dev0".format(output[0])
        else:
            release = 'dev' if len(output) == 4 and output[3] == 'dirty' else ''
            return "{}.{}{}+{}".format(output[0], release, output[1], output[2])
    except subprocess.CalledProcessError:
        try:
            commit = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode('utf-8').strip()
            status = subprocess.check_output(['git', 'status', '-s']).decode('utf-8').strip()
            return "{}.dev0+{}".format(version, commit) if len(status) > 0 else "{}+{}".format(version, commit)
        except subprocess.CalledProcessError:
            # finding the git version has utterly failed, use version.txt
            return version


setup(
    name="pysssp",
    version=determine_version(),
    author="Jan-Jonas Sämann",
    author_email="sprinterfreak@binary-kitchen.de",
    description="A wrapper library to talk to Sophos antivirus SAVDI",
    license="GPLv3",
    keywords="",
    url="https://github.com/sprinterfreak/pysssp",
    packages=find_packages(),
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python",
        "Environment :: Console",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ],
    install_requires=[
    ],
    extras_require={
    },
    entry_points={
        'console_scripts': [
            'milter-sssp=pysssp.milter:main',
            'clamscan-sssp=pysssp.clamscan:main',
        ],
    },
    data_files=[('readme', ['README.md'])]
)
