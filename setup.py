import sys
from setuptools import setup, find_packages


def get_package_manifest(filename):
    packages = []

    with open(filename) as package_file:
        for line in package_file.readlines():
            line = line.strip()

            if not line:
                continue

            if line.startswith('#'):
                # comment
                continue

            packages.append(line)

    return packages


def get_install_requires():
    """
    :returns: A list of packages required for installation.
    """
    return get_package_manifest('requirements.txt')


def get_tests_requires():
    """
    :returns: A list of packages required for running the tests.
    """
    packages = get_package_manifest('requirements_dev.txt')

    try:
        from unittest import mock
    except ImportError:
        packages.append('mock')

    if sys.version_info[:2] < (2, 7):
        packages.append('unittest2')

    return packages


setup(
    name="gevent-websocket",
    version="0.4.0",
    description=(
        "Websocket handler for the gevent pywsgi server, "
        "a Python network library"),
    long_description=open("README.rst").read(),
    author="Nick Joyce",
    author_email="nick.joyce@realkinetic.com",
    license="BSD",
    url="https://github.com/njoyce/gevent-websocket",
    download_url="https://github.com/njoyce/gevent-websocket",
    install_requires=get_install_requires(),
    tests_require=get_tests_requires(),
    test_suite='nose.collector',
    packages=find_packages(exclude=["examples", "tests"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Intended Audience :: Developers",
    ],
)
