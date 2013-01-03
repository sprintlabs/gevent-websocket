from setuptools import setup, find_packages

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
    install_requires=open('requirements.txt').readlines(),
    tests_require=open('requirements_dev.txt').readlines(),
    setup_requires=['nose>=1.0'],
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
