from setuptools import setup
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    readme = f.read()

setup(
    name='manuale',
    version='1.0.0',

    license='MIT',
    description="A fully manual Let's Encrypt/ACME client",
    long_description=readme,
    url='https://github.com/veeti/manuale',
    author="Veeti Paananen",
    author_email='veeti.paananen@rojekti.fi',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],

    packages=['manuale'],
    install_requires=[
        'cryptography >= 1.0',
        'requests',
    ],

    entry_points={
        'console_scripts': [
            'manuale = manuale.cli:main',
        ],
    },
)
