import subprocess
from setuptools import setup
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
readme = path.join(here, 'README.md')

# Convert the README to reStructuredText for PyPI if pandoc is available.
# Otherwise, just read it.
try:
    readme = subprocess.check_output(['pandoc', '-f', 'markdown', '-t', 'rst', readme]).decode('utf-8')
except:
    with open(readme, encoding='utf-8') as f:
        readme = f.read()

setup(
    name='manuale',
    version='1.1.0',

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
        'Programming Language :: Python :: 3 :: Only',
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
