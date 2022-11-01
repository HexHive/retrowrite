from setuptools import setup
from sys import version_info

setup(
    name='retrowrite',
    version='1.0.0',
    maintainer='',
    maintainer_email='',
    include_package_data=True,
    url='https://github.com/hexhive/retrowrite/',
    description='Retrowrite: A binary rewriting framework',
    packages=['retrowrite',
              ],
    install_requires=[
        'archinfo',
        'pyelftools',
        'capstone',
        'intervaltree'
    ],
    entry_points = {
        'console_scripts': [
            'retrowrite = retrowrite.command'
        ],
    },
    test_suite='nose.collector',
    tests_require=['nose'],
)
