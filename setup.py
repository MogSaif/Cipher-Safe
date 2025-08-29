from setuptools import setup, find_packages

setup(
    name="cipher-safe",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'pycryptodome>=3.18.0',
    ],
    entry_points={
        'console_scripts': [
            'cipher-safe=src.main:main',
        ],
    },
    python_requires='>=3.6',
)
