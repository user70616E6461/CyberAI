from setuptools import setup, find_packages

setup(
    name="cyberai",
    version="0.1.0",
    packages=find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "cyberai=cyberai.__main__:cli",
        ],
    },
    python_requires=">=3.10",
)
