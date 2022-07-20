from setuptools import setup

setup(
    name="dissect.eventlog",
    packages=["dissect.eventlog"],
    install_requires=[
        "dissect.cstruct>=3.0.dev,<4.0.dev",
        "dissect.util>=3.0.dev,<4.0.dev",
    ],
)
