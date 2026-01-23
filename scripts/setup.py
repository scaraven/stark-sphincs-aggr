from setuptools import setup, find_packages

setup(
    name="poseidon-hash-example",
    version="0.1.0",
    description="Wrapper for an external Poseidon hash library",
    author="Your Name",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=[
        "poseidon-hash>=0.0.1",  # adjust if you need a different package
    ],
)