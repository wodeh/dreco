from setuptools import setup, find_packages

setup(
    name="dreco",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "requests",
        "dnspython",
        "sublist3r",
        "python-nmap",
        "dnsrecon",
    ],
    entry_points={
        'console_scripts': [
            'dreco = dreco.main:main',
        ],
    },
    description="A comprehensive tool for domain enumeration and scanning.",
    author="Th3 0w1",
    author_email="waleed.odeh@gmail.com",
    url="https://github.com/wodeh/dreco",  # Replace with your GitHub URL
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)

