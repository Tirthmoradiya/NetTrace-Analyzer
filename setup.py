from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="network_analyzer",
    version="0.1.0",
    author="Network Security Team",
    author_email="security@example.com",
    description="Network traffic analysis tool for anomaly and intrusion detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/network_analyzer",
    license="MIT",  # <--- ADD THIS LINE
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        # "License :: OSI Approved :: MIT License",  <--- REMOVE THIS LINE
        "Operating System :: OS Independent",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
    install_requires=[
        "scapy>=2.5.0",
        "netaddr>=0.8.0",
        "aiohttp>=3.8.0",
        "orjson>=3.8.0",
        "tqdm>=4.65.0",
        "psutil>=5.9.0",
        "pyyaml>=6.0.0",
        "pandas>=1.5.0",
        "plotly>=5.13.0",
        "networkx>=3.0",
        "numpy>=1.23.0",
        "scikit-learn>=1.0.2",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.20.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "isort>=5.10.0",
        ],
        "docs": [
            "mkdocs>=1.4.0",
            "mkdocs-material>=9.0.0",
            "mkdocstrings>=0.20.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "network-analyze=network_analyzer.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "network_analyzer": ["templates/*.html"],
    },
)