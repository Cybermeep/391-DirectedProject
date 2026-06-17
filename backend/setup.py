"""
Setup script for the NIDS backend.
"""

from setuptools import setup, find_packages

setup(
    name="nids-backend",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "scapy>=2.5.0",
        "pyshark>=0.6",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
        "scikit-learn>=1.3.0",
        "flask>=2.3.0",
        "flask-cors>=4.0.0",
        "flask-socketio>=5.3.0",
        "python-socketio>=5.9.0",
        "eventlet>=0.33.0",
        "sqlalchemy>=2.0.0",
        "pyyaml>=6.0.0",
        "python-dotenv>=1.0.0",
        "requests>=2.31.0",
        "click>=8.1.0",
    ],
    python_requires=">=3.8",
)