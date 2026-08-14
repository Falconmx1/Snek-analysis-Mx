"""
Setup configuration for Snek Analysis Mx
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read version from package
version = '0.1.0'

# Read long description from README
readme_path = Path(__file__).parent / 'README.md'
if readme_path.exists():
    with open(readme_path, 'r', encoding='utf-8') as f:
        long_description = f.read()
else:
    long_description = 'Memory Forensics Toolkit - Volatility 3 Wrapper'

setup(
    name='snek-analysis-mx',
    version=version,
    author='Falconmx1',
    author_email='falconmx1@github.com',
    description='Memory Forensics Toolkit - Automated Volatility 3 Wrapper for Incident Response',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/Falconmx1/Snek-analysis-Mx',
    packages=find_packages(exclude=['tests', 'examples', 'docs']),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'Topic :: System :: Recovery Tools',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
    install_requires=[
        'volatility3>=2.5.0',
        'jinja2>=3.1.0',
        'pyyaml>=6.0',
        'colorama>=0.4.6',
        'tqdm>=4.66.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
            'mypy>=1.0.0',
        ],
        'full': [
            'orjson>=3.9.0',
            'requests>=2.31.0',
            'elasticsearch>=8.0.0',
            'matplotlib>=3.7.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'snek-analyze=snek_analysis.main:main',
            'snek-report=snek_analysis.reporters.cli:main',
        ],
    },
    package_data={
        'snek_analysis': [
            'reporters/templates/*.html',
        ],
    },
    include_package_data=True,
    zip_safe=False,
    project_urls={
        'Bug Reports': 'https://github.com/Falconmx1/Snek-analysis-Mx/issues',
        'Source': 'https://github.com/Falconmx1/Snek-analysis-Mx',
    },
)
