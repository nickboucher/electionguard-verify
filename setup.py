from setuptools import setup, find_packages

with open("README.md", "r") as f:
    long_description = f.read()

setup(name='electionguard_verify',
        version='0.1',
        description='Independent Python verifier for ElectionGuard election results.',
        long_description=long_description,
        long_description_content_type="text/markdown",
        url='https://github.com/nickboucher/electionguard-verify',
        author='Nicholas Boucher',
        author_email='nicholas.d.boucher+electionguardpy@gmail.com',
        license='MIT',
        packages=find_packages(),
        entry_points={
            'console_scripts': ['egverify=electionguard_verify.command_line:main'],
        },
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ],
        python_requires='>=3.8',
        install_requires=[
            'electionguard>=1.1.15'
        ]
)