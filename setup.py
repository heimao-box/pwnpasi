import os
import sys
import subprocess
from setuptools import setup

def install_system_dependencies():
    dependencies = [
        'checksec',
        'binutils',
        'binutils-common',
        'libc-bin'
    ]
    
    try:

        subprocess.check_call(['sudo', 'apt', 'update'])
        subprocess.check_call(['sudo', 'apt', 'install', '-y'] + dependencies)
    except subprocess.CalledProcessError:
        try:
 
            subprocess.check_call(['sudo', 'apt', 'install', '-y'] + dependencies)
        except subprocess.CalledProcessError:
            print("Failed to install system dependencies. Please install them manually:")
            print(" ".join(dependencies))
            sys.exit(1)

setup(
    name='pwnpasi-setup',
    version='1.0',
    description='Setup script for pwn tools and dependencies',
    author='Ba1_Ma0',
    author_email='baimao3389@gmail.com',
    python_requires='>=3.6',
    install_requires=[
        'pwntools',
        'LibcSearcher',
        'ropper',
    ],
)

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("This script will install system packages and Python dependencies.")
        print("It may ask for your sudo password for system package installation.")
    
    install_system_dependencies()
    
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-e', '.'])
    
    print("\nInstallation completed successfully!")
