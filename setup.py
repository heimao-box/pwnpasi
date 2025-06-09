#!/usr/bin/env python3
import os
import sys
import subprocess
from setuptools import setup, find_packages

def run_command(command, error_message):
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"Error: {error_message}")
        print(f"Details: {e.stderr.decode().strip()}")
        sys.exit(1)

def install_system_dependencies():
    dependencies = [

    ]
    
    print("\n[+] Updating package lists...")
    run_command(['sudo', 'apt', 'update'], "Failed to update package lists")

    for pkg, desc in dependencies:
        print(f"\n[+] Installing {desc}({pkg})...")
        run_command(['sudo', 'apt', 'install', '-y', pkg], f"Failed to install {pkg}")

def main():
    if os.geteuid() != 0:
        print("\n[!] Note: This script requires system package installation")
        print("[!] Will request sudo privileges to install system dependencies\n")

    install_system_dependencies()

    print("\n[✔] All components installed successfully!")

setup(
    name='pwnpasi-setup',
    version='1.2',
    description='Secure and reliable PWN environment configuration tool',
    author='Ba1_Ma0',
    author_email='baimao3389@gmail.com',
    packages=find_packages(),
    python_requires='>=3.6',
    install_requires=[
        'pwntools>=4.9.0',
        'LibcSearcher>=1.1.5',
        'ropper>=1.13.5',
    ],
)

if __name__ == '__main__':
    main()