#!/usr/bin/env python3
import os
import sys
import subprocess
from setuptools import setup, find_packages

def run_command(command, error_message):
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"错误: {error_message}")
        print(f"详细信息: {e.stderr.decode().strip()}")
        sys.exit(1)

def install_system_dependencies():
    dependencies = [

    ]
    
    print("\n[+] 正在更新软件包列表...")
    run_command(['sudo', 'apt', 'update'], "更新软件包列表失败")

    for pkg, desc in dependencies:
        print(f"\n[+] 正在安装 {desc}({pkg})...")
        run_command(['sudo', 'apt', 'install', '-y', pkg], f"安装 {pkg} 失败")

def main():
    if os.geteuid() != 0:
        print("\n[!] 注意: 此脚本需要安装系统软件包")
        print("[!] 将会请求sudo权限来安装系统依赖\n")

    install_system_dependencies()

    print("\n[✔] 所有组件安装完成！")

setup(
    name='pwnpasi-setup',
    version='1.2',
    description='安全可靠的PWN环境配置工具',
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