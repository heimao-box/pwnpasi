#!/usr/bin/env python3
import os
import sys
import time
import subprocess
from setuptools import setup, find_packages

# 科技化颜色方案
class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'
    BLINK = '\033[5m'

def print_banner():
    banner = f"""{Colors.CYAN}{Colors.BOLD}
    ██████╗ ██╗    ██╗███╗   ██╗██████╗  █████╗ ███████╗██╗
    ██╔══██╗██║    ██║████╗  ██║██╔══██╗██╔══██╗██╔════╝██║
    ██████╔╝██║ █╗ ██║██╔██╗ ██║██████╔╝███████║███████╗██║
    ██╔═══╝ ██║███╗██║██║╚██╗██║██╔═══╝ ██╔══██║╚════██║██║
    ██║     ╚███╔███╔╝██║ ╚████║██║     ██║  ██║███████║██║
    ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝
{Colors.END}
{Colors.MAGENTA}    ╔══════════════════════════════════════════════════════╗
    ║           {Colors.WHITE}{Colors.BOLD}ADVANCED PWN EXPLOITATION FRAMEWORK{Colors.END}{Colors.MAGENTA}         ║
    ║                    {Colors.YELLOW}Setup & Installation{Colors.END}{Colors.MAGENTA}                   ║
    ╚══════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)
    time.sleep(0.5)

def print_progress_bar(current, total, task_name, width=50):
    progress = current / total
    filled = int(width * progress)
    bar = '█' * filled + '░' * (width - filled)
    percentage = int(progress * 100)
    print(f"\r{Colors.CYAN}[{Colors.YELLOW}◉{Colors.CYAN}]{Colors.END} {task_name}: {Colors.MAGENTA}[{bar}]{Colors.END} {Colors.BOLD}{percentage}%{Colors.END}", end='', flush=True)
    if current == total:
        print(f" {Colors.GREEN}✓{Colors.END}")

def print_status(status_type, message):
    icons = {
        'info': f'{Colors.CYAN}[{Colors.WHITE}◉{Colors.CYAN}]{Colors.END}',
        'success': f'{Colors.GREEN}[{Colors.WHITE}✓{Colors.GREEN}]{Colors.END}',
        'warning': f'{Colors.YELLOW}[{Colors.WHITE}⚠{Colors.YELLOW}]{Colors.END}',
        'error': f'{Colors.RED}[{Colors.WHITE}✗{Colors.RED}]{Colors.END}',
        'process': f'{Colors.MAGENTA}[{Colors.WHITE}⟳{Colors.MAGENTA}]{Colors.END}'
    }
    timestamp = time.strftime('%H:%M:%S')
    print(f"{icons[status_type]} {Colors.DIM}[{timestamp}]{Colors.END} {message}")

def run_command(command, error_message):
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result
    except subprocess.CalledProcessError as e:
        print_status('error', f"{error_message}")
        print(f"    {Colors.RED}└─ {e.stderr.strip()}{Colors.END}")
        sys.exit(1)

def install_system_dependencies():
    dependencies = [
        # Add system dependencies here if needed
    ]
    
    if not dependencies:
        print_status('info', f"No system dependencies required")
        return
    
    print_status('process', f"Updating package repositories...")
    for i in range(1, 4):
        print_progress_bar(i, 3, "Repository sync", 40)
        time.sleep(0.3)
    
    run_command(['sudo', 'apt', 'update'], "Failed to update package list")
    print_status('success', "Package repositories updated")

    for i, (pkg, desc) in enumerate(dependencies, 1):
        print_status('process', f"Installing {desc} ({pkg})...")
        for j in range(1, 6):
            print_progress_bar(j, 5, f"Installing {pkg}", 35)
            time.sleep(0.2)
        run_command(['sudo', 'apt', 'install', '-y', pkg], f"Failed to install {pkg}")
        print_status('success', f"{desc} installed successfully")

def install_python_dependencies():
    python_deps = [
        ('pwntools>=4.9.0', 'PWN exploitation toolkit'),
        ('LibcSearcher>=1.1.5', 'Libc database searcher'),
        ('ropper>=1.13.5', 'ROP gadget finder')
    ]
    
    print_status('process', "Installing Python dependencies...")
    
    for i, (pkg, desc) in enumerate(python_deps, 1):
        print_status('info', f"Installing {desc}...")
        for j in range(1, 6):
            print_progress_bar(j, 5, f"Installing {pkg.split('>=')[0]}", 35)
            time.sleep(0.2)
        
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', pkg], 
                         check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print_status('success', f"{desc} installed successfully")
        except subprocess.CalledProcessError as e:
            print_status('error', f"Failed to install {pkg}")
            sys.exit(1)

def main():
    print_banner()
    
    print_status('info', f"Initializing PWNPASI setup environment...")
    time.sleep(0.5)
    
    if os.name == 'posix' and os.geteuid() != 0:
        print_status('warning', "System package installation may require sudo privileges")
        print_status('info', "You may be prompted for your password")
        print()
    
    # System dependencies
    print(f"\n{Colors.BOLD}{Colors.BLUE}╔═══════════════════════════════════════╗{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}║{Colors.END}     {Colors.CYAN}SYSTEM DEPENDENCIES PHASE{Colors.END}     {Colors.BOLD}{Colors.BLUE}║{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}╚═══════════════════════════════════════╝{Colors.END}")
    install_system_dependencies()
    
    # Python dependencies
    print(f"\n{Colors.BOLD}{Colors.BLUE}╔═══════════════════════════════════════╗{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}║{Colors.END}     {Colors.CYAN}PYTHON DEPENDENCIES PHASE{Colors.END}     {Colors.BOLD}{Colors.BLUE}║{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}╚═══════════════════════════════════════╝{Colors.END}")
    install_python_dependencies()
    
    # Completion
    print(f"\n{Colors.BOLD}{Colors.GREEN}╔═══════════════════════════════════════╗{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}║{Colors.END}        {Colors.WHITE}INSTALLATION COMPLETE{Colors.END}        {Colors.BOLD}{Colors.GREEN}║{Colors.END}")
    print(f"{Colors.BOLD}{Colors.GREEN}╚═══════════════════════════════════════╝{Colors.END}")
    
    print_status('success', f"PWNPASI framework successfully installed!")
    print_status('info', f"Ready for advanced PWN exploitation")
    print(f"\n{Colors.CYAN}    Usage: {Colors.WHITE}python pwnpasi.py -l <target_binary>{Colors.END}")
    print(f"{Colors.CYAN}    Help:  {Colors.WHITE}python pwnpasi.py --help{Colors.END}\n")

if __name__ == '__main__':
    main()
else:
    setup(
        name="pwnpasi",
        version="3.0.0",
        description="Advanced PWN Exploitation Framework",
        author="Ba1_Ma0",
        packages=find_packages(),
        install_requires=[
            'pwntools>=4.9.0',
            'LibcSearcher>=1.1.5',
            'ropper>=1.13.5'
        ],
        python_requires='>=3.8',
        entry_points={
            'console_scripts': [
                'pwnpasi=pwnpasi:main',
            ],
        },
    )