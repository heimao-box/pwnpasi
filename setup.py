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

def install_system_packages_for_pwntools():
    """Install system packages required for pwntools on Kali/Debian"""
    kali_packages = [
        ('python3-dev', 'Python development headers'),
        ('python3-pip', 'Python package installer'),
        ('build-essential', 'Build tools'),
        ('libssl-dev', 'SSL development libraries'),
        ('libffi-dev', 'FFI development libraries'),
        ('python3-setuptools', 'Python setuptools'),
        ('libc6-dev', 'C library development files'),
        ('gcc', 'GNU Compiler Collection')
    ]
    
    print_status('process', "Installing system packages for pwntools...")
    
    # Update package list first
    try:
        subprocess.run(['sudo', 'apt', 'update'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print_status('success', "Package list updated")
    except subprocess.CalledProcessError:
        print_status('warning', "Failed to update package list, continuing...")
    
    for pkg, desc in kali_packages:
        try:
            print_status('info', f"Installing {desc}...")
            subprocess.run(['sudo', 'apt', 'install', '-y', pkg], 
                         check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print_status('success', f"{desc} installed")
        except subprocess.CalledProcessError:
            print_status('warning', f"Failed to install {pkg}, may already be installed")

def install_python_dependencies():
    python_deps = [
        ('pwntools>=4.9.0', 'PWN exploitation toolkit'),
        ('LibcSearcher>=1.1.5', 'Libc database searcher'),
        ('ropper>=1.13.5', 'ROP gadget finder')
    ]
    
    print_status('process', "Installing Python dependencies...")
    
    # Check if we're on Kali/Debian and install system packages first
    if os.path.exists('/etc/debian_version'):
        print_status('info', "Detected Debian/Kali system, installing system dependencies...")
        install_system_packages_for_pwntools()
    
    for i, (pkg, desc) in enumerate(python_deps, 1):
        print_status('info', f"Installing {desc}...")
        for j in range(1, 6):
            print_progress_bar(j, 5, f"Installing {pkg.split('>=')[0]}", 35)
            time.sleep(0.2)
        
        # Try multiple installation methods
        success = False
        
        # Method 1: Regular pip install
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', pkg], 
                         check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print_status('success', f"{desc} installed successfully")
            success = True
        except subprocess.CalledProcessError as e:
            print_status('warning', f"Standard pip install failed for {pkg}")
        
        # Method 2: Try with --user flag
        if not success:
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', '--user', pkg], 
                             check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print_status('success', f"{desc} installed successfully (user mode)")
                success = True
            except subprocess.CalledProcessError:
                print_status('warning', f"User pip install failed for {pkg}")
        
        # Method 3: Try with --break-system-packages (for newer pip versions)
        if not success:
            try:
                subprocess.run([sys.executable, '-m', 'pip', 'install', '--break-system-packages', pkg], 
                             check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print_status('success', f"{desc} installed successfully (system override)")
                success = True
            except subprocess.CalledProcessError:
                print_status('warning', f"System override pip install failed for {pkg}")
        
        # Method 4: Try apt install for pwntools on Kali
        if not success and pkg.startswith('pwntools') and os.path.exists('/etc/debian_version'):
            try:
                subprocess.run(['sudo', 'apt', 'install', '-y', 'python3-pwntools'], 
                             check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print_status('success', f"{desc} installed via apt")
                success = True
            except subprocess.CalledProcessError:
                print_status('warning', f"APT install failed for pwntools")
        
        if not success:
            print_status('error', f"All installation methods failed for {pkg}")
            print_status('info', f"Please manually install {pkg} using:")
            print(f"    {Colors.YELLOW}sudo apt install python3-dev build-essential{Colors.END}")
            print(f"    {Colors.YELLOW}pip3 install {pkg}{Colors.END}")
            # Don't exit, continue with other packages
            continue

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

def setup_system_command():
    """Setup pwnpasi as a system command"""
    import shutil
    import stat
    
    # Get current script path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pwnpasi_script = os.path.join(current_dir, 'pwnpasi.py')
    
    # Determine system bin directory
    if os.name == 'posix':  # Linux/macOS
        bin_dirs = ['/usr/local/bin', '/usr/bin']
        target_name = 'pwnpasi'
    else:  # Windows
        # For Windows, we'll add to Python Scripts directory
        import sys
        scripts_dir = os.path.join(os.path.dirname(sys.executable), 'Scripts')
        bin_dirs = [scripts_dir] if os.path.exists(scripts_dir) else []
        target_name = 'pwnpasi.py'
    
    # Find writable bin directory
    target_dir = None
    for bin_dir in bin_dirs:
        if os.path.exists(bin_dir) and os.access(bin_dir, os.W_OK):
            target_dir = bin_dir
            break
    
    if not target_dir:
        print_status('warning', "No writable system directory found, trying with sudo...")
        target_dir = bin_dirs[0] if bin_dirs else '/usr/local/bin'
    
    target_path = os.path.join(target_dir, target_name)
    
    try:
        # Copy script to system directory
        print_status('process', f"Installing pwnpasi to {target_path}...")
        
        if os.name == 'posix':
            # For Linux/macOS, create a wrapper script
            wrapper_content = f"#!/usr/bin/env python3\n# PWNPASI System Command Wrapper\nimport sys\nimport os\nsys.path.insert(0, '{current_dir}')\nfrom pwnpasi import main\nif __name__ == '__main__':\n    main()\n"
            
            # Try to write directly first
            try:
                with open(target_path, 'w') as f:
                    f.write(wrapper_content)
                os.chmod(target_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            except PermissionError:
                # Use sudo if needed
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as tmp:
                    tmp.write(wrapper_content)
                    tmp_path = tmp.name
                
                run_command(['sudo', 'cp', tmp_path, target_path], f"Failed to install to {target_path}")
                run_command(['sudo', 'chmod', '+x', target_path], f"Failed to set permissions for {target_path}")
                os.unlink(tmp_path)
        else:
            # For Windows, copy the script directly
            shutil.copy2(pwnpasi_script, target_path)
        
        print_status('success', f"PWNPASI installed as system command: {target_name}")
        print_status('info', f"You can now run 'pwnpasi' from anywhere in the terminal")
        
        # Add to PATH if needed (Windows)
        if os.name == 'nt' and target_dir not in os.environ.get('PATH', '').split(os.pathsep):
            print_status('info', f"Add {target_dir} to your PATH environment variable for global access")
            
    except Exception as e:
        print_status('error', f"Failed to install system command: {str(e)}")
        print_status('info', "You can still run pwnpasi using: python pwnpasi.py")

if __name__ == '__main__':
    main()
    
    # Ask user if they want to install as system command
    print(f"\n{Colors.CYAN}╔═══════════════════════════════════════╗{Colors.END}")
    print(f"{Colors.CYAN}║{Colors.END}     {Colors.YELLOW}SYSTEM COMMAND SETUP{Colors.END}        {Colors.CYAN}║{Colors.END}")
    print(f"{Colors.CYAN}╚═══════════════════════════════════════╝{Colors.END}")
    
    response = input(f"{Colors.CYAN}[◉]{Colors.END} Install pwnpasi as system command? (y/N): ").strip().lower()
    if response in ['y', 'yes']:
        setup_system_command()
    else:
        print_status('info', "Skipped system command installation")
        print_status('info', "Run 'python setup.py' again and choose 'y' to install later")
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
        scripts=['pwnpasi.py'],
    )