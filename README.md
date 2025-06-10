# pwnpasi

**pwnpasi** is an automated tool specifically designed for introductory-level CTF PWN challenges, aimed at helping beginners quickly identify and exploit **stack overflow** and **format string vulnerabilities** in 32-bit and 64-bit programs.

## Key Features:

✅ Automated Vulnerability Analysis
```
Determines overflow offsets
Detects format string vulnerabilities
Identifies dynamically linked libraries (libc)
```
✅ One-Click Exploit Generation
```
Constructs ROP chains for:
Calling backdoor functions (e.g., system)
Automatically detect vulnerable functions and generate their associated assembly code
Shellcode injection
puts/write function ROP
syscall-based ROP
Format string exploitation
```
✅ Protection Bypass
```
Auto-detects and circumvents:
PIE (Position-Independent Executable)
Stack Canary
```
✅ Flexible Deployment
```
Supports local and remote exploitation
Integrates LibcSearcher to auto-resolve libc versions (even without provided addresses)
```

---

## Translation Notice

This is an English translation of the original [README](https://github.com/heimao-box/pwnpasi) written in Chinese.

Translated by [xkenchii](https://github.com/xkenchii). If you find any issues with the translation, feel free to open an issue or pull request.

---

## Stack Overflow Exploitation Demo  
https://github.com/user-attachments/assets/5b5abcdb-1011-4ed4-be6e-5b819eb3a3ab

## Format String Exploitation Demo  
https://github.com/user-attachments/assets/9bf09335-605a-4896-aacf-ea938b800ba0

## Bypassing Canary Protection Demo  
https://github.com/user-attachments/assets/a3d8037d-227a-4f01-a554-750df58e7b67

## Bypassing PIE Protection Demo  
https://github.com/user-attachments/assets/2a3b1e49-e372-43d7-b2f1-43b153ea7ec6


## Installation Dependencies  
Ensure **Python 3.x** is installed (Kali Linux is recommended). Install the required dependencies:

```bash
python3 setup.py install
````

If script installation fails, manually install the dependencies:

```bash
pip3 install pwntools  
pip3 install LibcSearcher
```

---

## Running the Tool

Execute the tool via the command line. Example commands:

### Basic usage:

```bash
python pwnpasi.py -l level3_x64
```

### Specify a dynamic library (libc):

```bash
python pwnpasi.py -l level3_x64 -libc /lib/i386-linux-gnu/libc.so.6
```

### Remote exploitation:

```bash
python pwnpasi.py -l level3_x64 -libc /lib/i386-linux-gnu/libc.so.6 -ip 192.168.0.1 -p 33333
```

---

## Future Plans

* Improve **64-bit register-based function calls**
* Add **multi-interaction program fuzzing** support
* Expand exploitation methods for **stack overflow & format string vulnerabilities**, supporting more architectures
* Enhance **automation and user-friendliness**

---

## Possible Errors & Solutions

* **Avoid special characters** (e.g., `_/*&^%$#@`) in program names—use **only letters or numbers**.
* Errors may occur if dependencies are not fully installed. Verify all required tools and libraries are correctly installed.

---

## Final Notes

This tool is designed for **CTF PWN challenges**, currently targeting **beginners** while also supporting users with PWN experience. We will **continue updating** and introducing more advanced features.

This project also serves as **technical groundwork** for future developments.

Join the PwnPasi Feedback & Discussion Group (Group ID: **256806296**) to share issues, suggestions, or contribute to development.

---

## Acknowledgments

Special thanks to **Melody**, **mycafday**, **落雨流辰**, and all group members for their valuable feedback—each suggestion has helped shape this project.

---

## License

This project is licensed under the [MIT License](LICENSE).
Original project by [heimao-box](https://github.com/heimao-box). Translation provided in compliance with the license.

