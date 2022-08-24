import sys
import random
import base64


def xor(data, key):
    obf_payload = ""
    for i in range(len(data)):
        obf_char = chr(data[i] ^ ord(key[i % len(key)]))
        hex_char = hex(ord(obf_char))
        if len(hex_char) == 3:
            hex_char = f"0x0{hex_char[-1]}"
        obf_payload += hex_char
    obf_bytes = obf_payload.encode('utf-8')
    base64_bytes = base64.b64encode(obf_bytes)
    base64_payload = base64_bytes.decode('utf-8')
    return ''.join(base64_payload)

 
def generate_key():
    letters = [chr(ascii_value) for ascii_value in range(33, 127)]
    key = "".join(random.choices(letters, k=random.randint(100, 500)))
    with open("key.bin", 'w') as f:
        f.write(key)
    return key


def printCiphertext():
    try:
        with open(sys.argv[1], "rb") as f:
            plaintext = f.read()
    except:
        print(f"File argument needed! {sys.argv[0]}")
        sys.exit()

    key = generate_key()
    ciphertext = xor(plaintext, key)
    with open("obfuscatedPayload.bin", 'w') as f:
        f.write(ciphertext)


def main():
    printCiphertext()


if __name__ == "__main__":
    main()
