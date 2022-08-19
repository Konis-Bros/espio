import sys
import random


def xor(data, key):
    obf_payload = []
    for i in range(len(data)):
        obf_char = chr(data[i] ^ ord(key[i % len(key)]))
        hex_char = hex(ord(obf_char))
        if len(hex_char) == 3:
            hex_char = f"0x0{hex_char[-1]}"
        obf_payload.append(hex_char)
    return ''.join(obf_payload)

 
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
    with open("payload.bin", 'w') as f:
        f.write(ciphertext)


def main():
    printCiphertext()


if __name__ == "__main__":
    main()

