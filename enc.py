from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

# Caesar Cipher
def caesar_cipher(text, shift):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char
    return result

# Transposition Cipher
def transposition_cipher(text):
    return text[::-1]

# Vigenère Cipher
def vigenere_cipher(text, key):
    result = []
    key_index = 0
    key = key.upper()
    
    for i in range(len(text)):
        char = text[i]
        if char.isalpha():
            shift = ord(key[key_index]) - 65
            if char.isupper():
                result.append(chr((ord(char) + shift - 65) % 26 + 65))
            else:
                result.append(chr((ord(char) + shift - 97) % 26 + 97))
            key_index = (key_index + 1) % len(key)
        else:
            result.append(char)

    return ''.join(result)

# AES Encryption
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv + ciphertext

def aes_decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext.decode()

# RSA Encryption
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

# Main program
def main():
    print("Select a cipher method:")
    print("1. Caesar Cipher")
    print("2. Transposition Cipher")
    print("3. Vigenère Cipher")
    print("4. AES Encryption")
    print("5. RSA Encryption")
    
    choice = int(input("Enter your choice (1-5): "))

    plaintext = input("Enter the plaintext: ")

    if choice == 1:
        shift = int(input("Enter the shift value for Caesar Cipher: "))
        ciphertext = caesar_cipher(plaintext, shift)
        print("Ciphertext:", ciphertext)

    elif choice == 2:
        ciphertext = transposition_cipher(plaintext)
        print("Ciphertext:", ciphertext)

    elif choice == 3:
        key = input("Enter the key for Vigenère Cipher: ")
        ciphertext = vigenere_cipher(plaintext, key)
        print("Ciphertext:", ciphertext)

    elif choice == 4:
        key = get_random_bytes(16)  # 128-bit key
        ciphertext = aes_encrypt(plaintext, key)
        print("AES Encrypted:", ciphertext)
        decrypted_text = aes_decrypt(ciphertext, key)
        print("AES Decrypted:", decrypted_text)

    elif choice == 5:
        private_key, public_key = generate_rsa_keys()
        ciphertext = rsa_encrypt(plaintext, public_key)
        print("RSA Encrypted:", ciphertext)
        decrypted_text = rsa_decrypt(ciphertext, private_key)
        print("RSA Decrypted:", decrypted_text)

    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()
