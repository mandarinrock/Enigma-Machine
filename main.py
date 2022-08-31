debug = True
debug = False

interactive = True
# interactive = False

def encryptSubstitutionCipher(plaintext, key):
    ciphertext = ""
    for c in plaintext:
        key += 1
        if c.isalpha():
            if c.isupper():
                ciphertext += chr((ord(c) - ord('A') + key) % 26 + ord('A'))
            else:
                ciphertext += chr((ord(c) - ord('a') + key) % 26 + ord('a'))
        else:
            ciphertext += c
    return ciphertext

def decryptSubstitutionCipher(ciphertext, key):
    plaintext = ""
    for c in ciphertext:
        key += 1
        if c.isalpha():
            if c.isupper():
                plaintext += chr((ord(c) - ord('A') - key) % 26 + ord('A'))
            else:
                plaintext += chr((ord(c) - ord('a') - key) % 26 + ord('a'))
        else:
            plaintext += c
    return plaintext

def encryptEnigma(plaintext, keys):
    for key in keys:
        plaintext = encryptSubstitutionCipher(plaintext, key)
        if debug:
            print("Encrypted text: " + plaintext)
    return plaintext

def decryptEnigma(ciphertext, keys):
    for key in keys:
        ciphertext = decryptSubstitutionCipher(ciphertext, key)
        if debug: print("Decrypted text: " + ciphertext)
    return ciphertext


def main():

    plaintext = "Welcome to the Enigma machine"
    password = plaintext
    keys = []

    if interactive: password = input("\nEnter a password: ")
    for c in password:
        keys.append(ord(c) - ord('a'))

    if interactive:
        while True:
            print("\nPress 'Enter' without typing anything to exit")
            plaintext = input("Enter a message to encrypt/decrypt: ")
            if plaintext == "": exit()
            print("Encrypted message: " + encryptEnigma(plaintext, keys))
            print("Decrypted message: " + decryptEnigma(plaintext, keys))
            # exit()


    ciphertext = encryptEnigma(plaintext, keys)
    decryptedtext = decryptEnigma(ciphertext, keys)

    print("\nPassword:\t  " + password)
    print("Keys:\t\t  " + str(keys))
    print("Plain text:\t  " + plaintext)
    print("Cipher text:\t  " + ciphertext)
    print("Decrypted text:\t  " + decryptedtext)
    if plaintext != decryptedtext:
        print("\nDecryption Failed!\n")
    else:
        print("\nDecryption Successful!\n")

if __name__ == "__main__":
    main()