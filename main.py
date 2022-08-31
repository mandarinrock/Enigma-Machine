debug = True
debug = False

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

def encryptEnigma(ciphertext, keys):
    for key in keys:
        ciphertext = encryptSubstitutionCipher(ciphertext, key)
    return ciphertext

def decryptEnigma(ciphertext, keys):
    for key in keys:
        ciphertext = decryptSubstitutionCipher(ciphertext, key)
    return ciphertext


def main():

    # plaintext = input("Enter plaintext: ")
    plaintext = "hello ethan"
    print("Plaintext: " + plaintext)

    # keyLength = int(input("Enter number of keys: "))
    keyLength = 3

    # keys = []
    # for i in range(keyLength):
    #     keys.append(int(input("Enter key " + str(i+1) + ": ")))
    keys = [1, 2, 3]

    ciphertext = encryptEnigma(plaintext, keys)
    print("Ciphertext: " + ciphertext)
    # previousText = ciphertext

    # for i in range(keyLength):
    #     decryptedtext = decryptSubstitutionCipher(previousText, keys[keyLength - i - 1])
    #     print("Plaintext " + str(i+1) + ": " + decryptedtext)
    #     previousText = decryptedtext
    decryptedtext = decryptEnigma(ciphertext, keys)

    if plaintext != decryptedtext:
        print("Decryption failed")
    else:
        print("Decryption successful")

if __name__ == "__main__":
    main()