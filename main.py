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



def main():
    plaintext = input("Enter plaintext: ")
    firstKey = int(input("Enter first key: "))
    secondKey = int(input("Enter second key: "))
    thirdKey = int(input("Enter third key: "))
    firstCipher = encryptSubstitutionCipher(plaintext, firstKey)
    print("First ciphertext: " + firstCipher)
    secondCipher = encryptSubstitutionCipher(firstCipher, secondKey)
    print("Second ciphertext: " + secondCipher)
    thirdCipher = encryptSubstitutionCipher(secondCipher, thirdKey)
    print("Third ciphertext: " + thirdCipher)
    firstPlain = decryptSubstitutionCipher(thirdCipher, thirdKey)
    print("First plaintext: " + firstPlain)
    secondPlain = decryptSubstitutionCipher(firstPlain, secondKey)
    print("Second plaintext: " + secondPlain)
    thirdPlain = decryptSubstitutionCipher(secondPlain, firstKey)
    print("Third plaintext: " + thirdPlain)
    if plaintext != thirdPlain:
        print("Decryption failed")
    else:
        print("Decryption successful")

if __name__ == "__main__":
    main()