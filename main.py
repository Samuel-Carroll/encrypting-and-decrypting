"""
Programmer Samuel Carroll (100783547)
Project: Encryption/Decryption Algorithems
Course Code: 202101 - Obj Oriented Programming IT - 74917
Description: This program will ask the user for a message and then randomly encrypt and decrypt it using one of six cyphers. The program will then display to the user the encrypted and decrypted messages along with the cipher chosen. It'll indefinitly repeat until the user types in "stop", in which it'll show all encrypted and decrypted messages along with the ciphers used for each message.
Date Created: March 20 2021
Date Last Updated: March 31 2021
"""

import binascii
import math
import random


# parent class that PlaintextMsg and CiphertextMsg are derived from
class Message:

    def __init__(self, inp):
        self.inp = inp
        self.alphabets = "abcdefghijklmnopqrstuvwxyz"


# PlaintextMsg = Encrypt
class PlaintextMsg(Message):

    def __init__(self, inp):
        Message.__init__(self, inp)

    def subsititionEncrypt(self):
        # storing message
        encryption = ""
        # creating key value which will help generate text
        key = 13
        # element will loop in user and will convert values
        # loop will go to letter position in user text and then add key to convert into new letter
        for element in self.inp:
            # taking variable position to find postion of the letter T
            pos = self.alphabets.find(element)  # searching for i and then return index value for where i is currently
            # new variable to store new postion
            npos = (pos + key) % 26  # adding key value of 13 into index value, adding %26 so if user enters z it will 26%26=0
            encryption += self.alphabets[npos]  # adding new variable into encryption new text will be generated
        return encryption

    def playfairEncrypt(self):

        def matrix(x, y, initial):
            return [[initial for i in range(x)] for j in range(y)]

        def locationIndex(c):  # get location of each character
            loc = []
            if c == 'J':
                c = 'I'
            for i, j in enumerate(matrix):
                for k, l in enumerate(j):
                    if c == l:
                        loc.append(i)
                        loc.append(k)
                        return loc

        # the main function that does all the calculations and adds the values to the list
        def encrypt():
            encryptedLetters = []
            # converts the input into upper case and replaces empty space
            msg = self.inp.upper()
            msg = msg.replace(" ", "")
            msgLength = len(msg)
            for length in range(msgLength + 1, 2):
                if length < len(msg) - 1:
                    if msg[length] == msg[length + 1]:
                        msg = msg[:length + 1] + 'X' + msg[length + 1:]
            if len(msg) % 2 != 0:  # Pads out the length of the message with "X" to make it even
                msg = msg[:] + 'X'

            for i in range(0, msgLength, 2):
                location = locationIndex(msg[i])
                nextLocation = locationIndex(msg[i + 1])
                if location[1] == nextLocation[1]:
                    letter = ("{}{}".format(matrix[(location[0] + 1) % 5][location[1]], matrix[(nextLocation[0] + 1) % 5][nextLocation[1]]))
                elif location[0] == nextLocation[0]:
                    letter = ("{}{}".format(matrix[location[0]][(location[1] + 1) % 5], matrix[nextLocation[0]][(nextLocation[1] + 1) % 5]))
                else:
                    letter = ("{}{}".format(matrix[location[0]][nextLocation[1]], matrix[nextLocation[0]][location[1]]))
                encryptedLetters.append(letter)

            return encryptedLetters

        # takes in the input for the key
        key = input("Enter key: ")
        if key == "" or len(key) > 25:
            return 0

        key = key.replace(" ", "")
        key = key.upper()

        result = []
        for character in key:  # storing key
            if character not in result:
                if character == 'J':
                    result.append('I')
                else:
                    result.append(character)
        flag = 0
        for i in range(65, 91):  # storing other character
            if chr(i) not in result:
                if i == 73 and chr(74) not in result:
                    result.append("I")
                    flag = 1
                elif flag == 0 and i == 73 or i == 74:
                    pass
                else:
                    result.append(chr(i))
        k = 0

        # initializes and makes the matrix
        matrix = matrix(5, 5, 0)
        for i in range(0, 5):
            for j in range(0, 5):
                matrix[i][j] = result[k]
                k += 1
        # returns the function which contains a list
        # of all the possible values as well as the key for decryption
        encryptedMessage = encrypt()
        final = ""
        for i in encryptedMessage:
            final += i
        return final, key

    def caesarEncrypt(self):

        import random
        randKey = random.randint(1, 25)
        cipher = ''
        punctuation = '!()-[]{};:’"\,<>./?@#$%^&*_~ '
        for letter in self.inp:
            # if the letter is in the punctuation string, it gets added without modification
            if letter in punctuation:
                cipher += letter
            elif letter.isupper():
                # ord() method gets the ascii values of the letter that is picked
                # ascii values for uppercase letters are from 65 to 90; key is subtracted from 65 to convert
                # mod of 26 is also added to 65 to match
                # chr used instead of str() since all letters are in ascii format afterwards
                cipher += chr((ord(letter) + randKey - 65) % 26 + 65)
            else:
                # lowercase ascii values are from 97 122; same technique used
                cipher += chr((ord(letter) + randKey - 97) % 26 + 97)

        return cipher, randKey

    def transpositionEncrypt(self):

        key = 2
        # making a list for word encryption
        ciphertext = [''] * key
        for column in range(key):
            pointer = column

            while pointer < len(self.inp):
                ciphertext[column] += self.inp[pointer]
                pointer += key
        # joining the encrpted list after it has been added together
        joined = (''.join(ciphertext))
        return joined

    def productEncrypt(self):
        '''
        Due to the nature of this cipher, there might be some ascii characters that are
        not visible or represented on online IDE's.
        However, it still encrypts and decrypts the message.
        Succesfully tested on pyCharm.
        '''
        ##  Generates a random binary string to be used as a key
        #   param binaryString,a string with binary numbers
        #   return key, a randomly generated binary string containing zeros and ones
        def generateKey(binaryString):
            key = ""
            for i in range(len(binaryString)):
                binary = random.randint(0, 1)
                key += str(binary)
            return key

        ##  Calculates the XOR value of two binary numebrs and adds it to a binary string
        #   param binaryA, a string with binary numbers
        #   param binaryB, a string with binary numbers
        #   return newBinary, a string containing all the XOR'd values of binaryA and binaryB
        def exor(binaryA, binaryB):
            newBinary = ""
            for i in range(len(binaryA)):
                newBinary += str(int(binaryA[i]) ^ int(binaryB[i]))
            return newBinary

        ##  Takes two binary numbers and perfroms a binary "AND" to it, adds the result to a new binary string
        #   param binary, a string with binary numbers
        #   param key, a string with binary numbers, used for round functions
        #   return newBinary, a string containing all the AND'd values of binaryA and binaryB
        def roundFunction(binary, key):
            newBinary = ""
            for i in range(len(binary)):
                newBinary += str(int(binary[i]) & int(key[i]))
            return newBinary

        ##  Encrypts the message using a feistel cipher algorithem
        #   param L, left half of the user's binary string
        #   param R, right half of the user's binary string
        #   param firstKey, a randomly generated binary string, used in round functions
        #   param secondKey, a randomly generated binary string, used in round functions
        #   return L3, a encoded version of the left half of the user's binary string
        #   return R3, a encoded version of the right half of the user's binary string
        #   return binaryMessage, an addition of both R3 and L3 as one string
        def feistelEncrypt(L, R, firstKey, secondKey):
            # First round of encryption
            f1 = roundFunction(R, firstKey)
            R2 = exor(f1, L)
            L2 = R

            # Second round of encryption
            f2 = roundFunction(R2, secondKey)
            R3 = exor(f2, L2)
            L3 = R2

            # Final round of encryption
            binaryMessage = L3 + R3

            return binaryMessage, L3, R3

        stringInBinary = ''.join(format(ord(binary), '08b') for binary in
                                 self.inp)  # Converts the string sentence into a binary string, adds 0 to pad out the string into even length

        #  Splits "stringInBinary" into two equal halfs, assigns them to two seperate variables
        L1 = stringInBinary[:int(len(stringInBinary) / 2)]
        R1 = stringInBinary[int(len(stringInBinary) / 2):]

        # Generates random binary keys of with the same length of half the user binary string
        keyA = generateKey(L1)
        keyB = generateKey(L1)

        productMessageEncrypted = feistelEncrypt(L1, R1, keyA, keyB)  # Encrypts the message with both halves and keys

        # Gets the returned tuple and assigns each of its varaibles to a new one
        encryptedMessageData = productMessageEncrypted[0]
        L2 = productMessageEncrypted[1]
        R2 = productMessageEncrypted[2]

        cipherText = ""
        for i in range(0, len(encryptedMessageData), 7):  # Converts the encoded message into a readable format
            cipherDataChunk = encryptedMessageData[i:i + 7]
            decimalData = int(cipherDataChunk, 2)
            cipherText += chr(decimalData)  # Decodes the decimal value into a ASCII value and adds it to cipherText

        return L2, R2, keyA, keyB, cipherText

    def rsaEncrypt(self):

        def possibleEValues(phi):
            array = []
            # e has to be between 1 and totient but cannot use 1 because GCD of e also has to be 1. So starting with 2
            for i in range(2, phi):
                if gcd(phi, i) == 1 and calculateD(i, totient) != None:
                    array.append(i)

            for i in array:
                if i == calculateD(i, totient):
                    array.remove(i)
            return array

        # needed to calculate modular inverse (d value)
        def calculateD(eVal, phiVal):
            for i in range(1, phiVal):
                if (eVal * i) % phiVal == 1:
                    return i
            return None

        # calculating the greatest common divisor, needed to calculate variable e
        def gcd(x, y):
            while y != 0:
                z = x % y
                x = y
                y = z
            return x

        # function is used by encyrption() in order to encrypt
        def encrypt(m):
            c = calculateD(m ** e, n)
            if c == None: print("No modular multiplicative inverse available ")
            return c

        # converts between ascii and then returns
        def encryption(s):
            try:
                return ''.join([chr(encrypt(ord(x))) for x in list(s)])
            except:
                print("Encryption Not possible with given parameters.")


        # function to print if a variable input is not correct and then to send the user input to another cypher
        def notApplicable():
            print("\nValue chosen is not applicable to complete RSA...Changing Ciphers...\n")


        # error checking for prime numbers
        try:
            p = int(input('Enter a prime number for p: '))
        except:
            notApplicable()
            return

        for i in range(3, p):
            if p % i == 0:
                notApplicable()
                return
        if p == 0:
            notApplicable()
            return

        try:
            q = int(input('Enter a prime number for q: '))
        except:
            notApplicable()
            return
        for i in range(3, q):
            if q % i == 0:
                notApplicable()
                return
        if q == 0:
            notApplicable()
            return
        # calculating variable n for the formula
        n = p * q
        # Eulers Toitent, calculating variable for formula
        totient = (p - 1) * (q - 1)
        # user has to pick possible e values since there are many different combinations
        print("Pick an e value for the encryption: ", "\n")
        print(str(possibleEValues(totient)), "\n")
        eVals = possibleEValues(totient)
        try:
            e = int(input())
        except:
            notApplicable()
            return

        if e not in eVals:
            notApplicable()
            return
        d = calculateD(e, totient)

        encryptedAnsw = encryption(self.inp)
        # returns the ciphered text plus other variables that might be required to decrypt
        return encryptedAnsw, d, e, n, totient


# CiphertextMsg = Decrypt
class CiphertextMsg(Message):

    def __init__(self, cypher=None, d=None, e=None, n=None, totient=None, randKey=None):
        self.e = e
        self.d = d
        self.n = n
        self.totient = totient
        self.cypher = cypher
        self.randKey = randKey
        Message.__init__(self, inp)

    def subsititionDecrypt(self):
        decrypt = ""
        for element in self.cypher:
            position = self.alphabets.find(element)
            new = (position - 13) % 26  # adding key value of 4 into index value #adding %26 so if user enters z it will 26%26=0
            decrypt += self.alphabets[new]  # adding new variable into encryption new text will be generated
        return decrypt

    def playfairDecrypt(self):

        def matrix(x, y, initial):
            return [[initial for i in range(x)] for j in range(y)]

        def locindex(c):  # get location of each character
            location = []
            if c == 'J':
                c = 'I'
            for i, j in enumerate(matrix):
                for k, l in enumerate(j):
                    if c == l:
                        location.append(i)
                        location.append(k)
                        return location
        #math for the decyryption alogirthm
        def decrypt(cipher):  # decryption
            lists = [] # list with all the decrypted letters
            msg = cipher.upper()
            msg = msg.replace(" ", "")
            msgLength = len(msg)
            for i in range(0, msgLength, 2):
                location = locindex(msg[i])
                nextLocation = locindex(msg[i + 1])
                if location[1] == nextLocation[1]:
                    letter = ("{}{}".format(matrix[(location[0] - 1) % 5][location[1]], matrix[(nextLocation[0] - 1) % 5][nextLocation[1]]))
                elif location[0] == nextLocation[0]:
                    letter = ("{}{}".format(matrix[location[0]][(location[1] - 1) % 5], matrix[nextLocation[0]][(nextLocation[1] - 1) % 5]))
                else:
                    letter = ("{}{}".format(matrix[location[0]][nextLocation[1]], matrix[nextLocation[0]][location[1]]))
                lists.append(letter)
            # returns the list with all the decrypted letters
            return lists

        result = []
        #self.d is the second  variable being initialized and the value of the key is being passed down as the second variable
        for c in self.d:  # storing key
            if c not in result:
                if c == 'J':
                    result.append('I')
                else:
                    result.append(c)

        flag = 0
        for i in range(65, 91):  # storing other character
            if chr(i) not in result:
                if i == 73 and chr(74) not in result:
                    result.append("I")
                    flag = 1
                elif flag == 0 and i == 73 or i == 74:
                    pass
                else:
                    result.append(chr(i))
        k = 0
        matrix = matrix(5, 5, 0)  # initialize matrix
        for i in range(0, 5):  # making matrix
            for j in range(0, 5):
                matrix[i][j] = result[k]
                k += 1

        #self.cypher is the first variable being initialized and the value of the cipher text is being passed down as the first variable
        decryptedMessage = decrypt(self.cypher)
        final = ""
        for i in decryptedMessage:  # Adds the "a" list elements into one variable to return
            final += i
        return final

    def caesarDecrypt(self):

        cipher = ''
        punctuation = '!()-[]{};:’"\,<>./?@#$%^&*_~ '
        # self.d is the second argument in init and in the type function in the parent class, the encrypted message is being passed down to it
        for letter in self.d:
            if letter in punctuation:
                cipher += letter
            elif letter.isupper():
                # decryption is a similar method that subtracts the key instead of adding it
                cipher += chr((ord(letter) - self.cypher - 65) % 26 + 65)
            else:
                cipher += chr((ord(letter) - self.cypher - 97) % 26 + 97)

        return cipher

    def transpositionDecrypt(self):

        # key number
        key = 2
        # calculating number of columns
        numcolumn = math.ceil(len(self.inp) / key)
        numrows = key
        numdone = (numcolumn * numrows) - len(self.inp)
        # making a list for the decrpted word
        decrypttext = [''] * numcolumn
        columns = 0
        rows = 0
        # self.cypher is the first parameter of  init function. This is  encrypted message that is being passed from the type() function inside the parent class
        for letter in self.cypher:
            decrypttext[columns] += letter
            columns += 1
            if (columns == numcolumn) or (columns == numcolumn - 1 and rows >= numrows - numdone):
                columns = 0
                rows += 1
        # joining list to get decrypted message
        joined = (''.join(decrypttext))
        return joined

    def productDecyrpt(self, encryptedData):

        ##  Calculates the XOR value of two binary numebrs and adds it to a binary string
        #   param binaryA, a string containing only zeros and ones
        #   param binaryB, a string containing only zeros and ones
        #   return newBinary, a string containing all the XOR'd values of binaryA and binaryB
        def exor(binaryA, binaryB):  # Used in product encryption/decryption
            newBinary = ""
            for i in range(len(binaryA)):
                newBinary += str(int(binaryA[i]) ^ int(binaryB[i]))
            return newBinary

        ##  Takes two binary numbers and perfroms a binary "AND" to it, add the result to a binary string
        #   param binary, a string containing only zeros and ones
        #   param key, a string containing only zeros and ones
        #   return newBinary, a string containing all the AND'd values of binaryA and binaryB
        def roundFunction(binary, key):  # Used in product encryption/decryption
            newBinary = ""
            for i in range(len(binary)):
                newBinary += str(int(binary[i]) & int(key[i]))
            return newBinary

        ##  Encrypts the message using a feistel cipher algorithem
        #   param L, left side of the user's binary string
        #   param R, right side of the user's binary string
        #   param firstKey, a randomly generated binary string
        #   param secondKey, a randomly generated binary string
        #   return L3, a decoded version of the left side of the user's binary string
        #   return R3, a decoded version of the right side of the user's binary string
        #   return binaryMessage, an addition of both R3 and L3 as one string
        def feistelDecrypt(L, R, firstKey, secondKey):
            # First round of decryption
            f1 = roundFunction(L, secondKey)
            L2 = exor(f1, R)
            R2 = L

            # Second round of decryption
            f2 = roundFunction(L2, firstKey)
            L3 = exor(f2, R2)
            R3 = L2

            # Final round of decryption
            binaryMessage = L3 + R3

            return binaryMessage, L3, R3

        productMessageDecrypted = feistelDecrypt(encryptedData[0], encryptedData[1], encryptedData[2],
                                                 encryptedData[3])  # Decrypts the message

        decryptedMessage = int(productMessageDecrypted[0], 2)  # Converts it to a base 2 format
        decipheredMessage = binascii.unhexlify('%x' % decryptedMessage)  # Converts the message into a ascii format

        return decipheredMessage.decode("ascii")

    def rsaDecrypt(self):

        # needed to calculate modular inverse (d value)
        def calculateD(eVal, phiVal):
            for i in range(1, phiVal):
                if (eVal * i) % phiVal == 1:
                    return i
            return None
        # takes in from decryption and performs math
        def decrypt(c):
            m = calculateD(c ** self.d, self.n)
            if m is None: print("No modular multiplicative inverse available")

            return m
        # sets up decryption and send to decrypt function
        def decryption(s):
            # sends as ascii and then converts and prints
            return ''.join([chr(decrypt(ord(x))) for x in list(s)])
        # used to calculate the d value from the formula
        # does calculations to find d in order to decrypt
        self.d = calculateD(self.e, self.totient)
        # takes value from cypher and send it to decryption
        decryption = decryption(self.cypher)
        return decryption


# Main Code
# Asks the user for input, the only input not allowed is blank, if it is blank, then loop restarts
# If the user types "stop", then the loop breaks, ending the program
finalList = []
print("Due to the nature of this cipher,\nthere might be some ascii characters that\nare not visible or represented on online IDE's.\nHowever, it still encrypts and decrypts the message.\n<Succesfully tested on pyCharm>\n")
while True:
    inp = input("Enter a String (Type 'stop' to exit the program): ")
    if inp == "":
        print("Your input is empty\n")
        continue
    elif inp == "stop":
        print("\nAll Encryptions/Decryptions with Ciphers:")
        for item in finalList:
            print("Cipher Chosen:", item[0])
            print("Encrypted Message:", item[1])
            print("Decrypted Message:", item[2])
            print("")
        break
    else:
        message = Message(inp)

    while True:  # Continues to run until a cipher successfully completes

        randomNum = random.randint(1,6) # picks a number from 1-6 to select which cipher is used

        if randomNum == 1:
            try:
                print("Cipher Chosen: Substituition")
                print("Your text: ", inp)
                for i in inp:
                    if i.lower() not in message.alphabets:
                        a = 0/0  #throw error
                ciphered = PlaintextMsg(inp).subsititionEncrypt()
                print("Encrypted message: ", ciphered)
                print("Decrypted message: ", CiphertextMsg(ciphered).subsititionDecrypt())
                print("")
                finalList.append(("Substitution", ciphered, CiphertextMsg(ciphered).subsititionDecrypt()))
                break
            except:
                print("\nCannot be encrypted with Substitution...Changing Ciphers...\n")
                continue

        elif randomNum == 2:
            try:
                print("Cipher Chosen: Playfair")
                print("Your text: ", inp)
                encryptedMessage = PlaintextMsg(inp).playfairEncrypt()
                if encryptedMessage == 0:
                  error = 0/0 #throw error
                print("Encrypted Message: ", encryptedMessage[0])
                decryptedMessage = CiphertextMsg(encryptedMessage[0], encryptedMessage[1]).playfairDecrypt()
                print("Decrypted Message: ", decryptedMessage)
                print("")
                finalList.append(("Playfair", encryptedMessage[0], decryptedMessage))
                break
            except:
                print("Encryption Not possible with given parameters.\n")
                continue

        elif randomNum == 3:
            try:
                print("Cipher Chosen: Caesar")
                print("Your text: ", inp)
                for i in inp:
                    if i.lower() not in message.alphabets:
                        error = 0/0 #throw error
                caesarCipher = PlaintextMsg(inp).caesarEncrypt()
                print("Encrypted Message: ", caesarCipher[0])
                print("Decrypted Message: ", CiphertextMsg(caesarCipher[1], caesarCipher[0]).caesarDecrypt())
                print("")
                finalList.append(("Substitution", caesarCipher[0], CiphertextMsg(caesarCipher[1], caesarCipher[0]).caesarDecrypt()))
                break
            except:
                print("\nCannot be encrypted with Caesar...Changing Ciphers...\n")
                continue

        elif randomNum == 4:
            print("Cipher Chosen: Transposition -> key = 2")
            print("Your text: ", inp)
            ciphered = PlaintextMsg(inp).transpositionEncrypt()
            print("Encrypted Message: ", ciphered)
            print("Decrypted Message: ", CiphertextMsg(ciphered).transpositionDecrypt())
            print("")
            finalList.append(("Transposition", ciphered, CiphertextMsg(ciphered).transpositionDecrypt()))
            break

        elif randomNum == 5:
            print("Cipher Chosen: Product")
            print("Your text: ", inp)
            cipher = PlaintextMsg(inp).productEncrypt()
            print("Encrypted message:", cipher[4])
            plainText = CiphertextMsg().productDecyrpt(cipher)
            print("Decrypted message: ", plainText)
            print("")
            finalList.append(("Product", cipher[4], plainText))
            break

        elif randomNum == 6:
            print("Cipher Chosen: RSA")
            print("Your text: ", inp)
            # if any problems, it attempts to encrypt or decrypt with another random cipher
            try:
                a = PlaintextMsg(inp).rsaEncrypt()
                print("Encrypted message: ", a[0])
                b = CiphertextMsg(a[0], a[1], a[2], a[3], a[4]).rsaDecrypt()
                print("Decrypted message: ", b)
                print("")
                finalList.append(("RSA", a[0], b))
                break
            except:
                continue

