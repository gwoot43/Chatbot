import time
from cryptography.fernet import Fernet
from PIL import Image
import hashlib
import os
key = Fernet.generate_key()
cipher = Fernet(key)

#Symmetric Encryption
def SymmetricEncryption (): 
    #the whole encryption/decryption process
    #Encryption
    print ('In order to encrypt a message, I will first generate a random secret key!')
    time.sleep(1)
    print('Computing key, please wait...')
    time.sleep(1)
    print('This will be our secret key:', key.decode())
    time.sleep(1)
    message = input ("Insert a message you'd like to encrypt: ").encode()
    print('Encrypting...')
    time.sleep(1)
    encrypted_msg = cipher.encrypt(message)
    print('The encrypted message looks like this:', encrypted_msg.decode())
    time.sleep(1)
    
    #Decryption
    print("If we want to decrypt the encrypted message, we use the same secret key to decrypt the encrypted message back into readable text")
    secret_key = input ('Insert the secret key you used to encrypt the original message: ')
    byte_key = bytes(secret_key,'utf-8')
    print("Decrypting...")
    time.sleep(1)
    if byte_key != key:
        print ('Decryption unsuccessful. Secret key is invalid')
        time.sleep(1)
        #second chance to write the correct secret key
        attempt_two = input ('Please try another secret key: ')
        byte_two = bytes(attempt_two, 'utf-8')
        if byte_two == key:
            decrypted_msg = Fernet(byte_two).decrypt(encrypted_msg)
            print('Decrypting...')
            time.sleep(1)
            print ('Decryption successful. The original message is:', decrypted_msg.decode())
        else: 
            print('Decryption unsuccessful again. Have a nice day!')
    else:
        decrypted_msg = Fernet(byte_key).decrypt(encrypted_msg)
        print ('Decryption successful. The original message is:', decrypted_msg.decode())
        time.sleep(2)
        Menu()

      
def SymmEncryptor ():
    #Just the encryption process so people can send messages to each other usuing the decryptor 
    print('Generating a secret key. Please hold')
    time.sleep(1)
    print('This will be our secret key:', key.decode())
    time.sleep(1)
    message = input ("Insert a message you'd like to encrypt: ").encode()
    print('Encrypting...')
    time.sleep(1)
    encrypted_msg = cipher.encrypt(message)
    print('Send this ciphertext [',encrypted_msg.decode(),'] along with your secret key to a friend so that they can decrypt your message using the decryptor!')
    time.sleep(1)
    Menu()

def SymmDecryptor ():
    #Just the decryption process so people can send messages to each other using the encryptor
    ciphertext = input ('Copy and paste the encrypted message: ')
    time.sleep(1)
    print('Saving...')
    encrypted_msg = bytes(ciphertext, 'utf-8')
    time.sleep(1)
    while True:
        secret_key = input ('Input the shared secret key to decrypt the file: ')
        byte_key = bytes(secret_key, 'utf-8')
        if secret_key == 'done':
            break
        try:
            time.sleep(1)
            print('Decrypting...')
            decrypted_msg = Fernet(byte_key).decrypt(encrypted_msg)
            print('Here is the decrypted message: ', decrypted_msg.decode())
            time.sleep(2)
            Menu()
        except ValueError:
            print("Invalid secret key. Type 'done' to exit")
            continue

#def AsymmetricEncryption ():

def Hashing ():
    hashmsg = input ("Insert a message you'd like to hash: ")
    print('Hashing...')
    time.sleep(1)
    hashbyte = bytes(hashmsg,'utf-8')
    hashvalue = hashlib.sha256(hashbyte)
    print('The hash value of your original message:', hashvalue.hexdigest())
    Menu()

#Images
def ImgSymm ():
    image = Image.open('SymmEncryption.jpg')
    image.show()

def ImgAsymm ():
    image = Image.open('AsymmEncryption.jpg')
    image.show()

def ImgHashing ():
    image = Image.open('Hashing.jpg')
    image.show()

def Diagrams ():
    choice = input ('Please select the diagrams you wish to view: \n 1. Symmetric Encryption \n 2. Asymmetric Encryption \n 3. Hashing \n 4. Menu \n')
    if choice == '1' :
        ImgSymm ()
        Diagrams () 
    elif choice == '2' :
        ImgAsymm ()
        Diagrams ()     
    elif choice == '3' :
        ImgHashing ()
        Diagrams()
    elif choice == '4' :
        Menu ()

def Menu ():
    choice = input ("\nWelcome to the cryptographic primitive library, your one stop location for all your encryption and hashing needs! Please select from one of the options below to proceed: \n 1. Explore the chatbot! \n 2. Symmetric Encryption Practical Example \n 	2a. Encryptor \n 	2b. Decryptor \n 3. Asymmetric Encryption Practical Example \n 4. Hashing Practical Example \n 5. Diagrams of Cryptographic Primitives \n 6. Exit \n")
    if choice == '1' :
        print('chatbot')
    elif choice == '2' :
        SymmetricEncryption ()
    elif choice == '2a' :
        SymmEncryptor ()
    elif choice == '2b' :
        SymmDecryptor () 
    elif choice == '3' :
        print('AsymmetricEncryption')
    elif choice == '4' :
        Hashing ()
    elif choice == '5' :
        Diagrams ()
    elif choice == '6' :
        exit ()
    else:
        print('Invalid input. Please input a number between 1-5')
        Menu ()

#run
Menu()