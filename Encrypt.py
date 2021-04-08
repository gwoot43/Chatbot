import time
import webbrowser
from cryptography.fernet import Fernet
from PIL import Image
import hashlib
import os
import random
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

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
            time.sleep(1)
            Menu()
        except ValueError:
            print("Invalid secret key. Type 'done' to exit")
            continue

def AsymmetricEncryption (): 
    messages = []
    fhand = open ('MessageList.txt', encoding='utf')
    for line in fhand:
        #split by new line 
        #getting rid of empty space
        new_msg = line.strip()
        messages.append(new_msg)
    new_message = random.choice(messages)
    new_message_bytes = bytes(new_message,'utf-8')
    print ('A message will be encrypted with your public key. Decrypt it by using your private key')
    #Key Generation: 128 bit key or 2048 byte key,  use 65537 for legacy purposes
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend=default_backend())
    public_key = private_key.public_key()

    #Key Storage: In order to store a key, they need to be serialised and written into a file
    #Private Enhanced Email (PEM) is the file format for storing and sending crytographic keys, certificates
    serial_private = private_key.private_bytes(
        encoding = serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8, 
        encryption_algorithm=serialization.NoEncryption())
    serial_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    print ('Generating our public and private keys...')
    time.sleep(1)
    print('This will be your private key:\n',serial_private.decode())
    print('Saving....')
    time.sleep(1)
    print ("Our private key will be saved under the name 'Private_key', type this to recall our key")
    time.sleep(1)
    print('This will be your public key:\n',serial_public.decode())

    #encryption
    ciphertext = public_key.encrypt(
        new_message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    time.sleep(1)
    print('Given our ciphertext, we now use our private key to decrypt this message which has been encrypted with our public key:\n\n',ciphertext)
    time.sleep(1)

    #decryption
    UI_private_key = input ('Insert your private key to decrypt the message: ')
    print('Decrypting...')
    time.sleep(1)
    if UI_private_key == 'Private_key':
        original_message = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        print('\nThe original message is:',original_message.decode(),'\n\nNow generate your own keys and send your public key to your friends so that you can decrypt their encrypted message with your private key!\n')
    else:
        print('Invalid private key, unable to decrypt')
    Menu()

def asymm_key_generation () :
    private_key1 = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend=default_backend())
    public_key1 = private_key1.public_key()

    private_key2 = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend=default_backend())
    public_key2 = private_key2.public_key()

    private_key3 = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend=default_backend())
    public_key3 = private_key3.public_key()

    serial_private_rob = private_key1.private_bytes(
        encoding = serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8, 
        encryption_algorithm=serialization.NoEncryption())
    with open('serial_private_rob.pem','wb') as f:
        f.write(serial_private_rob)
    serial_private_megan = private_key2.private_bytes(
        encoding = serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8, 
        encryption_algorithm=serialization.NoEncryption())
    with open('serial_private_megan.pem','wb') as f:
        f.write(serial_private_megan)
    serial_private_alex = private_key3.private_bytes(
        encoding = serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8, 
        encryption_algorithm=serialization.NoEncryption())
    with open('serial_private_alex.pem','wb') as f:
        f.write(serial_private_alex)
    #storing keys for Rob, Megan, Alex
    rob_public_key = public_key1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open('rob_public_key.pem','wb') as f:
        f.write(rob_public_key)

    megan_public_key = public_key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open('megan_public_key.pem','wb') as f:
        f.write(megan_public_key)
    
    alex_public_key = public_key3.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open('alex_public_key.pem','wb') as f:
        f.write(alex_public_key) 
    print('You should only run this once unless you want to reset the keys')
    time.sleep(1)
    print('Generating...')
    time.sleep(2)
    print('Public and Private Keys for Rob, Megan and Alex have been generated. Save the private and public key files in a seperate folder!')

def asymm_encryption () :
    person = input(str("Who would you like to send a message to?: Rob, Megan or Alex? "))
    if person == 'Rob' or person == 'rob':
        publickey = 'rob_public_key.pem'
        with open (publickey,'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend())
            #message encryption
            message = input('Insert your message: ')
            byte_message = bytes(message,'utf-8')
            ciphertext_rob = public_key.encrypt(
                byte_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
            print ('Your encrypted message to Rob:\n',ciphertext_rob)
            time.sleep(1)
            print ("The encrypted text will be saved as 'ciphertext_rob.txt'")
            with open ('ciphertext_rob.txt','wb') as f:
                f.write(ciphertext_rob)
            time.sleep(2)
            Menu()

    elif person == 'Megan' or person == 'megan':
        publickey = 'megan_public_key.pem'
        with open (publickey,'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend())
            #message encryption
            message = input('Insert your message: ')
            byte_message = bytes(message,'utf-8')
            ciphertext_megan = public_key.encrypt(
                byte_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
            print ('Your encrypted message to Megan:\n',ciphertext_megan)
            time.sleep(1)
            print ("The encrypted text will be saved as 'ciphertext_megan.txt'")
            with open ('ciphertext_megan.txt','wb') as f:
                f.write(ciphertext_megan)
            time.sleep(2)
            Menu()

    elif person == 'Alex' or person == 'alex':
        publickey = 'alex_public_key.pem'
        with open (publickey,'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend())
            #message encryption
            message = input('Insert your message: ')
            byte_message = bytes(message,'utf-8')
            ciphertext_alex = public_key.encrypt(
                byte_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
            print ('Your encrypted message to Alex:\n',ciphertext_alex)
            time.sleep(1)
            print ("The encrypted text will be saved as 'ciphertext_alex.txt'")
            with open ('ciphertext_alex.txt','wb') as f:
                f.write(ciphertext_alex)
            time.sleep(2)
            Menu()

    else:
        print('Invalid input, must type in either Rob, Megan or Alex!')
        Menu()

def asymm_decryption ():
    print('Before decrypting, make sure you put the encrypted file under the appropriate names. e.g. ciphertext_alex.txt for example')
    time.sleep(1)
    person = input ('Whose public key did you use to encrypt the message? Rob, Megan or Alex?: ')
    if person == 'Rob' or person == 'rob':
        privatekey = 'serial_private_rob.pem'
        with open (privatekey, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend())
        with open ('ciphertext_rob.txt','rb') as key_file:
            encrypted_message = key_file.read()
        original_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        print('Decrypting...')
        time.sleep(2)
        print('The encrypted message is:',original_message.decode())
    
    elif person == 'Megan' or person == 'megan' :
        privatekey = 'serial_private_megan.pem'
        with open(privatekey, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend())
        with open('ciphertext_megan.txt','rb') as key_file:
            encrypted_message = key_file.read()
        original_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        print('Decrypting...')
        time.sleep(2)
        print('The encrypted message is:',original_message.decode())

    elif person == 'Alex' or person == 'alex':
        privatekey = 'serial_private_alex.pem'
        with open(privatekey, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend())
        with open('ciphertext_alex.txt','rb') as key_file:
            encrypted_message = key_file.read()
        original_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        print('Decrypting...')
        time.sleep(2)
        print('The encrypted message is:',original_message.decode()) 

    else:
        print('Invalid input, must type in either Rob, Megan or Alex!')
        Menu()


def Hashing ():
    print ("A good example for hashing is in password storage. Let's say that Netflix has a stored hash value of your password")
    hashmsg = input ("Insert a password: ")
    print('Hashing...')
    time.sleep(1)
    hashbyte = bytes(hashmsg,'utf-8')
    hashvalue = hashlib.sha256(hashbyte)
    print("In Netflix's password database, their hash value of your password would be::", hashvalue.hexdigest())
    time.sleep(1)
    print ("In order to gain access, the hash value of your password input must match the stored hash value in Netflix's database")
    hashpwd = input ("Insert a password, or a different password to see a different hash value: ")
    if hashpwd == hashmsg:
        bytepass = bytes(hashpwd, 'utf-8')
        hashvaluepass = hashlib.sha256(bytepass)
        print ('Hashing...')
        time.sleep(1)
        print ("Access granted, hash value is: ", hashvaluepass.hexdigest())
    else:
        incorrectbytepass = bytes(hashpwd, 'utf-8')
        hashvalueincorrectpass = hashlib.sha256(incorrectbytepass)
        print('Hashing...')
        time.sleep(1)
        print ("Access denied, hash value is: ", hashvalueincorrectpass.hexdigest())
    time.sleep(1)
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

def ImgAES ():
    image = Image.open('AESJumblingProcess.jpg')
    image.show()
#when reuploading different image under same name in github, won't show the different img?
def ImgHMAC ():
    image = Image.open('HMAC.jpg')
    image.show()

def ImgSessionKeys ():
    image = Image.open('SessionKeys.jpg')
    image.show()

def ImgSSLKeys ():
    image = Image.open('SSLSessionKeys.jpg')
    image.show()

def Diagrams ():
    choice = input ('Please select the diagrams you wish to view: \n 1. Symmetric Encryption \n 2. AES Jumbling Process + New Key Generation \n 3. Asymmetric Encryption \n 4. Hashing \n 5. Hash-based Message Authentication Code (HMAC) \n 6. Session Keys \n 7. SSL Session Keys \n 8. Menu \n')
    if choice == '1' :
        ImgSymm ()
        Diagrams () 
    elif choice == '4' :
        ImgAES ()
        Diagrams ()
    elif choice == '2' :
        ImgAsymm ()
        Diagrams ()     
    elif choice == '3' :
        ImgHashing ()
        Diagrams()
    elif choice == '5' :
        ImgHMAC()
        Diagrams ()
    elif choice == '6' :
        ImgSessionKeys ()
        Diagrams ()
    elif choice == '7' :
        ImgSSLKeys ()
        Diagrams ()
    elif choice == '8' :
        Menu ()
    else: 
        print('Invalid input. Please input a number between 1-8')
        Diagrams ()

def CryptoReport () :
    webbrowser.open("https://www.openlearning.com/u/andreaskyungoukahn-qmdwe0/blog/CryptographicPrimitivesReport/")

def Menu ():
    choice = input ("\nWelcome to the cryptographic primitive library, your one stop location for all your encryption and hashing needs! Please select from one of the options below to proceed: \n 1. Summary and explanation of cryptographic primitives \n 2. Symmetric Encryption Practical Example \n 	2a. Encryptor \n 	2b. Decryptor \n 3. Asymmetric Encryption Practical Example \n 	3a. Key Generator\n 	3b. Encryptor \n 	3c. Decryptor \n 4. Hashing Practical Example \n 5. Diagrams of Cryptographic Primitives \n 6. Exit \n")
    if choice == '1' :
        CryptoReport ()
    elif choice == '2' :
        SymmetricEncryption ()
    elif choice == '2a' :
        SymmEncryptor ()
    elif choice == '2b' :
        SymmDecryptor () 
    elif choice == '3' :
        AsymmetricEncryption ()
    elif choice == '3a' :
        asymm_key_generation ()
    elif choice == '3b' :
        asymm_encryption ()
    elif choice == '3c' :
        asymm_decryption ()     
    elif choice == '4' :
        Hashing ()
    elif choice == '5' :
        Diagrams ()
    elif choice == '6' :
        exit ()
    else:
        print('Invalid input. Please input a number between 1-6')
        Menu ()

#run
Menu()
