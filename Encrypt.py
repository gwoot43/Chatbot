import time
from cryptography.fernet import Fernet
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


def SymmDecryptor ():
    #Just the decryption process so people can send messages to each other using the encryptor
    ciphertext = input ('Copy and paste the encrypted message: ')
    time.sleep(1)
    print('Saving...')
    encrypted_msg = bytes(ciphertext, 'utf-8')
    time.sleep(1)
    secret_key = input ('Input the shared secret key to decrypt the file: ')
    byte_key = bytes(secret_key, 'utf-8')
    time.sleep(1)
    print('Decrypting...')
    decrypted_msg = Fernet(byte_key).decrypt(encrypted_msg)
    print('Here is the decrypted message: ', decrypted_msg.decode())


#run
SymmDecryptor ()
