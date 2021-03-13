import time
from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher = Fernet(key)


#Symmetric Encryption
def SymmetricEncyption (): 
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
    if byte_key == key:
        decrypted_msg = Fernet(byte_key).decrypt(encrypted_msg)
        print ('Decryption successful. The original message is:', decrypted_msg.decode())
    else:
        print ('Decryption unsuccessful. Secret key is invalid')

        
    
#def SymmetricDecryption ():
    #given a key, use that key to decrypt the message, - fun activitiy 
    #secret_key = input ('In order to decrypt a message, please insert the secret key:')


#run
SymmetricEncyption ()
