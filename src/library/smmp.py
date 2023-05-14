import os
import json
import base64

from Crypto.PublicKey    import ECC
from Crypto.Cipher       import AES
from Crypto.Signature    import DSS
from Crypto.Hash         import SHA256
from Crypto.Random       import get_random_bytes

PASSPHRASE = get_random_bytes(4)
mrn        = ""


def set_mrn(pid):
    '''
    Sets the MRN of the agent based on the PID of the agent process,
    and creates a folder for the ECC key-pair based on the MRN

    Args:
        (int): PID of the agent process
    '''

    global mrn
    mrn = "urn:mrn:mcp:user:ipid:" + str(pid)

    # Creates directory named after mrn if it doesn't exist
    os.makedirs("keys/" + mrn, exist_ok = True)


def get_mrn():
    '''
    Gets the MRN of the agent

    Returns:
        str: The MRN
    '''

    return mrn


def encrypt_and_sign(message, recipient_mrn):
    '''
    Encrypts the given message using AES, encrypts the AES key
    using ECC, and then digitally signs the message
    
    Args:
        message (bytes): The message to be encrypted and signed
        
    Returns:
        str: A JSON string that contains the AES ciphertext and nonce, 
             ECC ciphertext, nonce, public key, and the signature, 
             all base64 encoded
    '''

    message = str(message).encode('utf-8')

    # Encrypts the message with AES
    aes_key = get_random_bytes(32)
    aes_ciphertext, aes_nonce = aes_encrypt(message, aes_key)

    # Encrypts the AES key with ECC
    ecc_ciphertext, ecc_nonce, sender_mrn = ecc_encrypt(aes_key, recipient_mrn)

    # Creates digital signature
    signature = digital_signature(message)

    # Adds all the variables to a json document
    data = {
        'aes': {
            'ciphertext': base64.b64encode(aes_ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(aes_nonce).decode('utf-8')
        },
        'ecc': {
            'ciphertext': base64.b64encode(ecc_ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(ecc_nonce).decode('utf-8'),
            'sender_mrn': base64.b64encode(sender_mrn.encode('utf-8')).decode('utf-8')
        },
        'signature': base64.b64encode(signature).decode('utf-8')
    }
    
    return json.dumps(data)


def decrypt_and_verify(json_data):
    '''
    Extracts the given JSON data, decrypts the AES key using ECC,
    decrypts the message using AES, and then verifies the digital signature
    
    Args:
        json_data (str): A JSON string that contains the AES ciphertext 
                         and nonce, ECC ciphertext, nonce, public key, and 
                         the signature, all base64 encoded
        
    Returns:
        str: The decrypted message if the signature is verified, otherwise None
    '''

    data = json.loads(json_data)

    # Extracts variables for AES decryption 
    aes_ciphertext = base64.b64decode(data['aes']['ciphertext'])
    aes_nonce = base64.b64decode(data['aes']['nonce'])

    # Extracts variables for ECC decryption 
    ecc_ciphertext = base64.b64decode(data['ecc']['ciphertext'])
    ecc_nonce = base64.b64decode(data['ecc']['nonce'])
    sender_mrn = (base64.b64decode(data['ecc']['sender_mrn'])).decode('utf-8')

    # Extracts digital signature
    signature = base64.b64decode(data['signature'])


    # Decrypts AES key, and uses AES key to decrypt message
    aes_key = ecc_decrypt(ecc_ciphertext, ecc_nonce, sender_mrn)
    message = aes_decrypt(aes_ciphertext, aes_key, aes_nonce)

    verified = verify_signature(message, signature, sender_mrn)

    if verified:
        return (sender_mrn, message.decode('utf-8'))
    
    return(None)


def generate_private_key():
    '''
    Generates a new private key using the P-256 curve, and then saves 
    it to a PEM-formatted file that is encrypted
    '''

    private_key = ECC.generate(curve = 'P-256') 

    
    f = open(f'keys/{mrn}/private_key.pem','wt')
    f.write(private_key.export_key(format     = 'PEM', 
                                   passphrase = PASSPHRASE, 
                                   protection = "PBKDF2WithHMAC-SHA1AndAES128-CBC"))
    f.close()


def get_private_key():
    '''
    Reads the private key file, decrypts it using the passphrase, 
    and returns the private key

    Returns:
        ECC.EccKey: The imported private key
    '''

    with open(f'keys/{mrn}/private_key.pem','rt') as f:
        return ECC.import_key(f.read(), PASSPHRASE)


def generate_public_key():
    '''
    Derives the public key from the private key and saves it to a
    PEM-formatted file 
    '''

    public_key = get_private_key().public_key()

    f = open(f'keys/{mrn}/public_key.pem','wt')
    f.write(public_key.export_key(format='PEM'))
    f.close()


def get_public_key(agent_mrn = mrn):
    '''
    Reads the public_key.pem file and returns the public key.
    This function can be used to get other agents public keys

    Args:
        agent_mrn (str): The MRN of the agent the public key 
                         belongs to, defaults to mrn of current
                         agent process
        
    Returns:
        ECC.EccKey: The imported public key
    '''

    with open(f'keys/{agent_mrn}/public_key.pem', 'rt') as f:
        return ECC.import_key(f.read())


def aes_encrypt(cleartext, key = get_random_bytes(32)): 
    '''
    Encrypts the given cleartext using AES in CTR mode with the provided key

    Args:
        cleartext (bytes):     The cleartext message to be encrypted
        key (bytes, optional): The 256-bit AES key for encryption,
                               the default is a random 32-byte key

    Returns:
        tuple: A tuple containing the encrypted ciphertext and the nonce
    '''

    cipher = AES.new(key, AES.MODE_CTR)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(cleartext)

    return (ciphertext, nonce)


def aes_decrypt(ciphertext, key, nonce):
    '''
    Decrypts the given ciphertext using AES in CTR mode 
    with the provided key and nonce

    Args:
        ciphertext (bytes): The ciphertext message to be decrypted
        key (bytes):        The 256-bit AES key used for decryption
        nonce (bytes):      The nonce used during encryption

    Returns:
        bytes: The decrypted cleartext message
    '''

    cipher = AES.new(key, AES.MODE_CTR, nonce = nonce)
    cleartext = cipher.decrypt(ciphertext)

    return cleartext


def ecc_to_aes(ecc_key):
    '''
    Derives a 128-bit AES key from an ECC key by hashing the x and y 
    coordinates of the ECC key using SHA-256, and lastly select
    and return only the first 128-bits

    Args:
        ecc_key (ECC.EccKey): An ECC key

    Returns:
        bytes: A 128-bit AES key derived from the ECC key
    '''

    secret_hash = SHA256.new(ecc_key.x.to_bytes())
    secret_hash.update(ecc_key.y.to_bytes())

    return secret_hash.digest()[:16] 


def ecc_encrypt(cleartext, recipient_mrn):
    '''
    Encrypts a given cleartext using ECC

    Args:
        cleartext (str):     The plaintext to encrypt
        recipient_mrn (str): MRN of recipient

    Returns:
        tuple: A tuple containing the ciphertext, nonce, and temporary 
               public key
    '''

    # Calculates a shared secret that can be used as an AES key for encryption
    shared_ecc_key = get_private_key().d * get_public_key(recipient_mrn).pointQ
    derived_key = ecc_to_aes(shared_ecc_key)

    # Encrypts the derived key with AES
    ciphertext, nonce = aes_encrypt(cleartext, derived_key)

    return (ciphertext, nonce, mrn)


def ecc_decrypt(ciphertext, nonce, sender_mrn):
    '''
    Decrypts a given ciphertext using ECC

    Args:
        ciphertext (str):                    The ciphertext to decrypt
        nonce (str):                         The nonce for CTR mode
        recipient_public_key (ECC.EccPoint): The recipient's public key

    Returns:
        str: The decrypted plaintext message.
    '''

    # Calculates a shared secret that can be used as an AES key for decryptions
    shared_ecc_key = get_private_key().d * get_public_key(sender_mrn).pointQ
    derived_key = ecc_to_aes(shared_ecc_key)
  
    # Decrypts the derived key with AES
    plaintext = aes_decrypt(ciphertext, derived_key, nonce)
      
    return plaintext

    
def digital_signature(message):
    '''
    Creates a digital signature for the given message using the sender's private key

    Args:
        message (bytes): The message to be signed

    Returns:
        bytes: The digital signature of the message
    '''

    private_key = get_private_key()
    message_hash = SHA256.new(message)
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(message_hash)

    return signature


def verify_signature(message, signature, sender_mrn):
    '''
    Verifies the digital signature of a message using the sender's public key

    Args:
        message (bytes):   The message whose signature needs to be verified
        signature (bytes): The digital signature to be verified

    Returns:
        bool: True if the signature is valid, False if it is not
    '''

    public_key = get_public_key(sender_mrn)
    message_hash = SHA256.new(message)
    verifier = DSS.new(public_key, 'fips-186-3')

    try:
        verifier.verify(message_hash, signature)
        return True

    except ValueError:
        return False