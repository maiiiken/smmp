import warnings
import timeit
import shutil
import pgpy
from   cryptography.utils import CryptographyDeprecationWarning

warnings.simplefilter("ignore", CryptographyDeprecationWarning)
warnings.simplefilter("ignore", UserWarning)

# Test variables
iterations = [1, 10, 100] # 1000 and 10000 takes several minutes
results    = []
average    = []

message = 'This is a test message!'

# Generates key-pair for sender
sender_key = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, 3072)
sender_uid = pgpy.PGPUID.new('Sender', comment = 'Test User', email = 'sender@example.com')
sender_key.add_uid(sender_uid, 
                   usage={pgpy.constants.KeyFlags.Sign, 
                          pgpy.constants.KeyFlags.EncryptCommunications})

# Generates key-pair for recipient
recipient_key = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, 3072)
recipient_uid = pgpy.PGPUID.new('Recipient', comment = 'Test User', email = 'recipient@example.com')
recipient_key.add_uid(recipient_uid, 
                      usage={pgpy.constants.KeyFlags.Sign, 
                             pgpy.constants.KeyFlags.EncryptCommunications})


# Tests encryption performance
def test_encrypt_and_sign():
    msg       = pgpy.PGPMessage.new(message)
    encrypted = recipient_key.pubkey.encrypt(msg)
    signed    = sender_key.sign(encrypted)
    return encrypted, signed

# Test decryption performance
encrypted, signed = test_encrypt_and_sign()
def test_decrypt_and_verify():
    decrypted = recipient_key.decrypt(encrypted)
    verified  = sender_key.pubkey.verify(str(decrypted), signed)
    return decrypted, verified


# Tests time to sign, encrypt, decrypt, and verify messages
def performance_test(iterations):
    encrypt_and_sign    = timeit.timeit(test_encrypt_and_sign,   number = iterations)
    decrypt_and_verify  = timeit.timeit(test_decrypt_and_verify, number = iterations)

    return encrypt_and_sign, decrypt_and_verify

# Prints test results in table format
def print_results(iterations, results):
    header = " Iterations |    encrypt_and_sign |   decrypt_and_verify"
    print(header)
    print("-" * len(header))

    for i, result in zip(iterations, results):
        print(f" {i:10} | {result[0]:18.5f}s |  {result[1]:18.5f}s")

    print("-" * len(header))

# Runs tests and adds results to list
for i in iterations:
    test = performance_test(i)
    results.append(test)
    average.append((test[0] / i, test[1] / i))
    
# Prints results
print("\n--------------------------TIME--------------------------\n")
print_results(iterations, results)
print("\n----------------------AVERAGE TIME----------------------\n")
print_results(iterations, average)