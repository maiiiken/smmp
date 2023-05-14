from   Crypto.PublicKey import ECC
import library.smmp as smmp
import timeit
import shutil
import os

# Test variables
iterations = [1, 10, 100, 1000] # 10000 takes a few minutes
results    = []
average    = []

message = b'This is a test message!'

# Sets MRN for sender and recipient
smmp.set_mrn(1234)
recipient_mrn = "urn:mrn:mcp:user:ipid:5678"

# Generates key-pair for sender
smmp.generate_private_key()
smmp.generate_public_key()

# Creates directory named after recipient mrn if it doesn't exist
os.makedirs("keys/" + recipient_mrn, exist_ok = True)

# Generates private key for recipient  
private_key = ECC.generate(curve = 'P-256')  
f = open(f'keys/{recipient_mrn}/private_key.pem','wt')
f.write(private_key.export_key(format     = 'PEM', 
                               passphrase = smmp.PASSPHRASE, 
                               protection = "PBKDF2WithHMAC-SHA1AndAES128-CBC"))
f.close()

# Generates public key for recipient
public_key = private_key.public_key()
f = open(f'keys/{recipient_mrn}/public_key.pem','wt')
f.write(public_key.export_key(format='PEM'))
f.close()

# Test encryption performance
def test_encrypt():
    encrypted = smmp.encrypt_and_sign(message, recipient_mrn)
    return encrypted

# Test decryption performance
encrypted = test_encrypt()  # Get the encrypted data
def test_decrypt():
    decrypted = smmp.decrypt_and_verify(encrypted)
    return decrypted

# Tests time to encrypt and sign messages, and time to decrypt and verify messages
def performance_test(iterations):
    encryption_time = timeit.timeit(test_encrypt, number = iterations)
    decryption_time = timeit.timeit(test_decrypt, number = iterations)

    return encryption_time, decryption_time


# Printstest results in table format
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

# Cleans up after the test by removing the keys directory
shutil.rmtree("keys/")