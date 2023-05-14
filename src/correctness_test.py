from   Crypto.PublicKey import ECC
import library.smmp as smmp
import shutil
import os

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


def correctness_test(message):

    # Encrypts and signs the test message
    encrypted = smmp.encrypt_and_sign(message, recipient_mrn)

    # Changes the mrn in SMMP to the recipient MRN
    smmp.set_mrn(5678)

    # Decrypts and verifies the test message
    decrypted = smmp.decrypt_and_verify(encrypted)

    # decrypt_and_verify always return message as string
    message = str(message)

    # Checks verification of digital signature and ompares original message to decrypted message
    if decrypted and message == decrypted[1]:
        print(f"[PASS] {message}")

    # If digital signature fails or original message is not equal to decrypted message
    else:
        print(f"[FAIL] {message}")


if __name__ == "__main__":
    correctness_test("This is a test message!")
    shutil.rmtree("keys/")