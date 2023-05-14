import library.smmp as smmp
import unittest
import shutil


class TestSmmp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        '''
        Sets up the test class by setting the MRN and generating a key pair
        '''
        
        smmp.set_mrn(2222)
        smmp.generate_private_key()
        smmp.generate_public_key()


    @classmethod
    def tearDownClass(cls):
        '''
        Cleans up after the test class by removing the keys directory
        '''
        
        shutil.rmtree("keys/urn:mrn:mcp:user:ipid:2222")


    def test_set_and_get_mrn(self):
        '''
        Tests the set_mrn and get_mrn functions
        '''

        smmp.set_mrn(2222)
        self.assertEqual(smmp.get_mrn(), "urn:mrn:mcp:user:ipid:2222")


    def test_encrypt_decrypt(self):
        '''
        Tests the encrypt_and_sign and decrypt_and_verify functions
        '''

        message = "Hello, world!"
        encrypted_data = smmp.encrypt_and_sign(message, smmp.get_mrn())
        sender_mrn, decrypted_message = smmp.decrypt_and_verify(encrypted_data)

        self.assertEqual(sender_mrn, smmp.get_mrn())
        self.assertEqual(decrypted_message, message)


    def test_signature_verification(self):
        '''
        Tests the digital_signature and verify_signature functions
        '''

        message = b'Correct signature message :D'
        signature = smmp.digital_signature(message)
        sender_mrn = smmp.get_mrn()

        self.assertTrue(smmp.verify_signature(message, signature, sender_mrn))

        incorrect_message = b'Incorrect signature message :/'
        self.assertFalse(smmp.verify_signature(incorrect_message, signature, sender_mrn))


    def test_aes_encryption_decryption(self):
        '''
        Tests the aes_encrypt and aes_decrypt functions
        '''

        message = b'AES test message'
        key = smmp.get_random_bytes(32)
        ciphertext, nonce = smmp.aes_encrypt(message, key)
        decrypted_message = smmp.aes_decrypt(ciphertext, key, nonce)

        self.assertEqual(message, decrypted_message)


    def test_ecc_encryption_decryption(self):
        '''
        Tests the ecc_encrypt and ecc_decrypt functions
        '''

        message = b'ECC test message'
        recipient_mrn = smmp.get_mrn()
        ciphertext, nonce, sender_mrn = smmp.ecc_encrypt(message, recipient_mrn)
        decrypted_message = smmp.ecc_decrypt(ciphertext, nonce, sender_mrn)

        self.assertEqual(message, decrypted_message)


if __name__ == '__main__':
    unittest.main()
