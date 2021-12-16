class CipherHelper:
    def ciphertext(self, msg_chunk):
        return pow(msg_chunk, self.encryption_key, self.public_key)

    def de_ciphertext(self, cipher_chunk):
        return pow(cipher_chunk, self.private_key, self.public_key)
