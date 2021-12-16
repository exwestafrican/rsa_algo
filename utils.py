def square_and_multiply(base, exponent, modulo):
    result = base
    binary_represntation = bin(exponent)
    for binary_bit in binary_represntation:
        result *= result
        result = result % modulo
        if binary_bit == 1:
            result = result * base
            result = result % modulo

    return result


class SquareMuliplierHelper:
    def ciphertext(self, msg_chunk):
        return square_and_multiply(msg_chunk, self.encryption_key, self.public_key)

    def de_ciphertext(self, cipher_chunk):
        return square_and_multiply(cipher_chunk, self.private_key, self.public_key)
