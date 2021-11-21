import math
import random


class RSA:
    def __init__(self) -> None:
        self.prime_numbers = list(self.eulers_sieve(65535))
        self.p = random.choice(self.prime_numbers)
        self.q = random.choice(self.prime_numbers)

        while self.value_is_equal(self.p, self.q):
            # p and q are never the same
            self.p = random.choice(self.prime_numbers)

        self.n = self.p * self.q
        self.phi_of_n = (self.p - 1) * (self.q - 1)

        lower_bound_for_e = min(self.p, self.q)
        possible_values_of_e = list(self.eulers_sieve(lower_bound_for_e))

        self.e = random.choice(possible_values_of_e)
        self.priv_key = self.mod_inverse(self.e, self.phi_of_n)

        # self.private_key = math.pow(self.e, -1) % self.phi

    def eulers_sieve(self, end):
        """
        generates prime numbers from 2 up till value of end
        """
        # take all numbers from zero till last last number
        possibilites = list(range(0, end + 1))
        not_prime = []
        # max num to go to: range(1,9) goes from 1 to 8 , 9 is not inclusive to include 9 stop at 10
        prime_end = int(math.sqrt(end)) + 1
        for num in range(2, prime_end):
            for i in range(num, int(end / num) + 1):
                not_prime.append(possibilites[num * i])
        return set(possibilites[2:]) - set(not_prime)

    def value_is_equal(self, x, y):
        return bool(x == y)

    def mod_inverse(self, a, m):
        # a^-1 mod m
        # sample solution https://jamboard.google.com/d/1be9MkgcTksomW4O1QgERKEevEIaBwieY6UG4IiJOTaY/viewer?f=0
        if a >= m:
            # example input 23^-1 mod 13
            # convert to 10^-1 mod 13
            #  move mode to acceptable range
            numbers_after_decimal = (a / m) - int(a / m)
            a = int(numbers_after_decimal * m)

        list_of_remainders = [m, a]
        list_of_whole_numbers = [0]
        third_l = [0, 1]

        while list_of_remainders[-1] != 1:
            try:
                whole_part = int(list_of_remainders[-2] / list_of_remainders[-1])
                remainder = list_of_remainders[-2] % list_of_remainders[-1]
                list_of_whole_numbers.append(whole_part)
                list_of_remainders.append(remainder)
            except ZeroDivisionError:
                continue

        for num in range(0, len(list_of_whole_numbers) - 1):
            next_item = third_l[num] - list_of_whole_numbers[num + 1] * third_l[num + 1]
            third_l.append(next_item)

        return third_l[-1] % m


class RsaMessenger:
    def __init__(
        self,
        msg="hi",
        encryption_key=None,
        public_key=None,
        private_key=None,
        chunk_size=3,
    ) -> None:
        # chunck size in bytes
        #  encription key is publiction
        self.max_bits = chunk_size * 8
        self.msg = msg
        self.encryption_algo = RSA()
        self.cipher_msg = None

        if encryption_key is None:
            self.encryption_key = self.encryption_algo.e
        else:
            self.encryption_key = encryption_key

        if public_key is None:
            self.public_key = self.encryption_algo.n
        else:
            self.public_key = public_key

        if private_key is None:
            self.private_key = self.encryption_algo.priv_key
        else:
            self.private_key = private_key

    def msg_to_chunks(self):
        chunks = []
        sub_chunk = ""
        num_of_bits = 0
        for word in self.msg:
            num_of_bits += self.num_of_bits(word)
            if num_of_bits < self.max_bits:
                sub_chunk += word
            else:
                chunks.append(sub_chunk)
                sub_chunk = word
                num_of_bits = self.num_of_bits(word)

        if num_of_bits != 0:
            chunks.append(sub_chunk)
        return chunks

    def clean_binary(self, binary):
        #  take binary from this form'0b10' to 10
        #  ignore first two characters
        return binary[2:]

    def clean_data(slf, data):
        return data[2:]

    def to_hex(self, sub_chunk):
        hexa = "".join([self.convert_to_hex(word) for word in sub_chunk])
        return "0x" + hexa

    def convert_to_hex(self, word):
        ascii_value = ord(word)
        dirty_hex = hex(ascii_value)
        return self.clean_data(dirty_hex)

    def convert_to_binary(self, word):
        ascii_value = ord(word)
        dirty_binary = bin(ascii_value)
        return self.clean_binary(dirty_binary)

    def num_of_bits(self, word):
        bits = self.convert_to_binary(word)
        return len(bits)

    def hex_to_int(self, hexa):
        return int(hexa, 16)

    def ciphertext(self, msg_chunk):
        return pow(msg_chunk, self.encryption_key, self.public_key)

    def de_ciphertext(self, cipher_chunk):
        return pow(cipher_chunk, self.private_key, self.public_key)

    def plaintext(self, de_ciphed_chunk):
        chunks = []
        for chunk in de_ciphed_chunk:
            dirty_hex_of_chunk = hex(chunk)
            hex_of_chunk = self.clean_data(dirty_hex_of_chunk)
            str_chunk = bytes.fromhex(hex_of_chunk).decode("utf-8")
            chunks.append(str_chunk)
        return "".join(chunks)

    def set_encrypted_message(self, encrypted_msg):
        self.cipher_msg = encrypted_msg

    def decrypt_msg(self, encrypted_msg=None):
        """
        message is given as cipher raised to private key
        mode public key
        given as m^e mod n
        """

        if self.cipher_msg is None:
            raise ValueError("Attempt to decrypt an unencrypted message")
        else:
            # do some vidu magic
            deciphered_chunk = [
                self.de_ciphertext(cipher_chunk) for cipher_chunk in self.cipher_msg
            ]
            return self.plaintext(deciphered_chunk)

    def encrypt_msg(self):
        chunks = self.msg_to_chunks()
        hex_notation_of_msg = [self.to_hex(sub_chunk) for sub_chunk in chunks]
        int_notation = [
            self.hex_to_int(hex_notation) for hex_notation in hex_notation_of_msg
        ]
        # print(int_notation)
        self.cipher_msg = [self.ciphertext(msg_chunk) for msg_chunk in int_notation]
        return self.cipher_msg


# snap_chat = RsaMessenger(
#     msg="Hello Arshdeep! My name is Perehrat",
#     encryption_key=1951,
#     public_key=160312903,
#     private_key=137017471,
# )


# snap_chat.encrypt_msg()
# snap_chat.decrypt_msg()


# for decreption
# snap_chat = RsaMessenger(
#     encryption_key=<the_guys_key>,
#     public_key=<the_guys_key,
#     private_key=<the_guys_key,
# )

# snap_chat.set_encrypted_message(<pass_the_encypted_message>)
# snap_chat.decrypt_msg()
