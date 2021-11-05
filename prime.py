import math
import random


class RSA:
    def __init__(self) -> None:
        self.prime_numbers = list(self.eulers_sieve(65535))
        self.p = random.choice(self.prime_numbers)
        self.q = random.choice(self.prime_numbers)
        self.phi = (self.p - 1) * (self.q - 1)

    def eulers_sieve(self, end):
        # take all numbers from zero till last last number
        possibilites = list(range(0, end + 1))
        not_prime = []
        # max num to go to: range(1,9) goes from 1 to 8 , 9 is not inclusive to include 9 stop at 10
        prime_end = int(math.sqrt(end)) + 1
        for num in range(2, prime_end):
            for i in range(num, int(end / num) + 1):
                not_prime.append(possibilites[num * i])
        return set(possibilites[2:]) - set(not_prime)
