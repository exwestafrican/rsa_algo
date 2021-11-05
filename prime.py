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
            whole_part = int(list_of_remainders[-2] / list_of_remainders[-1])
            remainder = list_of_remainders[-2] % list_of_remainders[-1]
            list_of_whole_numbers.append(whole_part)
            list_of_remainders.append(remainder)

        for num in range(0, len(list_of_whole_numbers) - 1):
            next_item = third_l[num] - list_of_whole_numbers[num + 1] * third_l[num + 1]
            third_l.append(next_item)

        return third_l[-1] % m


# rsa = RSA()
# rsa.priv_key
