import random
import math
import fractions

try:
    import gmpy
except ImportError:
    gmpy = None

DEFAULT_ITERATION = 1000

def is_prime(n, rnd=random.SystemRandom, k=DEFAULT_ITERATION):
    if gmpy:
        return gmpy.is_prime(n)
    else:
        return miller_rabin(n, k, rnd=rnd)


if not gmpy:
    def get_prime(size=128, rnd=random.SystemRandom, k=DEFAULT_ITERATION):
        if callable(rnd):
            rnd = rnd()
        while True:
            n = rnd.getrandbits(size-2)
            n = 2 ** (size-1) + n * 2 + 1
            if is_prime(n):
                return n
else:
    def get_prime(size=128, rnd=random.SystemRandom, k=DEFAULT_ITERATION):
        if callable(rnd):
            rnd = rnd()
        n = rnd.getrandbits(size-2)
        n = 2 ** (size-1) + n * 2 + 1
        if gmpy.is_prime(n):
            return n
        return gmpy.next_prime(n)

def miller_rabin(n, k, rnd=random.SystemRandom):
    s = 0
    d = n-1
    # Find nearest power of 2
    s = int(math.floor(math.log(n-1, 2)))
    # Find greatest factor which is a power of 2
    s = fractions.gcd(2**s, n-1)
    d = (n-1) // s
    if callable(rnd):
        rnd = rnd()
    while k:
        k = k - 1
        a = rnd.randint(2, n-2)
        x = pow(a,d,n)
        if x == 1 or x == n - 1:
            continue
        for r in xrange(1,s-1):
            x = pow(x,2,n)
            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False
    return True

