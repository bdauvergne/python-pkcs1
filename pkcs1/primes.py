import random
import math
import fractions

DEFAULT_ITERATION = 1000

def get_prime(size=128, random=random.SystemRandom, k=DEFAULT_ITERATION):
    random = random()
    while True:
        n = random.getrandbits(size-2)
        n = 2 ** (size-1) + n * 2 + 1
        sys.stdout.write('\r')

        if miller_rabin(n, k):
            return n

def miller_rabin(n, k):
    s = 0
    d = n-1
    # Find nearest power of 2
    s = int(math.floor(math.log(n-1, 2)))
    # Find greatest factor which is a power of 2
    s = fractions.gcd(2**s, n-1)
    d = (n-1) // s
    while k:
        k = k - 1
        a = random.randint(2, n-2)
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

