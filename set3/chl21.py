
class MT19937:
    # CONSTANTS OF THE MERSENNE TWISTER
    N = 624
    M = 397
    W = 32
    R = 31
    UMASK = 0x80000000 # can be seen as a calculation of r,w but im sticking to 32 bit mersenne twister for now
    LMASK = 0x7fffffff # same as above
    A = 0x9908b0df
    U = 11
    S = 7
    T = 15
    L = 18
    B = 0x9d2c5680
    C = 0xefc60000
    F = 1812433253
    # TWISTED_MT = [0] * N

    def __init__(self, seed):
        self.INDEX = self.N
        self.MT = [0] * self.N
        self.MT[0] = seed
        for i in range(1, self.N):
            self.MT[i] = (self.F * (self.MT[i - 1] ^ (self.MT[i - 1] >> (self.W - 2))) + i) & 0xFFFFFFFF

    def twist(self):
        for i in range(self.N):
            x = (self.MT[i] & self.UMASK) | (self.MT[(i+1) % self.N] & self.LMASK) # take the right bit from MT[i] and 31 left bits from MT[i+1]
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ self.A
            self.MT[i] = self.MT[(i + self.M) % self.N] ^ xA

    # temper
    def extract_number(self):
        if self.INDEX == self.N:
            self.INDEX = 0
            self.twist()

        y = self.MT[self.INDEX]
        y = y ^ (y >> self.U)
        y = y ^ ((y << self.S) & self.B)
        y = y ^ ((y << self.T) & self.C)
        y = y ^ (y >> self.L)
        y = y & 0xFFFFFFFF

        self.INDEX += 1
        return y


def main():
    mt = MT19937(123)
    for i in range(10):
        print(mt.extract_number())

if __name__ == "__main__":
    main()