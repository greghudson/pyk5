# Based on https://gist.github.com/bellbind/1414867
# ElGamal, DiffieHellman classes removed
# order method removed from EC class
# inv, sqrt replaced with efficient versions for primes 3 (mod 4)
# Some SEC1 conversions added
# P-256 and P-521 definitions added

# Basics of Elliptic Curve Cryptography implementation on Python
import collections

def inv(n, q):
    """div on PN modulo a/b mod q as a * inv(b, q) mod q
    >>> assert n * inv(n, q) % q == 1
    """
    return pow(n, q - 2, q)


def sqrt(n, q):
    """sqrt on PN modulo: returns two numbers or exception if not exist
    >>> assert (sqrt(n, q)[0] ** 2) % q == n
    >>> assert (sqrt(n, q)[1] ** 2) % q == n
    """
    assert q % 4 == 3
    assert 1 <= n < q
    if pow(n, (q - 1) / 2, q) != 1:
        raise Exception("not found")
    r = pow(n, (q + 1) / 4, q)
    assert (r ** 2) % q == n
    assert ((q - r) ** 2) % q == n
    return (r, q - r)


Coord = collections.namedtuple("Coord", ["x", "y"])


def int_to_bytes(n, q):
    """Convert an element of Fq to bytes per SEC1 section 2.3.5"""
    assert 0 <= n < q
    l = []
    q -= 1
    while q:
        l.append(chr(n & 0xFF))
        q >>= 8
        n >>= 8
    l.reverse()
    return ''.join(l)


def point_to_compressed(p, ec):
    """Convert a point to bytes per SEC1 section 2.3.3 with compression"""
    if p == Coord(0, 0):
        return '\0'
    ybyte = '\x03' if p[1] % 2 else '\x02'
    return ybyte + int_to_bytes(p[0], ec.q)


def point_to_uncompressed(p, ec):
    """Convert a point to bytes per SEC1 section 2.3.3 without compression"""
    if p == Coord(0, 0):
        return '\0'
    return '\x04' + int_to_bytes(p[0], ec.q) + int_to_bytes(p[1], ec.q)


def bytes_to_int(b):
    return int(b.encode('hex'), 16)


def bytes_to_point(b, ec):
    """Convert bytes to a point per SEC1 section 2.3.4 with compression"""
    if b[0] == '\0':
        return Coord(0, 0)
    elif b[0] == '\x04':
        xbytes = b[1:len(b+1)/2]
        ybytes = b[len(b+1)/2:]
        x = bytes_to_int(xbytes)
        y = bytes_to_int(ybytes)
        return Coord(x, y)
    else:
        ybyte = b[0]
        xbytes = b[1:]
        x = bytes_to_int(xbytes)
        assert 1 <= x < ec.q
        p1, p2 = ec.at(x)
        return p1 if (ord(ybyte) % 2 == p1[1] % 2) else p2


class EC(object):
    """System of Elliptic Curve"""
    def __init__(self, a, b, q):
        """elliptic curve as: (y**2 = x**3 + a * x + b) mod q
        - a, b: params of curve formula
        - q: prime number
        """
        assert 0 < a and a < q and 0 < b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2))  % q != 0
        self.a = a
        self.b = b
        self.q = q
        # just as unique ZERO value representation for "add": (not on curve)
        self.zero = Coord(0, 0)
        pass

    def is_valid(self, p):
        if p == self.zero: return True
        l = (p.y ** 2) % self.q
        r = ((p.x ** 3) + self.a * p.x + self.b) % self.q
        return l == r

    def at(self, x):
        """find points on curve at x
        - x: int < q
        - returns: ((x, y), (x,-y)) or not found exception
        >>> a, ma = ec.at(x)
        >>> assert a.x == ma.x and a.x == x
        >>> assert a.x == ma.x and a.x == x
        >>> assert ec.neg(a) == ma
        >>> assert ec.is_valid(a) and ec.is_valid(ma)
        """
        assert x < self.q
        ysq = (x ** 3 + self.a * x + self.b) % self.q
        y, my = sqrt(ysq, self.q)
        return Coord(x, y), Coord(x, my)

    def neg(self, p):
        """negate p
        >>> assert ec.is_valid(ec.neg(p))
        """
        return Coord(p.x, -p.y % self.q)

    def add(self, p1, p2):
        """<add> of elliptic curve: negate of 3rd cross point of (p1,p2) line
        >>> d = ec.add(a, b)
        >>> assert ec.is_valid(d)
        >>> assert ec.add(d, ec.neg(b)) == a
        >>> assert ec.add(a, ec.neg(a)) == ec.zero
        >>> assert ec.add(a, b) == ec.add(b, a)
        >>> assert ec.add(a, ec.add(b, c)) == ec.add(ec.add(a, b), c)
        """
        if p1 == self.zero: return p2
        if p2 == self.zero: return p1
        if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
            # p1 + -p1 == 0
            return self.zero
        if p1.x == p2.x:
            # p1 + p1: use tangent line of p1 as (p1,p1) line
            l = (3 * p1.x * p1.x + self.a) * inv(2 * p1.y, self.q) % self.q
            pass
        else:
            l = (p2.y - p1.y) * inv(p2.x - p1.x, self.q) % self.q
            pass
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Coord(x, y)

    def mul(self, p, n):
        """n times <mul> of elliptic curve
        >>> m = ec.mul(p, n)
        >>> assert ec.is_valid(m)
        >>> assert ec.mul(p, 0) == ec.zero
        """
        r = self.zero
        m2 = p
        # O(log2(n)) add
        while 0 < n:
            if n & 1 == 1:
                r = self.add(r, m2)
                pass
            n, m2 = n >> 1, self.add(m2, m2)
            pass
        return r

    pass

p256_p = 2**256 - 2**224 + 2**192 + 2**96 - 1
p256_a = p256_p - 3
p256_b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
p256 = EC(p256_a, p256_b, p256_p)
p256_G = bytes_to_point('036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33'
                        'A0F4A13945D898C296'.decode('hex'), p256)
p256_order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

p521_p = 2**521 - 1
p521_a = p521_p - 3
p521_b = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
p521 = EC(p521_a, p521_b, p521_p)
p521_G = bytes_to_point('0200C6858E06B70404E9CD9E3ECB662395B4429C64813905'
                        '3FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2F'
                        'FA8DE3348B3C1856A429BF97E7E31C2E5BD66'.decode('hex'),
                        p521)
p521_order = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
