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
        raise Exception('not found')
    r = pow(n, (q + 1) / 4, q)
    assert (r ** 2) % q == n
    assert ((q - r) ** 2) % q == n
    return (r, q - r)


class EC(object):
    pass


# TODO:
#   rename to Weierstrass, add EC base class
#   add to-string method using SEC1 compressed
#   add to-string uncompressed method (no equiv for Edwards)
#   add from-string method
#   add from-string-nbytes method
class Weierstrass(EC):
    """Implements a Weierstrass elliptic curve"""
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

    def identity(self):
        """Return the additive identity point (the point at infinity)."""
        return (0, 0)

    def is_valid(self, p):
        if p == (0, 0): return True
        x, y = p
        l = (y ** 2) % self.q
        r = ((x ** 3) + self.a * x + self.b) % self.q
        return l == r

    def at_x(self, x):
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
        return (x, y), (x, my)

    def neg(self, p):
        """negate p
        >>> assert ec.is_valid(ec.neg(p))
        """
        return (p[0], -p[1] % self.q)

    def add(self, p1, p2):
        """<add> of elliptic curve: negate of 3rd cross point of (p1,p2) line
        >>> d = ec.add(a, b)
        >>> assert ec.is_valid(d)
        >>> assert ec.add(d, ec.neg(b)) == a
        >>> assert ec.add(a, ec.neg(a)) == ec.zero
        >>> assert ec.add(a, b) == ec.add(b, a)
        >>> assert ec.add(a, ec.add(b, c)) == ec.add(ec.add(a, b), c)
        """
        if p1 == (0, 0): return p2
        if p2 == (0, 0): return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2 and (y1 != y2 or y1 == 0):
            # p1 + -p1 == 0
            return (0, 0)
        if x1 == x2:
            # p1 + p1: use tangent line of p1 as (p1,p1) line
            l = (3 * x1 * x1 + self.a) * inv(2 * y1, self.q) % self.q
        else:
            l = (y2 - y1) * inv(x2 - x1, self.q) % self.q
        x = (l * l - x1 - x2) % self.q
        y = (l * (x1 - x) - y1) % self.q
        return (x, y)

    def mul(self, p, n):
        """n times <mul> of elliptic curve
        >>> m = ec.mul(p, n)
        >>> assert ec.is_valid(m)
        >>> assert ec.mul(p, 0) == ec.zero
        """
        r = (0, 0)
        m2 = p
        # O(log2(n)) add
        while 0 < n:
            if n & 1 == 1:
                r = self.add(r, m2)
            n, m2 = n >> 1, self.add(m2, m2)
        return r

    def nbytes_int(self):
        return -(-self.q.bit_length() // 8)

    def encode_int(self, n):
        """Convert an element of Fq to bytes per SEC1 section 2.3.5."""
        assert 0 <= n < self.q
        l = [chr((n >> (8 * i)) % 256) for i in range(self.nbytes_int())]
        return ''.join(reversed(l))

    def decode_int(self, s):
        """Decode s as a big-endian integer per SEC1 section 2.3.5."""
        if len(s) != self.nbytes_int():
            raise Exception('integer representation has wrong length')
        return int(s.encode('hex'), 16)

    def nbytes_point(self):
        """Return the string length needed for decode_point."""
        # Assumes non-identity compressed point.
        return self.nbytes_int() + 1

    def encode_point(self, p, uncompressed=False):
        """Convert a point to bytes per SEC1 section 2.3.3."""
        if p == (0, 0):
            return '\0'
        x, y = p
        if uncompressed:
            return '\x04' + self.encode_int(x) + self.encode_int(y)
        else:
            return ('\x03' if y % 2 else '\x02') + self.encode_int(x)

    def decode_point(self, s):
        """Convert bytes to a point per SEC1 section 2.3.4."""
        if s[0] == '\0':
            return (0, 0)
        elif s[0] == '\x04':
            x = self.decode_int(s[1:len(b + 1) / 2])
            y = self.decode_int(s[len(b + 1) / 2:])
            if not 1 <= x < self.q or not 1 <= y < self.q:
                raise Exception('invalid coordinate')
            p = (x, y)
        elif s[0] == '\x02' or s[0] == '\x03':
            ybyte, xbytes = s[0], s[1:]
            x = self.decode_int(xbytes)
            if not 1 <= x < self.q:
                raise Exception('invalid X coordinate')
            p1, p2 = self.at_x(x)
            p = p1 if (ord(ybyte) % 2 == p1[1] % 2) else p2
        else:
            raise Exception('invalid first byte')
        if not self.is_valid(p):
            raise Exception('point is not on curve')
        return p

    def canon_pointstr(self, s):
        """Canonicalize a string of input_len(self) bytes into a well-formed
        (but not necessarily valid) input string."""
        return chr(ord(s[0]) & 1 | 2) + s[1:]


# Adapted from http://ed25519.cr.yp.to/cfrg/signatures.py version 2015.09.25
# by Daniel J. Bernstein

class Edwards(EC):
    """Implements an Edwards elliptical curve"""
    def __init__(self, q):
        self.q = q
        self.d = -121665 * inv(121666, q)
        self.i = pow(2, (q - 1) / 4, q)

    def identity(self):
        return (0, 1)

    def at_y(self, y):
        """Return the two curve points with the given y coordinate, starting
        with the positive one."""
        xx = (y * y - 1) * inv(self.d * y * y + 1, self.q)
        x = pow(xx, (self.q + 3) / 8, self.q)
        if (x * x - xx) % self.q != 0:
            x = (x * self.i) % self.q
        if (x & 1) != 0:
            x = self.q - x
        return (x, y), (self.q - x, y)

    def is_valid(self, p):
        x, y = p
        return (-x * x + y * y - 1 - self.d * x * x * y * y) % self.q == 0

    def add(self, p1, p2):
        x1, y1 = p1
        x2, y2 = p2
        x3 = (x1 * y2 + x2 * y1) * inv(1 + self.d * x1 * x2 * y1 * y2, self.q)
        y3 = (y1 * y2 + x1 * x2) * inv(1 - self.d * x1 * x2 * y1 * y2, self.q)
        return (x3 % self.q, y3 % self.q)

    def neg(self, p):
        return (-p[0] % self.q, p[1])

    # TODO: can probably push this up to EC; it should be functionally the
    # same as the Weierstrass implementation.  Also, don't use local q.
    # Need an abstract identity() method, I guess, since Weierstrass
    # identity is (0, 0).
    def mul(self, p, n):
        if n == 0:
            return (0, 1)
        q = self.mul(p, n / 2)
        q = self.add(q, q)
        if n & 1:
            q = self.add(q, p)
        return q

    def nbytes_int(self):
        return -(-self.q.bit_length() // 8)

    def encode_int(self, n):
        """Encode n (in Fq) as a little-endian integer of fixed length."""
        l = ([chr((n >> (8 * i)) % 256) for i in range(self.nbytes_int())])
        return ''.join(l)

    def decode_int(self, s):
        if len(s) != self.nbytes_int():
            raise Exception('integer representation has wrong length')
        return sum(256 ** i * ord(s[i]) for i in range(len(s)))

    def nbytes_point(self):
        # Need one bit for sign of x coordinate.  For ed25519, the
        # result still fits in 32 bytes.
        return -(-(self.q.bit_length() + 1) // 8)

    def encode_point(self, p):
        x, y = p
        ystr = self.encode_int(y)
        if self.nbytes_point() == self.nbytes_int():
            # Pack the x bit into the high bit of the last byte.
            return ystr[:-1] + chr(((x & 1) << 7) | ord(ystr[-1]))
        else:
            # Add the x bit in the high bit of the last byte by itself.
            return ystr + chr((x & 1) << 7)

    def decode_point(self, s):
        if len(s) != self.nbytes_point():
            raise Exception('point representation has wrong length')
        if s != self.canon_pointstr(s):
            raise Exception('point representation has extra overflow bits')
        xbit = ord(s[-1]) >> 7
        if self.nbytes_point() == self.nbytes_int():
            # Remove the x bit from the high bit of the first byte.
            # (XXX does not check that any intermediate bits are 0;
            # irrelevant for 25519 and 448)
            y = self.decode_int(s[:-1] + chr(ord(s[-1]) & 0x7F))
        else:
            # Remove the first byte.  (XXX does not check that low
            # seven bits are 0.)
            y = self.decode_int(s[:-1])
        p1, p2 = self.at_y(y)
        p = p1 if xbit == 0 else p2
        if not self.is_valid(p):
            raise Exception('point is not on curve')
        return p

    def canon_pointstr(self, s):
        o = self.q.bit_length() % 8
        # Keep the high bit plus the low o bits of the first byte.
        mask = ~((0x7F < o) & 0x7F)
        return chr(ord(s[0]) & mask) + s[1:]


p256_p = 2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1
p256_a = p256_p - 3
p256_b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
p256 = Weierstrass(p256_a, p256_b, p256_p)
p256_G = p256.decode_point('036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33'
                           'A0F4A13945D898C296'.decode('hex'))
p256_order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

p384_p = 2 ** 384 - 2 ** 128 - 2 ** 96 + 2 ** 32 - 1
p384_a = p384_p - 3
p384_b = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
p384 = Weierstrass(p384_a, p384_b, p384_p)
p384_G = p384.decode_point('03AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B'
                           '9859F741E082542A385502F25DBF55296C3A545E3872760A'
                           'B7'.decode('hex'))
p384_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973

p521_p = 2 ** 521 - 1
p521_a = p521_p - 3
p521_b = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
p521 = Weierstrass(p521_a, p521_b, p521_p)
p521_G = p521.decode_point('0200C6858E06B70404E9CD9E3ECB6623'
                           '95B4429C648139053FB521F828AF606B'
                           '4D3DBAA14B5E77EFE75928FE1DC127A2'
                           'FFA8DE3348B3C1856A429BF97E7E31C2'
                           'E5BD66'.decode('hex'))
p521_order = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409

ed25519_p = 2 ** 255 - 19
ed25519 = Edwards(ed25519_p)
ed25519_G = ed25519.decode_point('5866666666666666'
                                 '6666666666666666'
                                 '6666666666666666'
                                 '6666666666666666'.decode('hex'))
ed25519_order = 2 ** 252 + 27742317777372353535851937790883648493
