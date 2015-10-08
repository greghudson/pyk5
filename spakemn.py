from ecc import p256, p521, ed25519
from ecc import p256_order, p521_order, ed25519_order
from Crypto.Hash import SHA256


# Return the n'th iterated SHA-256 hash of seed.
def iterated_hash(seed, n):
    h = seed
    for i in xrange(n):
        h = SHA256.new(h).digest()
    return h


# Return the sz-byte string using as many iterated hashes as are
# needed, beginning with start.
def bighash(seed, start, sz):
    n = -(-sz // 32)
    hashes = [iterated_hash(seed, i) for i in xrange(start, start + n)]
    return ''.join(hashes)[:sz]


# Return the first valid point string for ec generated using
# get_bighash() on successive starting values, with the first byte
# normalized to make it an SEC1 compressed point.
def gen_point(seed, ec, order):
    for i in xrange(1, 1000):
        pointstr = ec.canon_pointstr(bighash(seed, i, ec.nbytes_point()))
        try:
            p = ec.decode_point(pointstr)
            if ec.mul(p, order) == ec.identity():
                return pointstr, i
        except Exception:
            pass


def display_point(ecname, oidstr, which, ec, order):
    seed = '%s point generation seed (%s)' % (oidstr, which)
    pstr, i = gen_point(seed, ec, order)
    pstrhex = pstr.encode('hex').upper()
    print '%s %s (%d): %s' % (ecname, which, i, pstrhex)


display_point('P-256', '1.2.840.10045.3.1.7', 'M', p256, p256_order)
display_point('P-256', '1.2.840.10045.3.1.7', 'N', p256, p256_order)
display_point('P-521', '1.3.132.0.35', 'M', p521, p521_order)
display_point('P-521', '1.3.132.0.35', 'N', p521, p521_order)
# XXX no OIDs assigned!
display_point('ed25519', 'ed25519', 'M', ed25519, ed25519_order)
display_point('ed25519', 'ed25519', 'N', ed25519, ed25519_order)
