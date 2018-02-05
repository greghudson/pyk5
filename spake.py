import random
import sys
from asn1 import _mfield, _ofield, _K5Sequence
from asn1 import EncryptedData, KDCReqBody, NameType, PrincipalName
from ecc import p256, p256_G, p256_order
from ecc import p384, p384_G, p384_order
from ecc import p521, p521_G, p521_order
from ecc import ed25519, ed25519_G, ed25519_order
from crypto import Enctype, seedsize, random_to_key, string_to_key
from crypto import prfplus, cf2
from Crypto.Hash import SHA256, SHA384, SHA512
from pyasn1.type.univ import Integer, OctetString, SequenceOf, Choice
from pyasn1.type.namedtype import NamedTypes
from pyasn1.codec.der.encoder import encode as der_encode
from struct import pack

KEY_USAGE_SPAKE = 65

class SPAKESecondFactor(_K5Sequence):
    componentType = NamedTypes(
        _mfield('type', 0, Integer()),
        _ofield('data', 1, OctetString()))


class SPAKESupport(_K5Sequence):
    componentType = NamedTypes(
        _mfield('groups', 0, SequenceOf(componentType=Integer())))


class SPAKEChallenge(_K5Sequence):
    componentType = NamedTypes(
        _mfield('group', 0, Integer()),
        _mfield('pubkey', 1, OctetString()),
        _mfield('factors', 2, SequenceOf(componentType=SPAKESecondFactor())))


class SPAKEResponse(_K5Sequence):
    componentType = NamedTypes(
        _mfield('pubkey', 0, OctetString()),
        _mfield('factor', 1, EncryptedData()))


class PA_SPAKE(Choice):
    componentType = NamedTypes(
        _mfield('support', 0, SPAKESupport()),
        _mfield('challenge', 1, SPAKEChallenge()),
        _mfield('response', 2, SPAKEResponse()),
        _mfield('encdata', 3, EncryptedData()))


def make_support_encoding(gnum):
    p = PA_SPAKE()
    p['support'] = None
    support = p['support']
    support['groups'] = None
    support['groups'][0] = gnum
    return der_encode(p)


def make_challenge_encoding(gnum, Tbytes):
    p = PA_SPAKE()
    p['challenge'] = None
    challenge = p['challenge']
    factor = SPAKESecondFactor()
    factor['type'] = 1
    challenge['group'] = gnum
    challenge['pubkey'] = Tbytes
    challenge['factors'] = None
    challenge['factors'][0] = factor
    return der_encode(challenge)


def make_body_encoding(enctype):
    client = PrincipalName()
    client['name-type'] = NameType.PRINCIPAL
    client['name-string'] = None
    client['name-string'][0] = 'raeburn'
    server = PrincipalName()
    server['name-type'] = NameType.SRV_INST
    server['name-string'] = None
    server['name-string'][0] = 'krbtgt'
    server['name-string'][1] = 'ATHENA.MIT.EDU'
    body = KDCReqBody()
    body['kdc-options'] = (False,)*32
    body['cname'] = client
    body['realm'] = 'ATHENA.MIT.EDU'
    body['sname'] = server
    body['till'] = '19700101000000Z'
    body['nonce'] = 0
    body['etype'] = None
    body['etype'][0] = enctype
    return der_encode(body)

code_output = False

def output(prefix, b):
    s = b.encode('hex')
    if code_output:
        s = s.upper()
        while len(s) > 66:
            print '      "' + s[:64] + '"'
            s = s[64:]
        print '      "' + s + '",'
        return

    maxlinelen = 69
    if len(prefix) + len(s) > maxlinelen:
        if len(prefix) <= maxlinelen - 64:
            maxlen = 64
        elif len(prefix) <= maxlinelen - 32 and len(s) == 64:
            maxlen = 32
        elif len(prefix) <= maxlinelen - 48:
            maxlen = 48
        elif len(prefix) <= maxlinelen - 20 and len(s) == 40:
            maxlen = 20
        elif len(prefix) <= maxlinelen - 32:
            maxlen = 32
        else:
            raise ValueError('Formatting error')
        while len(s) > maxlen:
            print prefix + s[:maxlen]
            s = s[maxlen:]
            prefix = ' ' * len(prefix)
    print prefix + s


def update_thash(hashfn, thash, b):
    return hashfn.new(thash + b).digest()


def derive_key(hashfn, gnum, ikey, w, Kbytes, thash, body, n):
    hashin = ('SPAKEkey' + pack('>I', gnum) + pack('>I', ikey.enctype) + w +
              Kbytes + thash + body + pack('>I', n) + '\1')
    hashout = hashfn.new(hashin).digest()
    klen = seedsize(ikey.enctype)
    # There are currently no scenarios where the seedsize exceeds the
    # hash size.  The protocol handles this situation by incrementing
    # the block counter (the last byte of hashin) to produce more
    # blocks, but we don't need to implement that yet.
    assert len(hashout) >= klen
    hash_key = random_to_key(ikey.enctype, hashout[:klen])
    return cf2(ikey.enctype, ikey, hash_key, "SPAKE", "keyderiv")


def vectors(enctype, gnum, ec, order, cofactor, wlen, G, M, N, hashfn,
            skip_support=False, rejected_challenge=None):
    assert not skip_support or not rejected_challenge

    k = string_to_key(enctype, 'password', 'ATHENA.MIT.EDUraeburn')

    wprf = prfplus(k, 'SPAKEsecret' + pack('>I', gnum), wlen)
    w = ec.decode_int(wprf) % order

    if code_output:
        print '      /* initial key, w, x, y, T, S, K */'
    output('key: ', k.contents)
    output('w (PRF+ output): ', wprf)
    if not code_output:
        output('w (reduced multiplier): ', ec.encode_int(w))

    x = random.randrange(0, order) * cofactor
    y = random.randrange(0, order) * cofactor
    X = ec.mul(G, x)
    Y = ec.mul(G, y)
    T = ec.add(ec.mul(M, w), X)
    S = ec.add(ec.mul(N, w), Y)
    K = ec.mul(X, y)
    assert K == ec.mul(Y, x)
    assert K == ec.mul(ec.add(S, ec.neg(ec.mul(N, w))), x)
    assert K == ec.mul(ec.add(T, ec.neg(ec.mul(M, w))), y)

    output('x: ', ec.encode_int(x))
    output('y: ', ec.encode_int(y))
    if not code_output:
        output('X: ', ec.encode_point(X))
        output('Y: ', ec.encode_point(Y))
    output('T: ', ec.encode_point(T))
    output('S: ', ec.encode_point(S))
    output('K: ', ec.encode_point(K))

    if rejected_challenge and not code_output:
        output('Optimistic SPAKEChallenge: ', rejected_challenge)

    if code_output:
        print '      /* support, challenge, thash, body */'

    if not skip_support:
        support = make_support_encoding(gnum)
        output('SPAKESupport: ', support)
    else:
        support = ''
        if code_output:
            print '      NULL,'

    challenge = make_challenge_encoding(gnum, ec.encode_point(T))
    thash = '\0' * hashfn.digest_size
    thash = update_thash(hashfn, thash, support + challenge)
    output('SPAKEChallenge: ', challenge)
    if not code_output:
        output('Transcript hash after challenge: ', thash)

    thash = update_thash(hashfn, thash, ec.encode_point(S))
    output('Final transcript hash after pubkey: ', thash)

    body = make_body_encoding(enctype)
    output('KDC-REQ-BODY: ', body)

    Kbytes = ec.encode_point(K)
    K0 = derive_key(hashfn, gnum, k, wprf, Kbytes, thash, body, 0)
    K1 = derive_key(hashfn, gnum, k, wprf, Kbytes, thash, body, 1)
    K2 = derive_key(hashfn, gnum, k, wprf, Kbytes, thash, body, 2)
    K3 = derive_key(hashfn, gnum, k, wprf, Kbytes, thash, body, 3)

    if code_output:
        print "      /* K'[0], K'[1], K'[2], K'[3] */"
    output("K'[0]: ", K0.contents)
    output("K'[1]: ", K1.contents)
    output("K'[2]: ", K2.contents)
    output("K'[3]: ", K3.contents)


p256_M = p256.decode_point('02886E2F97ACE46E55BA9DD7242579F2993B64E16EF3DCAB'
                           '95AFD497333D8FA12F'.decode('hex'))
p256_N = p256.decode_point('03D8BBD6C639C62937B04D997F38C3770719C629D7014D49'
                           'A24B4F98BAA1292B49'.decode('hex'))

p384_M = p384.decode_point('030FF0895AE5EBF6187080A82D82B42E2765E3B2F8749C7E'
                           '05EBA366434B363D3DC36F15314739074D2EB8613FCEEC28'
                           '53'.decode('hex'))
p384_N = p384.decode_point('02C72CF2E390853A1C1C4AD816A62FD15824F56078918F43'
                           'F922CA21518F9C543BB252C5490214CF9AA3F0BAAB4B665C'
                           '10'.decode('hex'))

p521_M = p521.decode_point('02003F06F38131B2BA2600791E82488E8D20AB88'
                           '9AF753A41806C5DB18D37D85608CFAE06B82E4A7'
                           '2CD744C719193562A653EA1F119EEF9356907EDC'
                           '9B56979962D7AA'.decode('hex'))
p521_N = p521.decode_point('0200C7924B9EC017F3094562894336A53C50167B'
                           'A8C5963876880542BC669E494B2532D76C5B53DF'
                           'B349FDF69154B9E0048C58A42E8ED04CEF052A3B'
                           'C349D95575CD25'.decode('hex'))

# From the BoringSSL edwards25519 SPAKE code; comments there explain
# how these points were found.
ed25519_M = ed25519.decode_point('D048032C6EA0B6D697DDC2E86BDA85A33ADAC920'
                                 'F1BF18E1B0C6D166A5CECDAF'.decode('hex'))
ed25519_N = ed25519.decode_point('D3BFB518F44F3430F29D0C92AF503865A1ED3281'
                                 'DC69B35DD868BA85F886C4AB'.decode('hex'))

if len(sys.argv) > 1 and sys.argv[1] == 'code':
    code_output = True

random.seed(0)

print 'DES3 edwards25519'
vectors(Enctype.DES3,
        1, ed25519, ed25519_order, 8, 32, ed25519_G, ed25519_M, ed25519_N,
        SHA256)

print '\nRC4 edwards25519'
vectors(Enctype.RC4,
        1, ed25519, ed25519_order, 8, 32, ed25519_G, ed25519_M, ed25519_N,
        SHA256)

print '\nAES128 edwards25519'
vectors(Enctype.AES128,
        1, ed25519, ed25519_order, 8, 32, ed25519_G, ed25519_M, ed25519_N,
        SHA256)

print '\nAES256 edwards25519'
vectors(Enctype.AES256,
        1, ed25519, ed25519_order, 8, 32, ed25519_G, ed25519_M, ed25519_N,
        SHA256)

print '\nAES256 P-256'
vectors(Enctype.AES256,
        2, p256, p256_order, 1, 32, p256_G, p256_M, p256_N, SHA256)

print '\nAES256 P-384'
vectors(Enctype.AES256,
        3, p384, p384_order, 1, 48, p384_G, p384_M, p384_N, SHA384)

print '\nAES256 P-521'
vectors(Enctype.AES256,
        4, p521, p521_order, 1, 66, p521_G, p521_M, p521_N, SHA512)

print '\nAES256 edwards25519 with accepted optimistic challenge'
vectors(Enctype.AES256,
        1, ed25519, ed25519_order, 8, 32, ed25519_G, ed25519_M, ed25519_N,
        SHA256, skip_support=True)

print '\nAES256 P-521 with rejected optimistic edwards25519 challenge'
k = string_to_key(Enctype.AES256, 'password', 'ATHENA.MIT.EDUraeburn')
w = ed25519.decode_int(prfplus(k, 'SPAKEsecret\0\0\0\2', 32))
x = random.randrange(0, ed25519_order) * 8
T = ed25519.add(ed25519.mul(ed25519_M, w), ed25519.mul(ed25519_G, x))
ch = make_challenge_encoding(2, ed25519.encode_point(T))
vectors(Enctype.AES256,
        4, p521, p521_order, 1, 66, p521_G, p521_M, p521_N, SHA512,
        rejected_challenge=ch)
