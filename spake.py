import random
from ecc import p256, p256_G, p256_order
from ecc import p384, p384_G, p384_order
from ecc import p521, p521_G, p521_order
from ecc import ed25519, ed25519_G, ed25519_order
from crypto import Enctype, Cksumtype, seedsize, random_to_key, string_to_key
from crypto import make_checksum, prfplus
from asn1 import _mfield, _ofield, _K5Sequence
from asn1 import EncryptedData, KDCReqBody, NameType, PrincipalName
from pyasn1.type.univ import Integer, OctetString, SequenceOf, Choice
from pyasn1.type.namedtype import NamedTypes
from pyasn1.codec.der.encoder import encode as der_encode
from struct import pack

# XXX not assigned
KEY_USAGE_SPAKE_TRANSCRIPT = 65
KEY_USAGE_SPAKE_FACTOR = 66

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


def hex(b):
    return b.encode('hex')


def update_checksum(cksumtype, key, cksum, b):
    return make_checksum(cksumtype, key, KEY_USAGE_SPAKE_TRANSCRIPT, cksum + b)


def derive_key(k, gnum, Kbytes, cksum, body, n):
    s = ('SPAKEkey' + pack('>I', gnum) + pack('>I', k.enctype) + Kbytes +
         cksum + body + pack('>I', n))
    return random_to_key(k.enctype, prfplus(k, s, seedsize(k.enctype)))


def vectors(enctype, cksumtype, gnum, ec, order, wbytes, G, M, N,
            skip_support=False, rejected_challenge=None):
    assert not skip_support or not rejected_challenge

    k = string_to_key(enctype, 'password', 'ATHENA.MIT.EDUraeburn')

    wprf = prfplus(k, 'SPAKEsecret' + pack('>I', gnum), wbytes)
    w = ec.decode_int(wprf) % order

    print 'key: %s' % hex(k.contents)
    print 'w: %s' % hex(ec.encode_int(w))

    x = random.randrange(0, order)
    y = random.randrange(0, order)
    X = ec.mul(G, x)
    Y = ec.mul(G, y)
    T = ec.add(ec.mul(M, w), X)
    S = ec.add(ec.mul(N, w), Y)
    K = ec.mul(X, y)
    assert K == ec.mul(Y, x)
    assert K == ec.mul(ec.add(S, ec.neg(ec.mul(N, w))), x)
    assert K == ec.mul(ec.add(T, ec.neg(ec.mul(M, w))), y)

    print 'x: %s' % hex(ec.encode_int(x))
    print 'y: %s' % hex(ec.encode_int(y))
    print 'X: %s' % hex(ec.encode_point(X))
    print 'Y: %s' % hex(ec.encode_point(Y))
    print 'T: %s' % hex(ec.encode_point(T))
    print 'S: %s' % hex(ec.encode_point(S))
    print 'K: %s' % hex(ec.encode_point(K))

    cksumlen = len(make_checksum(cksumtype, k, 0, ''))
    cksum = '\0' * cksumlen

    if rejected_challenge:
        cksum = update_checksum(cksumtype, k, cksum, rejected_challenge)
        print 'Optimistic SPAKEChallenge: %s' % hex(rejected_challenge)
        print 'Checksum after optimist SPAKEChallenge: %s' % hex(cksum)

    if not skip_support:
        support = make_support_encoding(gnum)
        cksum = update_checksum(cksumtype, k, cksum, support)
        print 'SPAKESupport: %s' % hex(support)
        print 'Checksum after SPAKESupport: %s' % hex(cksum)

    challenge = make_challenge_encoding(gnum, ec.encode_point(T))
    cksum = update_checksum(cksumtype, k, cksum, challenge)
    print 'SPAKEChallenge: %s' % hex(challenge)
    print 'Checksum after SPAKEChallenge: %s' % hex(cksum)

    cksum = update_checksum(cksumtype, k, cksum, ec.encode_point(S))
    print 'Checksum after pubkey: %s' % hex(cksum)

    body = make_body_encoding(enctype)
    print 'KDC-REQ-BODY: %s' % hex(body)

    Kbytes = ec.encode_point(K)
    K0 = derive_key(k, gnum, Kbytes, cksum, body, 0)
    K1 = derive_key(k, gnum, Kbytes, cksum, body, 1)
    K2 = derive_key(k, gnum, Kbytes, cksum, body, 2)
    K3 = derive_key(k, gnum, Kbytes, cksum, body, 3)

    print "K'[0]: %s" % hex(K0.contents)
    print "K'[1]: %s" % hex(K1.contents)
    print "K'[2]: %s" % hex(K2.contents)
    print "K'[3]: %s" % hex(K3.contents)


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
ed25519_M = ed25519.decode_point('5ADA7E4BF6DDD9ADB6626D32131C6B5C51A1E347'
                                 'A3478F53CFCF441B88EED12E'.decode('hex'))
ed25519_N = ed25519.decode_point('10E3DF0AE37D8E7A99B5FE74B44672103DBDDCBD'
                                 '06AF680D71329A11693BC778'.decode('hex'))

random.seed(0)

print 'DES3 edwards25519'
vectors(Enctype.DES3, Cksumtype.SHA1_DES3,
        1, ed25519, ed25519_order, 32, ed25519_G, ed25519_M, ed25519_N)

print '\nRC4 edwards25519'
vectors(Enctype.RC4, Cksumtype.HMAC_MD5,
        1, ed25519, ed25519_order, 32, ed25519_G, ed25519_M, ed25519_N)

print '\nAES128 edwards25519'
vectors(Enctype.AES128, Cksumtype.SHA1_AES128,
        1, ed25519, ed25519_order, 32, ed25519_G, ed25519_M, ed25519_N)

print '\nAES256 edwards25519'
vectors(Enctype.AES256, Cksumtype.SHA1_AES256,
        1, ed25519, ed25519_order, 32, ed25519_G, ed25519_M, ed25519_N)

print '\nAES256 P-256'
vectors(Enctype.AES256, Cksumtype.SHA1_AES256,
        2, p256, p256_order, 32, p256_G, p256_M, p256_N)

print '\nAES256 P-384'
vectors(Enctype.AES256, Cksumtype.SHA1_AES256,
        3, p384, p384_order, 48, p384_G, p384_M, p384_N)

print '\nAES256 P-521'
vectors(Enctype.AES256, Cksumtype.SHA1_AES256,
        4, p521, p521_order, 66, p521_G, p521_M, p521_N)

print '\nAES256 edwards25519 with accepted optimistic challenge'
vectors(Enctype.AES256, Cksumtype.SHA1_AES256,
        1, ed25519, ed25519_order, 32, ed25519_G, ed25519_M, ed25519_N,
        skip_support=True)

print '\nAES256 P-521 with rejected optimistic edwards25519 challenge'
k = string_to_key(Enctype.AES256, 'password', 'ATHENA.MIT.EDUraeburn')
w = ed25519.decode_int(prfplus(k, 'SPAKEsecret\0\0\0\2', 32))
x = random.randrange(0, ed25519_order)
T = ed25519.add(ed25519.mul(ed25519_M, w), ed25519.mul(ed25519_G, x))
ch = make_challenge_encoding(2, ed25519.encode_point(T))
vectors(Enctype.AES256, Cksumtype.SHA1_AES256,
        4, p521, p521_order, 66, p521_G, p521_M, p521_N, rejected_challenge=ch)
