import random
from ecc import p256, p256_G, p256_order
from ecc import p521, p521_G, p521_order
from ecc import bytes_to_int, bytes_to_point, point_to_compressed
from crypto import Enctype, Cksumtype, seedsize, random_to_key, string_to_key
from crypto import make_checksum, prfplus
from asn1 import _mfield, _ofield, _K5Sequence
from asn1 import EncryptedData, KDCReqBody, NameType, PrincipalName
from pyasn1.type.univ import Integer, OctetString, SequenceOf, Choice
from pyasn1.type.namedtype import NamedTypes
from pyasn1.codec.der.encoder import encode as der_encode
from struct import pack

# XXX not assigned
KEY_USAGE_SPAKE_TRANSCRIPT = 998
KEY_USAGE_SPAKE_FACTOR = 999

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
    return b.encode('hex').upper()


def update_checksum(cksumtype, key, cksum, b):
    return make_checksum(cksumtype, key, KEY_USAGE_SPAKE_TRANSCRIPT, cksum + b)


def derive_key(k, Kbytes, cksum, body, n):
    s = 'SPAKEKey' + Kbytes + cksum + body + pack('>I', n)
    return random_to_key(k.enctype, prfplus(k, s, seedsize(k.enctype)))


def vectors(enctype, cksumtype, gnum, ec, order, wbytes, G, M, N,
            skip_support=False, rejected_challenge=None):
    assert not skip_support or not rejected_challenge

    k = string_to_key(enctype, 'password', 'ATHENA.MIT.EDUraeburn')

    wprf = prfplus(k, 'SPAKEsecret' + pack('>I', gnum), wbytes)
    if ec is p521:
        wprf = chr(ord(wprf[0]) & 1) + wprf[1:]
    w = bytes_to_int(wprf)

    print 'key: %s' % hex(k.contents)
    print 'w: %d' % w

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

    print 'x: %d' % x
    print 'y: %d' % y
    print 'X: %s' % hex(point_to_compressed(X, ec))
    print 'Y: %s' % hex(point_to_compressed(Y, ec))
    print 'T: %s' % hex(point_to_compressed(T, ec))
    print 'S: %s' % hex(point_to_compressed(S, ec))
    print 'K: %s' % hex(point_to_compressed(K, ec))

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

    challenge = make_challenge_encoding(gnum, point_to_compressed(T, ec))
    cksum = update_checksum(cksumtype, k, cksum, challenge)
    print 'SPAKEChallenge: %s' % hex(challenge)
    print 'Checksum after SPAKEChallenge: %s' % hex(cksum)

    cksum = update_checksum(cksumtype, k, cksum, point_to_compressed(S, ec))
    print 'Checksum after pubkey: %s' % hex(cksum)

    body = make_body_encoding(enctype)
    print 'KDC-REQ-BODY: %s' % hex(body)

    Kbytes = point_to_compressed(K, ec)
    K0 = derive_key(k, Kbytes, cksum, body, 0)
    K1 = derive_key(k, Kbytes, cksum, body, 1)
    K2 = derive_key(k, Kbytes, cksum, body, 2)
    K3 = derive_key(k, Kbytes, cksum, body, 3)

    print "K'[0]: %s" % hex(K0.contents)
    print "K'[1]: %s" % hex(K1.contents)
    print "K'[2]: %s" % hex(K2.contents)
    print "K'[3]: %s" % hex(K3.contents)


p256_M = bytes_to_point('02886E2F97ACE46E55BA9DD7242579F2993B64E16EF3DCAB'
                        '95AFD497333D8FA12F'.decode('hex'), p256)
p256_N = bytes_to_point('03D8BBD6C639C62937B04D997F38C3770719C629D7014D49'
                        'A24B4F98BAA1292B49'.decode('hex'), p256)

p521_M = bytes_to_point('02003F06F38131B2BA2600791E82488E8D20AB889AF753A4'
                        '1806C5DB18D37D85608CFAE06B82E4A72CD744C719193562'
                        'A653EA1F119EEF9356907EDC9B56979962D7AA'.decode('hex'),
                        p521)
p521_N = bytes_to_point('0200C7924B9EC017F3094562894336A53C50167BA8C59638'
                        '76880542BC669E494B2532D76C5B53DFB349FDF69154B9E0'
                        '048C58A42E8ED04CEF052A3BC349D95575CD25'.decode('hex'),
                        p521)

random.seed(0)

print 'DES3 P-256'
vectors(Enctype.DES3, Cksumtype.SHA1_DES3,
        1, p256, p256_order, 32, p256_G, p256_M, p256_N)

print '\nRC4 P-256'
vectors(Enctype.RC4, Cksumtype.HMAC_MD5,
        1, p256, p256_order, 32, p256_G, p256_M, p256_N)

print '\nAES128 P-256'
vectors(Enctype.AES128, Cksumtype.SHA1_AES128,
        1, p256, p256_order, 32, p256_G, p256_M, p256_N)

print '\nAES128 P-256'
vectors(Enctype.AES128, Cksumtype.SHA1_AES128,
        1, p256, p256_order, 32, p256_G, p256_M, p256_N)

print '\nAES256 P-256'
vectors(Enctype.AES256, Cksumtype.SHA1_AES256,
        1, p256, p256_order, 32, p256_G, p256_M, p256_N)

print '\nAES128 P-521'
vectors(Enctype.AES128, Cksumtype.SHA1_AES128,
        2, p521, p521_order, 66, p521_G, p521_M, p521_N)

print '\nAES128 P-256 skipped challenge'
vectors(Enctype.AES128, Cksumtype.SHA1_AES128,
        1, p256, p256_order, 32, p256_G, p256_M, p256_N, skip_support=True)

print '\nAES256 P-521 with rejected optimistic P-256 challenge'
k = string_to_key(Enctype.AES256, 'password', 'ATHENA.MIT.EDUraeburn')
w = bytes_to_int(prfplus(k, 'SPAKEsecret\0\0\0\2', 32))
x = random.randrange(0, p256_order)
T = p256.add(p256.mul(p256_M, w), p256.mul(p256_G, x))
ch = make_challenge_encoding(2, point_to_compressed(T, p256))
vectors(Enctype.AES256, Cksumtype.SHA1_AES256,
        2, p521, p521_order, 66, p521_G, p521_M, p521_N, rejected_challenge=ch)

