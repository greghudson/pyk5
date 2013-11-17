# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.

# XXX current status:
# * Done and tested
#   - AES encryption, checksum, string2key, prf
#   - cf2 (needed for FAST)
# * Still to do:
#   - RC4, DES enctypes and cksumtypes
#   - Unkeyed checksums
#   - Special RC4, raw DES/DES3 operations for GSSAPI
# * Difficult or low priority:
#   - Camellia not supported by PyCrypto
#   - Cipher state only needed for kcmd suite
#   - Nonstandard enctypes and cksumtypes like des-hmac-sha1

from fractions import gcd
from struct import pack, unpack
from Crypto.Cipher import AES, DES3
from Crypto.Hash import HMAC, SHA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


class Enctype(object):
    DES_CBC_CRC = 1
    DES_CBC_MD4 = 2
    DES_CBC_MD5 = 3
    DES3_CBC = 16
    AES128_CTS = 17
    AES256_CTS = 18
    RC4_HMAC = 23


class Cksumtype(object):
    CRC32 = 1
    MD4 = 2
    MD4_DES = 3
    MD5 = 7
    MD5_DES = 8
    SHA1 = 9
    SHA1_DES3 = 12
    SHA1_AES128 = 15
    SHA1_AES256 = 16
    HMAC_MD5 = -138


def _zeropad(s, padsize):
    # Return s padded with 0 bytes to a multiple of padsize.
    padlen = (padsize - (len(s) % padsize)) % padsize
    return s + '\0'*padlen


def _xorbytes(b1, b2):
    # xor two strings together and return the resulting string.
    assert len(b1) == len(b2)
    return ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(b1, b2))


def _mac_equal(mac1, mac2):
    # Constant-time comparison function.  (We can't use HMAC.verify
    # since we use truncated macs.)
    assert len(mac1) == len(mac2)
    res = 0
    for x, y in zip(mac1, mac2):
        res |= ord(x) ^ ord(y)
    return res == 0


def _nfold(str, nbytes):
    # Convert str to a string of length nbytes using the RFC 3961 nfold
    # operation.

    # Rotate the bytes in str to the right by nbits bits.
    def rotate_right(str, nbits):
        nbytes, remain = (nbits//8) % len(str), nbits % 8
        return ''.join(chr((ord(str[i-nbytes]) >> remain) |
                           ((ord(str[i-nbytes-1]) << (8-remain)) & 0xff))
                       for i in xrange(len(str)))

    # Add equal-length strings together with end-around carry.
    def add_ones_complement(str1, str2):
        n = len(str1)
        v = [ord(a) + ord(b) for a, b in zip(str1, str2)]
        # Propagate carry bits to the left until there aren't any left.
        while any(x & ~0xff for x in v):
            v = [(v[i-n+1]>>8) + (v[i]&0xff) for i in xrange(n)]
        return ''.join(chr(x) for x in v)

    # Concatenate copies of str to produce the least common multiple
    # of len(str) and nbytes, rotating each copy of str to the right
    # by 13 bits times its list position.  Decompose the concatenation
    # into slices of length nbytes, and add them together as
    # big-endian ones' complement integers.
    slen = len(str)
    lcm = nbytes * slen / gcd(nbytes, slen)
    bigstr = ''.join((rotate_right(str, 13 * i) for i in xrange(lcm / slen)))
    slices = (bigstr[p:p+nbytes] for p in xrange(0, lcm, nbytes))
    return reduce(add_ones_complement, slices)


def _is_weak_des_key(keybytes):
    return keybytes in ('\x01\x01\x01\x01\x01\x01\x01\x01',
                        '\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE',
                        '\x1F\x1F\x1F\x1F\x0E\x0E\x0E\x0E',
                        '\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1',
                        '\x01\xFE\x01\xFE\x01\xFE\x01\xFE',
                        '\xFE\x01\xFE\x01\xFE\x01\xFE\x01',
                        '\x1F\xE0\x1F\xE0\x0E\xF1\x0E\xF1',
                        '\xE0\x1F\xE0\x1F\xF1\x0E\xF1\x0E',
                        '\x01\xE0\x01\xE0\x01\xF1\x01\xF1',
                        '\xE0\x01\xE0\x01\xF1\x01\xF1\x01',
                        '\x1F\xFE\x1F\xFE\x0E\xFE\x0E\xFE',
                        '\xFE\x1F\xFE\x1F\xFE\x0E\xFE\x0E',
                        '\x01\x1F\x01\x1F\x01\x0E\x01\x0E',
                        '\x1F\x01\x1F\x01\x0E\x01\x0E\x01',
                        '\xE0\xFE\xE0\xFE\xF1\xFE\xF1\xFE',
                        '\xFE\xE0\xFE\xE0\xFE\xF1\xFE\xF1')


class _EnctypeProfile(object):
    # Base class for enctype profiles.  Usable enctype classes must define:
    #   * enctype: enctype number
    #   * keysize: protocol size of key in bytes
    #   * seedsize: random_to_key input size in bytes
    #   * random_to_key (if the keyspace is not dense)
    #   * string_to_key
    #   * encrypt
    #   * decrypt
    #   * prf

    @classmethod
    def random_to_key(cls, seed):
        if len(seed) != cls.seedsize:
            raise ValueError('Wrong seed length')
        return Key(cls.enctype, seed)


class _SimplifiedEnctype(_EnctypeProfile):
    # Base class for enctypes using the RFC 3961 simplified profile.
    # Defines the encrypt, decrypt, and prf methods.  Subclasses must
    # define:
    #   * blocksize: Underlying cipher block size in bytes
    #   * padsize: Underlying cipher padding multiple (1 or blocksize)
    #   * macsize: Size of integrity MAC in bytes
    #   * hashmod: PyCrypto hash module for underlying hash function
    #   * basic_encrypt, basic_decrypt: Underlying CBC/CTS cipher

    @classmethod
    def derive(cls, key, constant):
        # RFC 3961 only says to n-fold the constant only if it is
        # shorter than the cipher block size.  But all Unix
        # implementations n-fold constants if their length is larger
        # than the block size as well, and n-folding when the length
        # is equal to the block size is a no-op.
        plaintext = _nfold(constant, cls.blocksize)
        rndseed = ''
        while len(rndseed) < cls.seedsize:
            ciphertext = cls.basic_encrypt(key, plaintext)
            rndseed += ciphertext
            plaintext = ciphertext
        return cls.random_to_key(rndseed[0:cls.seedsize])

    @classmethod
    def encrypt(cls, key, keyusage, plaintext, confounder):
        ki = cls.derive(key, pack('>IB', keyusage, 0x55))
        ke = cls.derive(key, pack('>IB', keyusage, 0xAA))
        if confounder is None:
            confounder = get_random_bytes(cls.blocksize)
        basic_plaintext = confounder + _zeropad(plaintext, cls.padsize)
        hmac = HMAC.new(ki.contents, basic_plaintext, cls.hashmod).digest()
        return cls.basic_encrypt(ke, basic_plaintext) + hmac[:cls.macsize]

    @classmethod
    def decrypt(cls, key, keyusage, ciphertext):
        ki = cls.derive(key, pack('>IB', keyusage, 0x55))
        ke = cls.derive(key, pack('>IB', keyusage, 0xAA))
        if len(ciphertext) < cls.blocksize + cls.macsize:
            raise ValueError('ciphertext too short')
        basic_ctext, mac = ciphertext[:-cls.macsize], ciphertext[-cls.macsize:]
        if len(basic_ctext) % cls.padsize != 0:
            raise ValueError('ciphertext does not meet padding requirement')
        basic_plaintext = cls.basic_decrypt(ke, basic_ctext)
        hmac = HMAC.new(ki.contents, basic_plaintext, cls.hashmod).digest()
        expmac = hmac[:cls.macsize]
        if not _mac_equal(mac, expmac):
            raise ValueError('ciphertext integrity failure')
        # Discard the confounder.
        return basic_plaintext[cls.blocksize:]

    @classmethod
    def prf(cls, key, string):
        # Hash the input.  RFC 3961 says to truncate to the padding
        # size, but implementations truncate to the block size.
        hashval = cls.hashmod.new(string).digest()
        truncated = hashval[:-(len(hashval) % cls.blocksize)]
        # Encrypt the hash with a derived key.
        kp = cls.derive(key, 'prf')
        return cls.basic_encrypt(kp, truncated)


class _DES3CBC(_SimplifiedEnctype):
    enctype = Enctype.DES3_CBC
    keysize = 24
    seedsize = 21
    blocksize = 8
    padsize = 8
    macsize = 20
    hashmod = SHA

    @classmethod
    def random_to_key(cls, seed):
        # XXX Maybe reframe as _DESEnctype.random_to_key and use that
        # way from DES3 random-to-key when DES is implemented, since
        # MIT does this instead of the RFC 3961 random-to-key.
        def expand(seed):
            def parity(b):
                # Return b with the low-order bit set to yield odd parity.
                b &= ~1
                return b if bin(b & ~1).count('1') % 2 else b | 1
            assert len(seed) == 7
            firstbytes = [parity(ord(b) & ~1) for b in seed]
            lastbyte = parity(sum((ord(seed[i])&1) << i+1 for i in xrange(7)))
            keybytes = ''.join(chr(b) for b in firstbytes + [lastbyte])
            if _is_weak_des_key(keybytes):
                keybytes[7] = chr(ord(keybytes[7]) ^ 0xF0)
            return keybytes
        
        if len(seed) != 21:
            raise ValueError('Wrong seed length')
        k1, k2, k3 = expand(seed[:7]), expand(seed[7:14]), expand(seed[14:])
        return Key(cls.enctype, k1 + k2 + k3)

    @classmethod
    def string_to_key(cls, string, salt, params):
        if params is not None and params != '':
            raise ValueError('Invalid DES3 string-to-key parameters')
        k = cls.random_to_key(_nfold(string + salt, 21))
        return cls.derive(k, 'kerberos')

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        assert len(plaintext) % 8 == 0
        des3 = DES3.new(key.contents, AES.MODE_CBC, '\0' * 8)
        return des3.encrypt(plaintext)

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        assert len(ciphertext) % 8 == 0
        des3 = DES3.new(key.contents, AES.MODE_CBC, '\0' * 8)
        return des3.decrypt(ciphertext)


class _AESEnctype(_SimplifiedEnctype):
    # Base class for aes128-cts and aes256-cts.
    blocksize = 16
    padsize = 1
    macsize = 12
    hashmod = SHA

    @classmethod
    def string_to_key(cls, string, salt, params):
        (iterations,) = unpack('>L', params or '\x00\x00\x10\x00')
        prf = lambda p, s: HMAC.new(p, s, SHA).digest()
        seed = PBKDF2(string, salt, cls.seedsize, iterations, prf)
        tkey = cls.random_to_key(seed)
        return cls.derive(tkey, 'kerberos')

    @classmethod
    def basic_encrypt(cls, key, plaintext):
        assert len(plaintext) >= 16
        aes = AES.new(key.contents, AES.MODE_CBC, '\0' * 16)
        ctext = aes.encrypt(_zeropad(plaintext, 16))
        if len(plaintext) > 16:
            # Swap the last two ciphertext blocks and truncate the
            # final block to match the plaintext length.
            lastlen = len(plaintext) % 16 or 16
            ctext = ctext[:-32] + ctext[-16:] + ctext[-32:-16][:lastlen]
        return ctext

    @classmethod
    def basic_decrypt(cls, key, ciphertext):
        assert len(ciphertext) >= 16
        aes = AES.new(key.contents, AES.MODE_ECB)
        if len(ciphertext) == 16:
            return aes.decrypt(ciphertext)
        # Split the ciphertext into blocks.  The last block may be partial.
        cblocks = [ciphertext[p:p+16] for p in xrange(0, len(ciphertext), 16)]
        lastlen = len(cblocks[-1])
        # CBC-decrypt all but the last two blocks.
        prev_cblock = '\0' * 16
        plaintext = ''
        for b in cblocks[:-2]:
            plaintext += _xorbytes(aes.decrypt(b), prev_cblock)
            prev_cblock = b
        # Decrypt the second-to-last cipher block.  The left side of
        # the decrypted block will be the final block of plaintext
        # xor'd with the final partial cipher block; the right side
        # will be the omitted bytes of ciphertext from the final
        # block.
        b = aes.decrypt(cblocks[-2])
        lastplaintext =_xorbytes(b[:lastlen], cblocks[-1])
        omitted = b[lastlen:]
        # Decrypt the final cipher block plus the omitted bytes to get
        # the second-to-last plaintext block.
        plaintext += _xorbytes(aes.decrypt(cblocks[-1] + omitted), prev_cblock)
        return plaintext + lastplaintext


class _AES128CTS(_AESEnctype):
    enctype = Enctype.AES128_CTS
    keysize = 16
    seedsize = 16


class _AES256CTS(_AESEnctype):
    enctype = Enctype.AES256_CTS
    keysize = 32
    seedsize = 32


class _ChecksumProfile(object):
    # Base class for checksum profiles.  Usable checksum classes must
    # define:
    #   * checksum
    #   * verify
    pass


class _SimplifiedChecksum(_ChecksumProfile):
    # Base class for checksums using the RFC 3961 simplified profile.
    # Defines the checksum and verify methods.  Subclasses must
    # define:
    #   * macsize: Size of checksum in bytes
    #   * enc: Profile of associated enctype

    @classmethod
    def checksum(cls, key, keyusage, text):
        if key.enctype != cls.enc.enctype:
            raise ValueError('Wrong key type for checksum')
        kc = cls.enc.derive(key, pack('>IB', keyusage, 0x99))
        hmac = HMAC.new(kc.contents, text, cls.enc.hashmod).digest()
        return hmac[:cls.macsize]

    @classmethod
    def verify(cls, key, keyusage, text, cksum):
        expected = cls.checksum(key, keyusage, text)
        if not _mac_equal(cksum, expected):
            raise ValueError('checksum verification failure')


class _SHA1AES128(_SimplifiedChecksum):
    macsize = 12
    enc = _AES128CTS


class _SHA1AES256(_SimplifiedChecksum):
    macsize = 12
    enc = _AES256CTS


class _SHA1DES3(_SimplifiedChecksum):
    macsize = 20
    enc = _DES3CBC


_enctype_table = {
    Enctype.DES3_CBC: _DES3CBC,
    Enctype.AES128_CTS: _AES128CTS,
    Enctype.AES256_CTS: _AES256CTS
}


_checksum_table = {
    Cksumtype.SHA1_DES3: _SHA1DES3,
    Cksumtype.SHA1_AES128: _SHA1AES128,
    Cksumtype.SHA1_AES256: _SHA1AES256
}


def _get_enctype_profile(enctype):
    if enctype not in _enctype_table:
        raise ValueError('Invalid enctype %d' % enctype)
    return _enctype_table[enctype]


def _get_checksum_profile(cksumtype):
    if cksumtype not in _checksum_table:
        raise ValueError('Invalid cksumtype %d' % cksumtype)
    return _checksum_table[cksumtype]


class Key(object):
    def __init__(self, enctype, contents):
        e = _get_enctype_profile(enctype)
        if len(contents) != e.keysize:
            raise ValueError('Wrong key length')
        self.enctype = enctype
        self.contents = contents


def random_to_key(enctype, seed):
    e = _get_enctype_profile(enctype)
    if len(seed) != e.seedsize:
        raise ValueError('Wrong crypto seed length')
    return e.random_to_key(seed)


def string_to_key(enctype, string, salt, params=None):
    e = _get_enctype_profile(enctype)
    return e.string_to_key(string, salt, params)


def encrypt(key, keyusage, plaintext, confounder=None):
    e = _get_enctype_profile(key.enctype)
    return e.encrypt(key, keyusage, plaintext, confounder)


def decrypt(key, keyusage, ciphertext):
    e = _get_enctype_profile(key.enctype)
    return e.decrypt(key, keyusage, ciphertext)


def prf(key, string):
    e = _get_enctype_profile(key.enctype)
    return e.prf(key, string)


def make_checksum(cksumtype, key, keyusage, text):
    c = _get_checksum_profile(cksumtype)
    return c.checksum(key, keyusage, text)


def verify_checksum(cksumtype, key, keyusage, text, cksum):
    c = _get_checksum_profile(cksumtype)
    return c.verify(key, keyusage, text, cksum)


def cf2(enctype, key1, key2, pepper1, pepper2):
    # Combine two keys and two pepper strings to produce a result key
    # of type enctype, using the RFC 6113 KRB-FX-CF2 function.
    def prfplus(key, pepper, l):
        # Produce l bytes of output using the RFC 6113 PRF+ function.
        out = ''
        count = 1
        while len(out) < l:
            out += prf(key, chr(count) + pepper)
            count += 1
        return out[:l]

    e = _get_enctype_profile(enctype)
    return e.random_to_key(_xorbytes(prfplus(key1, pepper1, e.seedsize),
                                     prfplus(key2, pepper2, e.seedsize)))


#####
# XXX remove these tests later.

def printhex(s):
    print ''.join('{0:02X}'.format(ord(c)) for c in s)

#print 'encrypt AES128'
#k=Key(17, '\x90\x62\x43\x0C\x8C\xDA\x33\x88\x92\x2E\x6D\x6A\x50\x9F\x5B\x7A')
#c=encrypt(k, 2, '9 bytesss',
#          '\x94\xB4\x91\xF4\x81\x48\x5B\x9A\x06\x78\xCD\x3C\x4E\xA3\x86\xAD')
#printhex(c)

#print 'decrypt AES128'
#k=Key(17, '\x90\x62\x43\x0C\x8C\xDA\x33\x88\x92\x2E\x6D\x6A\x50\x9F\x5B\x7A')
#p=decrypt(k, 2,
#          '\x68\xFB\x96\x79\x60\x1F\x45\xC7\x88\x57\xB2\xBF\x82\x0F\xD6\xE5'
#          '\x3E\xCA\x8D\x42\xFD\x4B\x1D\x70\x24\xA0\x92\x05\xAB\xB7\xCD\x2E'
#          '\xC2\x6C\x35\x5D\x2F')
#print p

#print 'encrypt AES256'
#k=Key(18,
#      '\xF1\xC7\x95\xE9\x24\x8A\x09\x33\x8D\x82\xC3\xF8\xD5\xB5\x67\x04'
#      '\x0B\x01\x10\x73\x68\x45\x04\x13\x47\x23\x5B\x14\x04\x23\x13\x98')
#c=encrypt(k, 4, '30 bytes bytes bytes bytes byt',
#          '\xE4\x5C\xA5\x18\xB4\x2E\x26\x6A\xD9\x8E\x16\x5E\x70\x6F\xFB\x60')
#printhex(c)

#print 'decrypt AES256'
#k=Key(18,
#      '\xF1\xC7\x95\xE9\x24\x8A\x09\x33\x8D\x82\xC3\xF8\xD5\xB5\x67\x04'
#      '\x0B\x01\x10\x73\x68\x45\x04\x13\x47\x23\x5B\x14\x04\x23\x13\x98')
#p=decrypt(k, 4,
#          '\xD1\x13\x7A\x4D\x63\x4C\xFE\xCE\x92\x4D\xBC\x3B\xF6\x79\x06\x48'
#          '\xBD\x5C\xFF\x7D\xE0\xE7\xB9\x94\x60\x21\x1D\x0D\xAE\xF3\xD7\x9A'
#          '\x29\x5C\x68\x88\x58\xF3\xB3\x4B\x9C\xBD\x6E\xEB\xAE\x81\xDA\xF6'
#          '\xB7\x34\xD4\xD4\x98\xB6\x71\x4F\x1C\x1D')
#print p

#print 'checksum SHA1AES128'
#k=Key(17, '\x90\x62\x43\x0C\x8C\xDA\x33\x88\x92\x2E\x6D\x6A\x50\x9F\x5B\x7A')
#verify_checksum(15, k, 3, 'eight nine ten eleven twelve thirteen',
#                '\x01\xA4\xB0\x88\xD4\x56\x28\xF6\x94\x66\x14\xE3')

#print 'checksum SHA1AES256'
#k=Key(18,
#      '\xB1\xAE\x4C\xD8\x46\x2A\xFF\x16\x77\x05\x3C\xC9\x27\x9A\xAC\x30'
#      '\xB7\x96\xFB\x81\xCE\x21\x47\x4D\xD3\xDD\xBC\xFE\xA4\xEC\x76\xD7')
#verify_checksum(16, k, 4, 'fourteen',
#                '\xE0\x87\x39\xE3\x27\x9E\x29\x03\xEC\x8E\x38\x36')

#print 's2k AES128'
#k=string_to_key(17, 'password', 'ATHENA.MIT.EDUraeburn', '\0\0\0\2')
#printhex(k.contents)
## C651BF29E2300AC27FA469D693BDDA13

#print 's2k AES256'
#k=string_to_key(18, 'X'*64, 'pass phrase equals block size', '\0\0\x04\xB0')
#printhex(k.contents)
## 89ADEE3608DB8BC71F1BFBFE459486B0
## 5618B70CBAE22092534E56C553BA4B34

#print 'prf AES128'
#k=string_to_key(17, 'key1', 'key1')
#printhex(prf(k, '\x01\x61'))
## 77B39A37A868920F2A51F9DD150C5717

#print 'prf AES256'
#k=string_to_key(18, 'key2', 'key2')
#printhex(prf(k, '\x02\x62'))
## 0D674DD0F9A6806525A4D92E828BD15A

#print 'cf2 AES128'
#k1=string_to_key(17, 'key1', 'key1')
#k2=string_to_key(17, 'key2', 'key2')
#k=cf2(17, k1, k2, 'a', 'b')
#printhex(k.contents)
## 97DF97E4B798B29EB31ED7280287A92A

#print 'cf2 AES256'
#k1=string_to_key(18, 'key1', 'key1')
#k2=string_to_key(18, 'key2', 'key2')
#k=cf2(18, k1, k2, 'a', 'b')
#printhex(k.contents)
## 4D6CA4E629785C1F01BAF55E2E548566B9617AE3A96868C337CB93B5E72B1C7B

# print 's2k DES3'
#k = string_to_key(16, 'password', 'ATHENA.MIT.EDUraeburn')
#printhex(k.contents)
## 850BB51358548CD05E86768C313E3BFEF7511937DCF72C3E

#print 'encrypt AES128'
#k=Key(16,
#      '\x0D\xD5\x20\x94\xE0\xF4\x1C\xEC\xCB\x5B\xE5\x10\xA7\x64\xB3\x51'
#      '\x76\xE3\x98\x13\x32\xF1\xE5\x98')
#c=encrypt(k, 3, '13 bytes byte', '\x94\x69\x0A\x17\xB2\xDA\x3C\x9B')
#printhex(c)

#print 'decrypt DES3'
#k=Key(16,
#      '\x0D\xD5\x20\x94\xE0\xF4\x1C\xEC\xCB\x5B\xE5\x10\xA7\x64\xB3\x51'
#      '\x76\xE3\x98\x13\x32\xF1\xE5\x98')
#p=decrypt(k, 3,
#          '\x83\x9A\x17\x08\x1E\xCB\xAF\xBC\xDC\x91\xB8\x8C\x69\x55\xDD\x3C'
#          '\x45\x14\x02\x3C\xF1\x77\xB7\x7B\xF0\xD0\x17\x7A\x16\xF7\x05\xE8'
#          '\x49\xCB\x77\x81\xD7\x6A\x31\x6B\x19\x3F\x8D\x30')
#print p

#print 'checksum SHA1DES3'
#k=Key(16,
#      '\x7A\x25\xDF\x89\x92\x29\x6D\xCE\xDA\x0E\x13\x5B\xC4\x04\x6E\x23'
#      '\x75\xB3\xC1\x4C\x98\xFB\xC1\x62')
#verify_checksum(12, k, 2, 'six seven',
#                '\x0E\xEF\xC9\xC3\xE0\x49\xAA\xBC\x1B\xA5'
#                '\xC4\x01\x67\x7D\x9A\xB6\x99\x08\x2B\xB4')

#print 'cf2 DES3'
#k1=string_to_key(16, 'key1', 'key1')
#k2=string_to_key(16, 'key2', 'key2')
#k=cf2(16, k1, k2, 'a', 'b')
#printhex(k.contents)
## E58F9EB643862C13AD38E529313462A7F73E62834FE54A01

