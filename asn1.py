# Copyright (c) 2013, Marc Horowitz
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Copyright (C) 2013 by the Massachusetts Institute of Technology.
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

# This module defines pyasn1 classes for Kerberos ASN.1 types.
# Because the goal of pyk5 is to be malleable, there are no
# constraints--we want to be able to encode messages with invalid pvno
# or msg-type fields, flag bitstrings shorter than 32 bits, etc..  For
# brevity, we do not define classes for simple type assignments like
# KerberosString and TicketFlags.

from pyasn1.type import base
from pyasn1.type.char import GeneralString
from pyasn1.type.univ import BitString, Integer, OctetString
from pyasn1.type.univ import Sequence, SequenceOf
from pyasn1.type.useful import GeneralizedTime
from pyasn1.type.namedtype import NamedType, NamedTypes, OptionalNamedType
from pyasn1.type.tag import Tag, tagClassContext, tagClassApplication
from pyasn1.type.tag import tagFormatSimple, tagFormatConstructed

# Return an explicit constructed application tag with the specified value.
def _apptag(tagnum):
    return Sequence.tagSet.tagExplicitly(
        Tag(tagClassApplication, tagFormatConstructed, int(tagnum)))


# Return a context-tagged mandatory sequence field.
def _mfield(name, tagnum, asn1type):
    return NamedType(name, asn1type.subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, tagnum)))


# Return a context-tagged optional sequence field.
def _ofield(name, tagnum, asn1type):
    return OptionalNamedType(name, asn1type.subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, tagnum)))


class _K5Sequence(Sequence):
    # pyasn1 sequence types do not normally allow nested objects to be
    # built from the bottom up; you get a type error when you try to
    # assign the untagged pyasn1 object to the tagged sequence field.
    # Normally nested sequences are built from the top down (that is,
    # seq['field'] = None, then seq['field']['subfield'] = value).
    # But we want to be able to pass around protocol units in
    # interfaces to make it easy to construct unusual requests and
    # responses, and we don't want to build a complete parallel
    # collection of plain Python types and translators.  So we work
    # around the pyasn1 limitation with an intermediate sequence type,
    # which puts the context tag on the value if it isn't already
    # present.
    #
    # Warning: we make a clone of the value in order to modify its tag
    # set, so changes to the value will not be reflected in the
    # containing sequence as they should.  Treat interior objects as
    # immutable once they are assigned to a containing sequence, at
    # least until you are done using the containing sequence.
    def setComponentByPosition(self, idx, value=None, verifyConstraints=True):
        if isinstance(value, base.Asn1Item):
            ftags = self._componentType.getTypeByPosition(idx).getTagSet()
            vtags = value.getTagSet()
            if (ftags[-1][0] == tagClassContext and
                (vtags == ftags[:-1] or vtags[:-1] == ftags[:-1])):
                # The value matches the field except for the context
                # tag (implicit or explicit).  Clone the value with
                # the field's tag set to make the assignment work.
                if isinstance(value, base.AbstractConstructedAsn1Item):
                    value = value.clone(tagSet=ftags, cloneValueFlag=True)
                else:
                    value = value.clone(tagSet=ftags)
        return Sequence.setComponentByPosition(self, idx, value,
                                               verifyConstraints)


class PrincipalName(_K5Sequence):
    componentType = NamedTypes(
        _mfield('name-type', 0, Integer()),
        _mfield('name-string', 1, SequenceOf(componentType=GeneralString())))


class HostAddress(_K5Sequence):
    componentType = NamedTypes(
        _mfield('addr-type', 0, Integer()),
        _mfield('address', 1, OctetString()))


class HostAddresses(SequenceOf):
    componentType = HostAddress()


class AuthorizationData(SequenceOf):
    componentType = Sequence(componentType=NamedTypes(
            _mfield('ad-type', 0, Integer()),
            _mfield('ad-data', 1, GeneralizedTime())))


class PAData(_K5Sequence):
    componentType = NamedTypes(
        _mfield('padata-type', 1, Integer()),
        _mfield('padata-value', 2, OctetString()))


class EncryptedData(_K5Sequence):
    componentType = NamedTypes(
        _mfield('etype', 0, Integer()),
        _ofield('kvno', 1, Integer()),
        _mfield('cipher', 2, OctetString()))


class EncryptionKey(_K5Sequence):
    componentType = NamedTypes(
        _mfield('keytype', 0, Integer()),
        _mfield('keyvalue', 1, OctetString()))


class Checksum(_K5Sequence):
    componentType = NamedTypes(
        _mfield('cksumtype', 0, Integer()),
        _mfield('checksum', 1, OctetString()))


class Ticket(_K5Sequence):
    tagSet = _apptag(1)
    componentType = NamedTypes(
        _mfield('tkt-vno', 0, Integer()),
        _mfield('realm', 1, GeneralString()),
        _mfield('sname', 2, PrincipalName()),
        _mfield('enc-part', 3, EncryptedData()))


class KDCReqBody(_K5Sequence):
    componentType = NamedTypes(
        _mfield('kdc-options', 0, BitString()),
        _ofield('cname', 1, PrincipalName()),
        _mfield('realm', 2, GeneralString()),
        _ofield('sname', 3, PrincipalName()),
        _ofield('from', 4, GeneralizedTime()),
        _mfield('till', 5, GeneralizedTime()),
        _ofield('rtime', 6, GeneralizedTime()),
        _mfield('nonce', 7, Integer()),
        _mfield('etype', 8, SequenceOf(componentType=Integer())),
        _ofield('addresses', 9, HostAddresses()),
        _ofield('enc-authorization-data', 10, EncryptedData()),
        _ofield('additional-tickets', 11, SequenceOf(componentType=Ticket())))


class KDCReq(_K5Sequence):
    componentType = NamedTypes(
        _mfield('pvno', 1, Integer()),
        _mfield('msg-type', 2, Integer()),
        _ofield('padata', 3, SequenceOf(componentType=PAData())),
        _mfield('req-body', 4, KDCReqBody()))


class ASReq(KDCReq):
    tagSet = _apptag(10)


class TGSReq(KDCReq):
    tagSet = _apptag(12)


class KDCRep(_K5Sequence):
    componentType = NamedTypes(
        _mfield('pvno', 0, Integer()),
        _mfield('msg-type', 1, Integer()),
        _ofield('padata', 2, SequenceOf(componentType=PAData())),
        _mfield('crealm', 3, GeneralString()),
        _mfield('cname', 4, PrincipalName()),
        _mfield('ticket', 5, Ticket()),
        _mfield('enc-part', 6, EncryptedData()))


class ASRep(KDCRep):
    tagSet = _apptag(11)


class TGSRep(KDCRep):
    tagSet = _apptag(13)


class LastReq(SequenceOf):
    componentType = Sequence(componentType=NamedTypes(
            _mfield('lr-type', 0, Integer()),
            _mfield('lr-value', 1, GeneralizedTime())))


class EncKDCRepPart(_K5Sequence):
    componentType = NamedTypes(
        _mfield('key', 0, EncryptionKey()),
        _mfield('last-req', 1, LastReq()),
        _mfield('nonce', 2, Integer()),
        _ofield('key-expiration', 3, GeneralizedTime()),
        _mfield('flags', 4, BitString()),
        _mfield('authtime', 5, GeneralizedTime()),
        _ofield('starttime', 6, GeneralizedTime()),
        _mfield('endtime', 7, GeneralizedTime()),
        _ofield('renew-till', 8, GeneralizedTime()),
        _mfield('srealm', 9, GeneralString()),
        _mfield('sname', 10, PrincipalName()),
        _ofield('caddr', 11, HostAddresses()))


class EncASRepPart(EncKDCRepPart):
    tagSet = _apptag(25)


class EncTGSRepPart(EncKDCRepPart):
    tagSet = _apptag(26)


class Authenticator(_K5Sequence):
    tagSet = _apptag(2)
    componentType = NamedTypes(
        _mfield('authenticator-vno', 0, Integer()),
        _mfield('crealm', 1, GeneralString()),
        _mfield('cname', 2, PrincipalName()),
        _ofield('cksum', 3, Checksum()),
        _mfield('cusec', 4, Integer()),
        _mfield('ctime', 5, GeneralizedTime()),
        _ofield('subkey', 6, EncryptionKey()),
        _ofield('seq-number', 7, Integer()),
        _ofield('authorization-data', 8, AuthorizationData()))


class APReq(_K5Sequence):
    tagSet = _apptag(14)
    componentType = NamedTypes(
        _mfield('pvno', 0, Integer()),
        _mfield('msg-type', 1, Integer()),
        _mfield('ap-options', 2, BitString()),
        _mfield('ticket', 3, Ticket()),
        _mfield('authenticator', 4, EncryptedData()))


class KrbError(_K5Sequence):
    tagSet = _apptag(30)
    componentType = NamedTypes(
        _mfield('pvno', 0, Integer()),
        _mfield('msg-type', 1, Integer()),
        _ofield('ctime', 2, GeneralizedTime()),
        _ofield('cusec', 3, Integer()),
        _mfield('stime', 4, GeneralizedTime()),
        _mfield('susec', 5, Integer()),
        _mfield('error-code', 6, Integer()),
        _ofield('crealm', 7, GeneralString()),
        _ofield('cname', 8, PrincipalName()),
        _mfield('realm', 9, GeneralString()),
        _mfield('sname', 10, PrincipalName()),
        _ofield('e-text', 11, GeneralString()),
        _ofield('e-data', 12, OctetString()))


class MethodData(SequenceOf):
    componentType = PAData()


class PAEncTSEnc(_K5Sequence):
    componentType = NamedTypes(
        _mfield('patimestamp', 0, GeneralizedTime()),
        _ofield('pausec', 1, Integer()))


class ETypeInfoEntry(_K5Sequence):
    componentType = NamedTypes(
        _mfield('etype', 0, Integer()),
        _ofield('salt', 1, OctetString()))


class ETypeInfo(SequenceOf):
    componentType = ETypeInfoEntry()


class ETypeInfo2Entry(_K5Sequence):
    componentType = NamedTypes(
        _mfield('etype', 0, Integer()),
        _ofield('salt', 1, GeneralString()),
        _ofield('a2kparams', 2, OctetString()))


class ETypeInfo2(SequenceOf):
    componentType = ETypeInfo2Entry()


class NameType(object):
    UNKNOWN = 0
    PRINCIPAL = 1
    SRV_INST = 2
    SRV_HOST = 3
    ENTERPRISE = 10
