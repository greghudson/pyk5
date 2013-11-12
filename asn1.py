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

from pyasn1.type import char, univ, useful
from pyasn1.type.namedtype import NamedType, NamedTypes, OptionalNamedType
from pyasn1.type.tag import Tag, tagClassContext, tagClassApplication
from pyasn1.type.tag import tagFormatSimple, tagFormatConstructed

# Return an explicit constructed application tag with the specified value.
def _apptag(tagnum):
    return univ.Sequence.tagSet.tagExplicitly(
        Tag(tagClassApplication, tagFormatConstructed, int(tagnum)))


# Return a context-tagged mandatory sequence field.
def _mfield(name, tagnum, type):
    return NamedType(name, type.subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, tagnum)))


# Return a context-tagged optional sequence field.
def _ofield(name, tagnum, type):
    return OptionalNamedType(name, type.subtype(
            explicitTag=Tag(tagClassContext, tagFormatSimple, tagnum)))


class PrincipalName(univ.Sequence):
    componentType = NamedTypes(
        _mfield('name-type', 0, univ.Integer()),
        _mfield('name-string', 1,
                univ.SequenceOf(componentType=char.GeneralString())))


class HostAddress(univ.Sequence):
    componentType = NamedTypes(
        _mfield('addr-type', 0, univ.Integer()),
        _mfield('address', 1, univ.OctetString()))


class HostAddresses(univ.SequenceOf):
    componentType = HostAddress()


class AuthorizationData(univ.SequenceOf):
    componentType = univ.Sequence(componentType=NamedTypes(
            _mfield('ad-type', 0, univ.Integer()),
            _mfield('ad-data', 1, useful.GeneralizedTime())))


class PAData(univ.Sequence):
    componentType = NamedTypes(
        _mfield('padata-type', 1, univ.Integer()),
        _mfield('padata-value', 2, univ.OctetString()))


class EncryptedData(univ.Sequence):
    componentType = NamedTypes(
        _mfield('etype', 0, univ.Integer()),
        _ofield('kvno', 1, univ.Integer()),
        _mfield('cipher', 2, univ.OctetString()))


class EncryptionKey(univ.Sequence):
    componentType = NamedTypes(
        _mfield('keytype', 0, univ.Integer()),
        _mfield('keyvalue', 1, univ.OctetString()))


class Checksum(univ.Sequence):
    componentType = NamedTypes(
        _mfield('cksumtype', 0, univ.Integer()),
        _mfield('checksum', 1, univ.OctetString()))


class Ticket(univ.Sequence):
    tagSet = _apptag(1)
    componentType = NamedTypes(
        _mfield('tkt-vno', 0, univ.Integer()),
        _mfield('realm', 1, char.GeneralString()),
        _mfield('sname', 2, PrincipalName()),
        _mfield('enc-part', 3, EncryptedData()))


class KDCReqBody(univ.Sequence):
    componentType = NamedTypes(
        _mfield('kdc-options', 0, univ.BitString()),
        _ofield('cname', 1, PrincipalName()),
        _mfield('realm', 2, char.GeneralString()),
        _ofield('sname', 3, PrincipalName()),
        _ofield('from', 4, useful.GeneralizedTime()),
        _mfield('till', 5, useful.GeneralizedTime()),
        _ofield('rtime', 6, useful.GeneralizedTime()),
        _mfield('nonce', 7, univ.Integer()),
        _mfield('etype', 8, univ.SequenceOf(componentType=univ.Integer())),
        _ofield('addresses', 9, HostAddresses()),
        _ofield('enc-authorization-data', 10, EncryptedData()),
        _ofield('additional-tickets', 11,
                univ.SequenceOf(componentType=Ticket())))


class KDCReq(univ.Sequence):
    componentType = NamedTypes(
        _mfield('pvno', 1, univ.Integer()),
        _mfield('msg-type', 2, univ.Integer()),
        _ofield('padata', 3, univ.SequenceOf(componentType=PAData())),
        _mfield('req-body', 4, KDCReqBody()))


class ASReq(KDCReq):
    tagSet = _apptag(10)


class TGSReq(KDCReq):
    tagSet = _apptag(12)


class KDCRep(univ.Sequence):
    componentType = NamedTypes(
        _mfield('pvno', 0, univ.Integer()),
        _mfield('msg-type', 1, univ.Integer()),
        _ofield('padata', 2, univ.SequenceOf(componentType=PAData())),
        _mfield('crealm', 3, char.GeneralString()),
        _mfield('cname', 4, PrincipalName()),
        _mfield('ticket', 5, Ticket()),
        _mfield('enc-part', 6, EncryptedData()))


class ASRep(KDCRep):
    tagSet = _apptag(11)


class TGSRep(KDCRep):
    tagSet = _apptag(13)


class LastReq(univ.SequenceOf):
    componentType = univ.Sequence(componentType=NamedTypes(
            _mfield('lr-type', 0, univ.Integer()),
            _mfield('lr-value', 1, useful.GeneralizedTime())))


class EncKDCRepPart(univ.Sequence):
    componentType = NamedTypes(
        _mfield('key', 0, EncryptionKey()),
        _mfield('last-req', 1, LastReq()),
        _mfield('nonce', 2, univ.Integer()),
        _ofield('key-expiration', 3, useful.GeneralizedTime()),
        _mfield('flags', 4, univ.BitString()),
        _mfield('authtime', 5, useful.GeneralizedTime()),
        _ofield('starttime', 6, useful.GeneralizedTime()),
        _mfield('endtime', 7, useful.GeneralizedTime()),
        _ofield('renew-till', 8, useful.GeneralizedTime()),
        _mfield('srealm', 9, char.GeneralString()),
        _mfield('sname', 10, PrincipalName()),
        _ofield('caddr', 11, HostAddresses()))


class EncASRepPart(EncKDCRepPart):
    tagSet = _apptag(25)


class EncTGSRepPart(EncKDCRepPart):
    tagSet = _apptag(26)


class Authenticator(univ.Sequence):
    tagSet = _apptag(2)
    componentType = NamedTypes(
        _mfield('authenticator-vno', 0, univ.Integer()),
        _mfield('crealm', 1, char.GeneralString()),
        _mfield('cname', 2, PrincipalName()),
        _ofield('cksum', 3, Checksum()),
        _mfield('cusec', 4, univ.Integer()),
        _mfield('ctime', 5, useful.GeneralizedTime()),
        _ofield('subkey', 6, EncryptionKey()),
        _ofield('seq-number', 7, univ.Integer()),
        _ofield('authorization-data', 8, AuthorizationData()))


class APReq(univ.Sequence):
    tagSet = _apptag(14)
    componentType = NamedTypes(
        _mfield('pvno', 0, univ.Integer()),
        _mfield('msg-type', 1, univ.Integer()),
        _mfield('ap-options', 2, univ.BitString()),
        _mfield('ticket', 3, Ticket()),
        _mfield('authenticator', 4, EncryptedData()))


class KrbError(univ.Sequence):
    tagSet = _apptag(30)
    componentType = NamedTypes(
        _mfield('pvno', 0, univ.Integer()),
        _mfield('msg-type', 1, univ.Integer()),
        _ofield('ctime', 2, useful.GeneralizedTime()),
        _ofield('cusec', 3, univ.Integer()),
        _mfield('stime', 4, useful.GeneralizedTime()),
        _mfield('susec', 5, univ.Integer()),
        _mfield('error-code', 6, univ.Integer()),
        _ofield('crealm', 7, char.GeneralString()),
        _ofield('cname', 8, PrincipalName()),
        _mfield('realm', 9, char.GeneralString()),
        _mfield('sname', 10, PrincipalName()),
        _ofield('e-text', 11, char.GeneralString()),
        _ofield('e-data', 12, univ.OctetString()))


class MethodData(univ.SequenceOf):
    componentType = PAData()


class PAEncTSEnc(univ.Sequence):
    componentType = NamedTypes(
        _mfield('patimestamp', 0, useful.GeneralizedTime()),
        _ofield('pausec', 1, univ.Integer()))


class ETypeInfoEntry(univ.Sequence):
    componentType = NamedTypes(
        _mfield('etype', 0, univ.Integer()),
        _ofield('salt', 1, univ.OctetString()))


class ETypeInfo(univ.SequenceOf):
    componentType = ETypeInfoEntry()


class ETypeInfo2Entry(univ.Sequence):
    componentType = NamedTypes(
        _mfield('etype', 0, univ.Integer()),
        _ofield('salt', 1, char.GeneralString()),
        _ofield('a2kparams', 2, univ.OctetString()))


class ETypeInfo2(univ.SequenceOf):
    componentType = ETypeInfo2Entry()
