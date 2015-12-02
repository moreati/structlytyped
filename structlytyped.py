from cStringIO import StringIO

s = b'\x00\xffHello\x00\x00\x00\x00\x00'
a = (
    b'\xF1\xD0\x00\x00\x00\x00\x23\x01\x00'
    b'\x00\x06pubkey'
    b'\x00\x09keyhandle'
    b'\x00\x0eclientdatahash'
)

import struct
status, greeting = struct.unpack('> H 10s', s)
print 'struct', struct.unpack('>H10s', s)


import cstruct # MIT
class Example(cstruct.CStruct):
    __byte_order__ = cstruct.BIG_ENDIAN
    __struct__ = '''
        unsigned short  status;
        unsigned char   greeting[10];
    '''

example = Example()
example.unpack(s)
print 'cstruct'
print '\t', example
print '\t', example.status, example.greeting


import binstruct # GPL 3
@binstruct.big_endian
class Example(binstruct.StructTemplate):
    status =    binstruct.UInt16Field(0)
    greeting =  binstruct.StringField(2, 10)


example = Example(bytearray(s), start_offset=0)
print 'binstruct'
print '\t', example
print '\t', example.status, example.greeting


import bitstruct # MIT, appears to only support big-endian
print 'bitstruct'
print '\t', bitstruct.unpack('u16b80', bytearray(s))


import construct # MIT
PascalString = construct.Struct("PascalString",
    construct.UBInt8("length"),
    construct.Bytes("data", lambda ctx: ctx.length),
)
print 'construct'
print '\t', PascalString.parse("\x05helloXXX")
print '\t', PascalString.build(construct.Container(length=6, data="foobar"))

PascalString2 = construct.ExprAdapter(PascalString,
    encoder = lambda obj, ctx: construct.Container(length=len(obj), data=obj),
    decoder = lambda obj, ctx: obj.data,
)
print '\t', PascalString2.parse("\x05hello")
print '\t', PascalString2.build("i'm a long string")


#import destruct
#class Example(destruct.StructBase):
#    status =    destruct.fields.U16Field()
# destruct has not byte string field (that I can spot)


import vstruct.types
class Example(vstruct.types.VStruct):
    def __init__(self):
        vstruct.types.VStruct.__init__(self)
        self.status =   vstruct.types.uint16(endian='big')
        self.greeting = vstruct.types.vbytes(10)

example = Example()
example.vsParse(s)
print 'vstruct'
print '\t', example
print '\t', example.status, repr(example.greeting)


from estruct import estruct
example = estruct.EStruct('example', 'status greeting', '> H 10s')
result = example.unpack(s)
print 'estruct'
print '\t', result
print '\t', result.status, repr(result.greeting)

# Based on http://www.w3.org/Submission/2015/SUBM-fido-key-attestation-20151120/#attestation-rawdata-type-packed
# This is only a partial description - extension fields are not included
# TODO Can estruct return byte strings instead of a list of chars?
FIDOAttestation = estruct.EStruct(
    'FIDOAttestation',
    '''tag flags sign_count pubkey_encoding
       pubkey_len pubkey
       key_handle_len key_handle
       client_data_hash_len client_data_hash
       ''',
    '>HBLHH{pubkey_len}[s]H{key_handle_len}[c]H{client_data_hash_len}[c]',
)
result = FIDOAttestation.unpack(a)
print '\t', type(result), hex(result[0]), result.pubkey


import netstruct # Apache, big-endian by default
result = netstruct.unpack('H B L H H$ H$ H$', a)
print 'netstruct'
print '\t', result


from infi.instruct.buffer import (
    Buffer, be_uint_field, bytearray_field,
    after_ref, bytes_ref, len_ref, num_ref, self_ref,
)
class FIDOAttestation(Buffer):
    tag                 = be_uint_field(where=bytes_ref[0:2])
    flags               = be_uint_field(where=bytes_ref[2:3])
    sign_count          = be_uint_field(where=bytes_ref[3:7])
    pubkey_encoding     = be_uint_field(where=bytes_ref[7:9])

    pubkey_len          = be_uint_field(where=bytes_ref[9:11],
                                        set_before_pack=len_ref(self_ref.pubkey))
    pubkey              = bytearray_field(where=bytes_ref[after_ref(pubkey_len):after_ref(pubkey_len)+num_ref(pubkey_len)])

    key_handle_len      = be_uint_field(where=bytes_ref[after_ref(pubkey):after_ref(pubkey)+2],
                                        set_before_pack=len_ref(self_ref.key_handle))
    key_handle          = bytearray_field(where=bytes_ref[after_ref(key_handle_len):after_ref(key_handle_len)+num_ref(key_handle_len)])

    client_data_hash_len= be_uint_field(where=bytes_ref[after_ref(key_handle):after_ref(key_handle)+2],
                                        set_before_pack=len_ref(self_ref.client_data_hash))
    client_data_hash    = bytearray_field(where=bytes_ref[after_ref(client_data_hash_len):after_ref(client_data_hash_len)+num_ref(client_data_hash_len)])


example = FIDOAttestation()
print 'infi.instruct'
print '\t', example
print '\t', example.unpack(a)
print '\t', example


# MPL
from suitcase.fields import UBInt8, UBInt16, UBInt32, LengthField, Payload
from suitcase.structure import Structure

class FIDOAttestation(Structure):
    tag                 = UBInt16()
    flags               = UBInt8()
    sign_count          = UBInt32()
    pubkey_encoding     = UBInt16()
    pubkey_len          = LengthField(UBInt16())
    pubkey              = Payload(pubkey_len)
    key_handle_len      = LengthField(UBInt16())
    key_handle          = Payload(key_handle_len)
    client_data_hash_len= LengthField(UBInt16())
    client_data_hash    = Payload(client_data_hash_len)
example = FIDOAttestation()
example.unpack(a)
print 'suitcase'
print '\t', example


from chunker.chunks import Chunk
from chunker.fields import (
    UnsignedCharField, UnsignedShortField, UnsignedLongField, StringField,
)
from chunker.parsers import Parser
class FIDOAttestationChunk(Chunk):
    Fields = (
        UnsignedShortField  ('tag', big_endian=True),
        UnsignedCharField   ('flags', big_endian=True),
        UnsignedLongField   ('sign_count', big_endian=True),
        UnsignedShortField  ('pubkey_encoding', big_endian=True),
        UnsignedShortField  ('pubkey_len', big_endian=True),
        StringField         ('pubkey', length_field_name='pubkey_len'),
        UnsignedShortField  ('key_handle_len', big_endian=True),
        StringField         ('key_handle',
                             length_field_name='key_handle_len'),
        UnsignedShortField  ('client_data_hash_len', big_endian=True),
        StringField         ('client_data_hash',
                             length_field_name='client_data_hash_len'),
    )
class FIDOAttestationParser(Parser):
    ChunkClasses = (
        FIDOAttestationChunk,
    )
example = FIDOAttestationParser(StringIO(a), len(a))
#example.parse() Loops forever
#print 'chunker'
#print '\t', example.chunks
