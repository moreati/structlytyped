s = b'\x00\xffHello\x00\x00\x00\x00\x00'

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
result = FIDOAttestation.unpack(b'\xF1\xD0\x00\x00\x00\x00\x23\x01\x00'
                                b'\x00\x06pubkey'
                                b'\x00\x09keyhandle'
                                b'\x00\x0eclientdatahash')
print '\t', type(result), hex(result[0]), result.pubkey


import netstruct # Apache, big-endian by default
result = netstruct.unpack('H B L H H$ H$ H$',
                          b'\xF1\xD0\x00\x00\x00\x00\x23\x01\x00'
                          b'\x00\x06pubkey'
                          b'\x00\x09keyhandle'
                          b'\x00\x0eclientdatahash')
print 'netstruct'
print '\t', result