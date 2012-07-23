# -*- Mode: Python -*-

# If you can't (or don't want to) use the ctypes ssl code, this drop-in
#   replacement uses the pure-python ecdsa package.  Note: it stores private keys
#   using an OID to indicate the curve, while openssl puts the curve parameters
#   in each key.  The ecdsa package doesn't understand that DER, though.  So if you
#   create a wallet using one version, you must continue to use that version.  In an
#   emergency you could write a converter.

#
# https://github.com/warner/python-ecdsa
# $ easy_install ecdsa
#

# curve parameters below were taken from: 
#  http://forum.bitcoin.org/index.php?topic=23241.msg292364#msg292364

# WORRY: are the random numbers from random.SystemRandom() good enough?

import ecdsa
import random
from ecdsa import der

# secp256k1
_p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b  = 0x0000000000000000000000000000000000000000000000000000000000000007L
_a  = 0x0000000000000000000000000000000000000000000000000000000000000000L
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L

curve_secp256k1 = ecdsa.ellipticcurve.CurveFp (_p, _a, _b)
generator_secp256k1 = g = ecdsa.ellipticcurve.Point (curve_secp256k1, _Gx, _Gy, _r)
randrange = random.SystemRandom().randrange
secp256k1 = ecdsa.curves.Curve (
    "secp256k1",
    curve_secp256k1,
    generator_secp256k1,
    (1, 3, 132, 0, 10)
    )
# add this to the list of official NIST curves.
ecdsa.curves.curves.append (secp256k1)

class KEY:

    def __init__ (self):
        self.prikey = None
        self.pubkey = None

    def generate (self, secret=None):
        if secret:
            exp = int ('0x' + secret.encode ('hex'), 16)
            self.prikey = ecdsa.SigningKey.from_secret_exponent (exp, curve=secp256k1)
        else:
            self.prikey = ecdsa.SigningKey.generate (curve=secp256k1)
        self.pubkey = self.prikey.get_verifying_key()
        return self.prikey.to_der()

    def set_privkey (self, key):
        if len(key) == 279:
            seq1, rest = der.remove_sequence (key)
            integer, rest = der.remove_integer (seq1)
            octet_str, rest = der.remove_octet_string (rest)
            tag1, cons1, rest, = der.remove_constructed (rest)
            tag2, cons2, rest, = der.remove_constructed (rest)
            point_str, rest = der.remove_bitstring (cons2)
            self.prikey = ecdsa.SigningKey.from_string (octet_str, curve=secp256k1)
        else:
            self.prikey = ecdsa.SigningKey.from_der (key)

    def set_pubkey (self, key):
        key = key[1:]
        self.pubkey = ecdsa.VerifyingKey.from_string (key, curve=secp256k1)

    def get_privkey (self):
        _p = self.prikey.curve.curve.p ()
        _r = self.prikey.curve.generator.order () # key.curve.order
        _Gx = self.prikey.curve.generator.x ()
        _Gy = self.prikey.curve.generator.y ()
        encoded_oid2 = der.encode_oid (*(1, 2, 840, 10045, 1, 1))
        encoded_gxgy = "\x04" + ("%64x" % _Gx).decode('hex') + ("%64x" % _Gy).decode('hex')
        param_sequence = der.encode_sequence (
            ecdsa.der.encode_integer(1),
                der.encode_sequence (
                encoded_oid2,
                der.encode_integer (_p),
            ),
            der.encode_sequence (
                der.encode_octet_string("\x00"),
                der.encode_octet_string("\x07"),
            ),
            der.encode_octet_string (encoded_gxgy),
            der.encode_integer (_r),
            der.encode_integer (1),
        );
        encoded_vk = "\x00\x04" + self.pubkey.to_string ()
        return der.encode_sequence (
            der.encode_integer (1),
            der.encode_octet_string (self.prikey.to_string ()),
            der.encode_constructed (0, param_sequence),
            der.encode_constructed (1, der.encode_bitstring (encoded_vk)),
        )

    def get_pubkey (self):
        return "\x04" + self.pubkey.to_string()

    def sign (self, hash):
        sig = self.prikey.sign_digest (hash, sigencode=ecdsa.util.sigencode_der)
        return sig.to_der()

    def verify (self, hash, sig):
        return self.pubkey.verify_digest (sig[:-1], hash, sigdecode=ecdsa.util.sigdecode_der)

if __name__ == '__main__':
    # ethalone keys
    ec_secret = '' + \
        'a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e'
    ec_private = '308201130201010420' + \
        'a0dc65ffca799873cbea0ac274015b9526505daaaed385155425f7337704883e' + \
        'a081a53081a2020101302c06072a8648ce3d0101022100' + \
        'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f' + \
        '300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2d' + \
        'ce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a6' + \
        '8554199c47d08ffb10d4b8022100' + \
        'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141' + \
        '020101a14403420004' + \
        '0791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a' + \
        'a762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90'

    k = KEY()
    print ec_private
    k.generate (ec_secret.decode('hex'))
    print k.get_privkey ().encode('hex')
    k.set_privkey (k.get_privkey ())
    print k.get_privkey ().encode('hex')
