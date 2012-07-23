# -*- Mode: Python -*-

NID_secp256k1 = 714 # from openssl/obj_mac.h

class der:
    pass

class ssl:
    def EC_KEY_new_by_curve_name(nid):
        pass
    def EC_KEY_free (key):
        pass
    def d2i_ECPrivateKey(key):
        pass
    def i2d_ECPrivateKey(key):
        pass
    def i2o_ECPublicKey(key):
        pass
    def ECDSA_sign(key):
        pass
    def ECDSA_verify(key):       
        pass
            
class KEY:
    def __init__ (self):
        self.k = ssl.EC_KEY_new_by_curve_name (NID_secp256k1)

    def __del__ (self):
        ssl.EC_KEY_free (self.k)
        self.k = None

    def generate (self, secret=None):
        if secret:
            priv_key = ssl.BN_bin2bn (secret, 32, ssl.BN_new())
            group = ssl.EC_KEY_get0_group (self.k)
            pub_key = ssl.EC_POINT_new (group)
            ctx = ssl.BN_CTX_new ()
            ssl.EC_POINT_mul (group, pub_key, priv_key, None, None, ctx)
            ssl.EC_KEY_set_private_key (self.k, priv_key)
            ssl.EC_KEY_set_public_key (self.k, pub_key)
            ssl.EC_POINT_free (pub_key)
            ssl.BN_CTX_free (ctx)
            return self.k
        else:
            return ssl.EC_KEY_generate_key (self.k)

    def set_privkey (self, key):
        self.mb = ctypes.create_string_buffer (key)
        print ssl.d2i_ECPrivateKey (ctypes.byref (self.k), ctypes.byref (ctypes.pointer (self.mb)), len(key))

    def set_pubkey (self, key):
        self.mb = ctypes.create_string_buffer (key)
        print ssl.o2i_ECPublicKey (ctypes.byref (self.k), ctypes.byref (ctypes.pointer (self.mb)), len(key))

    def get_privkey (self):
        size = ssl.i2d_ECPrivateKey (self.k, 0)
        mb_pri = ctypes.create_string_buffer (size)
        ssl.i2d_ECPrivateKey (self.k, ctypes.byref (ctypes.pointer (mb_pri)))
        return mb_pri.raw

    def get_pubkey (self):
        size = ssl.i2o_ECPublicKey (self.k, 0)
        mb = ctypes.create_string_buffer (size)
        ssl.i2o_ECPublicKey (self.k, ctypes.byref (ctypes.pointer (mb)))
        return mb.raw

    def sign (self, hash):
        sig_size = ssl.ECDSA_size (self.k)
        mb_sig = ctypes.create_string_buffer (sig_size)
        sig_size0 = ctypes.POINTER (ctypes.c_int)()
        assert 1 == ssl.ECDSA_sign (0, hash, len (hash), mb_sig, ctypes.byref (sig_size0), self.k)
        return mb_sig.raw

    def verify (self, hash, sig):
        return ssl.ECDSA_verify (0, hash, len(hash), sig, len(sig), self.k)

if __name__ == '__main__':
    print "ecdsa module"
