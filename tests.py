import bitcoin

def check_addr(addrtype, addr):
    bitcoin.addrtype = addrtype
    key = bitcoin.address_to_key(addr)
    addr_res = bitcoin.key_to_address(key)
    print "prefix %d, %d bytes:\n %s\n %s" % (addrtype, len(key), addr, addr_res)

def test_addr():

    print "testing address_to_key/key_to_address"

    # regular
    check_addr(0, '111pUniM4FDyzzqUEnAFnGjiAAjvJXGHH')
    check_addr(0, '123CrJxHRTN2CMHctb2eY6hgXjundR7TYk')
    # testnet
    check_addr(111, 'mnorSNMwfa8qoo6o5WxcQGk2bM1FW62gcW')
    check_addr(111, 'n3UujJA86tP4eNrNcEm6iak3snZH73AmCW')
    # private keys
    check_addr(0+128, '5Jr9HyPQFr16hp1GgYBeTfy7LQ4o2smTBjEK3V3u1CiDaG4Tuhy')
    check_addr(0+128, '5Jcrw1AorYxPnoAw84Ze5i98FcksTDTT1nb7HYJuVwa3wYJRBJa')
    check_addr(111+128, '92U9JfnevJTobRwn8S9SkTew8rcfh8UezH6CsZFssr3Q85QgR4x')
    check_addr(111+128, '93MF7bFx9egsUSmFxwx9pGtvzCVU7TkeQts63BzCdpb5CA8Tr8y')

def test_ecdsa(module_name):

    print "testing ecdsa - ", module_name

    KEY = __import__(module_name).KEY

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
    k.generate ( ec_secret.decode('hex') )
    print ec_private
    print k.get_privkey ().encode('hex')

if __name__ == '__main__':
    test_addr()
    test_ecdsa("ecdsa_pure")
    test_ecdsa("ecdsa_ssl")

