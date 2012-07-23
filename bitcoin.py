# -*- Mode: Python -*-

# A prototype bitcoin implementation.
#
# Author: Sam Rushing. http://www.nightmare.com/~rushing/
# July 2011.
#
# Status: much of the protocol is done.  The crypto bits are now
#   working, and I can verify 'standard' address-to-address transactions.
#   There's a simple wallet implementation, which will hopefully soon
#   be able to transact actual bitcoins.
# Todo: consider implementing the scripting engine.
# Todo: actually participate in the p2p network rather than being a lurker.
#
# One of my goals here is to keep the implementation as simple and small
#   as possible - with as few outside dependencies as I can get away with.
#   For that reason I'm using ctypes to get to openssl rather than building
#   in a dependency on M2Crypto or any of the other crypto packages.

import copy
import hashlib
import random
import struct
import socket
import time
import os
import pickle
import string
import sys

import asyncore
import asynchat
import asynhttp

from hashlib import sha256
from pprint import pprint as pp

# these are overriden for testnet
BITCOIN_PORT = 8333
BITCOIN_MAGIC = '\xf9\xbe\xb4\xd9'
BLOCKS_PATH = 'blocks.bin'
genesis_block_hash = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
addrtype = 0

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode (n):
    l = []
    while n > 0:
        n, r = divmod (n, 58)
        l.insert (0, (b58_digits[r]))
    return ''.join (l)

def base58_decode (s):
    n = 0
    for ch in s:
        n *= 58
        digit = b58_digits.index (ch)
        n += digit
    return n

def dhash (s):
    return sha256(sha256(s).digest()).digest()

def rhash (s):
    h1 = hashlib.new ('ripemd160')
    h1.update (sha256(s).digest())
    return h1.digest()

def bcrepr (n):
    return '%d.%08d' % divmod (n, 100000000)

# https://en.bitcoin.it/wiki/Proper_Money_Handling_(JSON-RPC)
def float_to_btc (f):
    return long (round (f * 1e8))

#'1Ncui8YjT7JJD91tkf42dijPnqywbupf7w'
#'\xed%3\x12/\xfd\x7f\x07$\xc4$Y\x92\x06\xcc\xb2>\x89\xd6\xf7'

class BadAddress (Exception):
    pass

def base58_encode_padded (s):
    res = base58_encode (int ('0x' + s.encode ('hex'), 16))
    pad = 0
    for c in s:
        if c == chr(0): pad += 1
        else: break
    return b58_digits[0] * pad + res

def base58_decode_padded (s):
    pad = 0
    for c in s:
        if c == b58_digits[0]: pad += 1
        else: break
    h = '%x' % base58_decode (s)
    if len(h) % 2:
        h = '0' + h
    res = h.decode ('hex')
    return chr(0) * pad + res

def key_to_address (s):
    vs = chr (addrtype) + s
    check = dhash(vs)[:4]
    return base58_encode_padded (vs + check)

def address_to_key (s):
    k = base58_decode_padded (s)
    hash160, check0 = k[1:-4], k[-4:]
    check1 = dhash (chr (addrtype) + hash160)[:4]
    if check0 != check1:
        raise BadAddress (s)
    return hash160

# for some reason many hashes are reversed, dunno why.  [this may just be block explorer?]
def hexify (s, flip=False):
    if flip:
        return s[::-1].encode ('hex')
    else:
        return s.encode ('hex')

def unhexify (s, flip=False):
    if flip:
        return s.decode ('hex')[::-1]
    else:
        return s.decode ('hex')

def frob_hash (s):
    r = []
    for i in range (0, len (s), 2):
        r.append (s[i:i+2])
    r.reverse()
    return ''.join (r)

# wallet file format: (<8 bytes of size> <private-key>)+
class wallet:

    # self.keys  : public_key -> private_key
    # self.addrs : addr -> public_key
    # self.value : addr -> { outpoint : value, ... }

    def __init__ (self, path):
        self.path = path
        self.keys = {}
        self.addrs = {}
        # these will load from the cache
        self.last_block = 0
        self.total_btc = 0
        self.value = {}
        #
        try:
            file = open (path, 'rb')
        except IOError:
            file = open (path, 'wb')
            file.close()
            file = open (path, 'rb')
        while 1:
            size = file.read (8)
            if not size:
                break
            else:
                size, = struct.unpack ('<Q', size)
                key = file.read (size)
                public_key = key[-65:] # XXX
                self.keys[public_key] = key
                pub0 = rhash (public_key)
                addr = key_to_address (pub0)
                self.addrs[addr] = public_key
                self.value[addr] = {} # overriden by cache if present
        # try to load value from the cache.
        self.load_value_cache()

    def load_value_cache (self):
        db = the_block_db
        cache_path = self.path + '.cache'
        try:
            file = open (cache_path, 'rb')
        except IOError:
            pass
        else:
            self.last_block, self.total_btc, self.value = pickle.load (file)
            file.close()
        db_last = db.block_num[db.last_block]
        if not len(self.keys):
            print 'no keys in wallet'
            self.last_block = db_last
            self.write_value_cache()
        elif db_last < self.last_block:
            print 'the wallet is ahead of the block chain.  Disabling wallet for now.'
            global the_wallet
            the_wallet = None
        elif self.last_block < db_last:
            print 'scanning %d blocks from %d-%d' % (db_last - self.last_block, self.last_block, db_last)
            self.scan_block_chain (self.last_block)
            self.last_block = db_last
            # update the cache
            self.write_value_cache()
        else:
            print 'wallet cache is caught up with the block chain'
        print 'total btc in wallet:', bcrepr (self.total_btc)

    def write_value_cache (self):
        cache_path = self.path + '.cache'
        file = open (cache_path, 'wb')
        self.last_block = the_block_db.last_block_index
        pickle.dump ((self.last_block, self.total_btc, self.value), file)
        file.close()

    def new_key (self):
        k = KEY()
        k.generate()
        key = k.get_privkey()
        size = struct.pack ('<Q', len(key))
        file = open (self.path, 'ab')
        file.write (size)
        file.write (key)
        file.close()
        pubkey = k.get_pubkey()
        addr = key_to_address (rhash (pubkey))
        self.addrs[addr] = pubkey
        self.keys[pubkey] = key
        self.value[addr] = {}
        self.write_value_cache()
        return addr

    def check_tx (self, tx):
        dirty = False
        # did we send money somewhere?
        for outpoint, iscript, sequence in tx.inputs:
            sig, pubkey = parse_iscript (iscript)
            if sig and pubkey:
                addr = key_to_address (rhash (pubkey))
                if self.addrs.has_key (addr):
                    if not self.value[addr].has_key (outpoint):
                        raise KeyError ("input for send tx missing?")
                    else:
                        value = self.value[addr][outpoint]
                        self.value[addr][outpoint] = 0
                        self.total_btc -= value
                        dirty = True
                    print 'SEND: %s %s' % (bcrepr (value), addr,)
                    #import pdb; pdb.set_trace()
        # did we receive any moneys?
        i = 0
        rtotal = 0
        index = 0
        for value, oscript in tx.outputs:
            addr = parse_oscript (oscript)
            if addr and self.addrs.has_key (addr):
                hash = tx.get_hash()
                outpoint = hash, index
                if self.value[addr].has_key (outpoint):
                    #raise KeyError ("outpoint already present?")
                    pass
                else:
                    self.value[addr][outpoint] = value
                    self.total_btc += value
                    dirty = True
                print 'RECV: %s %s' % (bcrepr (value), addr)
                rtotal += 1
            index += 1
            i += 1
        if dirty:
            self.write_value_cache()
        return rtotal

    def dump_value (self):
        addrs = self.value.keys()
        addrs.sort()
        sum = 0
        for addr in addrs:
            if len(self.value[addr]):
                print 'addr: %s' % (addr,)
                for (outpoint, index), value in self.value[addr].iteritems():
                    print '  %s %s:%d' % (bcrepr (value), outpoint.encode ('hex'), index)
                    sum += value
        print 'total: %s' % (bcrepr(sum),)

    def scan_block_chain (self, start):
        # scan the whole chain for an TX related to this wallet
        db = the_block_db
        blocks = db.num_block.keys()
        blocks.sort()
        total = 0
        for num in blocks:
            if num >= start:
                b = db[db.num_block[num]]
                for tx in b.transactions:
                    total += self.check_tx (tx)
        print 'found %d txs' % (total,)

    def new_block (self, block):
        # only scan blocks if we have keys
        if len (self.addrs):
            for tx in block.transactions:
                self.check_tx (tx)

    def __getitem__ (self, addr):
        pubkey = self.addrs[addr]
        key = self.keys[pubkey]
        k = KEY()
        k.set_privkey (key)
        return k
    
    def build_send_request (self, value, dest_addr, fee=0):
        # first, make sure we have enough money.
        total = value + fee
        if total > self.total_btc:
            raise ValueError ("not enough funds")
        elif value <= 0:
            raise ValueError ("zero or negative value?")
        elif value < 1000000 and fee < 50000:
            # any output less than one cent needs a fee.
            raise ValueError ("fee too low")
        else:
            # now, assemble the total
            sum = 0
            inputs = []
            for addr, outpoints in self.value.iteritems():
                for outpoint, v0 in outpoints.iteritems():
                    if v0:
                        sum += v0
                        inputs.append ((outpoint, v0, addr))
                        if sum >= total:
                            break
                if sum >= total:
                    break
            # assemble the outputs
            outputs = [(value, dest_addr)]
            if sum > value:
                # we need a place to dump the change
                change_addr = self.get_change_addr()
                outputs.append ((sum - total, change_addr))
            inputs0 = []
            keys = []
            for outpoint, v0, addr in inputs:
                pubkey = self.addrs[addr]
                keys.append (self[addr])
                iscript = make_iscript ('bogus-sig', pubkey)
                inputs0.append ((outpoint, iscript, 4294967295))
            outputs0 = []
            for val0, addr0 in outputs:
                outputs0.append ((val0, make_oscript (addr0)))
            lock_time = 0
            tx = TX (inputs0, outputs0, lock_time)
            for i in range (len (inputs0)):
                tx.sign (keys[i], i)
            return tx

    def get_change_addr (self):
        # look for an empty key
        for addr, outpoints in self.value.iteritems():
            empty = True
            for outpoint, v0 in outpoints.iteritems():
                if v0 != 0:
                    empty = False
                    break
            if empty:
                # found one
                return addr
        return self.new_key()

# --------------------------------------------------------------------------------
#        ECDSA
# --------------------------------------------------------------------------------

# pull in one of the ECDSA key implementations.

from ecdsa_ssl import KEY
#from ecdsa_pure import KEY

# --------------------------------------------------------------------------------

OBJ_TX    = 1
OBJ_BLOCK = 2

object_types = {
    0: "ERROR",
    1: "TX",
    2: "BLOCK"
    }

# used to keep track of the parsing position when cracking packets
class position:
    def __init__ (self, val=0):
        self.val = val
    def __int__ (self):
        return self.val
    def __index__ (self):
        return self.val
    def incr (self, delta):
        self.val += delta
    def __repr__ (self):
        return '<pos %d>' % (self.val,)

# like struct.unpack_from, but it updates <position> as it reads
def unpack_pos (format, data, pos):
    result = struct.unpack_from (format, data, pos)
    pos.incr (struct.calcsize (format))
    return result

def unpack_var_int (d, pos):
    n0, = unpack_pos ('<B', d, pos)
    if n0 < 0xfd:
        return n0
    elif n0 == 0xfd:
        n1, = unpack_pos ('<H', d, pos)
        return n1
    elif n0 == 0xfe:
        n2, = unpack_pos ('<I', d, pos)
        return n2
    elif n0 == 0xff:
        n3, = unpack_pos ('<Q', d, pos)
        return n3

def unpack_var_str (d, pos):
    n = unpack_var_int (d, pos)
    result = d[pos.val:pos.val+n]
    pos.incr (n)
    return result

def unpack_net_addr (data, pos):
    services, addr, port = unpack_pos ('<Q16s2s', data, pos)
    addr = read_ip_addr (addr)
    port, = struct.unpack ('!H', port) # pos adjusted above
    return services, (addr, port)

def pack_net_addr ((services, (addr, port))):
    addr = pack_ip_addr (addr)
    port = struct.pack ('!H', port)
    return struct.pack ('<Q', services) + addr + port

def make_nonce():
    return random.randint (0, 1<<64L)

def pack_version (me_addr, you_addr, nonce):
    data = struct.pack ('<IQQ', 31900, 1, int(time.time()))
    data += pack_net_addr ((1, you_addr))
    data += pack_net_addr ((1, me_addr))
    data += struct.pack ('<Q', nonce)
    data += pack_var_str ('')
    start_height = the_block_db.last_block_index
    if start_height < 0:
        start_height = 0
    data += struct.pack ('<I', start_height)
    return make_packet ('version', data)

class TX:
    def __init__ (self, inputs, outputs, lock_time):
        self.inputs = inputs
        self.outputs = outputs
        self.lock_time = lock_time

    def copy (self):
        return copy.deepcopy (self)

    def get_hash (self):
        return dhash (self.render())

    def dump (self):
        print 'hash: %s' % (hexify (dhash (self.render())),)
        print 'inputs: %d' % (len(self.inputs))
        for i in range (len (self.inputs)):
            (outpoint, index), script, sequence = self.inputs[i]
            print '%3d %s:%d %s %d' % (i, hexify(outpoint), index, hexify (script), sequence)
        print '%d outputs' % (len(self.outputs))
        for i in range (len (self.outputs)):
            value, pk_script = self.outputs[i]
            addr = parse_oscript (pk_script)
            if not addr:
                addr = hexify (pk_script)
            print '%3d %s %s' % (i, bcrepr (value), addr)
        print 'lock_time:', self.lock_time

    def render (self):
        version = 1
        result = [struct.pack ('<I', version)]
        result.append (pack_var_int (len (self.inputs)))
        for (outpoint, index), script, sequence in self.inputs:
            result.extend ([
                    struct.pack ('<32sI', outpoint, index),
                    pack_var_int (len (script)),
                    script,
                    struct.pack ('<I', sequence),
                    ])
        result.append (pack_var_int (len (self.outputs)))
        for value, pk_script in self.outputs:
            result.extend ([
                    struct.pack ('<Q', value),
                    pack_var_int (len (pk_script)),
                    pk_script,
                    ])
        result.append (struct.pack ('<I', self.lock_time))
        return ''.join (result)

    # Hugely Helpful: http://forum.bitcoin.org/index.php?topic=2957.20
    def get_ecdsa_hash (self, index):
        tx0 = self.copy()
        iscript = tx0.inputs[index][1]
        # build a new version of the input script as an output script
        sig, pubkey = parse_iscript (iscript)
        pubkey_hash = rhash (pubkey)
        new_script = chr(118) + chr (169) + chr (len (pubkey_hash)) + pubkey_hash + chr (136) + chr (172)
        for i in range (len (tx0.inputs)):
            outpoint, script, sequence = tx0.inputs[i]
            if i == index:
                script = new_script
            else:
                script = ''
            tx0.inputs[i] = outpoint, script, sequence
        to_hash = tx0.render() + struct.pack ('<I', 1)
        return dhash (to_hash), sig, pubkey

    def sign (self, key, index):
        hash, _, pubkey = self.get_ecdsa_hash (index)
        assert (key.get_pubkey() == pubkey)
        # tack on the hash type byte.
        sig = key.sign (hash) + '\x01'
        iscript = make_iscript (sig, pubkey)
        op0, _, seq = self.inputs[index]
        self.inputs[index] = op0, iscript, seq
        return sig

    def verify (self, index):
        hash, sig, pubkey = self.get_ecdsa_hash (index)
        k = KEY()
        k.set_pubkey (pubkey)
        return k.verify (hash, sig)

def unpack_tx (data, pos):
    # has its own version number
    version, = unpack_pos ('<I', data, pos)
    if version != 1:
        raise ValueError ("unknown tx version: %d" % (version,))
    txin_count = unpack_var_int (data, pos)
    inputs = []
    outputs = []
    for i in range (txin_count):
        outpoint = unpack_pos ('<32sI', data, pos)
        script_length = unpack_var_int (data, pos)
        script = data[pos.val:pos.val+script_length]
        pos.incr (script_length)
        sequence, = unpack_pos ('<I', data, pos)
        inputs.append ((outpoint, script, sequence))
    txout_count = unpack_var_int (data, pos)
    for i in range (txout_count):
        value, = unpack_pos ('<Q', data, pos)
        pk_script_length = unpack_var_int (data, pos)
        pk_script = data[pos.val:pos.val+pk_script_length]
        pos.incr (pk_script_length)
        outputs.append ((value, pk_script))
    lock_time, = unpack_pos ('<I', data, pos)
    return TX (inputs, outputs, lock_time)

def parse_iscript (s):
    # these tend to be push, push
    s0 = ord (s[0])
    if s0 > 0 and s0 < 76:
        # specifies the size of the first key
        k0 = s[1:1+s0]
        #print 'k0:', hexify (k0)
        if len(s) == 1+s0:
            return k0, None
        else:
            s1 = ord (s[1+s0])
            if s1 > 0 and s1 < 76:
                k1 = s[2+s0:2+s0+s1]
                #print 'k1:', hexify (k1)
                return k0, k1
            else:
                return None, None
    else:
        return None, None

def make_iscript (sig, pubkey):
    sl = len (sig)
    kl = len (pubkey)
    return chr(sl) + sig + chr(kl) + pubkey

def parse_oscript (s):
    if (ord(s[0]) == 118 and ord(s[1]) == 169 and ord(s[-2]) == 136 and ord(s[-1]) == 172):
        size = ord(s[2])
        addr = key_to_address (s[3:size+3])
        assert (size+5 == len(s))
        return addr
    else:
        return None

def make_oscript (addr):
    # standard tx oscript
    key_hash = address_to_key (addr)
    return chr(118) + chr(169) + chr(len(key_hash)) + key_hash + chr(136) + chr(172)

def inet_ntop(af, addr):
    if af == socket.AF_INET:
        return socket.inet_ntoa(addr)
    elif af == socket.AF_INET6:
        if len(addr) != 16:
            raise ValueError("address length incorrect")
        parts = struct.unpack('!8H', addr)
        curBase = bestBase = None
        for i in range(8):
            if not parts[i]:
                if curBase is None:
                    curBase = i
                    curLen = 0
                curLen += 1
            else:
                if curBase is not None:
                    if bestBase is None or curLen > bestLen:
                        bestBase = curBase
                        bestLen = curLen
                    curBase = None
        if curBase is not None and (bestBase is None or curLen > bestLen):
            bestBase = curBase
            bestLen = curLen
        parts = [hex(x)[2:] for x in parts]
        if bestBase is not None:
            parts[bestBase:bestBase + bestLen] = ['']
        if parts[0] == '':
            parts.insert(0, '')
        if parts[-1] == '':
            parts.insert(len(parts) - 1, '')
        return ':'.join(parts)
    else:
        raise socket.error(97, 'Address family not supported by protocol')

def read_ip_addr (s):
    r = inet_ntop (socket.AF_INET6, s)
    if r.startswith ('::ffff:'):
        return r[7:]
    else:
        return r

def inet_pton(af, addr):
    if af == socket.AF_INET:
        return socket.inet_aton(addr)
    elif af == getattr(socket, 'AF_INET6', 'AF_INET6'):
        if [x for x in addr if x not in string.hexdigits + ':.']:
            raise ValueError("Illegal characters: %r" % (''.join(x),))

        parts = addr.split(':')
        elided = parts.count('')
        ipv4Component = '.' in parts[-1]

        if len(parts) > (8 - ipv4Component) or elided > 3:
            raise ValueError("Syntactically invalid address")

        if elided == 3:
            return '\x00' * 16

        if elided:
            zeros = ['0'] * (8 - len(parts) - ipv4Component + elided)

            if addr.startswith('::'):
                parts[:2] = zeros
            elif addr.endswith('::'):
                parts[-2:] = zeros
            else:
                idx = parts.index('')
                parts[idx:idx+1] = zeros

            if len(parts) != 8 - ipv4Component:
                raise ValueError("Syntactically invalid address")
        else:
            if len(parts) != (8 - ipv4Component):
                raise ValueError("Syntactically invalid address")

        if ipv4Component:
            if parts[-1].count('.') != 3:
                raise ValueError("Syntactically invalid address")
            rawipv4 = socket.inet_aton(parts[-1])
            unpackedipv4 = struct.unpack('!HH', rawipv4)
            parts[-1:] = [hex(x)[2:] for x in unpackedipv4]

        parts = [int(x, 16) for x in parts]
        return struct.pack('!8H', *parts)
    else:
        raise socket.error(97, 'Address family not supported by protocol')

def pack_ip_addr (addr):
    # only v4 right now
    return inet_pton (socket.AF_INET6, '::ffff:%s' % (addr,))

def pack_var_int (n):
    if n < 0xfd:
        return chr(n)
    elif n < 1<<16:
        return '\xfd' + struct.pack ('<H', n)
    elif n < 1<<32:
        return '\xfe' + struct.pack ('<I', n)
    else:
        return '\xff' + struct.pack ('<Q', n)

def pack_var_str (s):
    return pack_var_int (len (s)) + s

def make_packet (command, payload):
    assert (len(command) < 12)
    lc = len(command)
    cmd = command + ('\x00' * (12 - lc))
    if command == 'version':
        return struct.pack (
            '<4s12sI',
            BITCOIN_MAGIC,
            cmd,
            len(payload),
            ) + payload
    else:
        h = dhash (payload)
        checksum = struct.unpack ('<I', h[:4])[0]
        return struct.pack (
            '<4s12sII',
            BITCOIN_MAGIC,
            cmd,
            len(payload),
            checksum
            ) + payload

class proto_version:
    pass

def unpack_version (data):
    pos = position()
    v = proto_version()
    v.version, v.services, v.timestamp = unpack_pos ('<IQQ', data, pos)
    v.me_addr = unpack_net_addr (data, pos)
    v.you_addr = unpack_net_addr (data, pos)
    v.nonce = unpack_pos ('<Q', data, pos)
    v.sub_version_num = unpack_var_str (data, pos)
    v.start_height, = unpack_pos ('<I', data, pos)
    print pp (v.__dict__)
    return v

def unpack_inv (data, pos):
    count = unpack_var_int (data, pos)
    result = []
    for i in range (count):
        objid, hash = unpack_pos ('<I32s', data, pos)
        objid_str = object_types.get (objid, "Unknown")
        result.append ((objid, hash))
        print objid_str, hexify (hash, flip=True)
    return result

def pack_inv (pairs):
    result = [pack_var_int (len(pairs))]
    for objid, hash in pairs:
        result.append (struct.pack ('<I32s', objid, hash))
    return ''.join (result)

def unpack_addr (data):
    pos = position()
    count = unpack_var_int (data, pos)
    for i in range (count):
        # timestamp & address
        timestamp, = unpack_pos ('<I', data, pos)
        net_addr = unpack_net_addr (data, pos)
        print timestamp, net_addr

def unpack_getdata (data, pos):
    # identical to INV
    return unpack_inv (data, pos)

class BLOCK:
    def __init__ (self, prev_block, merkle_root, timestamp, bits, nonce, transactions):
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.transactions = transactions

    def get_hash (self):
        return hexify (
            struct.pack (
                '<I32s32sIII', 
                self.version, self.prev_block, self.merkle_root,
                self.timestamp, self.bits, self.nonce
                ),
            True
            )

def unpack_block (data, pos=None):
    if pos is None:
        pos = position()
    version, prev_block, merkle_root, timestamp, bits, nonce = unpack_pos ('<I32s32sIII', data, pos)
    if version != 1:
        raise ValueError ("unsupported block version: %d" % (version,))
    count = unpack_var_int (data, pos)
    transactions = []
    for i in range (count):
        transactions.append (unpack_tx (data, pos))
    return BLOCK (prev_block, merkle_root, timestamp, bits, nonce, transactions)

def unpack_block_header (data):
    # version, prev_block, merkle_root, timestamp, bits, nonce
    return struct.unpack ('<I32s32sIII', data)

# --------------------------------------------------------------------------------
# block_db file format: (<8 bytes of size> <block>)+

class block_db:

    def __init__ (self, read_only=False):
        self.read_only = read_only
        self.blocks = {}
        self.prev = {}
        self.next = {}
        self.block_num = {}
        self.num_block = {}
        self.last_block = '00' * 32
        self.build_block_chain()
        self.file = None
        # hold new blocks until they link in
        self.embargo = {}

    def get_header (self, name):
        path = os.path.join ('blocks', name)
        return open (path).read (80)

    def build_block_chain (self):
        if not os.path.isfile (BLOCKS_PATH):
            open (BLOCKS_PATH, 'wb').write('')
        file = open (BLOCKS_PATH, 'rb')
        print 'reading block headers...'
        file.seek (0)
        i = -1
        last = None
        name = '00' * 32
        self.next[name] = genesis_block_hash
        self.block_num[name] = -1
        self.prev[genesis_block_hash] = name
        self.block_num[genesis_block_hash] = 0
        self.num_block[0] = genesis_block_hash
        while 1:
            pos = file.tell()
            size = file.read (8)
            if not size:
                break
            else:
                size, = struct.unpack ('<Q', size)
                header = file.read (80)
                (version, prev_block, merkle_root,
                 timestamp, bits, nonce) = unpack_block_header (header)
                # skip the rest of the block
                file.seek (size-80, 1)
                prev_block = hexify (prev_block, True)
                assert prev_block == name
                name = hexify (dhash (header), True)
                self.prev[name] = prev_block
                self.next[prev_block] = name
                i += 1
                self.block_num[name] = i
                self.num_block[i] = name
                self.blocks[name] = pos
        self.last_block = name
        self.last_block_index = i
        print 'last block (%d): %s' % (i, name)
        file.close()
        self.read_only_file = open (BLOCKS_PATH, 'rb')

    def open_for_append (self):
        # reopen in append mode
        self.file = open (BLOCKS_PATH, 'ab')

    def get_block (self, name):
        pos =  self.blocks[name]
        self.read_only_file.seek (pos)
        size = self.read_only_file.read (8)
        size, = struct.unpack ('<Q', size)
        return self.read_only_file.read (size)

    def __getitem__ (self, name):
        return unpack_block (self.get_block (name))

    def add (self, name, block):
        header = block[:80]
        (version, prev_block, merkle_root,
         timestamp, bits, nonce) = unpack_block_header (header)
        prev_block = hexify (prev_block, True)
        if self.blocks.has_key (name):
            print 'ignoring block we already have:', name
        else:
            for name0, block0 in self.embargo.iteritems():
                if name0 == prev_block:
                    # case 0: it links to an embargo block (normal case)
                    #    * release that embargo block
                    #    * toss any other embargo blocks
                    #    * embargo this block
                    self.release_embargo (name0, block0)
                    # Note: a full node will need to inject any lost txs back into the network.
                    if len (self.embargo) > 2:
                        print 'tossing %d orphan embargo blocks' % (len(orphans),)
                        del self.embargo[name]
                        self.toss_orphan_blocks (self.embargo.items())
                    self.embargo = { name:block }
                    break
            else:
                if prev_block == self.last_block:
                    # case 1: it links to the last block (racing blocks / competing subnet)
                    #    * add to the embargo list
                    self.embargo[name] = block
                else:
                    # case 2: it links to neither (problem or lame hack attempt?)
                    #    * toss it
                    print 'tossing orphan block: %s' % (name,)
                    self.orphan_blocks ([(name, block)])

            if name == genesis_block_hash:
                print "we got genesis block"
                self.last_block = '00' * 32
                self.prev[self.last_block] = True
                self.release_embargo(name, block)
                del self.embargo[name]

    def toss_orphan_blocks (self, orphans):
        # for now, just dump them into a binary log file
        f = open ('orphans.bin', 'ab')
        for name, orphan in orphans:
            f.write (struct.pack ('<Q', len(block)))
            f.write (block)
        f.close()

    def release_embargo (self, name, block):
        if self.file is None:
            self.open_for_append()
        (version, prev_block, merkle_root,
         timestamp, bits, nonce) = unpack_block_header (block[:80])
        prev_block = hexify (prev_block, True)
        if self.has_key (prev_block):
            size = len (block)
            pos = self.file.tell()
            self.file.write (struct.pack ('<Q', size))
            self.file.write (block)
            self.file.flush()
            self.prev[name] = prev_block
            self.next[prev_block] = name
            self.blocks[name] = pos
            print 'wrote block %s' % (name,)
            i = self.block_num[prev_block]
            self.block_num[name] = i+1
            self.num_block[i+1] = name
            self.last_block = name
            self.last_block_index = i+1
            if the_wallet:
                the_wallet.new_block (unpack_block (block))
        else:
            print 'cannot chain block %s' % (name,)

    def has_key (self, name):
        return self.prev.has_key (name)

# --------------------------------------------------------------------------------
#                               protocol
# --------------------------------------------------------------------------------

def make_verack():
    return (
        BITCOIN_MAGIC + 
        'verack\x00\x00\x00\x00\x00\x00' # verackNUL...
        '\x00\x00\x00\x00'               # payload length == 0
        )

# state machine.
HEADER   = 0 # waiting for a header
CHECKSUM = 1 # waiting for a checksum
PAYLOAD  = 2 # waiting for a payload

class BadState (Exception):
    pass

class connection (asynchat.async_chat):

    # my client version when I started this code
    version = 31900

    def __init__ (self, addr='127.0.0.1'):
        self.addr = addr
        self.nonce = make_nonce()
        self.conn = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        asynchat.async_chat.__init__ (self, self.conn)
        self.addr = addr
        self.ibuffer = []
        self.seeking = []
        self.pending = {}
        self.state_header()
        self.connect ((addr, BITCOIN_PORT))
        if not the_block_db.prev:
            # totally empty block database, seek the genesis block
            self.seeking.append (genesis_block_hash)

    def collect_incoming_data (self, data):
        self.ibuffer.append (data)

    def handle_connect (self):
        self.push (
            pack_version (
                (my_addr, BITCOIN_PORT),
                (self.addr, BITCOIN_PORT),
                self.nonce
                )
            )

    def state_header (self):
        self.state = HEADER
        self.set_terminator (20)

    def state_checksum (self):
        self.state = CHECKSUM
        self.set_terminator (4)

    def state_payload (self, length):
        assert (length > 0)
        self.state = PAYLOAD
        self.set_terminator (length)

    def check_command_name (self, command):
        for ch in command:
            if ch not in string.letters:
                return False
        return True

    def found_terminator (self):
        data, self.ibuffer = ''.join (self.ibuffer), []
        if self.state == HEADER:
            # ok, we got a header
            magic, command, length = struct.unpack ('<I12sI', data)
            command = command.strip ('\x00')
            self.header = magic, command, length
            if command not in ('version', 'verack'):
                self.state_checksum()
            elif length == 0:
                self.do_command (command, '')
                self.state_header()
            else:
                self.state_payload (length)
        elif self.state == CHECKSUM:
            magic, command, length = self.header
            self.checksum, = struct.unpack ('<I', data)
            # XXX actually verify the checksum, duh
            self.state_payload (length)
        elif self.state == PAYLOAD:
            magic, command, length = self.header
            self.do_command (command, data)
            self.state_header()
        else:
            raise BadState (self.state)
            
    def do_command (self, cmd, data):
        if self.check_command_name (cmd):
            try:
                method = getattr (self, 'cmd_%s' % cmd,)
            except AttributeError:
                print 'no support for "%s" command' % (cmd,)
            else:
                try:
                    method (data)
                except:
                    (file, fun, line), t, v, tbinfo = asyncore.compact_traceback()
                    print 'caesure error: %s, %s: file: %s line: %s' % (t, v, file, line)
                    print '     ********** problem processing %r command: packet=%r' % (cmd, data)
        else:
            print 'bad command: "%r", ignoring' % (cmd,)

    def kick_seeking (self):
        if len (self.seeking) and len (self.pending) < 10:
            ask, self.seeking = self.seeking[:10], self.seeking[10:]
            payload = [pack_var_int (len(ask))]
            for name in ask:
                hash = unhexify (name, True)
                self.pending[name] = True
                payload.append (struct.pack ('<I32s', OBJ_BLOCK, hash))
            print 'requesting %d blocks' % (len (ask),)
            packet = make_packet ('getdata', ''.join (payload))
            self.push (packet)
        if (the_block_db.last_block_index >= 0
            and the_block_db.last_block_index < self.other_version.start_height):
            # we still need more blocks
            self.getblocks()

    # bootstrapping a block collection.  It'd be nice if we could just ask
    # for blocks after '00'*32, but getblocks returns a list starting with
    # block 1 first, not block 0.
    def getblocks (self):
        # the wiki seems to have changed the description of this packet,
        #  and I can't make any sense out of what it's supposed to do when
        #  <count> is greater than one.
        start = the_block_db.last_block
        payload = ''.join ([
            struct.pack ('<I', self.version),
            pack_var_int (1),
            unhexify (start, flip=True),
            '\x00' * 32,
            ])
        packet = make_packet ('getblocks', payload)
        self.push (packet)

    def getdata (self, kind, name):
        kind = {'TX':1,'BLOCK':2}[kind.upper()]
        # decode hash
        hash = unhexify (name, flip=True)
        payload = [pack_var_int (1)]
        payload.append (struct.pack ('<I32s', kind, hash))
        packet = make_packet ('getdata', ''.join (payload))
        self.push (packet)

    def cmd_version (self, data):
        # packet traces show VERSION, VERSION, VERACK, VERACK.
        print 'in cmd_version'
        self.other_version = unpack_version (data)
        self.push (make_verack())

    def cmd_verack (self, data):
        print 'in cmd_verack'
        if not len(the_block_db.blocks):
            self.seeking = [genesis_block_hash]
        self.kick_seeking()

    def cmd_addr (self, data):
        return unpack_addr (data)

    def cmd_inv (self, data):
        pairs = unpack_inv (data, position())
        # request those blocks we don't have...
        seeking = []
        for objid, hash in pairs:
            if objid == OBJ_BLOCK:
                name = hexify (hash, True)
                if not the_block_db.has_key (name):
                    self.seeking.append (name)
        self.kick_seeking()

    def cmd_getdata (self, data):
        return unpack_inv (data, position())

    def cmd_tx (self, data):
        return unpack_tx (data, position())

    def cmd_block (self, data):
        # the name of a block is the hash of its 'header', which
        #  lives in the first 80 bytes.
        name = hexify (dhash (data[:80]), True)
        # were we waiting for this block?
        if self.pending.has_key (name):
            del self.pending[name]
        the_block_db.add (name, data)
        self.kick_seeking()

def valid_ip (s):
    parts = s.split ('.')
    nums = map (int, parts)
    assert (len (nums) == 4)
    for num in nums:
        if num > 255:
            raise ValueError


the_wallet = None
the_block_db = None

if __name__ == '__main__':
    if '-t' in sys.argv:
        sys.argv.remove ('-t')
        BITCOIN_PORT = 18333
        BITCOIN_MAGIC = '\xfa\xbf\xb5\xda'
        BLOCKS_PATH = 'blocks.testnet.bin'
        genesis_block_hash = '00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008'
        addrtype = 111

    # mount the block database
    the_block_db = block_db()

    if '-w' in sys.argv:
        i = sys.argv.index ('-w')
        the_wallet = wallet (sys.argv[i+1])
        del sys.argv[i:i+2]

    # client mode
    if '-c' in sys.argv:
        i = sys.argv.index ('-c')
        if len(sys.argv) < 3:
            print 'usage: %s -c <externally-visible-ip-address> <server-ip-address>' % (sys.argv[0],)
        else:
            [my_addr, other_addr] = sys.argv[i+1:i+3]
            valid_ip (my_addr)
            import monitor
            # for now, there's a single global connection.  later we'll have a bunch.
            bc = connection (other_addr)
            m = monitor.monitor_server()
            h = asynhttp.http_server ('127.0.0.1', 8380)
            import webadmin
            h.install_handler (webadmin.handler())
            try:
                asyncore.loop(timeout = 5)
            except:
                print("received interrupt signal, stopping")
    else:
        # database browsing mode
        db = the_block_db # alias
