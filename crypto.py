from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from Crypto import Random
from operator import xor

random = Random.new() # random number generator
IV = bytes.fromhex("0000000000000000")
# MK = "MASTERADMKEY_005".encode("ascii")
MK = bytes.fromhex("01010101010101010101010101010101")

# Help Functions
def hex_string_to_int(hxs):
    hxs = hxs.replace(" ", "")
    return int(hxs, 16)

def nt_to_ntf(ntf):
    nt = hex_string_to_int(ntf) - 1
    nt = "%x" % int(nt)
    if len(nt) % 2 == 1:
        nt = "0"+nt
    nt = ' '.join(a+b for a,b in zip(nt[::2], nt[1::2]))
    l = 2 - len(nt.split(" "))
    nt = ("00 "*l)+nt
    return nt

def mask_nt(nt):
    nt = "00 00 00 "+nt+" 00 00 00" # ??
    nt = nt.replace(" ", "")
    return bytes.fromhex(nt)

def xor(var1, var2):
    encrypted = [ a ^ b for (a,b) in zip(var1, var2) ]
    str = ""
    for e in encrypted:
        hx = hex(e)
        str = str + hx[2:]

    str = (16 - len(str))*"0"+str

    bt = bytes.fromhex(str)
    return bt

# Handshake 1, send nonce
def get_rn(l=8):
    hx = random.read(l).hex()
    if len(hx) % 2 == 1:
        hx = "0"+hx
    rt = ' '.join(a+b for a,b in zip(hx[::2], hx[1::2]))
    return rt

# Handshake 2, check rnc
def check_rnc(nt, rnc, rn, mk=MK):
    mk1 = mk[:8]
    mk2 = mk[8:]

    ntf = nt_to_ntf(nt)
    ntf = mask_nt(ntf)

    des1 = DES3.new(mk1+mk2, DES3.MODE_CBC, IV)
    des2 = DES3.new(mk2+mk1, DES3.MODE_CBC, IV)

    skt = des1.encrypt(ntf).hex() + des2.encrypt(ntf).hex()
    skt = bytes.fromhex(skt)

    dest = DES3.new(skt, DES3.MODE_CBC, IV)

    rn = bytes.fromhex(rn)
    new_rnc = dest.encrypt(rn)

    rnc = bytes.fromhex(rnc)

    print("new_rnc: "+str(new_rnc.hex()))
    print("old_rnc: "+str(rnc.hex()))

    return bool(new_rnc == rnc)


# Handshake 3, get ntf calculate sk
def get_sk(nt, mk=MK):
    mk1 = mk[:8]
    mk2 = mk[8:]

    nt = mask_nt(nt)

    des1 = DES3.new(mk1+mk2, DES3.MODE_CBC, IV)
    des2 = DES3.new(mk2+mk1, DES3.MODE_CBC, IV)

    sk1 = des1.encrypt(nt)
    sk2 = des2.encrypt(nt)

    return sk1.hex()+sk2.hex() # returns in hex


def sign_command(cmd, sk):
    cmd = bytes.fromhex(cmd)
    sk = bytes.fromhex(sk)

    # Add padding if neccessary
    cmd = [cmd[i:i+8] for i in range(0, len(cmd), 8)]
    scmd = cmd[-1].hex()
    scmd += "0"*(16-len(scmd))
    cmd[-1] = bytes.fromhex(scmd)

    # calculate s2
    cb = DES.new(sk[:8], DES.MODE_CBC, IV).encrypt(cmd[0])

    for c in cmd[1:-1]:
        xored = xor(cb, c)
        cb = DES.new(sk[:8], DES.MODE_CBC, IV).encrypt(xored)

    xored = xor(cmd[-1], cb)
    s2 = DES3.new(sk, DES3.MODE_CBC, IV).encrypt(xored)

    return s2

def encrypt_data(data, sk):
    data = bytes.fromhex(data).hex()
    sk = bytes.fromhex(sk)

    padd = 16 - (len(data) % 16)

    if padd == 16:
        padd = 0

    data = data + "0" * padd

    data = bytes.fromhex(data)
    edata = DES3.new(sk, DES3.MODE_CBC, IV).encrypt(data)

    return edata.hex()
