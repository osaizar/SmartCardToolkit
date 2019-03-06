from Crypto.Cipher import DES3
from Crypto.Cipher import DES
from Crypto import Random
from operator import xor

random = Random.new() # random number generator

# Help Functions
def hex_string_to_int(hxs):
    hxs = hxs.replace(" ", "")
    return int(hxs, 16)

def ntf_to_nt(ntf):
    nt = hex_string_to_int(ntf)
    nt = "%x" % int(nt)
    if len(nt) % 2 == 1:
        nt = "0"+nt
    nt = ' '.join(a+b for a,b in zip(nt[::2], nt[1::2]))
    l = 2 - len(nt.split(" "))
    nt = ("00 "*l)+nt
    return nt

def mask_NT(nt):
    nt = "00 00 00 "+nt+" 00 00 00" # ??
    nt = nt.replace(" ", "")
    return bytes.fromhex(nt)

# Handshake 1, send nonce
def get_RN(l=8):
    hx = random.read(l)
    if len(hx) % 2 == 1:
        hx = "0"+hx
    rt = ' '.join(a+b for a,b in zip(hx[::2], hx[1::2]))
    return rt

# Handshake 2, check RNCt
def check_RNCt(NTf, RNCt, RN, MK="MASTERADMKEY_005"):
    mk = MK.encode("ascii")
    mk1 = mk[:8]
    mk2 = mk[8:]
    nt = ntf_to_nt(NTf)
    nt = mask_NT(nt)
    des1 = DES3.new(mk1+mk2, DES3.MODE_CBC, "0"*8)
    des2 = DES3.new(mk2+mk1, DES3.MODE_CBC, "0"*8)
    skt = des1.encrypt(nt) + des2.encrypt(nt)

    dest = DES3.new(skt, DES3.MODE_CBC, "0"*8)
    hRN = bytes.fromhex(RN)
    hRNCt = bytes.fromhex(RNCt)
    hRN = dest.encrypt(hRN)
    print("[DEBUG] rnc_new: "+str(hRN))
    print("[DEBUG] rnct: "+str(hRNCt))
    return bool(hRN == hRNCt)


# Handshake 3, get NTf calculate SK
def get_SK(NTf, MK="MASTERADMKEY_005"):
    mk = MK.encode("ascii")
    mk1 = mk[:8]
    mk2 = mk[8:]
    NTf = mask_NT(NTf)
    des1 = DES3.new(mk1+mk2, DES3.MODE_CBC, "0"*8)
    des2 = DES3.new(mk2+mk1, DES3.MODE_CBC, "0"*8)
    sk1 = des1.encrypt(NTf)
    sk2 = des2.encrypt(NTf)
    return sk1.hex()+sk2.hex() # returns in hex
