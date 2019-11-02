from cryptography.hazmat.primitives.ciphers import (
    algorithms)
import app.api.encr_decr
from requests import codes, Session

SETCOINS_FORM_URL = "http://localhost:8080/setcoins"


# You should implement this padding oracle object
# to craft the requests containing the mauled
# ciphertexts to the right URL.
class PaddingOracle(object):

    def __init__(self, po_url):
        self.url = po_url
        self._block_size_bytes = int(algorithms.AES.block_size / 8)

    @property
    def block_length(self):
        return self._block_size_bytes

    # you'll need to send the provided ciphertext
    # as the admin cookie, retrieve the request,
    # and see whether there was a padding error or not.
    def test_ciphertext(self, ct):

        pass


def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]


def bxor(b1, b2):  # use xor for bytes
    result = bytes(a ^ b for (a, b) in zip(b1, b2))
    return result


def po_attack_2blocks(po, ctx):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle.
    @ctx: a ciphertext
    """
    assert len(ctx) == 2 * po.block_length, "This function only accepts 2 block " \
                                            "cipher texts. Got {} block(s)!".format(len(ctx) / po.block_length)
    c0, c1 = list(split_into_blocks(ctx, po.block_length))
    msg = ''
    # TODO: Implement padding oracle attack for 2 blocks of messages.
    return msg


def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle.
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)

    cleartext = []
    for a in range(nblocks - 1):
        c1 = ctx_blocks[a]
        c2 = ctx_blocks[a + 1]

        print("cracking block {} out of {}".format(a, nblocks))

        i2 = [0] * po.block_length
        p2 = [0] * po.block_length

        for i in range(po.block_length - 1, -1, -1):
            for b in range(0, 256):
                prefix = c1[:i]
                pad_byte = (po.block_length - i)

                suffix = [pad_byte ^ val for val in i2[i + 1:]]

                evil_c1 = prefix + b.to_bytes(1, 'little')
                for j in range(len(suffix)):
                    evil_c1 += suffix[j].to_bytes(1, 'little')

                dpt = decrypt(bytes(evil_c1) + c2)

                if dpt is not None:
                    if dpt is False:
                        continue
                    else:
                        i2[i] = evil_c1[i] ^ pad_byte
                        p2[i] = c1[i] ^ i2[i]
                        break
        cleartext += p2

    print(stringify(cleartext))


def stringify(numbers):
    return "".join(map(lambda x: chr(x), numbers))


def decrypt(ctx):
    encryption_key = b'\x00' * 16
    hash_key = b'\x01'
    cbc = app.api.encr_decr.Encryption(encryption_key)

    # first decrypt the cookie
    return cbc.decrypt(ctx)


def do_attack(cookie):
    po = PaddingOracle(SETCOINS_FORM_URL)
    cookie_bytes = bytes.fromhex(cookie)
    po_attack(po, cookie_bytes)

def testCookie():
    encryption_key = b'\x00' * 16
    hash_key = b'\x01'
    cbc = app.api.encr_decr.Encryption(encryption_key)

    admin_cookie_pt = get_admin_cookie()

    ctxt = cbc.encrypt(admin_cookie_pt)
    return ctxt.hex()


def get_admin_cookie():
    return app.api.encr_decr.format_plaintext(0, "victim")


if __name__ == '__main__':
    # do_attack("e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d")
    # do_attack("e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d")
    do_attack(testCookie())
    pass
