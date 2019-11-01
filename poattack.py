from cryptography.hazmat.primitives import ciphers

SETCOINS_FORM_URL = "http://localhost:8080/setcoins"


# You should implement this padding oracle object
# to craft the requests containing the mauled
# ciphertexts to the right URL.
class PaddingOracle(object):

    def __init__(self, po_url):
        self.url = po_url
        self._block_size_bytes = ciphers.algorithms.AES.block_size / 8

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
    # TODO: Implement padding oracle attack for arbitrary length message.


def do_attack(cookie):
    po = PaddingOracle(SETCOINS_FORM_URL)
    po_attack(po, cookie)


if __name__ == '__main__':
    do_attack("")
    pass
