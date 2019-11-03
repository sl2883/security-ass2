import siphash

HASH_KEY = b'\x00' * 16

def callhash(hashkey, inval):
    return siphash.SipHash_2_4(hashkey, inval).hash()


def ht_hash(hashkey, inval, htsize):
    return callhash(hashkey, inval) % htsize


class HashValTracker:
    def __init__(self):
        self.myDict = {}

    def insert(self, val):
        count = self.myDict.get(val)

        if count is None:
            count = 1
            self.myDict.setdefault(val, count)
        else:
            count = count + 1
            self.myDict.update({val: count})

        return count


def best_hash_fn(key, max_count):
    len_table = len(key)
    hash_size = 2 ** len_table

    i = 0

    tracker = HashValTracker()
    prev_max_strikes = -1
    best_hash = -1

    while prev_max_strikes < max_count:
        val = i
        inval = str(val).encode('utf8')
        hash_val = ht_hash(key, inval, hash_size)
        strike_count = tracker.insert(str(hash_val))

        if strike_count > max_count:
            print("{} has got {} count".format(hash_val, max_count))
        if strike_count > prev_max_strikes:
            print("Previous max beaten - old {}, new {}".format(prev_max_strikes, strike_count))
            prev_max_strikes = strike_count
            best_hash = hash_val

        i = i + 1

    return best_hash


def find_collision_for_hash(key, best_hash, max_count):
    ret = []
    len_table = len(key)
    hash_size = 2 ** len_table
    i = 0
    count = 0
    while count < max_count:
        val = i
        inval = str(val).encode('utf8')
        hash_val = ht_hash(key, inval, hash_size)

        if hash_val == best_hash:
            count = count + 1
            ret.append(i)
            print("i is {} and hash {} and count is {}".format(i, hash_val, count))

        i = i + 1

    return ret


# Put your collision-finding code here.
# Your function should output the colliding strings in a list.
def find_collisions(key):
    max_count = 20
    best_hash = best_hash_fn(key, max_count)
    ret = find_collision_for_hash(key, best_hash, max_count)

    return ret


def find_collisions_for_n(key, hash, max_count):
    len_table = len(key)
    hash_size = 2 ** len_table
    best_hash = hash
    return find_collision_for_hash(key, best_hash, max_count)

    # class HashTuple:
    #     def __init__(self, h=None, v=None):
    #         self.hash = h
    #         self.val = v
    #
    #     def set_hash(self, h):
    #         self.hash = h
    #
    #     def set_val(self, v):
    #         self.val = v

    # def find_collisions_optimized(key):
    #     len_table = len(key)
    #     hash_size = 2 ** len_table
    #     bits_count = 18
    #     hashes = []
    #     for i in range(2**bits_count):
    #         inval = i.to_bytes(16, 'little')
    #         hash_val = ht_hash(key, inval, hash_size)
    #         hashes.append(HashTuple(hash_val, inval))
    #         # print(i)
    #
    #     hashes.sort(key=lambda hash_tuple: hash_tuple.hash)
    #
    #     max_count = 0
    #     max_index = 0
    #     cur_check = hashes[0].hash
    #     cur_count = 0
    #     for i in range(2 ** bits_count):
    #         if cur_check == hashes[i].hash:
    #             cur_count = cur_count + 1
    #         else:
    #             if cur_count > max_count:
    #                 max_count = cur_count
    #                 max_index = i - cur_count
    #                 cur_check = hashes[i].hash
    #                 cur_count = 1

    pass


# Implement this function, which takes the list of
# collisions and verifies they all have the same
# SipHash output under the given key.
def check_collisions(key, colls):
    len_table = len(key)
    hash_size = 2 ** len_table

    for i in range(len(colls)):
        assert ht_hash(key, colls[i], hash_size) == 1, "collision check failed"
    pass


if __name__ == '__main__':
    # Look in the source code of the app to
    # find the key used for hashing.
    # key = None

    colls = find_collisions(key)
    # check_collisions(key, colls)
