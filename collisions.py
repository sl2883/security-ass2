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

    check_collisions(key, ret, best_hash)
    return ret


def find_collisions_for_n(key, hash, max_count):
    len_table = len(key)
    hash_size = 2 ** len_table
    best_hash = hash
    return find_collision_for_hash(key, best_hash, max_count)


# Implement this function, which takes the list of
# collisions and verifies they all have the same
# SipHash output under the given key.
def check_collisions(key, colls, best_hash):
    len_table = len(key)
    hash_size = 2 ** len_table

    for i in range(len(colls)):
        assert ht_hash(key, str(colls[i]).encode('utf8'), hash_size) == best_hash, "collision check failed"
    print("collision check validated")
    pass


if __name__ == '__main__':
    colls = find_collisions(HASH_KEY)
