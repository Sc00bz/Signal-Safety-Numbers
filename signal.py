#!/usr/bin/python

import hashlib
import binascii

# Just call genSignalSafetyNumbers() with your fingerprint and phone number
# in international format as just numbers and a plus sign (ie "+12223335555")

def genSignalSafetyNumbers(publicKey, phoneNumber):
	# is valid public key/fingerprint
	try:
		if (len(publicKey) == 98):
			publicKey = binascii.unhexlify(publicKey.replace(" ", ""))
		elif (len(publicKey) == 66):
			publicKey = binascii.unhexlify(publicKey)
		elif (len(publicKey) == 64):
			publicKey = "\x05" + binascii.unhexlify(publicKey)
		elif (len(publicKey) == 32):
			publicKey = "\x05" + publicKey
	except:
		return "bad public key"

	if (len(publicKey) != 33 or publicKey[0] != "\x05"):
		return "bad public key"


	# Generate
	m = hashlib.sha512()
	m.update("\0\0")
	m.update(publicKey)
	m.update(phoneNumber)
	m.update(publicKey)
	hash = m.digest()
	for i in xrange(5200-1):
		m = hashlib.sha512()
		m.update(hash)
		m.update(publicKey)
		hash = m.digest()

	safetyNumbers = ""
	for i in xrange(6):
		num = int(binascii.hexlify(hash[5*i : 5*i + 5]), 16) % 100000
		safetyNumbers = safetyNumbers + format(num, '05') + " "

	return safetyNumbers[:-1]

# Test vector from signal
print \
	genSignalSafetyNumbers("05 06 86 3b c6 6d 02 b4 0d 27 b8 d4 9c a7 c0 9e 92 39 23 6f 9d 7d 25 d6 fc ca 5c e1 3c 70 64 d8 68", "+14152222222"), \
	genSignalSafetyNumbers("05 f7 81 b6 fb 32 fe d9 ba 1c f2 de 97 8d 4d 5d a2 8d c3 40 46 ae 81 44 02 b5 c0 db d9 6f da 90 7b", "+14153333333")
print "30035 44776 92869 39689 28698 76765 45825 75691 62576 84344 09180 79131"
