import socket
import base64
import string
import os
import sys

tunnel_domain = "a.stonedcoder.org"
filelen = "filelen"
fileget= "file"
BYTES_PER_ENTRY = 3
ENTRIES_PER_RESPONSE = 8

STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
ENCODE_TRANS = string.maketrans(STANDARD_ALPHABET,CUSTOM_ALPHABET)

def dns_get_file_len(file):
	flen = 0
	encfile = base64.b64encode(file).translate(ENCODE_TRANS).replace("=","")
	host = "%s.%s.%s" % (filelen,encfile,tunnel_domain)
	ip = socket.gethostbyname_ex(host)[2][0]
	b = ip.split(".")
	o = 24
	for n in b:
		flen |= (int(n)<<o) 
		o -= 8
	return flen

def dns_get_file_data(file,offset):
	data = []
	encfile = base64.b64encode(file).translate(ENCODE_TRANS).replace("=","")
	host = "%s.%s.%s.%s" % (fileget,encfile, offset, tunnel_domain)
	ips = socket.gethostbyname_ex(host)[2]
	ips.sort(key=lambda x: int(x.split(".")[0]) & 0x0f)
	for i in ips:
		print i
		b = i.split(".")
		for n in xrange((int(b[0]) >> 4)):
			data.append(chr(int(b[1:][n])))
	print " "
	return "".join(data)

if len(sys.argv) < 2:
	print "you need to specify a filename"
	sys.exit()

file = []
for i in xrange(0,dns_get_file_len(sys.argv[1]), BYTES_PER_ENTRY*ENTRIES_PER_RESPONSE):
	file.append(dns_get_file_data(sys.argv[1],i))
print "".join(file)


