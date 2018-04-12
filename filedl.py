import socket
import base64
import string
import os
import sys
import argparse

BYTES_PER_ENTRY = 3
ENTRIES_PER_RESPONSE = 15

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--domain", action="store",required=1,help="dns file server")
parser.add_argument("-f", "--file", action="store",required=1, help="filename to download")

args = parser.parse_args()

STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
ENCODE_TRANS = string.maketrans(STANDARD_ALPHABET,CUSTOM_ALPHABET)



def dns_get_file_data(domain,file,offset):
	data = []
	encfile = base64.b64encode(file).translate(ENCODE_TRANS).replace("=","")
	host = "f.%s.%s.%s" % (encfile, offset, domain)
	ips = socket.gethostbyname_ex(host)[2]
	ips.sort(key=lambda x: int(x.split(".")[0]) & 0x0f)
	datalen = 0
	for i in ips:
		b = i.split(".")
		thislen = (int(b[0]) >> 4)
		for n in xrange(thislen):
			data.append(chr(int(b[1:][n])))
		datalen += thislen

	return (datalen,"".join(data))


file = []
stat = 1
filelen = 0
while stat:
	(stat,dat) = dns_get_file_data(args.domain, args.file ,filelen)
	print stat
	filelen += stat
	file.append(dat)
print "".join(file)


