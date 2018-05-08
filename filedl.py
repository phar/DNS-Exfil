import socket
import base64
import string
import os
import sys
import argparse
try:
	import hexdump
	dohexdump = 1
except ImportError:
	dohexdump = 0

BYTES_PER_ENTRY = 3
ENTRIES_PER_RESPONSE = 15

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--domain", action="store",required=1,help="dns file server")
parser.add_argument("-f", "--file", action="store",required=1, help="filename to download")
parser.add_argument("-o", "--out", action="store",required=1,default="-", help="filename to write to")
parser.add_argument("-x", "--hex", action="store",default=0, help="hex output during download")

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


stat = 1
filelen = 0
if args.out == "-":
	f = sys.stdout
else:
	f = open(args.out,"w")
while stat:
	(stat,dat) = dns_get_file_data(args.domain, args.file ,filelen)
	if  dohexdump and (args.hex != 0) :
		hexdump.hexdump(dat)
		print ""
	else:
		print "%d bytes." % stat
	filelen += stat
	f.write(dat)
f.close()


