import datetime
import sys
import time
import threading
import traceback
import SocketServer
import socket
import string
import base64
from dnslib import *
import select
import struct
import argparse
import lfsr

STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'


parser = argparse.ArgumentParser()
parser.add_argument("-d", "--domain", action="store",default="localhost", help="domain this server services")
parser.add_argument("-p", "--port", action="store",default=53, help="dns server port number")
parser.add_argument("-r", "--respcnt", action="store",default=10, help="dns entries per query response")
parser.add_argument("-f", "--filedir", action="store",default="files", help="file transfer directory")
parser.add_argument("-s", "--host", action="store",default="localhost", help="tunnel connect host")
parser.add_argument("-c", "--hostport", action="store",default=22, help="tunnel connect port")
args = parser.parse_args()



TTL = 0

FILE_TRANSFER_DIR = args.filedir
DECODE_TRANS = string.maketrans(CUSTOM_ALPHABET, STANDARD_ALPHABET)
DNS_RESPONSES_PER_REQUEST = args.respcnt



sessions = {}



def dns_response(request):
	global sessions
	reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
	qname = request.q.qname
	qn = str(qname)
	qtype = request.q.qtype
	qt = QTYPE[qtype]
	replycount = 0
	
	if qn.find('.'+args.domain):
		tdata = qn[:qn.index('.'+args.domain)]
		splitstring = tdata.split('.')
		if splitstring[0] == "c":
			nonce = int(splitstring[1],16)
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:
				s.connect((args.host, int(args.hostport)))
				debuglog("connect %s:%d" % (args.host, int(args.hostport)))
				seq = lfsr.LFSRThing(lfsr.lfsr_taps32,nonce)

				session_ip = socket.inet_ntoa(struct.pack('>I', seq.getVal()))
				reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A(session_ip)))
				replycount += 1

				sessions[nonce] = {"seq":seq, "sock":s, "inbuff":"", "outbuff":""}
			except:
				print "connect failed! %s:%d" % (args.host, int(args.hostport))
				reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A("0.0.0.0")))
				replycount += 1


		elif splitstring[0] == "close":
			debuglog("close")
			seq = int(splitstring[1],16)
			for n,s in sessions.items():
				if s['seq'].getVal() == seq:
					s['sock'].close()
					sesssions[n]

		elif splitstring[0] == "filelen":
			debuglog("filelen")
			tdata = splitstring[1]
			needs_padding = len(tdata) % 4
			if needs_padding:
				tdata += b'='* (4 - needs_padding)
			data = base64.b64decode(tdata.translate(DECODE_TRANS))
			size = os.path.getsize(FILE_TRANSFER_DIR+os.path.sep+data)
			size_ip = socket.inet_ntoa(struct.pack('>I', size))
			reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A(size_ip)))
			replycount += 1

		elif splitstring[0] == "sf":
			debuglog("simple file")
			tdata = splitstring[2]
			offset = int(splitstring[1])
			try:
				f = open(FILE_TRANSFER_DIR+os.path.sep+os.path.basename(tdata))
				f.seek(offset, 0)
				data = 1
				for e in xrange(3):
					data |= (ord(f.read(1)) << (16 - (8 * e)))
					data |= e << 28;
			except:
				data = 0

			data_ip = socket.inet_ntoa(struct.pack('>I', data))
			reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A(data_ip)))
			replycount += 1
			f.close()

		elif splitstring[0] == "file":
			print "file"
			tdata = splitstring[1]
			offset = int(splitstring[2])
			needs_padding = len(tdata) % 4
			if needs_padding:
				tdata += b'='* (4 - needs_padding)
			data = base64.b64decode(tdata.translate(DECODE_TRANS))
			f = open(FILE_TRANSFER_DIR+os.path.sep+os.path.basename(data))
			f.seek(offset, 0)
			for i in xrange(DNS_RESPONSES_PER_REQUEST):
				data = ((i & 0x0f) << 24)
				try:
					for e in xrange(3):
						data |= (ord(f.read(1)) << (16 - (8 * e)))
						data |= e << 28;
				except:
					print "fixme"
					pass
				data_ip = socket.inet_ntoa(struct.pack('>I', data))
				reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A(data_ip)))
				replycount += 1

			f.close()

		elif splitstring[0] in ["d","p"] :
			seq = int(splitstring[1],16)

			for n,s in sessions.items():

				if s['seq'].getVal() == seq:
					s['seq'].lfsr_inc_32()
					if splitstring[0] == "d":
						tdata = "".join(splitstring[2:])
						needs_padding = len(tdata) % 4
						if needs_padding:
							tdata += b'='* (4 - needs_padding)
						data = base64.b64decode(tdata.translate(DECODE_TRANS))
						s['outbuff'] += data

					if s['inbuff']:
						for i in xrange(DNS_RESPONSES_PER_REQUEST):
							if len(s['inbuff']):
								payload  = 0

								if len(s['inbuff']) < 3:
									xmtlen = len(s['inbuff'])
								else:
									xmtlen = 3

								payload |= ((xmtlen & 0x03) << 4)			#payload length

								if  len(s['inbuff']) > xmtlen:		#is more data
									payload |= (1 << 6)

								payload |= i & 0x0f 						#sequenc
								payload = payload << 24;
								if xmtlen >= 1:
									payload |= ord(s['inbuff'][0]) << 16
								if xmtlen >= 2:
									payload |= ord(s['inbuff'][1]) << 8
								if xmtlen >= 3:
									payload |= ord(s['inbuff'][2])
								
								seq_ip = socket.inet_ntoa(struct.pack('>I', payload))
								reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A(seq_ip)))
								replycount += 1
								s['inbuff'] = s['inbuff'][3:]

	else:
		print "not for me, ignored"
		pass

	if replycount == 0:
		reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A("0.0.0.0")))
	return reply.pack()


class BaseRequestHandler(SocketServer.BaseRequestHandler):
	def get_data(self):
		raise NotImplementedError
	def send_data(self, data):
		raise NotImplementedError
	def handle(self):
		try:
			data = self.get_data()
			request = DNSRecord.parse(data)
			debuglog("request (%s %s) - %s" % (self.client_address[0], self.client_address[1],  request.q.qname))
			self.send_data(dns_response(request))
		except Exception:
			pass


def debuglog(debugstring):
	now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
	print "[%s] - %s" % (now,debugstring)

class UDPRequestHandler(BaseRequestHandler):
	def get_data(self):
		return self.request[0].strip()
	def send_data(self, data):
		return self.request[1].sendto(data, self.client_address)


if __name__ == '__main__':
	print "Starting nameserver..."


	servers = [
		SocketServer.ThreadingUDPServer(('', args.port), UDPRequestHandler),
	]
	for s in servers:
		thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
		thread.daemon = True  # exit the server thread when the main thread terminates
		thread.start()
		print "%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name)

#	try:
	while 1:
		inputs = []
		outputs = []
		for n,s in sessions.items():
			inputs.append(s['sock'])
			outputs.append(s['sock'])

		readable, writable, exceptional = select.select(inputs, outputs, inputs, .125)

		for r in exceptional:
			for n,s in sessions.items():
				if w == s['sock']:
					print "exception, closed"
					del sessions[n]

		for r in readable:
			for n,s in sessions.items():
				if r == s['sock']:
					try:
						s['inbuff'] += s['sock'].recv(1024)
					except socket.error:
						#fixme
						pass
					break

		for w in writable:
			for n,s in sessions.items():
				if w == s['sock']:
					if len(s['outbuff']):
						try:
							s['sock'].send(s['outbuff'])
							s['outbuff'] = ""
						except socket.error:
							#fixme remove socket
							pass
						break

		sys.stderr.flush()
		sys.stdout.flush()


