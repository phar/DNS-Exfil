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
import hexdump
import lfsr

STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'


parser = argparse.ArgumentParser()
parser.add_argument("-d", "--domain", action="store",required=1, help="domain this server services")
parser.add_argument("-p", "--port", action="store",default=53, help="dns server port number")
parser.add_argument("-r", "--respcnt", action="store",default=10, help="dns entries per query response")
parser.add_argument("-f", "--filedir", action="store",default="files", help="file transfer directory")
parser.add_argument("-s", "--host", action="store",default="localhost", help="tunnel connect host")
parser.add_argument("-c", "--hostport", action="store",default=22, help="tunnel connect port")
parser.add_argument("-x", "--debug", action="store",default=1, help="debug level")
args = parser.parse_args()



DEBUG_LEVEL = int(args.debug)

DEBUG_LEVEL_OFF = 0
DEBUG_LEVEL_NORMAL  = 1
DEBUG_LEVEL_DEBUG = 2
DEBUG_LEVEL_HIGH  = 3


TTL = 0

FILE_TRANSFER_DIR = args.filedir
DECODE_TRANS = string.maketrans(CUSTOM_ALPHABET, STANDARD_ALPHABET)
DNS_RESPONSES_PER_REQUEST = int(args.respcnt)


SESSIONS  = []


def printSessions():
	for s in xrange(len(SESSIONS)):
		print SESSIONS[s].getSeq()
	return None


def getSessionBySeq(seq):
	for s in xrange(len(SESSIONS)):
#		print "sess, %d %d" % (SESSIONS[s].getSeq() , seq)
		if SESSIONS[s].getSeq() == seq:
			return SESSIONS[s]
	return None


def delSessionBySeq(seq):
	for s in xrange(len(SESSIONS)):
		if SESSIONS[s].getSeq() == seq:
			del SESSIONS[s]
			return
	return None


class ProxyConnection():
	def __init__(self, initseq):
		self.seq = lfsr.LFSRThing(initseq)
		self.sock = None
		self.to_client_buff = ""
		self.to_serv_buff = ""
	
	def getSeq(self):
		return self.seq.getVal()

	def setSeq(self, val):
		return self.seq.setVal(val)

	def connect(self, host, port):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect((args.host, int(args.hostport)))
	
	def close(self):
		if self.sock != None:
			self.sock.close()
	
	def server_push(self, data):
		self.to_serv_buff += data
	
	def server_hasdata(self):
		return (len(self.to_serv_buff) > 0)

	def server_push(self, data):
		self.to_serv_buff += data

	def lfsr_inc(self):
		self.seq.lfsr_inc()
	
	def server_pop(self, length):
		if length < len(self.to_serv_buff):
			length = len(self.to_serv_buff)
		poped = self.to_serv_buff[:length]
		self.to_serv_buff = self.to_serv_buff[length:]
		return poped

	def client_push(self, data):
		self.to_client_buff += data

	def client_hasdata(self):
		return (len(self.to_client_buff) > 0)
	
	def client_pop(self, length):
		length = int(length)
		if length > len(self.to_client_buff):
			length = len(self.to_client_buff)

		poped = self.to_client_buff[:length]
		self.to_client_buff = self.to_client_buff[length:]
#		self.seq.lfsr_inc()
		return (self.getSeq(),poped)

	def client_pop_Arecord(self, recordcnt):
		recordcnt = int(recordcnt)
		(seq,data) = self.client_pop(3 * recordcnt)
		datalist = [data[i:i+3] for i in range(0, len(data), 3)]
		records = []
		i = 0
		for dat in datalist:
			payload = 0
			if len(dat) < 3:
				xmtlen = len(dat)
			else:
				xmtlen = 3
			payload |= ((xmtlen & 0x03) << 4)			#payload length
			if  self.client_hasdata():		#is more data
				payload |= (1 << 6)
			payload |= i & 0x0f 						#sequenc
			payload = payload << 24;
			if xmtlen >= 1:
				payload |= ord(dat[0]) << 16
			if xmtlen >= 2:
				payload |= ord(dat[1]) << 8
			if xmtlen >= 3:
				payload |= ord(dat[2])
			i += 1

			records.append(socket.inet_ntoa(struct.pack('>I', payload)))
		return records




def dns_response(request, session, cmd, payload):
	reply = []

	if cmd == "c":
		session.lfsr_inc()
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			session.connect(args.host, args.hostport)
			session_ip = socket.inet_ntoa(struct.pack('>I', session.getSeq()))
			reply.append(session_ip)
		except socket.error:
			debuglog(DEBUG_LEVEL_NORMAL,"connect failed! %s:%d" % (args.host, int(args.hostport)))
			reply.append("0.0.0.0")

	elif cmd == "x":
		session.lfsr_inc()
		debuglog(DEBUG_LEVEL_NORMAL,"close")
		session.close()
		delSessionBySeq(session.getSeq())
		reply.append("0.0.0.0")

	elif cmd in ["d","p"] :
		session.lfsr_inc()
		if cmd == "d":
			session.server_push(payload)

		resps = session.client_pop_Arecord(DNS_RESPONSES_PER_REQUEST)
		if (len(resps)):
			for r in resps:
				reply.append(r)
		else:
			reply.append("0.0.0.0")




#	return reply.pack()
	return reply

class BaseRequestHandler(SocketServer.BaseRequestHandler):
	def get_data(self):
		raise NotImplementedError
	def send_data(self, data):
		raise NotImplementedError
	def handle(self):
		try:
			data = self.get_data()
			request = DNSRecord.parse(data)
			qname = request.q.qname
			qn = str(qname)
			if qn.find('.'+args.domain):
				tdata = qn[:qn.index('.'+args.domain)]
				simplecmd = tdata.split(".")[0]
				answers = []
				if len(simplecmd) <= 2:
					if simplecmd == "sf":
						debuglog(DEBUG_LEVEL_NORMAL,"simple file")
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
						answers.append(data_ip)
						f.close()
			
					elif simplecmd == "f":
						debuglog(DEBUG_LEVEL_NORMAL,"file");
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
							data_ip = socket.inet_ntoa(struct.pack('>I', data))
							answers.append(data_ip)
						f.close()
							
				else:
					tdata = "".join(tdata[1:].split("."))
					needs_padding = len(tdata) % 4
					if needs_padding:
						tdata += b'='* (4 - needs_padding)
					odata = base64.b64decode(tdata.translate(DECODE_TRANS))
					
					hdrstrct = ">LBB"
					
					try:
						(seq,cmd,length) = struct.unpack(hdrstrct,odata[:struct.calcsize(hdrstrct)])
						cmd = chr(cmd)
						payload = odata[struct.calcsize(hdrstrct):struct.calcsize(hdrstrct)+length]

					except:
						debuglog(DEBUG_LEVEL_NORMAL,"error unpacking data from message")
						seq = None
					
					if seq != None:
						session = getSessionBySeq(seq)
					else:
						session = None
						cmd = None
					
					if session == None and cmd == 's':
						debuglog(DEBUG_LEVEL_NORMAL,"new cmd: %s (%s %s) - %s" % (cmd, self.client_address[0], self.client_address[1],  request.q.qname))
						session = ProxyConnection(seq)
						SESSIONS.append(session)
						session.lfsr_inc()
						session.client_push(struct.pack('>I', session.getSeq()))
						answers = session.client_pop_Arecord(struct.calcsize('>I'))
					else:
						if(session != None):
							debuglog(DEBUG_LEVEL_NORMAL,"maint cmd: %s (%s %s) - %s" % (cmd,self.client_address[0], self.client_address[1],  request.q.qname))
							answers = dns_response(request, session, cmd, payload)
						else:
							answers = []
#							print "ignoring for now", qname
#							pass

				if len(answers):
					reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

					for r in answers:
						reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A(r)))
				
					self.send_data(reply.pack())
				else:
					print "ignoring ", qname
			else:
				debuglog(DEBUG_LEVEL_NORMAL,"ignoring (%s %s) - %s" % (self.client_address[0], self.client_address[1],  request.q.qname))
		except DNSError:
			debuglog(DEBUG_LEVEL_NORMAL,"unparsable query \n%s" % hexdump.hexdump(data))


def debuglog(debuglevel, debugstring):
	if DEBUG_LEVEL >= debuglevel:
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
		SocketServer.ThreadingUDPServer(('', int(args.port)), UDPRequestHandler),
	]
	for s in servers:
		thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
		thread.daemon = True  # exit the server thread when the main thread terminates
		thread.start()
		print "%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name)

	while 1:
		inputs = []
		outputs = []
		
		for sess in SESSIONS:
			if sess.sock != None:
				inputs.append(sess.sock)
				outputs.append(sess.sock)
		
		readable, writable, exceptional = select.select(inputs, outputs, inputs, .125)

		for i in xrange(len(SESSIONS)):
			sess = SESSIONS[i]
			if sess.sock in exceptional:
				sess.close()
				del SESSIONS[i]
			if sess.sock in readable:
				try:
					sess.client_push(sess.sock.recv(1024))
				except socket.error:
					sess.close()
					del SESSIONS[i]

			if sess.sock in writable:
				if sess.server_hasdata():
					try:
						sess.sock.send(sess.server_pop(1024))
					except socket.error:
						sess.close()
						del SESSIONS[i]
							
		sys.stderr.flush()
		sys.stdout.flush()


