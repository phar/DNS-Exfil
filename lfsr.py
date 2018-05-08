

class LFSRThing():
	def __init__(self,init=0,taps= [0xFFFFFFFF, (1 << 31), (1 << 21), (1 << 1), (1 << 0), 0]):
		self.taps = taps
		self.lfsr = init
	
	def lfsr_inc(self):
		i = 1
		tap = 0

		while(self.taps[i]):
			tap ^= (self.taps[i] & self.lfsr) > 0
			i+=1
		self.lfsr <<= 1
		self.lfsr |= tap
		self.lfsr &= self.taps[0]
		return self.lfsr

	def getVal(self):
		return self.lfsr

	def setVal(self,val):
		self.lfsr = val

if __name__ == "__main__":
	a = LFSRThing(65)
	print "%08x" % a.lfsr_inc()
	print "%08x" % a.lfsr_inc()
	print "%08x" % a.lfsr_inc()
	print "%08x" % a.lfsr_inc()
