
lfsr_taps4 = [0xF, (1 << 3), (1 << 2), 0]
lfsr_taps8 = [0xFF, (1 << 7), (1 << 5), (1 << 4), (1 << 3), 0]
lfsr_taps12 = [0xFFF, (1 << 11), (1 << 5), (1 << 3), (1 << 0), 0]
lfsr_taps16 = [0xFFFF, (1 << 15), (1 << 14), (1 << 12), (1 << 3), 0]
lfsr_taps20 = [0xFFFFF, (1 << 19), (1 << 16), 0]
lfsr_taps24 = [0xFFFFFF, (1 << 23), (1 << 22), (1 << 21), (1 << 16), 0]
lfsr_taps28 = [0xFFFFFFF, (1 << 27), (1 << 24), 0]
lfsr_taps32 = [0xFFFFFFFF, (1 << 31), (1 << 21), (1 << 1), (1 << 0), 0]


class LFSRThing():
	def __init__(self,taps,init=0):
		self.taps = taps
		self.lfsr = init
	
	def lfsr_inc_32(self):
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

if __name__ == "__main__":
	a = LFSRThing(lfsr_taps32,65)
	print "%08x" % a.lfsr_inc_32()
	print "%08x" % a.lfsr_inc_32()
	print "%08x" % a.lfsr_inc_32()
	print "%08x" % a.lfsr_inc_32()
