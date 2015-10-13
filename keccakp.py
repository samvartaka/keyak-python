# -*- coding: utf-8 -*-
# Keyak v2 implementation by Jos Wetzels and Wouter Bokslag
# hereby denoted as "the implementer".

# Based on Keccak Python and Keyak v2 C++ implementations
# by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
# Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer
#
# For more information, feedback or questions, please refer to:
# http://keyak.noekeon.org/
# http://keccak.noekeon.org/
# http://ketje.noekeon.org/

# KeccakF class
# KeccakF(b, n, s) specifies KeccakF[b] (as per Keccak documentation) with n rounds, starting at round index s
class KeccakF(object):
	def __init__(self, b, aNrRounds, aStartRoundIndex = 0):
		self.width = b
		# Alignment unit in bits
		self.W = (b // 25)
		# Alignment unit in bytes
		self.Wb = (self.W // 8)
		self.aNrRounds = aNrRounds
		self.aStartRoundIndex = aStartRoundIndex
		self.nominalNrRounds = (aStartRoundIndex + aNrRounds)

		self._InitRoundConstants()	
		return

	# Public methods
	# Get KeccakF permutation width
	def getWidth(self):
		return self.width

	# Apply permutation to input state
	def apply(self, state):
		# Make sure input state width is correct
		assert(len(state) == (self.width / 8))

		lanes = [[self._load(state[self.Wb*(x+5*y):self.Wb*(x+5*y)+self.Wb]) for y in range(5)] for x in range(5)]
		lanes = self._KeccakFonLanes(lanes)
		state = bytearray(self.width / 8)
		for x in range(5):
			for y in range(5):
				state[self.Wb*(x+5*y):self.Wb*(x+5*y)+self.Wb] = self._store(lanes[x][y])
		return state

	# 'Protected' methods
	# Pre-compute round constant table
	def _InitRoundConstants(self):
		self.RC = [0]*self.nominalNrRounds
		R = 1
		for roundIndex in range(self.nominalNrRounds):
			rc = 0
			for j in range(7):
				R = ((R << 1) ^ ((R >> 7)*0x71)) % 256
				if (R & 2):
					rc ^= (1 << ((1<<j)-1))
			self.RC[roundIndex] = rc
		return

	# Apply permutation to lanes
	def _KeccakFonLanes(self, lanes):
		R = 1
		for roundIndex in range(self.aStartRoundIndex, (self.aStartRoundIndex + self.aNrRounds)):
			# θ
			C = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
			D = [C[(x+4)%5] ^ self._ROL(C[(x+1)%5], 1) for x in range(5)]
			lanes = [[lanes[x][y]^D[x] for y in range(5)] for x in range(5)]

			# ρ and π
			(x, y) = (1, 0)
			current = lanes[x][y]
			for t in range(24):
				(x, y) = (y, (2*x+3*y)%5)
				(current, lanes[x][y]) = (lanes[x][y], self._ROL(current, (t+1)*(t+2)//2))

			# χ
			for y in range(5):
				T = [lanes[x][y] for x in range(5)]
				for x in range(5):
					lanes[x][y] = T[x] ^((~T[(x+1)%5]) & T[(x+2)%5])

			# ι		
			lanes[0][0] ^= self.RC[roundIndex]
		return lanes

	# Helper functions
	def _ROL(self, a, n):
		return ((a >> (self.W-(n%self.W))) + (a << (n%self.W))) % (1 << self.W)

	def _load(self, b):
		return sum((b[i] << (8*i)) for i in range(self.Wb))

	def _store(self, a):
		return list((a >> (8*i)) % 256 for i in range(self.Wb))

# KeccakP class
# KeccakP(b, nr) specifies KeccakP[b, nr] (as per Keyak documentation) and consists of the application of the last nr rounds of KeccakF[b]
class KeccakP(KeccakF):
	def __init__(self, b, nr):
		# Make sure permutation width is valid
		assert(b in [25, 50, 100, 200, 400, 800, 1600])

		# Determine nominal number of rounds and starting round index
		nominalNrRounds = {25: 12, 50: 14, 100: 16, 200: 18, 400: 20, 800: 22, 1600: 24}
		return super(KeccakP, self).__init__(b, nr, (nominalNrRounds[b] - nr))