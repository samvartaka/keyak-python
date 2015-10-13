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

from StringIO import StringIO

class stringStream(StringIO):
	# Peek (extract byte without advancing position, return None if no more stream is available)
	def peek(self):
		oldPos = self.tell()
		b = self.read(1)
		newPos = self.tell()
		if((newPos == (oldPos+1)) and (b != '')):
			r = ord(b)
		else:
			r = None

		self.seek(oldPos, 0)
		return r

	# Pop a single byte (as integer representation)
	def get(self):
		return ord(self.read(1))

	# Push a single byte (as integer representation)
	def put(self, b):
		self.write(chr(b))
		return

	# Erase buffered contents
	def erase(self):
		self.truncate(0)
		self.seek(0, 0)
		return

	# Set buffered contents
	def setvalue(self, s):
		self.erase()
		self.write(s)
		return

def hasMore(I):
	return (I.peek() != None)

def enc8(x):
	if (x > 255):
		raise Exception("The integer %d cannot be encoded on 8 bits." % x)
	else:
		return x

# Constant-time comparison from the Django source: https://github.com/django/django/blob/master/django/utils/crypto.py
# Is constant-time only if both strings are of equal length but given the use-case that is always the case.
def constant_time_compare(val1, val2):
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0