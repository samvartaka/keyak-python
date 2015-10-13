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

from motorist import *
from keccakp import *
from utils import *

# Main Keyak class
class Keyak(object):
    def __init__(self, b, nr, Pi, ac, tau):
        self.b = b
        self.nr = nr
        self.Pi = Pi
        self.tau = tau
        self.W = max((b/25), 8)
        self.c = ac
        self.motorist = Motorist(KeccakP(b, nr), Pi, self.W, self.c, tau)
        return

    # Public methods
    def StartEngine(self, K, N, tagFlag, T, unwrapFlag, forgetFlag):
        lk = (self.W/8*((self.c+9+self.W-1)/self.W))
        SUV = stringStream(self._keypack(K, lk) + N)
        return self.motorist.StartEngine(SUV, tagFlag, T, unwrapFlag, forgetFlag)

    def Wrap(self, I, O, A, T, unwrapFlag, forgetFlag):
        return self.motorist.Wrap(I, O, A, T, unwrapFlag, forgetFlag)

    # Fetch info string on keyak object
    def GetInfo(self):
        return "Keyak[b=%d, nr=%d, Pi=%d, c=%d, tau=%d]" % (self.b, self.nr, self.Pi, self.c, self.tau)

    # 'Protected' methods
    def _keypack(self, K, l):
        if ((len(K) + 2) > l):
            raise Exception("The key is too big and does not fit in the key pack.")

        result = chr(enc8(l)) + K + chr(0x01)

        while (len(result) < l):
            result += chr(0x00)
        return result

# Keyak named instances
class RiverKeyak(Keyak):
    def __init__(self):
        return super(RiverKeyak, self).__init__(800, 12, 1, 256, 128)

class LakeKeyak(Keyak):
    def __init__(self):
        return super(LakeKeyak, self).__init__(1600, 12, 1, 256, 128)

class SeaKeyak(Keyak):
    def __init__(self):
        return super(SeaKeyak, self).__init__(1600, 12, 2, 256, 128)

class OceanKeyak(Keyak):
    def __init__(self):
        return super(OceanKeyak, self).__init__(1600, 12, 4, 256, 128)

class LunarKeyak(Keyak):
    def __init__(self):
        return super(LunarKeyak, self).__init__(1600, 12, 8, 256, 128)