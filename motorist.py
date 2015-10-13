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

from utils import *

# Pre-PEP 435 compatible 'enum' types
class EnginePhase:
     fresh, crypted, endOfCrypt, endOfMessage = range(4)

class MotoristPhase:
    ready, riding, failed = range(3)

# State class
class State(object):
    def __init__(self, stateSize):
        self.stateSize = stateSize
        self.s = bytearray([0 for i in range(self.stateSize)])
        return

    def reset(self):
        self.s = bytearray([0 for i in range(self.stateSize)])
        return

# Piston class
class Piston(object):
    # Support multiple constructor types
    def __init__(self, *args, **kwargs):
        if(len(kwargs) == 0):
            other = args[0]
            assert(isinstance(other, Piston))
            self.f = other.f
            self.Rs = other.Rs
            self.Ra = other.Ra
            self.EOM = other.EOM
            self.CryptEnd = other.CryptEnd
            self.InjectStart = other.InjectStart
            self.InjectEnd = other.InjectEnd

            b = self.f.getWidth()

            self.state = State((b+7)/8)
            # State is initalized to other state
            self.state.s = other.state.s
        else:
            self.f = kwargs['aF']
            self.Rs = kwargs['aRs']
            self.Ra = kwargs['aRa']         

            b = self.f.getWidth()
            if (self.Rs > self.Ra):
                raise Exception("Rs is larger than Ra.")
            if (self.Ra > ((b-32)/8)):
                raise Exception("Ra is larger than (b-32)/8.")

            # State is initialized to all zero
            self.state = State((b+7)/8)

            self.EOM = self.Ra
            self.CryptEnd = (self.Ra + 1)
            self.InjectStart = (self.Ra + 2)
            self.InjectEnd = (self.Ra + 3)
        return

    # Public methods
    def Crypt(self, I, O, omega, unwrapFlag):
        while(hasMore(I) and (omega < self.Rs)):
            x = I.get()
            O.put(self.state.s[omega] ^ x)
            if(unwrapFlag):
                self.state.s[omega] = x
            else:
                self.state.s[omega] ^= x
            omega += 1
        self.state.s[self.CryptEnd] ^= enc8(omega)
        return

    def Inject(self, X, cryptingFlag):
        if(cryptingFlag):
            omega = self.Rs
        else:
            omega = 0
        self.state.s[self.InjectStart] ^= enc8(omega)

        while(hasMore(X) and (omega < self.Ra)):
            self.state.s[omega] ^= X.get()
            omega += 1

        self.state.s[self.InjectEnd] ^= enc8(omega)
        return

    def Spark(self, eomFlag, l):
        if(eomFlag):
            if (l == 0):
                self.state.s[self.EOM] ^= enc8(255)
            else:
                self.state.s[self.EOM] ^= enc8(l)
        else:
            self.state.s[self.EOM] ^= enc8(0)

        self.state.s = self.f.apply(self.state.s)
        return

    def GetTag(self, T, l):
        if (l > self.Rs):
            raise Exception("The requested tag is too long.")
        for i in xrange(l):
            T.put(self.state.s[i])
        return

# Engine class
class Engine(object):
    def __init__(self, aPistons):
        self.Pi = len(aPistons)
        self.Pistons = aPistons
        self.phase = EnginePhase.fresh
        self.Et = [0x00]*self.Pi
        return

    # Public methods
    def Crypt(self, I, O, unwrapFlag):
        if(self.phase != EnginePhase.fresh):
            raise Exception("The phase must be fresh to call Engine::Crypt().")

        for i in xrange(self.Pi):
            self.Pistons[i].Crypt(I, O, self.Et[i], unwrapFlag)

        if (hasMore(I)):
            self.phase = EnginePhase.crypted
        else:
            self.phase = EnginePhase.endOfCrypt
        return

    def Inject(self, A):
        if ((self.phase != EnginePhase.fresh) and (self.phase != EnginePhase.crypted) and (self.phase != EnginePhase.endOfCrypt)):
            raise Exception("The phase must be fresh, crypted or endOfCrypt to call Engine.Inject().")

        cryptingFlag = ((self.phase == EnginePhase.crypted) or (self.phase == EnginePhase.endOfCrypt))

        for i in xrange(self.Pi):
            self.Pistons[i].Inject(A, cryptingFlag)

        if((self.phase == EnginePhase.crypted) or (hasMore(A))):
            self._Spark(False, [0x00]*self.Pi)
            self.phase = EnginePhase.fresh
        else:
            self.phase = EnginePhase.endOfMessage
        return

    def GetTags(self, T, l):
        if (self.phase != EnginePhase.endOfMessage):
            raise Exception("The phase must be endOfMessage to call Engine.GetTags().")
        self._Spark(True, l)

        for i in xrange(self.Pi):
            self.Pistons[i].GetTag(T, l[i])

        self.phase = EnginePhase.fresh
        return

    def InjectCollective(self, X, diversifyFlag):
        if (self.phase != EnginePhase.fresh):
            raise Exception("The phase must be fresh to call Engine.InjectCollective().")

        Xt = [stringStream() for i in range(self.Pi)]
        while (hasMore(X)):
            x = X.get()
            for i in xrange(self.Pi):
                Xt[i].put(x)

        if (diversifyFlag):
            for i in xrange(self.Pi):
                Xt[i].put(enc8(self.Pi))
                Xt[i].put(enc8(i))

        for i in xrange(self.Pi):
            Xt[i].seek(0, 0)

        while(hasMore(Xt[0])):
            for i in xrange(self.Pi):
                self.Pistons[i].Inject(Xt[i], 0)
            if (hasMore(Xt[0])):
                self._Spark(False, [0x00]*self.Pi)

        self.phase = EnginePhase.endOfMessage
        return

    # 'Protected' methods
    def _Spark(self, eomFlag, l):
        for i in xrange(self.Pi):
            self.Pistons[i].Spark(eomFlag, l[i])
        self.Et = l
        return

# Motorist class
class Motorist(object):
    def __init__(self, aF, aPi, aW, ac, atau):
        self.Pi = aPi
        self.W = aW
        self.c = ac

        self.Pistons = [Piston(aF=aF, aRs=(aW/8*((aF.getWidth() - max(ac, 32))/aW)), aRa=(aW/8*((aF.getWidth() - 32)/aW))) for i in xrange(aPi)]
        self.engine = Engine(self.Pistons)

        self.cprime = (aW*((ac + aW - 1)/aW))

        self.tau = atau
        self.phase = MotoristPhase.ready
        return

    # Public methods
    def StartEngine(self, SUV, tagFlag, T, unwrapFlag, forgetFlag):
        if (self.phase != MotoristPhase.ready):
            raise Exception("The phase must be ready to call Motorist.StartEngine().")

        self.engine.InjectCollective(SUV, True)

        if (forgetFlag):
            self._MakeKnot()

        res = self._HandleTag(tagFlag, T, unwrapFlag)

        if (res):
            self.phase = MotoristPhase.riding
        return res

    def Wrap(self, I, O, A, T, unwrapFlag, forgetFlag):
        if (self.phase != MotoristPhase.riding):
            raise Exception("The phase must be riding to call Motorist.Wrap().")

        if(not(hasMore(I)) and not(hasMore(A))):
            self.engine.Inject(A)

        while (hasMore(I)):
            self.engine.Crypt(I, O, unwrapFlag)
            self.engine.Inject(A)

        while (hasMore(A)):
            self.engine.Inject(A)

        if ((self.Pi > 1) or (forgetFlag)):
            self._MakeKnot()

        res = self._HandleTag(True, T, unwrapFlag)

        if not(res):
            O.erase()
        return res

    # 'Protected' methods
    def _MakeKnot(self):
        Tprime = stringStream()
        self.engine.GetTags(Tprime, [self.cprime/8]*self.Pi)
        Tprime.seek(0, 0)
        self.engine.InjectCollective(Tprime, False)
        return

    def _HandleTag(self, tagFlag, T, unwrapFlag):
        Tprime = stringStream()
        if not(tagFlag):
            self.engine.GetTags(Tprime, [0x00]*self.Pi)
        else:
            l = [0x00]*self.Pi
            l[0] = (self.tau/8)
            self.engine.GetTags(Tprime, l)

            if not(unwrapFlag):
                T.setvalue(Tprime.getvalue())
            elif not(constant_time_compare(Tprime.getvalue(), T.getvalue())):
                self.phase = MotoristPhase.failed
                return False
        return True