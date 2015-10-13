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

from keyak import *

class Sender():
    def __init__(self, K, N, forgetFlag):
        self.k = LakeKeyak()
        self.T = stringStream()
        status = self.k.StartEngine(K, N, False, self.T, False, forgetFlag)
        assert(status)
        return

    def sendAEADMsg(self, message, metadata, forgetFlag):
        I = stringStream(message)
        A = stringStream(metadata)
        O = stringStream()

        status = self.k.Wrap(I, O, A, self.T, False, forgetFlag)
        assert(status)
        return O.getvalue(), self.T.getvalue()

class Receiver():
    def __init__(self, K, N, forgetFlag):
        self.k = LakeKeyak()
        self.T = stringStream()
        status = self.k.StartEngine(K, N, False, self.T, True, forgetFlag)
        assert(status)
        return

    def recvAEADMsg(self, message, metadata, forgetFlag, T=None):
        I = stringStream(message)
        A = stringStream(metadata)
        O = stringStream()
        if(T):
            self.T = stringStream(T)

        status = self.k.Wrap(I, O, A, self.T, True, forgetFlag)
        assert(status)
        return O.getvalue()

# Test message
test_message = "Hello, world!"
# Test header
test_metadata = "[KeyakV2]"

# Key
K = "221f1c191613100d0a070401fefbf8f5".decode('hex')
# Nonce
N = "433c352e272019120b04fdf6efe8e1da".decode('hex')

sender = Sender(K, N, False)
receiver = Receiver(K, N, False)

print "[+] Plaintext message: [%s]" % test_message

O, T = sender.sendAEADMsg(test_message, test_metadata, False)

print "[+] Sent {Metadata: [%s], Ciphertext: [%s], Tag: [%s]}" % (test_metadata, O.encode('hex'), T.encode('hex'))

P = receiver.recvAEADMsg(O, test_metadata, False, T)

print "[+] Received {Metadata: [%s], Plaintext: [%s], Tag: [%s]}" % (test_metadata, P, T.encode('hex'))

assert (P == test_message), "[-] Decrypted plaintext does not match original plaintext!"