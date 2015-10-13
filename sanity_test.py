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

from keccakp import *
from keyak import *
from utils import *

# Generate testing materials
def generate_simple_raw_material(length, seed1, seed2):
	s = ""
	for i in xrange(length):
		iRolled = ((((i % 256) << seed2) | ((i % 256) >> (8 - seed2))) % 256)
		s += chr((seed1 + 161*length - iRolled + i) % 256)
	return s

# Test Keyak engine starting functionality
def test_keyak_start_engine(gl, wrap, unwrap, fout, K, N, forgetFlag, tagFlag):

	fout.write("*** " + wrap.GetInfo()+"\n")
	fout.write("StartEngine(K, N, tagFlag=" + str(tagFlag) + ", T, unwrapFlag=False, forgetFlag=" + str(forgetFlag) + "), with:"+"\n")
	fout.write("> K: [%s]" % K.encode('hex')+"\n")
	fout.write("> N: [%s]" % N.encode('hex')+"\n")

	T = stringStream()

	rv = wrap.StartEngine(K, N, tagFlag, T, False, forgetFlag)
	assert (rv == True), "wrap.StartEngine() did not return true."

	if (tagFlag):
		fout.write("< T (tag): [%s]" % T.getvalue().encode('hex')+"\n")

		empty = stringStream()
		dummy = stringStream()
		TT = stringStream(T.getvalue())
		gl.Wrap(empty, dummy, TT, dummy, False, False)

	T.seek(0, 0)

	rv = unwrap.StartEngine(K, N, tagFlag, T, True, forgetFlag)
	assert (rv == True), "unwrap.StartEngine() did not return true."

	return

# Test Keyak (un)wrapping functionality
def test_keyak_wrap_unwrap(gl, wrap, unwrap, fout, Acontent, Pcontent, forgetFlag):
	metadata = stringStream(Acontent)
	plaintext = stringStream(Pcontent)

	fout.write("Wrap(I, O, A, T, unwrapFlag=false, forgetFlag=" + str(forgetFlag) + "), with:"+"\n")
	fout.write("> A (metadata): [%s]" % metadata.getvalue().encode('hex')+"\n")
	fout.write("> I (plaintext): [%s]" % plaintext.getvalue().encode('hex')+"\n")

	ciphertext = stringStream()
	plaintextPrime = stringStream()
	tag = stringStream()

	rv = wrap.Wrap(plaintext, ciphertext, metadata, tag, False, (forgetFlag != False))
	assert (rv == True), "wrap.Wrap() did not return true."

	fout.write("< O (ciphertext): [%s]" % ciphertext.getvalue().encode('hex')+"\n")
	fout.write("< T (tag): [%s]" % tag.getvalue().encode('hex')+"\n")

	empty = stringStream()
	dummy = stringStream()

	O = stringStream(ciphertext.getvalue())
	T = stringStream(tag.getvalue())

	gl.Wrap(empty, dummy, O, dummy, False, False)
	gl.Wrap(empty, dummy, T, dummy, False, False)

	ciphertext.seek(0, 0)
	metadata.seek(0, 0)
	tag.seek(0, 0)

	rv = unwrap.Wrap(ciphertext, plaintextPrime, metadata, tag, True, (forgetFlag != False))

	assert (rv == True), "unwrap.Wrap() did not return true."
	assert (plaintext.getvalue() == plaintextPrime.getvalue()), "The plaintexts do not match."

	return

# General keyak testing function
def test_keyak(fout, b, nr, Pi, c, tau, expectedGlobalTag):

	gl = Keyak(b, nr, Pi, c, tau)

	print "*** " + gl.GetInfo()

	dummy = stringStream()
	gl.StartEngine("", "", False, dummy, False, False)

	Rs = 168 if (b == 1600) else 68
	Ra = 192 if (b == 1600) else 96
	W = 8 if (b == 1600) else 4

	for Klen in xrange(16, 33):
		for Nlen in xrange(0, 201, (1 if (Klen == 16) else 200)):
			for forgetFlag in [False, True]:
				for tagFlag in [False, True]:
					wrap = Keyak(b, nr, Pi, c, tau)
					unwrap = Keyak(b, nr, Pi, c, tau)

					K = generate_simple_raw_material(Klen, Klen+Nlen+0x12, 3)
					N = generate_simple_raw_material(Nlen, Klen+Nlen+0x45, 6)
					test_keyak_start_engine(gl, wrap, unwrap, fout, K, N, (forgetFlag != False), (tagFlag != False))
					test_keyak_wrap_unwrap(gl, wrap, unwrap, fout, "ABC", "DEF", False)

	Alengths = [0, 1, Pi*(Ra-Rs)-1, Pi*(Ra-Rs), Pi*(Ra-Rs)+1]

	for forgetFlag in [False, True]:
		for tagFlag in [False, True]:
			for Aleni in xrange(len(Alengths)):
				if (Aleni == 0):
					stepSize = 1
				else:
					stepSize = ((Pi+int(forgetFlag))*(W+int(tagFlag)))+1

				for Mlen in xrange(0, (Rs*Pi+1)+1, stepSize):
					Klen = 16
					Nlen = 150 if (b == 1600) else 58
					Alen = Alengths[Aleni]

					wrap = Keyak(b, nr, Pi, c, tau)
					unwrap = Keyak(b, nr, Pi, c, tau)

					K = generate_simple_raw_material(Klen, 0x23+Mlen+Alen, 4)
					N = generate_simple_raw_material(Nlen, 0x56+Mlen+Alen, 7)

					m1 = generate_simple_raw_material(Alen, 0xAB+Mlen+Alen, 3)
					m2 = generate_simple_raw_material(Mlen, 0xCD+Mlen+Alen, 4)

					m3 = generate_simple_raw_material(Alen, 0xCD+Mlen+Alen, 3)
					m4 = generate_simple_raw_material(Mlen, 0xEF+Mlen+Alen, 4)

					test_keyak_start_engine(gl, wrap, unwrap, fout, K, N, (forgetFlag != False), (tagFlag != False))
					test_keyak_wrap_unwrap(gl, wrap, unwrap, fout, m1, m2, (forgetFlag != False))
					test_keyak_wrap_unwrap(gl, wrap, unwrap, fout, m3, m4, (forgetFlag != False))

	Mlengths = [0, 1, Pi*Rs-1, Pi*Rs, Pi*Rs+1]

	for forgetFlag in [False, True]:
		for tagFlag in [False, True]:
			for Mleni in xrange(len(Mlengths)):
				if (Mleni == 0):
					stepSize = 1
				else:
					stepSize = ((Pi+int(forgetFlag))*(W+int(tagFlag)))+1

				for Alen in xrange(0, (Ra*Pi+1)+1, stepSize):
					Klen = 16
					Nlen = 150 if (b == 1600) else 58
					Mlen = Mlengths[Mleni]

					wrap = Keyak(b, nr, Pi, c, tau)
					unwrap = Keyak(b, nr, Pi, c, tau)

					K = generate_simple_raw_material(Klen, 0x34+Mlen+Alen, 5)
					N = generate_simple_raw_material(Nlen, 0x45+Mlen+Alen, 6)

					m1 = generate_simple_raw_material(Alen, 0x01+Mlen+Alen, 5)
					m2 = generate_simple_raw_material(Mlen, 0x23+Mlen+Alen, 6)

					m3 = generate_simple_raw_material(Alen, 0x45+Mlen+Alen, 5)
					m4 = generate_simple_raw_material(Mlen, 0x67+Mlen+Alen, 6)

					test_keyak_start_engine(gl, wrap, unwrap, fout, K, N, (forgetFlag != False), (tagFlag != False))
					test_keyak_wrap_unwrap(gl, wrap, unwrap, fout, m1, m2, (forgetFlag != False))
					test_keyak_wrap_unwrap(gl, wrap, unwrap, fout, m3, m4, (forgetFlag != False))

	for forgetFlag in [False, True]:
		for tagFlag in [False, True]:
			Klen = 16
			Nlen = 150 if (b == 1600) else 58

			wrap = Keyak(b, nr, Pi, c, tau)
			unwrap = Keyak(b, nr, Pi, c, tau)

			K = generate_simple_raw_material(Klen, (int(forgetFlag)*2)+int(tagFlag), 1)
			N = generate_simple_raw_material(Nlen, (int(forgetFlag)*2)+int(tagFlag), 2)

			test_keyak_start_engine(gl, wrap, unwrap, fout, K, N, (forgetFlag != False), (tagFlag != False))

			# Use while loops as Python's range/xrange do not support dynamically updatable stepsizes
			# and a custom iterator seems unnecessary
			Alen = 0
			while (Alen <= (Ra*Pi*2)):
				Mlen = 0
				while (Mlen <= (Rs*Pi*2)):
					m1 = generate_simple_raw_material(Alen, 0x34+Mlen+Alen, 3)
					m2 = generate_simple_raw_material(Mlen, 0x45+Mlen+Alen, 4)

					test_keyak_wrap_unwrap(gl, wrap, unwrap, fout, m1, m2, (forgetFlag != False))

					Mlen += (Mlen/2 + 1 + Alen)

				Alen += (Alen/3 + 1)

	empty = stringStream()
	dummy = stringStream()
	T = stringStream()

	gl.Wrap(empty, dummy, empty, T, False, False)
	fout.write("+++ Global tag: [%s]" % T.getvalue().encode('hex')+"\n")

	if(T.getvalue() != expectedGlobalTag):
		print "!!! The global tag does not match."
		print "Expected: [%s]" % expectedGlobalTag.encode('hex')
		print "Actual: [%s]" % T.getvalue().encode('hex')

	assert (T.getvalue() == expectedGlobalTag), "The global tag is incorrect."

	return

# Sanity test for KeccakF[800], KeccakF[1600]
def test_keccakf():
	test_vectors = {
					# KeccakF-800 test vectors from https://github.com/gvanas/KeccakCodePackage/blob/master/TestVectors/KeccakF-800-IntermediateValues.txt
					800: (bytearray([0 for i in range(800/8)]),
						  bytearray([0x5D, 0xD4, 0x31, 0xE5, 0xFB, 0xC6, 0x04, 0xF4, 0x99, 0xBF, 0xA0, 0x23, 0x2F, 0x45, 0xF8, 0xF1, 0x42, 0xD0, 0xFF, 0x51, 0x78, 0xF5, 0x39, 0xE5, 0xA7, 0x80, 0x0B, 0xF0, 0x64, 0x36, 0x97, 0xAF, 0x4C, 0xF3, 0x5A, 0xBF, 0x24, 0x24, 0x7A, 0x22, 0x15, 0x27, 0x17, 0x88, 0x84, 0x58, 0x68, 0x9F, 0x54, 0xD0, 0x5C, 0xB1, 0x0E, 0xFC, 0xF4, 0x1B, 0x91, 0xFA, 0x66, 0x61, 0x9A, 0x59, 0x9E, 0x1A, 0x1F, 0x0A, 0x97, 0xA3, 0x87, 0x96, 0x65, 0xAB, 0x68, 0x8D, 0xAB, 0xAF, 0x15, 0x10, 0x4B, 0xE7, 0x98, 0x1A, 0x00, 0x34, 0xF3, 0xEF, 0x19, 0x41, 0x76, 0x0E, 0x0A, 0x93, 0x70, 0x80, 0xB2, 0x87, 0x96, 0xE9, 0xEF, 0x11]),
						  bytearray([0x0D, 0x2D, 0xBF, 0x75, 0x89, 0x0E, 0x61, 0x9B, 0x40, 0xAF, 0x26, 0xC8, 0xAB, 0x84, 0xCD, 0x64, 0xD6, 0xBD, 0x05, 0xF9, 0x35, 0x28, 0x83, 0xBC, 0xB9, 0x01, 0x80, 0x5F, 0xCE, 0x2C, 0x66, 0x15, 0x5E, 0xC9, 0x38, 0x8E, 0x43, 0xE5, 0x1F, 0x70, 0x80, 0x43, 0x54, 0x1B, 0xFF, 0xDE, 0xAC, 0x89, 0xDE, 0xB5, 0xED, 0x51, 0xD9, 0x02, 0x97, 0x0E, 0x16, 0xAA, 0x19, 0x6C, 0xEE, 0x3E, 0x91, 0xA2, 0x9A, 0x4E, 0x75, 0x60, 0x3C, 0x06, 0x19, 0x98, 0x54, 0x92, 0x70, 0xF4, 0x84, 0x90, 0x9F, 0xD0, 0x59, 0xA2, 0x2D, 0x77, 0xF7, 0x5D, 0xB3, 0x1D, 0x62, 0x01, 0xA6, 0x5A, 0xD5, 0x25, 0x88, 0x35, 0xAB, 0x3B, 0x78, 0xB3])),

					# KeccakF-1600 test vectors from https://github.com/gvanas/KeccakCodePackage/blob/master/TestVectors/KeccakF-1600-IntermediateValues.txt
					1600: (bytearray([0 for i in range(1600/8)]),
						   bytearray([0xE7, 0xDD, 0xE1, 0x40, 0x79, 0x8F, 0x25, 0xF1, 0x8A, 0x47, 0xC0, 0x33, 0xF9, 0xCC, 0xD5, 0x84, 0xEE, 0xA9, 0x5A, 0xA6, 0x1E, 0x26, 0x98, 0xD5, 0x4D, 0x49, 0x80, 0x6F, 0x30, 0x47, 0x15, 0xBD, 0x57, 0xD0, 0x53, 0x62, 0x05, 0x4E, 0x28, 0x8B, 0xD4, 0x6F, 0x8E, 0x7F, 0x2D, 0xA4, 0x97, 0xFF, 0xC4, 0x47, 0x46, 0xA4, 0xA0, 0xE5, 0xFE, 0x90, 0x76, 0x2E, 0x19, 0xD6, 0x0C, 0xDA, 0x5B, 0x8C, 0x9C, 0x05, 0x19, 0x1B, 0xF7, 0xA6, 0x30, 0xAD, 0x64, 0xFC, 0x8F, 0xD0, 0xB7, 0x5A, 0x93, 0x30, 0x35, 0xD6, 0x17, 0x23, 0x3F, 0xA9, 0x5A, 0xEB, 0x03, 0x21, 0x71, 0x0D, 0x26, 0xE6, 0xA6, 0xA9, 0x5F, 0x55, 0xCF, 0xDB, 0x16, 0x7C, 0xA5, 0x81, 0x26, 0xC8, 0x47, 0x03, 0xCD, 0x31, 0xB8, 0x43, 0x9F, 0x56, 0xA5, 0x11, 0x1A, 0x2F, 0xF2, 0x01, 0x61, 0xAE, 0xD9, 0x21, 0x5A, 0x63, 0xE5, 0x05, 0xF2, 0x70, 0xC9, 0x8C, 0xF2, 0xFE, 0xBE, 0x64, 0x11, 0x66, 0xC4, 0x7B, 0x95, 0x70, 0x36, 0x61, 0xCB, 0x0E, 0xD0, 0x4F, 0x55, 0x5A, 0x7C, 0xB8, 0xC8, 0x32, 0xCF, 0x1C, 0x8A, 0xE8, 0x3E, 0x8C, 0x14, 0x26, 0x3A, 0xAE, 0x22, 0x79, 0x0C, 0x94, 0xE4, 0x09, 0xC5, 0xA2, 0x24, 0xF9, 0x41, 0x18, 0xC2, 0x65, 0x04, 0xE7, 0x26, 0x35, 0xF5, 0x16, 0x3B, 0xA1, 0x30, 0x7F, 0xE9, 0x44, 0xF6, 0x75, 0x49, 0xA2, 0xEC, 0x5C, 0x7B, 0xFF, 0xF1, 0xEA]),
						   bytearray([0x3C, 0xCB, 0x6E, 0xF9, 0x4D, 0x95, 0x5C, 0x2D, 0x6D, 0xB5, 0x57, 0x70, 0xD0, 0x2C, 0x33, 0x6A, 0x6C, 0x6B, 0xD7, 0x70, 0x12, 0x8D, 0x3D, 0x09, 0x94, 0xD0, 0x69, 0x55, 0xB2, 0xD9, 0x20, 0x8A, 0x56, 0xF1, 0xE7, 0xE5, 0x99, 0x4F, 0x9C, 0x4F, 0x38, 0xFB, 0x65, 0xDA, 0xA2, 0xB9, 0x57, 0xF9, 0x0D, 0xAF, 0x75, 0x12, 0xAE, 0x3D, 0x77, 0x85, 0xF7, 0x10, 0xD8, 0xC3, 0x47, 0xF2, 0xF4, 0xFA, 0x59, 0x87, 0x9A, 0xF7, 0xE6, 0x9E, 0x1B, 0x1F, 0x25, 0xB4, 0x98, 0xEE, 0x0F, 0xCC, 0xFE, 0xE4, 0xA1, 0x68, 0xCE, 0xB9, 0xB6, 0x61, 0xCE, 0x68, 0x4F, 0x97, 0x8F, 0xBA, 0xC4, 0x66, 0xEA, 0xDE, 0xF5, 0xB1, 0xAF, 0x6E, 0x83, 0x3D, 0xC4, 0x33, 0xD9, 0xDB, 0x19, 0x27, 0x04, 0x54, 0x06, 0xE0, 0x65, 0x12, 0x83, 0x09, 0xF0, 0xA9, 0xF8, 0x7C, 0x43, 0x47, 0x17, 0xBF, 0xA6, 0x49, 0x54, 0xFD, 0x40, 0x4B, 0x99, 0xD8, 0x33, 0xAD, 0xDD, 0x97, 0x74, 0xE7, 0x0B, 0x5D, 0xFC, 0xD5, 0xEA, 0x48, 0x3C, 0xB0, 0xB7, 0x55, 0xEE, 0xC8, 0xB8, 0xE3, 0xE9, 0x42, 0x9E, 0x64, 0x6E, 0x22, 0xA0, 0x91, 0x7B, 0xDD, 0xBA, 0xE7, 0x29, 0x31, 0x0E, 0x90, 0xE8, 0xCC, 0xA3, 0xFA, 0xC5, 0x9E, 0x2A, 0x20, 0xB6, 0x3D, 0x1C, 0x4E, 0x46, 0x02, 0x34, 0x5B, 0x59, 0x10, 0x4C, 0xA4, 0x62, 0x4E, 0x9F, 0x60, 0x5C, 0xBF, 0x8F, 0x6A, 0xD2, 0x6C, 0xD0, 0x20]))
				   }
	
	nominalNrRounds = {800: 22, 1600: 24}

	for b in nominalNrRounds:
		f = KeccakF(b, nominalNrRounds[b])
		for i in xrange(len(test_vectors[b])-1):			
			s = f.apply(test_vectors[b][i])
			assert (s == test_vectors[b][i+1]), ("[-] KeccakF[%d] test vector %d failed" % (b, i))
	return True

# Sanity test for KeccakP[800, 12], KeccakP[1600, 12]
def test_keccakp():
	test_vectors = {
					# KeccakP[800, 12] test vectors derived from C++ implementation in KeyakTools https://github.com/gvanas/KeccakTools
					800: (bytearray([0 for i in range(800/8)]),
						  bytearray([0x0b, 0x3e, 0x6e, 0x25, 0xcb, 0x9a, 0xeb, 0xd2, 0x4d, 0x7f, 0x25, 0xc1, 0x66, 0x96, 0x36, 0xed, 0xa9, 0xcf, 0x4e, 0xf7, 0xc9, 0xea, 0x4d, 0xd5, 0x8c, 0x30, 0x8e, 0x17, 0x93, 0xea, 0x19, 0x68, 0xad, 0x9f, 0x8d, 0x11, 0xc2, 0x06, 0xfe, 0x01, 0x91, 0xe2, 0x8d, 0x44, 0x92, 0x42, 0x2b, 0xa4, 0x5a, 0xf6, 0x7a, 0x62, 0xc6, 0xf0, 0x49, 0x97, 0x8f, 0xc1, 0xf2, 0xc5, 0x9a, 0x3a, 0xb1, 0x48, 0xc7, 0x33, 0x81, 0xd0, 0x2b, 0xb9, 0xf6, 0x03, 0xe2, 0xa0, 0x81, 0xee, 0xca, 0xe2, 0xb8, 0x38, 0x14, 0xba, 0x14, 0xe9, 0xb8, 0xf2, 0x3d, 0x2d, 0x2e, 0x53, 0x7a, 0x35, 0xac, 0x91, 0x80, 0x49, 0x3a, 0x82, 0x6f, 0xdd]),
						  bytearray([0x5f, 0xe7, 0x4d, 0xf2, 0xd9, 0x31, 0x55, 0x4b, 0xed, 0xb0, 0xe9, 0x81, 0x94, 0xf3, 0x2b, 0x8e, 0xf4, 0x43, 0x74, 0xf7, 0x43, 0xe6, 0xb1, 0x65, 0x61, 0x2a, 0x46, 0xa9, 0xeb, 0x0c, 0xf5, 0x93, 0x21, 0x65, 0x2c, 0xf0, 0xc2, 0x3d, 0x6c, 0x4c, 0x75, 0xc7, 0xcd, 0x32, 0x37, 0xed, 0x22, 0x26, 0x45, 0x36, 0x5b, 0x16, 0x04, 0x4a, 0x9c, 0x40, 0x95, 0x8b, 0x56, 0xb9, 0x66, 0xda, 0xa0, 0xae, 0xfa, 0x0d, 0xd3, 0x9e, 0x0b, 0xae, 0x2e, 0xdd, 0x38, 0x47, 0xb4, 0x33, 0x38, 0x15, 0x74, 0xf4, 0x46, 0x16, 0x9f, 0xbc, 0x8a, 0x34, 0x9a, 0x41, 0xcf, 0xf7, 0xdb, 0xbd, 0xcc, 0x13, 0x9d, 0x5a, 0x82, 0x37, 0xe1, 0x67])),

					# KeccakP[1600, 12] test vectors derived from C++ implementation in KeyakTools https://github.com/gvanas/KeccakTools
					1600: (bytearray([0 for i in range(1600/8)]),
						   bytearray([0x17, 0x86, 0xa7, 0xb9, 0x38, 0x54, 0x5e, 0x8e, 0x1e, 0xd0, 0x59, 0xf2, 0x50, 0x6a, 0xcd, 0xd9, 0x35, 0x1f, 0xa9, 0x52, 0xc6, 0xe7, 0xb8, 0x87, 0xc5, 0xe0, 0xe4, 0xcd, 0x67, 0xe0, 0x93, 0x10, 0x45, 0x5a, 0xd9, 0xf2, 0x90, 0xab, 0x33, 0xb0, 0x45, 0x1a, 0xdd, 0xa8, 0x72, 0x2f, 0xa7, 0xe0, 0x9c, 0x2f, 0x67, 0x14, 0xaa, 0x80, 0x37, 0xc5, 0x1d, 0x07, 0x51, 0x00, 0xf5, 0x47, 0xdd, 0x3e, 0xcc, 0x8a, 0x17, 0x0c, 0x31, 0x1d, 0xa3, 0xb3, 0xa0, 0xaa, 0x57, 0x92, 0xa5, 0x86, 0xb5, 0x79, 0x9b, 0xf9, 0xb1, 0xb3, 0x3d, 0x7c, 0x4a, 0xbc, 0x93, 0x67, 0x8a, 0xe6, 0x63, 0x40, 0x87, 0x68, 0x66, 0x25, 0x0e, 0x2e, 0x33, 0x03, 0x6c, 0x5c, 0xda, 0x30, 0xf0, 0xb9, 0x02, 0x12, 0xaa, 0x9c, 0x9f, 0x7a, 0xcf, 0x2b, 0x78, 0x9a, 0x3b, 0x5f, 0x23, 0x79, 0xae, 0x61, 0xe0, 0xc1, 0x36, 0xe5, 0xec, 0x87, 0x3c, 0xb7, 0x18, 0xb6, 0xe9, 0x6d, 0xc2, 0x8a, 0x91, 0x70, 0xf1, 0xd1, 0xbe, 0x2a, 0xb7, 0x24, 0xed, 0xda, 0x53, 0xbd, 0xab, 0x6a, 0x5a, 0xe1, 0x2e, 0x2c, 0x6a, 0x41, 0xc1, 0xbf, 0xaf, 0x52, 0x09, 0xb9, 0x36, 0xe0, 0xcf, 0xc6, 0xd7, 0x60, 0x70, 0xdc, 0x17, 0x36, 0x50, 0x45, 0xe4, 0x7a, 0x9f, 0xc2, 0xb2, 0x11, 0x56, 0x62, 0x7a, 0x64, 0x30, 0x2c, 0xdb, 0x71, 0x36, 0xd4, 0x1c, 0xa0, 0x2c, 0x22, 0x76, 0x0d, 0xfd, 0xcf]),
						   bytearray([0x04, 0x8c, 0xbb, 0x36, 0xdc, 0x66, 0x03, 0x4b, 0xc9, 0x6a, 0x2d, 0xe6, 0x98, 0x35, 0x16, 0x5f, 0x46, 0xe7, 0x3b, 0x55, 0xde, 0x05, 0x1b, 0x43, 0x6c, 0x7a, 0x61, 0x54, 0xc9, 0x46, 0x9f, 0x48, 0x67, 0x33, 0x47, 0x9b, 0x77, 0x4d, 0xe1, 0x48, 0x63, 0xd6, 0x7b, 0xe3, 0xc0, 0xa3, 0xef, 0x91, 0x5c, 0x93, 0x96, 0x07, 0x18, 0xd3, 0x62, 0xb5, 0x9e, 0x9f, 0xac, 0xf3, 0x8c, 0x22, 0xcf, 0x27, 0x98, 0x5f, 0x2d, 0x8b, 0x4e, 0x0b, 0xad, 0xde, 0xb5, 0x67, 0x0c, 0x1d, 0xd8, 0xda, 0x75, 0x5d, 0x08, 0xfe, 0x66, 0xf6, 0xbc, 0xd4, 0xa7, 0x8b, 0x5f, 0x5e, 0x13, 0x67, 0x8d, 0x9f, 0x73, 0x8f, 0x37, 0x1d, 0x43, 0xfb, 0x79, 0xf6, 0x74, 0xff, 0x33, 0xcf, 0x91, 0x08, 0x52, 0xb4, 0x7b, 0x40, 0x2e, 0xeb, 0xfe, 0x6e, 0x5f, 0x3c, 0x9a, 0xab, 0x6d, 0x94, 0xf9, 0x2f, 0x69, 0xec, 0xb7, 0xeb, 0xcd, 0x32, 0xc5, 0xdd, 0x2c, 0xcf, 0xd9, 0x7c, 0xc1, 0xc7, 0xb7, 0x03, 0x92, 0x48, 0xf7, 0x7a, 0x08, 0x27, 0xb9, 0xbe, 0xba, 0x7f, 0xd2, 0x19, 0x5a, 0x8f, 0x6c, 0x28, 0x43, 0xfd, 0xbf, 0xd8, 0x9c, 0x3d, 0xbc, 0xd5, 0x36, 0x73, 0x1d, 0x11, 0x4c, 0x2b, 0xae, 0x87, 0x48, 0x4d, 0x53, 0x05, 0xf1, 0x1c, 0xff, 0x2d, 0xc8, 0xd9, 0x48, 0xea, 0x3e, 0x89, 0xd8, 0x79, 0xc5, 0xbe, 0x0d, 0xce, 0x3c, 0x95, 0x99, 0x54, 0xf2, 0x2e, 0x0c, 0xec]))
				   }

	# KeccakP permutations for all named instances of Keyak
	permutations = {800: 12, 1600: 12}

	for b in permutations:
		f = KeccakP(b, permutations[b])
		for i in xrange(len(test_vectors[b])-1):			
			s = f.apply(test_vectors[b][i])
			assert (s == test_vectors[b][i+1]), ("[-] KeccakP[%d, %d] test vector %d failed" % (b, permutations[b], i))
	return True

# Sanity test for all named instances of Keyak v2
def test_all_keyak():
	print "[*] Testing RiverKeyak"
	fout = open("TestVectors/RiverKeyak.txt", "wb")
	test_keyak(fout, 800, 12, 1, 256, 128, b"\x6e\xba\x81\x33\x0b\xb8\x5a\x4d\x8d\xb3\x7f\xde\x4d\x67\xcd\x0e")
	fout.close()

	print "[*] Testing LakeKeyak"
	fout = open("TestVectors/LakeKeyak.txt", "wb")
	test_keyak(fout, 1600, 12, 1, 256, 128, b"\x83\x95\xc6\x41\x22\xbb\x43\x04\x32\xd8\xb0\x29\x82\x09\xb7\x36")
	fout.close()

	print "[*] Testing SeaKeyak"
	fout = open("TestVectors/SeaKeyak.txt", "wb")
	test_keyak(fout, 1600, 12, 2, 256, 128, b"\xb8\xc0\xe2\x35\x22\xcc\x1d\xe1\x4c\x22\xd0\xb8\xaf\x73\x8e\x33")
	fout.close()

	print "[*] Testing OceanKeyak"
	fout = open("TestVectors/OceanKeyak.txt", "wb")
	test_keyak(fout, 1600, 12, 4, 256, 128, b"\x70\x7c\x06\x47\xf9\xe8\x52\xb6\x00\xee\xd0\xf1\x1c\x66\xe1\x1d")
	fout.close()

	print "[*] Testing LunarKeyak"
	fout = open("TestVectors/LunarKeyak.txt", "wb")
	test_keyak(fout, 1600, 12, 8, 256, 128, b"\xb7\xec\x21\x1d\xc0\x30\xd2\x4d\x66\x70\x44\xc2\xed\x34\x52\x11")
	fout.close()

	return True

if(test_keccakf()):
	print "[+] KeccakF sanity tests succeeded"

if(test_keccakp()):
	print "[+] KeccakP sanity tests succeeded"	

if(test_all_keyak()):
	print "[+] Keyak sanity tests succeeded"