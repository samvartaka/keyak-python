# Keyak v2 Pure Python Implementation

>MIT License (MIT)
>
>Copyright (c) 2015, Jos Wetzels and Wouter Bokslag

This repository contains a pure Python implementation of Keyak v2 as specified [here](http://keyak.noekeon.org/Keyak-2.0.pdf). This implementation is based on the pure Python [FIPS202](http://keccak.noekeon.org/) and C++ [Keyak v2](https://github.com/gvanas/KeccakTools) implementations by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni, Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer.

For an introductory overview of the algorithms, primitives and design components underlying the Keyak encryption scheme see our accompanying document [Sponges and Engines: An introduction to Keccak and Keyak](sponges_and_engines.pdf) (arXiv:1510.02856) which seeks to condense available literature in order to provide a "bird's eye view" of the matter. For in-depth specifications of [Keccak](http://keccak.noekeon.org) and [Keyak](http://keyak.noekeon.org) (including design considerations and security proofs) see their respective reference documents:

* [Keccak reference document](http://keccak.noekeon.org/Keccak-reference-3.0.pdf)
* [Keyak v2 reference document](http://keyak.noekeon.org/Keyak-2.0.pdf)

## Code structure

* [keyak.py](keyak.py) contains the top-level Keyak object definition and the five named instances (River, Lake, Sea, Ocean and Lunar Keyak) as child classes.
* [motorist.py](motorist.py) contains the object definition of the motorist mode of operation which can be used with a variable underlying primitive.
* [keccakp.py](keccakp.py) contains the KeccakP object definition as a child class of (a modified version of) the KeccakF object as defined in the FIPS202 pure Python implementation by the Keccak team.
* [utils.py](utils.py) contains several helper functions (mostly relating to string streaming functionality).

* [sanity_test.py](sanity_test.py) contains sanity tests for the KeccakF and KeccakP permutations as well as sanity tests for all named Keyak instances as derived from sanity tests contained in the [KeccakTools package](https://github.com/gvanas/KeccakTools).
* [example.py](example.py) contains an example of using Keyak for a simple AEAD message transfer.