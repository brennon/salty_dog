# SaltyDog - Ruby PBKDF2 Implementation #

## Description ##

SaltyDog is a pure-Ruby implementation of PBKDF2 (password-based key derivation function), as set forth in [PKCS #5: Password-Based Cryptography Standard](http://www.rsa.com/rsalabs/node.asp?id=2127) from RSA Laboratories. PKCS #5 is also under review by the IETF as a potential standard.

Other Ruby implementations of PBKDF2 do exist. However, customizing input parameters to the PBKDF is not as straightforward as one might hope. SaltyDog allows easy customization of hashing scheme, iterations, and other parameters to the function.

## Password-Based Cryptography ##

PKCS #5 represents a set of recommendations for password-based cryptography. The techniques described in PKCS #5 use key derivation techniques that are, relatively speaking, computationally expensive. This expense increases the search space for keys, adding to their security. This is achieved through

 - 'Salting' the plaintext password. In essence, a random number is appended to the plaintext password before hashing the password.
 - Performing extra iterations of hashing on the salted password.

Thus, in the words of the RSA definition, password-based key derivation is defined as a function of a password, a salt, and an iteration count, *where the latter two quantitites need not be kept secret*. For more details about these procedures, refer to the document linked above. Also, note that all random number generation is performed with cryptographically secure functions from the Ruby standard library (OpenSSL::HMAC).

## Quick Example ##

Generate an 80-byte key with the input password +pa55word+ and salt +NaCl+ using the SHA512 hash function and 100,000 iterations.

	SaltyDog::PBKDF2.digest(
		password: 'pa55word', 
		salt: 'NaCl', 
		length: 80, 
		digest: :sha512, 
		iterations: 100000)
		
	=> "fca11af240b5870a4096da3f1f3a1b14cfbdb172f3810b24d6707a9ea897bf26bf903461d9c3f8743878da05fe8794a49f1e78335c7732c044c959bb0ee32d2635ab107bee9f7022fd17778c893fa87f"

## License ##

SaltyDog is Copyright © 2013 Brennon Bortz. SaltyDog is free software, and may be redistributed under the terms specified in LICENSE.md.

## Warranty ##

This software is provided "as is" and without any express or implied warranties, including, without limitation, the implied warranties of merchantability and fitness for a particular purpose.
