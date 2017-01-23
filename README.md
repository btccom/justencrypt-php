### JustEncrypt PHP library
===========================

[![Build Status](https://travis-ci.org/btccom/justencrypt-php.png?branch=master)](https://travis-ci.org/btccom/justencrypt-php)
[![Code Coverage](https://scrutinizer-ci.com/g/btccom/justencrypt-php/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/btccom/justencrypt-php/?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/btccom/justencrypt-php/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/btccom/justencrypt-php/?branch=master)
[![Latest Stable Version](https://poser.pugx.org/btccom/justencrypt-php/v/stable.png)](https://packagist.org/packages/btccom/justencrypt)

#### PHP Support

This library supports PHP versions 5.6 through 7.1. Using PHP 7.1 is *highly*
recommended, because the OpenSSL extension now supports the algorithm we use.
Otherwise, you fall back on a much slower implementation in native PHP.

Usage 
-----

#### Key Derivation

The following example shows simple key derivation from a password/salt/iterations
[Simple derivation example](examples/simple_key_derivation.php)

`KeyDerivation::generateSalt()` will return a salt using the current default.
`Encryption::encrypt` will generate the salt/iterations above using library defaults

#### Encryption

An encrypted blob is the concatenation of `saltLen (uint8) || salt || iv || ct || tag`
The serialized parameters allow us to decrypt on any machine knowing only the password.

[Simple encryption example](examples/simple_encryption.php)
[Advanced example with subkeys & root key recovery](examples/example.php)

Encryption::encrypt returns an [EncryptedBlob](src/EncryptedBlob.php), which encapsulates
key derivation data and ciphertext details. It also exposes useful methods for the ciphertext:
  
  - `$blob->getBinary()` - returns raw binary for encrypted blob, for base64, etc.
  - `$blob->getMnemonic()` - returns the Encryption Mnemonic (see below)
  - `$blob->getBuffer()` - returns a Buffer, useful for converting to hex, etc
 
#### Encryption Mnemonic

To make the result of encrypt human readable (so it is easier to write down) it's possible to encode it as an mnemonic.
We're using the Bitcoin BIP39 way of encoding entropy to mnemonic, but ignoring the (weak) password protection BIP39 originally had.
We also ensure the data is padded correctly.

`$encrypted->getMnemonic()` calls the `EncryptedMnemonic` class to produce 
[Encryption Mnemonic example](examples/simple_encryption_mnemonic.php)

#### Choosing iterations
The default iterations is `justencrypt.KeyDerivation.defaultIterations` and is set to **35000**, 
this is a number that should remain secure enough for a while when using a password.  
If you don't pass in the `iterations` argument it will default to this.

If you're encrypting with a CSPRNG generated random byte string as the password then you can use the same code,
except in that case setting the iterations to 1 is secure as there's no need to stretch the password.  
You can use `justencrypt.KeyDerivation.subkeyIterations` in that case to make it clear what your intentions are.

This type of usage is demonstrated in [this example](examples/example.php)

Development / Contributing
--------------------------

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on contributing.

License
-------

JustEncrypt is released under the terms of the MIT license. See LICENCE.md for more information or see http://opensource.org/licenses/MIT.