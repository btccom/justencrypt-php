<?php

require "vendor/autoload.php";

use Btccom\JustEncrypt\Encryption;
use Btccom\JustEncrypt\KeyDerivation;
use BitWasp\Buffertools\Buffer;

// Users password, protects secret
$password = new Buffer("password");

// protect secret with the password
$secret = new Buffer(random_bytes(32));
$encryptedSecret = Encryption::encrypt($secret, $password);

// protect secret with the recovery secret - recovery secret to server, user keeps recoveryEncryptedSecret
$recoverySecret = new Buffer(random_bytes(32));
$recoveryEncryptedSecret = Encryption::encrypt($secret, $recoverySecret);

// protect primarySecret with the secret (first usage of secret to encrypt something)
$primarySecret = new Buffer(random_bytes(32));
$encryptedPrimarySecret = Encryption::encrypt($primarySecret, $secret, KeyDerivation::SUBKEY_ITERATIONS);

echo "[private] primary seed: " . $primarySecret->getHex() . PHP_EOL . PHP_EOL;
echo "Encrypted Secret: " . $encryptedSecret->getMnemonic() . PHP_EOL . PHP_EOL;
echo "Encrypted Primary Seed: " . $encryptedPrimarySecret->getMnemonic() . PHP_EOL . PHP_EOL;
echo "Recovery Encrypted Secret: " . $recoveryEncryptedSecret->getMnemonic() . PHP_EOL . PHP_EOL;

// Server returns encrypted secret and encrypted primary secret //

$decryptedSecret = Encryption::decrypt($encryptedSecret->getBuffer(), $password);
$decryptedPrimarySecret = Encryption::decrypt($encryptedPrimarySecret->getBuffer(), $decryptedSecret);
echo "[private] primary seed, decrypted with secret which was decrypted by password: ". $decryptedPrimarySecret->getHex().PHP_EOL;