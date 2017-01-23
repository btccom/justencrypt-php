<?php

require __DIR__ . "/../vendor/autoload.php";

use Btccom\JustEncrypt\EncryptionMnemonic;
use BitWasp\Buffertools\Buffer;

$encryptedBuffer = new Buffer("\x41\x41\x41\x41\x6e\x6f\x74\x61\x72\x65\x61\x6c\x63\x69\x70\x68\x65\x72\x74\x65\x78\x74");

$mnemonicString = EncryptionMnemonic::encode($encryptedBuffer);
echo "Encoded: " . $mnemonicString . PHP_EOL;

$decoded = EncryptionMnemonic::decode($mnemonicString);
echo "Decoded: " . $decoded->getHex() . PHP_EOL;