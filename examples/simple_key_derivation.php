<?php

require __DIR__ . "/../vendor/autoload.php";

use Btccom\JustEncrypt\KeyDerivation;
use BitWasp\Buffertools\Buffer;

$salt = KeyDerivation::generateSalt();
$iterations = 35000;
$key = KeyDerivation::compute(new Buffer('password'), $salt, $iterations);

echo $key->getHex().PHP_EOL;
echo base64_encode($key->getBinary()).PHP_EOL;
