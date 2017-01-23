<?php

require __DIR__ . "/../vendor/autoload.php";

use Btccom\JustEncrypt\Encryption;
use BitWasp\Buffertools\Buffer;

$plainText = 'Hi there, great to meet you!';
$password = new Buffer('われる　われる');

$blob = Encryption::encrypt(new Buffer($plainText), $password);
$encoded = base64_encode($blob->getBinary());

$decoded = new Buffer(base64_decode($encoded));
$plainTextAgain = Encryption::decrypt($decoded, $password);
echo $plainTextAgain->getBinary() . PHP_EOL;