<?php

namespace Btccom\JustEncrypt\Test;


use BitWasp\Buffertools\Buffer;
use Btccom\JustEncrypt\HeaderBlob;

class HeaderBlobTest extends AbstractTestCase
{
    public function testValues() {

        $salt = new Buffer(random_bytes(4));
        $iterations = 1024;

        $pw = new Buffer("passwords can be long, and even consist of unprintable characters \x01\x90");

        $headerBlob = new HeaderBlob($salt->getSize(), $salt, $iterations);
        $this->assertEquals($salt->getSize(), $headerBlob->getSaltLen());
        $this->assertEquals($salt->getBinary(), $headerBlob->getSalt()->getBinary());
        $this->assertEquals($iterations, $headerBlob->getIterations());
        $this->assertTrue($salt->equals($headerBlob->getSalt()));

        $expectedBinary = pack('c', $salt->getSize()) . $salt->getBinary() . pack('V', $headerBlob->getIterations());
        $this->assertEquals($expectedBinary, $headerBlob->getBinary());

        $expectedKey = hash_pbkdf2('sha512', $pw->getBinary(), $salt->getBinary(), $iterations, 32, true);
        $this->assertEquals($expectedKey, $headerBlob->deriveKey($pw)->getBinary());
    }
}