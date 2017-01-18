<?php

namespace Btccom\JustEncrypt\Test;


use BitWasp\Buffertools\Buffer;
use Btccom\JustEncrypt\EncryptedBlob;
use Btccom\JustEncrypt\HeaderBlob;

class EncryptedBlobTest extends AbstractTestCase
{
    public function testBlobParameters() {
        $header = new HeaderBlob(1, new Buffer("\x00"), 1);
        $iv = new Buffer("\x01", 16);
        $tag = new Buffer("\x02", 16);
        $ciphertext = new Buffer("\x41");
        $encryptedBlob = new EncryptedBlob($header, $iv, $ciphertext, $tag);

        $this->assertSame($header, $encryptedBlob->getHeader());
        $this->assertTrue($iv->equals($encryptedBlob->getIv()));
        $this->assertTrue($tag->equals($encryptedBlob->getTag()));
        $this->assertTrue($ciphertext->equals($encryptedBlob->getCipherText()));

        $expected = $header->getBinary() . $iv->getBinary() . $ciphertext->getBinary() . $tag->getBinary();
        $this->assertEquals($expected, $encryptedBlob->getBinary());
        $this->assertEquals($expected, $encryptedBlob->getBuffer()->getBinary());
    }
}