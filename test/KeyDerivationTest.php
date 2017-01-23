<?php

namespace Btccom\JustEncrypt\Test;

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use Btccom\JustEncrypt\HeaderBlob;
use Btccom\JustEncrypt\KeyDerivation;

class KeyDerivationTest extends AbstractTestCase
{
    /**
     * @return array
     */
    public function getKeyDerivationVectors()
    {
        return array_map(function (array $row) {
            if (isset($row['password_utf8'])) {
                $password = new Buffer($row['password_utf8']);
            } else {
                $password = Buffer::hex($row['password']);
            }
            return [$password, Buffer::hex($row['salt']), $row['iterations'], Buffer::hex($row['output'])];
        }, $this->getTestVectors()['keyderivation']);
    }

    /**
     * @param BufferInterface $password
     * @param BufferInterface $salt
     * @param BufferInterface $expectedOutput
     * @param int $iterations
     * @dataProvider getKeyDerivationVectors
     */
    public function testKeyDerivation(BufferInterface $password, BufferInterface $salt, $iterations, BufferInterface $expectedOutput)
    {
        $output = KeyDerivation::compute($password, $salt, $iterations);
        $this->assertTrue($expectedOutput->equals($output), 'key derivation produces same output');
    }
}
