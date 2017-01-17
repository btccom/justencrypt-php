<?php

namespace Btccom\JustEncrypt\Test;

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use Btccom\JustEncrypt\EncryptionMnemonic;

class EncryptionMnemonicTest extends AbstractTestCase
{
    /**
     * @return array
     */
    public function getConsistencyCheckVectors()
    {
        return array_map(function (array $row) {
            return [Buffer::hex($row['data']), $row['mnemonic']];
        }, $this->getTestVectors()['mnemonic']);
    }

    /**
     * @dataProvider getConsistencyCheckVectors
     * @param BufferInterface $data
     * @param $mnemonic
     */
    public function testConsistency(BufferInterface $data, $mnemonic)
    {
        $this->assertEquals($mnemonic, EncryptionMnemonic::encode($data));
        $this->assertTrue($data->equals(EncryptionMnemonic::decode($mnemonic)));
    }
}
