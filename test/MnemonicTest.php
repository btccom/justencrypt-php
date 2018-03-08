<?php

namespace BitWasp\Bitcoin\Tests\Mnemonic\Bip39;

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use Btccom\JustEncrypt\Encoding\Mnemonic;
use Btccom\JustEncrypt\Encoding\Wordlist;
use Btccom\JustEncrypt\Test\AbstractTestCase;

class MnemonicTest extends AbstractTestCase
{
    /**
     * @return array
     */
    public function getBip39Vectors()
    {
        $file = json_decode($this->dataFile('bip39.json'), true);
        $vectors = [];

        $bip39 = new Mnemonic(new Wordlist());
        foreach ($file as $list => $testSet) {
            foreach ($testSet as $set) {
                $vectors[] = [
                    $bip39,
                    Buffer::hex($set[0]),
                    $set[1],
                    Buffer::hex($set[2])
                ];
            }
        }

        return $vectors;
    }

    /**
     * @dataProvider getBip39Vectors
     * @param Mnemonic $bip39
     * @param BufferInterface $entropy
     * @param $eMnemonic
     * @param BufferInterface $eSeed
     */
    public function testEntropyToMnemonic(Mnemonic $bip39, BufferInterface $entropy, $eMnemonic, BufferInterface $eSeed)
    {
        $mnemonic = $bip39->entropyToMnemonic($entropy);
        $this->assertEquals($eMnemonic, $mnemonic);
    }

    /**
     * @dataProvider getBip39Vectors
     * @param Mnemonic $bip39
     * @param BufferInterface $eEntropy
     * @param $mnemonic
     * @param BufferInterface $eSeed
     */
    public function testMnemonicToEntropy(Mnemonic $bip39, BufferInterface $eEntropy, $mnemonic, BufferInterface $eSeed)
    {
        $entropy = $bip39->mnemonicToEntropy($mnemonic);
        $this->assertEquals($eEntropy->getBinary(), $entropy->getBinary());
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid mnemonic
     */
    public function testIncorrectWordCount()
    {
        $bip39 = new Mnemonic(new Wordlist());
        $mnemonic = 'letter advice';
        $bip39->mnemonicToEntropy($mnemonic);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Checksum does not match
     */
    public function testFailsOnInvalidChecksum()
    {
        $bip39 = new Mnemonic(new Wordlist());
        $mnemonic = 'jelly better achieve collect unaware mountain thought cargo oxygen act hood oxygen';
        $bip39->mnemonicToEntropy($mnemonic);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid entropy, must be multitude of 4 bytes
     */
    public function testFailsOnEntropyMod4()
    {
        $bip39 = new Mnemonic(new Wordlist());
        $bip39->entropyToMnemonic(Buffer::hex(str_repeat('00', 5)));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid entropy, max 1024 bytes
     */
    public function testFailsOnEntropyTooLong()
    {
        $bip39 = new Mnemonic(new Wordlist());
        $bip39->entropyToMnemonic(Buffer::hex(str_repeat('00', 1028)));
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid mnemonic, too long
     */
    public function testFailsOnMnemonicOfEntropyTooLong()
    {
        $bip39 = new Mnemonic(new Wordlist());
        $mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about end grace oxygen maze bright face loan ticket trial leg cruel lizard bread worry reject journey perfect chef section caught neither install industry';
        $bip39->mnemonicToEntropy($mnemonic);
    }
}
