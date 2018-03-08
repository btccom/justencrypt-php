<?php

namespace Btccom\JustEncrypt;

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use Btccom\JustEncrypt\Encoding\Mnemonic;
use Btccom\JustEncrypt\Encoding\Wordlist;

class EncryptionMnemonic
{
    const CHUNK_SIZE = 4;
    const PADDING_DUMMY = "\x81";

    /**
     * @var Mnemonic
     */
    protected static $encoder;

    /**
     * @return Mnemonic
     */
    protected static function getEncoder()
    {
        if (null === static::$encoder) {
            static::$encoder = new Mnemonic(new Wordlist());
        }
        return static::$encoder;
    }

    /**
     * @param string $data
     * @return string
     */
    private static function derivePadding($data)
    {
        if (strlen($data) > 0 && ord($data[0]) > 0x80) {
            throw new \RuntimeException('Sanity check: data for mnemonic is not valid');
        }

        $padLen = self::CHUNK_SIZE - (strlen($data) % self::CHUNK_SIZE);
        return str_pad('', $padLen, self::PADDING_DUMMY);
    }

    /**
     * @param BufferInterface $data
     * @return string
     */
    public static function encode(BufferInterface $data)
    {
        $encoder = static::getEncoder();
        $mnemonic = $encoder->entropyToMnemonic(new Buffer(self::derivePadding($data->getBinary()) . $data->getBinary()));

        try {
            $encoder->mnemonicToEntropy($mnemonic);
        } catch (\Exception $e) {
            throw new \RuntimeException('BIP39 produced an invalid mnemonic');
        }

        return $mnemonic;
    }

    /**
     * @param string $mnemonic
     * @return BufferInterface
     */
    public static function decode($mnemonic)
    {
        $bip39 = static::getEncoder();
        $decoded = $bip39->mnemonicToEntropy($mnemonic)->getBinary();
        $padFinish = 0;
        while ($decoded[$padFinish] === self::PADDING_DUMMY) {
            $padFinish++;
        }

        $data = substr($decoded, $padFinish);
        if (self::derivePadding($data) !== substr($decoded, 0, $padFinish)) {
            throw new \RuntimeException('The data was incorrectly padded');
        }

        return new Buffer($data);
    }
}
