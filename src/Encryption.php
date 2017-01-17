<?php

namespace Btccom\JustEncrypt;

use AESGCM\AESGCM;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Parser;

class Encryption
{

    const DEFAULT_SALTLEN = 10;
    const TAGLEN_BITS = 128;
    const IVLEN_BYTES = 16;

    /**
     * @param BufferInterface $plainText
     * @param BufferInterface $passphrase
     * @param int $iterations
     * @return EncryptedBlob
     */
    public static function encrypt(BufferInterface $plainText, BufferInterface $passphrase, $iterations = KeyDerivation::DEFAULT_ITERATIONS)
    {
        $salt = new Buffer(random_bytes(self::DEFAULT_SALTLEN));
        $iv = new Buffer(random_bytes(self::IVLEN_BYTES));
        if (!is_int($iterations) || $iterations < 1) {
            throw new \InvalidArgumentException('Iterations must be an integer > 0');
        }

        return self::encryptWithSaltAndIV($plainText, $passphrase, $salt, $iv, $iterations);
    }

    /**
     * @param BufferInterface $pt
     * @param BufferInterface $pw
     * @param BufferInterface $salt
     * @param BufferInterface $iv
     * @param int $iterations
     * @return EncryptedBlob
     */
    public static function encryptWithSaltAndIV(BufferInterface $pt, BufferInterface $pw, BufferInterface $salt, BufferInterface $iv, $iterations)
    {
        $header = new HeaderBlob($salt->getSize(), $salt, $iterations);

        list ($ct, $tag) = AESGCM::encrypt(
            $header->deriveKey($pw)->getBinary(),
            $iv->getBinary(),
            $pt->getBinary(),
            $header->getBinary()
        );

        return new EncryptedBlob($header, $iv, new Buffer($ct), new Buffer($tag));
    }

    /**
     * @param BufferInterface $ct
     * @param BufferInterface $pw
     * @return BufferInterface
     */
    public static function decrypt(BufferInterface $ct, BufferInterface $pw)
    {
        return EncryptedBlob::fromParser(new Parser($ct))->decrypt($pw);
    }
}
