<?php

namespace Btccom\JustEncrypt;

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Parser;

class Encryption
{

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
        $salt = KeyDerivation::generateSalt();
        $iv = new Buffer(random_bytes(self::IVLEN_BYTES));
        return self::encryptWithSaltAndIV($plainText, $passphrase, $salt, $iv, $iterations);
    }

    /**
     * @param BufferInterface $plainText
     * @param BufferInterface $password
     * @param BufferInterface $salt
     * @param BufferInterface $iv
     * @param int $iterations
     * @return EncryptedBlob
     */
    public static function encryptWithSaltAndIV(BufferInterface $plainText, BufferInterface $password, BufferInterface $salt, BufferInterface $iv, $iterations)
    {
        $header = new HeaderBlob($salt->getSize(), $salt, $iterations);
        $blob = $header->encrypt($plainText, $password, $iv);
        return $blob;
    }

    /**
     * @param BufferInterface $cipherText
     * @param BufferInterface $password
     * @return BufferInterface
     */
    public static function decrypt(BufferInterface $cipherText, BufferInterface $password)
    {
        return EncryptedBlob::fromParser(new Parser($cipherText))->decrypt($password);
    }
}
