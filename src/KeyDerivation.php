<?php

namespace Btccom\JustEncrypt;

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;

class KeyDerivation
{
    const HASHER = 'sha512';
    const DEFAULT_SALTLEN = 10;
    const DEFAULT_ITERATIONS = 35000;
    const SUBKEY_ITERATIONS = 1;
    const KEYLEN_BITS = 256;

    /**
     * @param int $length
     * @return BufferInterface
     */
    public static function generateSalt($length = self::DEFAULT_SALTLEN)
    {
        if (!is_int($length) || $length < 0 || $length > 128) {
            throw new \RuntimeException('Invalid salt length, should be between 0 - 128 bytes');
        }

        return new Buffer(random_bytes($length));
    }

    /**
     * @param BufferInterface $password
     * @param BufferInterface $salt
     * @param int $iterations
     * @return BufferInterface
     */
    public static function compute(BufferInterface $password, BufferInterface $salt, $iterations = self::DEFAULT_ITERATIONS)
    {
        $header = new HeaderBlob($salt->getSize(), $salt, $iterations);
        return $header->deriveKey($password);
    }
}
