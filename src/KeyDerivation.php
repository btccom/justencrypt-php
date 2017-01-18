<?php

namespace Btccom\JustEncrypt;

use BitWasp\Buffertools\BufferInterface;

class KeyDerivation
{
    const HASHER = 'sha512';
    const DEFAULT_ITERATIONS = 35000;
    const SUBKEY_ITERATIONS = 1;
    const KEYLEN_BITS = 256;

    /**
     * @param BufferInterface $password
     * @param BufferInterface $salt
     * @param int $iterations
     * @return BufferInterface
     */
    public static function compute(BufferInterface $password, BufferInterface $salt, $iterations)
    {
        $header = new HeaderBlob($salt->getSize(), $salt, $iterations);
        return $header->deriveKey($password);
    }
}
