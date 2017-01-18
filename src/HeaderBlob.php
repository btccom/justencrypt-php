<?php

namespace Btccom\JustEncrypt;


use AESGCM\AESGCM;
use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Parser;

class HeaderBlob
{
    /**
     * @var int
     */
    private $saltLen;

    /**
     * @var BufferInterface
     */
    private $salt;

    /**
     * @var int
     */
    private $iterations;

    /**
     * HeaderBlob constructor.
     * @param int $saltLen
     * @param BufferInterface $salt
     * @param int $iterations
     */
    public function __construct($saltLen, BufferInterface $salt, $iterations)
    {
        if ($saltLen > 0x80) {
            throw new \RuntimeException('Salt too long');
        }

        if ($saltLen !== $salt->getSize()) {
            throw new \RuntimeException('Mismatch in salt size');
        }

        if (!is_int($iterations) || $iterations < 1) {
            throw new \InvalidArgumentException('Iterations must be an integer > 0');
        }

        $this->saltLen = $saltLen;
        $this->salt = $salt;
        $this->iterations = $iterations;
    }

    /**
     * @return int
     */
    public function getSaltLen()
    {
        return $this->saltLen;
    }

    /**
     * @return BufferInterface
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * @return int
     */
    public function getIterations()
    {
        return $this->iterations;
    }

    /**
     * @param BufferInterface $passphrase
     * @return BufferInterface
     */
    public function deriveKey(BufferInterface $passphrase)
    {
        if ($passphrase->getSize() === 0) {
            throw new \RuntimeException('Password must not be empty');
        }

        if (!($this->iterations >= 0 && $this->iterations < pow(2, 32))) {
            throw new \RuntimeException('Iterations must be a number between 1 and 2^32');
        }

        if ($this->iterations < 0) {
            throw new \RuntimeException('Iteration count should be at least 1');
        }

        if ($this->salt->getSize() === 0) {
            throw new \RuntimeException('Salt must not be empty');
        }

        if ($this->salt->getSize() > 0x80) {
            throw new \RuntimeException('Sanity check: Invalid salt, length can never be greater than 128');
        }

        return new Buffer(hash_pbkdf2(KeyDerivation::HASHER, $passphrase->getBinary(), $this->salt->getBinary(), $this->iterations, KeyDerivation::KEYLEN_BITS / 8, true));
    }

    /**
     * @return string
     */
    public function getBinary()
    {
        return pack('c', $this->saltLen) . $this->salt->getBinary() . pack('V', $this->iterations);
    }

    /**
     * @param BufferInterface $plainText
     * @param BufferInterface $passphrase
     * @param BufferInterface $iv
     * @return EncryptedBlob
     */
    public function encrypt(BufferInterface $plainText, BufferInterface $passphrase, BufferInterface $iv)
    {
        $iv = $iv ?: new Buffer(random_bytes(16));

        list ($ct, $tag) = AESGCM::encrypt(
            $this->deriveKey($passphrase)->getBinary(),
            $iv->getBinary(),
            $plainText->getBinary(),
            $this->getBinary()
        );

        return new EncryptedBlob($this, $iv, new Buffer($ct), new Buffer($tag));
    }

    /**
     * @return Buffer
     */
    public function getBuffer()
    {
        return new Buffer($this->getBinary());
    }

    /**
     * @param Parser $parser
     * @return HeaderBlob
     */
    public static function fromParser(Parser $parser)
    {
        $saltLen = unpack('c', $parser->readBytes(1)->getBinary())[1];
        $salt = $parser->readBytes($saltLen);
        $iterations = unpack('V', $parser->readBytes(4)->getBinary())[1];
        return new self($saltLen, $salt, $iterations);
    }
}