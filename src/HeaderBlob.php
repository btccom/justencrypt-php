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
        return KeyDerivation::compute($passphrase, $this->salt, $this->iterations);
    }

    /**
     * @return string
     */
    public function getBinary()
    {
        return pack('c', $this->saltLen) . $this->salt->getBinary() . pack('V', $this->iterations);
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