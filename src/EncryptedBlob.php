<?php

namespace Btccom\JustEncrypt;


use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use BitWasp\Buffertools\Parser;

class EncryptedBlob
{
    /**
     * @var HeaderBlob
     */
    private $header;

    /**
     * @var BufferInterface
     */
    private $iv;

    /**
     * @var BufferInterface
     */
    private $cipherText;

    /**
     * @var BufferInterface
     */
    private $tag;

    /**
     * EncryptedBlob constructor.
     * @param HeaderBlob $header
     * @param BufferInterface $iv
     * @param BufferInterface $cipherText
     * @param BufferInterface $tag
     */
    public function __construct(HeaderBlob $header, BufferInterface $iv, BufferInterface $cipherText, BufferInterface $tag)
    {
        if ($iv->getSize() !== 16) {
            throw new \RuntimeException('IV must be exactly 16 bytes');
        }

        if ($tag->getSize() !== 16) {
            throw new \RuntimeException('Tag must be exactly 16 bytes');
        }

        $this->header = $header;
        $this->iv = $iv;
        $this->cipherText = $cipherText;
        $this->tag = $tag;
    }

    /**
     * @return HeaderBlob
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * @return BufferInterface
     */
    public function getIv()
    {
        return $this->iv;
    }

    /**
     * @return BufferInterface
     */
    public function getCipherText()
    {
        return $this->cipherText;
    }

    /**
     * @return BufferInterface
     */
    public function getTag()
    {
        return $this->tag;
    }

    /**
     * @return string
     */
    public function getMnemonic()
    {
        return EncryptionMnemonic::encode($this->getBuffer());
    }

    /**
     * @return string
     */
    public function getBinary()
    {
        return
            $this->header->getBinary() .
            $this->iv->getBinary() .
            $this->cipherText->getBinary() .
            $this->tag->getBinary();
    }

    /**
     * @return BufferInterface
     */
    public function getBuffer()
    {
        return new Buffer($this->getBinary());
    }

    /**
     * @param Parser $parser
     * @return EncryptedBlob
     */
    public static function fromParser(Parser $parser)
    {
        $size = $parser->getBuffer()->getSize();

        return new EncryptedBlob(
            HeaderBlob::fromParser($parser),
            $parser->readBytes(16),
            $parser->readBytes($size - $parser->getPosition() - 16),
            $parser->readBytes(16)
        );
    }
}