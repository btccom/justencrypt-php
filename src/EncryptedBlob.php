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
        $header = HeaderBlob::fromParser($parser);
        $iv = $parser->readBytes(16);
        $act = $parser->readBytes($size - $parser->getPosition());
        $tag = $act->slice(-16);
        $ct = $act->slice(0, -16);

        return new EncryptedBlob($header, $iv, $tag, $ct);
    }
}