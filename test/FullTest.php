<?php

namespace Btccom\JustEncrypt\Test;

use BitWasp\Buffertools\Buffer;
use BitWasp\Buffertools\BufferInterface;
use Btccom\JustEncrypt\Encryption;
use Btccom\JustEncrypt\EncryptionMnemonic;

class FullTest extends AbstractTestCase
{
    /**
     * @param int $len
     * @return BufferInterface
     */
    public function random($len)
    {
        return new Buffer(random_bytes($len));
    }

    public function testProcedure()
    {
        $passphrase = new Buffer('FFUgnayLMUDLqpTY2bctzBvx5ckPhFt3n5VadNxyMp8XwpZ8SjVJRZpALTWaUvnE7Fru8j8GqgSzC8zdHeQxV6CM2jzL46ULQeRjPXAsVrbSSYnvW8Axrfgv');
        $primarySeed = $this->random(32);
        $secret = $this->random(32);

        $encryptedSecret = Encryption::encrypt($secret, $passphrase)->getBuffer();
        $this->assertTrue($secret->equals(Encryption::decrypt($encryptedSecret, $passphrase)));

        $encryptedPrimarySeed = Encryption::encrypt($primarySeed, $secret)->getBuffer();
        $this->assertTrue($primarySeed->equals(Encryption::decrypt($encryptedPrimarySeed, $secret)));

        $recoverySecret = $this->random(32);
        $recoveryEncryptedSecret = Encryption::encrypt($secret, $recoverySecret)->getBuffer();
        $this->assertTrue($secret->equals(Encryption::decrypt($recoveryEncryptedSecret, $recoverySecret)));

        $backupInfo = [
            'encryptedPrimarySeed' => EncryptionMnemonic::encode($encryptedPrimarySeed),
            'encryptedSecret' => EncryptionMnemonic::encode($encryptedSecret),
            'recoveryEncryptedSecret' => EncryptionMnemonic::encode($recoveryEncryptedSecret),
        ];

        foreach ($backupInfo as $key => $val) {
            $cmp = $$key;
            $this->assertTrue(EncryptionMnemonic::decode($val)->equals($cmp));
        }
    }
}
