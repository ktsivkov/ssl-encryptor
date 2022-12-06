<?php

namespace Ktsivkov\SslEncryptor\Tests\Unit\Security\SSL\Service;

use Ktsivkov\SslEncryptor\Security\SSL\Dto\SSLCertificateDto;
use Ktsivkov\SslEncryptor\Security\SSL\Service\SSLGenerationService;
use PHPUnit\Framework\TestCase;

class SSLGenerationServiceTest extends TestCase
{
    public function testGenerate(): void
    {
        $sslGenerationService = new SSLGenerationService();
        $certificate = $sslGenerationService->generate();
        $this->assertInstanceOf(SSLCertificateDto::class, $certificate);

        $this->assertIsString($certificate->privateKey);
        $this->assertStringStartsWith("-----BEGIN PRIVATE KEY-----\n", $certificate->privateKey);
        $this->assertStringEndsWith("-----END PRIVATE KEY-----\n", $certificate->privateKey);

        $this->assertIsString($certificate->publicKey);
        $this->assertStringStartsWith("-----BEGIN PUBLIC KEY-----\n", $certificate->publicKey);
        $this->assertStringEndsWith("-----END PUBLIC KEY-----\n", $certificate->publicKey);
    }
}
