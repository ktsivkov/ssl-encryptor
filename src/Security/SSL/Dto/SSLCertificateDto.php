<?php
declare(strict_types=1);

namespace Ktsivkov\SslEncryptor\Security\SSL\Dto;

class SSLCertificateDto
{
    public function __construct(public readonly string $publicKey, public readonly string $privateKey) {}
}
