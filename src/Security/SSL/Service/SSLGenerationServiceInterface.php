<?php
declare(strict_types=1);

namespace Ktsivkov\SslEncryptor\Security\SSL\Service;

use Ktsivkov\SslEncryptor\Security\SSL\Dto\SSLCertificateDto;

interface SSLGenerationServiceInterface
{
    /**
     * Generates an SSL Certificate and returns it as an SSLCertificateDto object.
     *
     * @return SSLCertificateDto
     */
    public function generate(): SSLCertificateDto;
}
