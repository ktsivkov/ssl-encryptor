<?php
declare(strict_types=1);

namespace Ktsivkov\SslEncryptor\Security\SSL\Service;

use Ktsivkov\SslEncryptor\Security\SSL\Dto\SSLCertificateDto;
use Ktsivkov\SslEncryptor\Security\SSL\Exception\FailedDecryptionException;
use Ktsivkov\SslEncryptor\Security\SSL\Exception\FailedEncryptionException;

interface SSLEncryptionSecurityServiceInterface
{
    /**
     * Encrypts some data based on the provided SSL certificate.
     *
     * @param SSLCertificateDto $certificate
     * @param string $data
     * @return string
     * @throws FailedEncryptionException
     */
    public function encrypt(SSLCertificateDto $certificate, string $data): string;

    /**
     * Decrypts some data using the provided SSL certificate.
     *
     * @param SSLCertificateDto $certificate
     * @param string $data
     * @return string
     * @throws FailedDecryptionException
     */
    public function decrypt(SSLCertificateDto $certificate, string $data): string;
}
