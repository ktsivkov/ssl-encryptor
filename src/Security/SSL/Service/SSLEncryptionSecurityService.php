<?php
declare(strict_types=1);

namespace Ktsivkov\SslEncryptor\Security\SSL\Service;

use Ktsivkov\SslEncryptor\Security\SSL\Dto\SSLCertificateDto;
use Ktsivkov\SslEncryptor\Security\SSL\Exception\FailedDecryptionException;
use Ktsivkov\SslEncryptor\Security\SSL\Exception\FailedEncryptionException;
use Throwable;

class SSLEncryptionSecurityService implements SSLEncryptionSecurityServiceInterface
{
    /**
     * {@inheritDoc}
     */
    public function encrypt(SSLCertificateDto $certificate, string $data): string
    {
        try {
            $isSuccessful = openssl_public_encrypt($data, $encrypted, $certificate->publicKey);
        } catch (Throwable $exception) {
            throw new FailedEncryptionException(publicKey: $certificate->publicKey, data: $data, message: FailedEncryptionException::MESSAGE, code: 1, previous: $exception);
        }
        if (!$isSuccessful) {
            throw new FailedEncryptionException(publicKey: $certificate->publicKey, data: $data);
        }
        return $encrypted;
    }

    /**
     * {@inheritDoc}
     */
    public function decrypt(SSLCertificateDto $certificate, string $data): string
    {
        try {
            $isSuccessful = openssl_private_decrypt($data, $decrypted, $certificate->privateKey);
        } catch (Throwable $exception) {
            throw new FailedDecryptionException(privateKey: $certificate->privateKey, data: $data, message: FailedDecryptionException::MESSAGE, code: 1, previous: $exception);
        }
        if (!$isSuccessful) {
            throw new FailedDecryptionException(privateKey: $certificate->privateKey, data: $data);
        }
        return $decrypted;
    }
}
