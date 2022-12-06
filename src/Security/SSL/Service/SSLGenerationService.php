<?php
declare(strict_types=1);

namespace Ktsivkov\SslEncryptor\Security\SSL\Service;

use Ktsivkov\SslEncryptor\Security\SSL\Dto\SSLCertificateDto;

class SSLGenerationService implements SSLGenerationServiceInterface
{
    public function __construct(private readonly array $config = ["digest_alg" => "sha512", "private_key_bits" => 4096, "private_key_type" => OPENSSL_KEYTYPE_RSA,])
    {
    }

    public function generate(): SSLCertificateDto
    {
        $sslKey = openssl_pkey_new($this->config);
        openssl_pkey_export($sslKey, $privateKey);
        $publicKey = openssl_pkey_get_details($sslKey)["key"];
        return new SSLCertificateDto(publicKey: $publicKey, privateKey: $privateKey);
    }
}
