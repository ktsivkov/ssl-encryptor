<?php
declare(strict_types=1);

namespace Ktsivkov\SslEncryptor\Security\SSL\Exception;

use RuntimeException;
use Throwable;

class FailedEncryptionException extends RuntimeException
{
    public const MESSAGE = "Encryption Failed";

    public function __construct(private readonly string $publicKey, private readonly string $data, string $message = self::MESSAGE, int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct(message: $message, code: $code, previous: $previous);
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function getData(): string
    {
        return $this->data;
    }
}
