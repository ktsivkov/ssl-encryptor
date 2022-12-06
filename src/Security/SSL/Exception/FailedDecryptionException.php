<?php
declare(strict_types=1);

namespace Ktsivkov\SslEncryptor\Security\SSL\Exception;

use RuntimeException;
use Throwable;

class FailedDecryptionException extends RuntimeException
{
    public const MESSAGE = "Decryption Failed";

    public function __construct(private readonly string $privateKey, private readonly string $data, string $message = self::MESSAGE, int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct(message: $message, code: $code, previous: $previous);
    }

    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    public function getData(): string
    {
        return $this->data;
    }
}
