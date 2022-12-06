<?php

namespace Ktsivkov\SslEncryptor\Tests\Unit\Security\SSL\Service;

use Ktsivkov\SslEncryptor\Security\SSL\Dto\SSLCertificateDto;
use Ktsivkov\SslEncryptor\Security\SSL\Exception\FailedDecryptionException;
use Ktsivkov\SslEncryptor\Security\SSL\Exception\FailedEncryptionException;
use Ktsivkov\SslEncryptor\Security\SSL\Service\SSLEncryptionSecurityService;
use PHPUnit\Framework\TestCase;

class SSLEncryptionSecurityServiceTest extends TestCase
{
    private const PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsqnvNITFknjCpthz2/6s
KKxa2x2gTdltO/vRZYVr2h9k7/deuYuMGEGPH6mWsiDdLYCnSB+KAg+NNBrnlmcK
flUcc6ims1vCdkJJtWz74BMgCv1tRdshNeprSn67AEup+0R6VCY0Hu9S7gf/+LA3
xWrbeXhWGDV1kMIlkigISi0bkPX/xmulSQKoJo5JrLe8pQ8ZvnrRt6eJ50RRF7EL
hIR25msTKRMm6voc+5cVGp8M+xkIXPPhmGKlKsgWOdIjX1xn6GStCTeJh3c9j68K
TushRssfHqZdYLaVbR9Q1RDm1chSkdyYTKYUdsavpgLH4mGJsDYXI+jtp1BaKL2X
Ui1TQOYTZGJ1Pk0kNmcltAgv2v6YAUMxfMEtOg8VIGsw16Hve7I8ykC+BnD1of+D
qzgj9P2NikUlJIZubxHexd6Yn3Wt8mNVemkG4k4gjl8r9NA00Bym2KaTfF3tLoKT
GO+a/fUz6mZ7xCMjGS6uk6361dWI62fLpH/aWhD/Sfqq6xrFYlP/pY/3Nyfp9Som
l6T31GzxbyTDF3eBQU/Hp3kqZn6RW/n0Wm82F05VsMDNTktfVH2r0G73vAP0ldmt
7AD4ffBhLMYJClv0ckJeLhEfYdzvXWShDproWzfcDl2nPvax79OzPE5W1dJEA9NL
7zQ52/5knUjL5TItXDbk8SsCAwEAAQ==
-----END PUBLIC KEY-----';

    private const PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----
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
VOUfzeJkXmrmKoUq4uz2sFJQdIbDgUNG
-----END PRIVATE KEY-----';

    public function testEncryptSuccess(): void
    {
        $myData = 'dataToEncrypt';
        $SSLEncryptionSecurityService = new SSLEncryptionSecurityService();
        $certificate = new SSLCertificateDto(
            publicKey: self::PUBLIC_KEY,
            privateKey: 'doesntMatter',
        );
        $encrypted = $SSLEncryptionSecurityService->encrypt($certificate, $myData);
        $this->assertIsString($encrypted);
    }

    public function testEncryptFailWrongCertificate(): void
    {
        $myData = 'dataToEncrypt';
        $SSLEncryptionSecurityService = new SSLEncryptionSecurityService();
        $certificate = new SSLCertificateDto(
            publicKey: 'wrongCertificate',
            privateKey: 'doesntMatter',
        );
        $this->expectException(FailedEncryptionException::class);
        $this->expectExceptionCode(1);
        $this->expectExceptionMessage('Encryption Failed');
        $SSLEncryptionSecurityService->encrypt($certificate, $myData);
    }

    public function testDecryptSuccess(): void
    {
        $expected = 'dataToDecrypt';
        $myData = 'GUQ+k50UWN4ec3zDqaa7Ne7kpAtsN0H2HphVUDQPq3ea/VXcbLiupIBi18+7cLGGTBerT/GDLvOVvugmv83G+mknwoTG8/KMxNc+HyycPKJlVgvQ2n4/dmIvfqXClNaOgdFi4gd2Hhk8JX6/Ykv2wT7pBT54bT8hPkSUmYxpPLhgCTY2AEguwS8zHxtfFbCYKlg7jKEWnsEY2OQQ5EJd7Yb2gFBOtoF+wQME6aDTPzrLHWXQ/mmzXF8j+PQCWzMUMD15EGnV+eODKeTvmvjK/J5KB7+WxdalPEBAYRU2M+al1ofzZZBs8236hONFebCOm6PjERPtv5GP+0HLc4oDPukyiLKLeXeZJjmA9pX9cicteF9IbvZqfI1udItS1zzSDWmrP9FAOlJGADgpppeDB2Xr/whymFNGr166XgUoK0B+jIXiEAMtsEVrhQuvUlYOSUm4g9V9UsXIyd9fUcsmcCAXMB2op2lrmM3CxEueVZ/bNO0S1ZntG7rBevCG/OOrA8grcbkYOSt30LV+oijs/mvlGyMYmoosGJ59ojwbEKpTHjG+xoPCHW9v5UG+lJVtzEL0tr6GpLM4m8ckRI+R+MRYuShR9dooL8JSxp5W5CWQBAM+LVROEaBzd7iBnANrlePBCankwEi6RUSm96aE6VgWHE7ST/p9XtvmyrP6kvw=';
        $SSLEncryptionSecurityService = new SSLEncryptionSecurityService();
        $certificate = new SSLCertificateDto(
            publicKey: 'doesntMatter',
            privateKey: self::PRIVATE_KEY,
        );
        $decrypted = $SSLEncryptionSecurityService->decrypt($certificate, base64_decode($myData));
        $this->assertIsString($decrypted);
        $this->assertSame($expected, $decrypted);
    }

    public function testDecryptFailWrongInputData(): void
    {
        $myData = 'GUQ+k50UWN4ec3zDqaa7Ne7kpAtsN0H2HphVUDQPq3ea/VXcbLiupIBi18+7cLGGTBerT/GDLvOVvugmv83G+mknwoTG8/KMxNc+HyycPKJlVgvQ2n4/dmIvfqXClNaOgdFi4gd2Hhk8JX6/Ykv2wT7pBT54bT8hPkSUmYxpPLhgCTY2AEguwS8zHxtfFbCYKlg7jKEWnsEY2OQQ5EJd7Yb2gFBOtoF+wQME6aDTPzrLHWXQ/mmzXF8j+PQCWzMUMD15EGnV+eODKeTvmvjK/J5KB7+WxdalPEBAYRU2M+al1ofzZZBs8236hONFebCOm6PjERPtv5GP+0HLc4oDPukyiLKLeXeZJjmA9pX9cicteF9IbvZqfI1udItS1zzSDWmrP9FAOlJGADgpppeDB2Xr/whymFNGr166XgUoK0B+jIXiEAMtsEVrhQuvUlYOSUm4g9V9UsXIyd9fUcsmcCAXMB2op2lrmM3CxEueVZ/bNO0S1ZntG7rBevCG/OOrA8grcbkYOSt30LV+oijs/mvlGyMYmoosGJ59ojwbEKpTHjG+xoPCHW9v5UG+lJVtzEL0tr6GpLM4m8ckRI+R+MRYuShR9dooL8JSxp5W5CWQBAM+LVROEaBzd7iBnANrlePBCankwEi6RUSm96aE6VgWHE7ST/p9XtvmyrP6kvw=';
        $SSLEncryptionSecurityService = new SSLEncryptionSecurityService();
        $certificate = new SSLCertificateDto(
            publicKey: 'doesntMatter',
            privateKey: self::PRIVATE_KEY,
        );
        $this->expectException(FailedDecryptionException::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('Decryption Failed');
        $SSLEncryptionSecurityService->decrypt($certificate, $myData);
    }

    public function testDecryptFailWrongCertificate(): void
    {
        $myData = 'GUQ+k50UWN4ec3zDqaa7Ne7kpAtsN0H2HphVUDQPq3ea/VXcbLiupIBi18+7cLGGTBerT/GDLvOVvugmv83G+mknwoTG8/KMxNc+HyycPKJlVgvQ2n4/dmIvfqXClNaOgdFi4gd2Hhk8JX6/Ykv2wT7pBT54bT8hPkSUmYxpPLhgCTY2AEguwS8zHxtfFbCYKlg7jKEWnsEY2OQQ5EJd7Yb2gFBOtoF+wQME6aDTPzrLHWXQ/mmzXF8j+PQCWzMUMD15EGnV+eODKeTvmvjK/J5KB7+WxdalPEBAYRU2M+al1ofzZZBs8236hONFebCOm6PjERPtv5GP+0HLc4oDPukyiLKLeXeZJjmA9pX9cicteF9IbvZqfI1udItS1zzSDWmrP9FAOlJGADgpppeDB2Xr/whymFNGr166XgUoK0B+jIXiEAMtsEVrhQuvUlYOSUm4g9V9UsXIyd9fUcsmcCAXMB2op2lrmM3CxEueVZ/bNO0S1ZntG7rBevCG/OOrA8grcbkYOSt30LV+oijs/mvlGyMYmoosGJ59ojwbEKpTHjG+xoPCHW9v5UG+lJVtzEL0tr6GpLM4m8ckRI+R+MRYuShR9dooL8JSxp5W5CWQBAM+LVROEaBzd7iBnANrlePBCankwEi6RUSm96aE6VgWHE7ST/p9XtvmyrP6kvw=';
        $SSLEncryptionSecurityService = new SSLEncryptionSecurityService();
        $certificate = new SSLCertificateDto(
            publicKey: 'doesntMatter',
            privateKey: 'wrongCertificate',
        );
        $this->expectException(FailedDecryptionException::class);
        $this->expectExceptionCode(1);
        $this->expectExceptionMessage('Decryption Failed');
        $SSLEncryptionSecurityService->decrypt($certificate, $myData);
    }

    public function testEncryptDecryptSuccess(): void
    {
        $expected = 'dataToEncrypt';
        $SSLEncryptionSecurityService = new SSLEncryptionSecurityService();
        $certificate = new SSLCertificateDto(
            publicKey: self::PUBLIC_KEY,
            privateKey: self::PRIVATE_KEY,
        );
        $encrypted = $SSLEncryptionSecurityService->encrypt($certificate, $expected);
        $decrypted = $SSLEncryptionSecurityService->decrypt($certificate, $encrypted);
        $this->assertSame($expected, $decrypted);
    }
}
