<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature\Providers;

use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotVerifySignatureException;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtSignatureGnuPgProviderTest extends TestCase
{

	public function testSignAndVerify(): void
	{
		$gnuPg = new SecurityTxtSignatureGnuPgProvider(/* Intentionally no homedir specified */);
		$added = $gnuPg->addSignKey('2F632C7E0D1E115599CE14DB1E2FC2BFE8D5E8C4');
		Assert::false($added);
		$errorInfo = $gnuPg->getErrorInfo();
		Assert::same(117456895, $errorInfo->getCode());
		Assert::same('get_key failed', $errorInfo->getMessage());

		$gnuPg = new SecurityTxtSignatureGnuPgProvider(__DIR__ . '/gnupg');
		$added = $gnuPg->addSignKey('2F632C7E0D1E115599CE14DB1E2FC2BFE8D5E8C4');
		Assert::true($added);
		Assert::false($gnuPg->sign('hack the planet'));
		$errorInfo = $gnuPg->getErrorInfo();
		Assert::same(67109041, $errorInfo->getCode());
		Assert::same('data signing failed', $errorInfo->getMessage());

		$gnuPg = new SecurityTxtSignatureGnuPgProvider(__DIR__ . '/gnupg');
		$fingerprint = '81845AF734473E623BB72216EB871D6296D433D2';
		$added = $gnuPg->addSignKey($fingerprint, 'how do you do fellow kids');
		Assert::true($added);
		$signed = $gnuPg->sign('hack the planet');
		assert(is_string($signed));
		$verified = $gnuPg->verify($signed);
		Assert::same($fingerprint, $verified->getFingerprint());
		Assert::same(GNUPG_SIGSUM_VALID | GNUPG_SIGSUM_GREEN, $verified->getSummary());
	}


	public function testSignClearsignHeader(): void
	{
		$gnuPg = new SecurityTxtSignatureGnuPgProvider(__DIR__ . '/gnupg');
		$signature = new SecurityTxtSignature($gnuPg);
		$signed = $gnuPg->sign('i was zero cool');
		assert(is_string($signed));
		Assert::true($signature->isClearsignHeader(trim(new SecurityTxtSplitLines()->splitLines($signed)[0])));
	}


	public function testVerifyInvalidSignature(): void
	{
		$gnuPg = new SecurityTxtSignatureGnuPgProvider();
		$e = Assert::throws(function () use ($gnuPg): void {
			$gnuPg->verify('fifteen hundred and seven systems in one day');
		}, SecurityTxtCannotVerifySignatureException::class);
		assert($e instanceof SecurityTxtCannotVerifySignatureException);
		Assert::same('Cannot verify signature: verify failed; code: 117440570, source: GPGME, library message: No data', $e->getMessage());
		$errorInfo = $gnuPg->getErrorInfo();
		Assert::same('verify failed', $errorInfo->getMessage());
	}


	public function testVerifyUnknownKey(): void
	{
		$signed = <<< EOT
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		https://youtu.be/H9Anw9hFNQE?t=32
		-----BEGIN PGP SIGNATURE-----

		iJIEARYKADoWIQSvbhd14xH/eOkR59x/h5ABqcj1CgUCaH7y/xwcc3RpbGwudGVz
		dHNAbGlicmFyeS5leGFtcGxlAAoJEH+HkAGpyPUKRvEA/2cVGZs54ieQ7s1nSTla
		6O+JHJNaLOf3llvGRi55gW+BAQCDVLTj2q7cbHPS78lD/uvsgFI3NVWwZx8m72sx
		SmjCCQ==
		=bZYA
		-----END PGP SIGNATURE-----
		EOT;
		$verified = new SecurityTxtSignatureGnuPgProvider()->verify($signed);
		Assert::same('AF6E1775E311FF78E911E7DC7F879001A9C8F50A', $verified->getFingerprint());
		Assert::same(GNUPG_SIGSUM_KEY_MISSING, $verified->getSummary());
		Assert::same(1753150207, $verified->getTimestamp());
	}

}

new SecurityTxtSignatureGnuPgProviderTest()->run();
