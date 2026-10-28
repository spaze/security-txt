<?php
/**
 * @testCase
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature\Providers;

use FilesystemIterator;
use gnupg;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotVerifySignatureException;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use SplFileInfo;
use Tester\Assert;
use Tester\TestCase;
use function Spaze\SecurityTxt\Test\gnupgHomeDir;

require __DIR__ . '/../../bootstrap.php';

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

		$gnuPg = new SecurityTxtSignatureGnuPgProvider(gnupgHomeDir());
		$added = $gnuPg->addSignKey('2F632C7E0D1E115599CE14DB1E2FC2BFE8D5E8C4');
		Assert::true($added);
		Assert::false($gnuPg->sign('hack the planet'));
		$errorInfo = $gnuPg->getErrorInfo();
		Assert::same(67109041, $errorInfo->getCode());
		Assert::same('data signing failed', $errorInfo->getMessage());

		$gnuPg = new SecurityTxtSignatureGnuPgProvider(gnupgHomeDir());
		$fingerprint = '81845AF734473E623BB72216EB871D6296D433D2';
		$added = $gnuPg->addSignKey($fingerprint, 'how do you do fellow kids');
		Assert::true($added);
		$signed = $gnuPg->sign('hack the planet');
		assert(is_string($signed));
		$verified = $gnuPg->verify($signed);
		Assert::same($fingerprint, $verified->getFingerprint());
		Assert::same(GNUPG_SIGSUM_VALID | GNUPG_SIGSUM_GREEN, $verified->getSummary());
	}


	/**
	 * GnuPG says nothing about a good signature by a key the keyring has but doesn't trust, no summary bit and no error, which is what a keyring the key was
	 * imported into without ownertrust gives, so it is accepted like one by a key that isn't there, while a bad one still has the red bit
	 */
	public function testVerifyKeyWithoutTrust(): void
	{
		$fingerprint = '81845AF734473E623BB72216EB871D6296D433D2';
		$signer = new SecurityTxtSignatureGnuPgProvider(gnupgHomeDir());
		$signer->addSignKey($fingerprint, 'how do you do fellow kids');
		$signed = $signer->sign('hack the planet');
		assert(is_string($signed));
		$key = new gnupg(['home_dir' => gnupgHomeDir()])->export($fingerprint);
		assert(is_string($key));
		$homeDir = sys_get_temp_dir() . '/security-txt-' . bin2hex(random_bytes(8));
		mkdir($homeDir, 0700);
		try {
			new gnupg(['home_dir' => $homeDir])->import($key);
			$verified = new SecurityTxtSignatureGnuPgProvider($homeDir)->verify($signed);
			Assert::same([$fingerprint, 0, 0], [$verified->getFingerprint(), $verified->getSummary(), $verified->getStatus()]);
			Assert::same($fingerprint, new SecurityTxtSignature(new SecurityTxtSignatureGnuPgProvider($homeDir))->verify($signed)->getKeyFingerprint());
			$tampered = str_replace('hack the planet', 'hack the planets', $signed);
			$verified = new SecurityTxtSignatureGnuPgProvider($homeDir)->verify($tampered);
			Assert::same([GNUPG_SIGSUM_RED, 117440520], [$verified->getSummary(), $verified->getStatus()]);
		} finally {
			foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($homeDir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $file) {
				assert($file instanceof SplFileInfo);
				$file->isDir() && !$file->isLink() ? rmdir($file->getPathname()) : unlink($file->getPathname());
			}
			rmdir($homeDir);
		}
	}


	public function testSignClearsignHeader(): void
	{
		$gnuPg = new SecurityTxtSignatureGnuPgProvider(gnupgHomeDir());
		Assert::true($gnuPg->addSignKey('81845AF734473E623BB72216EB871D6296D433D2', 'how do you do fellow kids'));
		$signature = new SecurityTxtSignature($gnuPg);
		$signed = $gnuPg->sign('i was zero cool');
		assert(is_string($signed));
		Assert::true($signature->isClearsignHeader(trim((new SecurityTxtSplitLines(new SecurityTxtPregSplitProvider()))->splitLines($signed)[0])));
	}


	public function testVerifyInvalidSignature(): void
	{
		$gnuPg = new SecurityTxtSignatureGnuPgProvider(gnupgHomeDir());
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
		$verified = (new SecurityTxtSignatureGnuPgProvider(gnupgHomeDir()))->verify($signed);
		Assert::same('AF6E1775E311FF78E911E7DC7F879001A9C8F50A', $verified->getFingerprint());
		Assert::same(GNUPG_SIGSUM_KEY_MISSING, $verified->getSummary());
		Assert::same(9, $verified->getStatus());
		Assert::same(1753150207, $verified->getTimestamp());
	}

}

(new SecurityTxtSignatureGnuPgProviderTest())->run();
