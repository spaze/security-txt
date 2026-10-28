<?php
/**
 * @testCase
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature\Providers;

use Closure;
use FilesystemIterator;
use gnupg;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotVerifySignatureException;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureKeyExpired;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureKeyRevoked;
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
		$this->withKeyring($key, function (string $homeDir) use ($fingerprint, $signed): void {
			$verified = new SecurityTxtSignatureGnuPgProvider($homeDir)->verify($signed);
			Assert::same([$fingerprint, 0, 0], [$verified->getFingerprint(), $verified->getSummary(), $verified->getStatus()]);
			Assert::same($fingerprint, new SecurityTxtSignature(new SecurityTxtSignatureGnuPgProvider($homeDir))->verify($signed)->getKeyFingerprint());
			$tampered = str_replace('hack the planet', 'hack the planets', $signed);
			$verified = new SecurityTxtSignatureGnuPgProvider($homeDir)->verify($tampered);
			Assert::same([GNUPG_SIGSUM_RED, 117440520], [$verified->getSummary(), $verified->getStatus()]);
		});
	}


	/**
	 * GnuPG calls a signature good even when the key that made it has been revoked, the summary and the error say it was
	 */
	public function testVerifyRevokedKey(): void
	{
		$key = <<< EOT
		-----BEGIN PGP PUBLIC KEY BLOCK-----

		mDMEXgvhABYJKwYBBAHaRw8BAQdAJg/6C/ZIl4NtKRRTazdnlvWY7lf+X6nrWpEA
		S0wcwBaIeAQgFgoAIBYhBCvk7spW9+zrybhhGRc92OGhKKJIBQJeC+ECAh0AAAoJ
		EBc92OGhKKJIeokA/ix24SxXQDMUwxDO7vstBn3wpXTZJXxF0v6+Dc4DP9nSAP4n
		oQ+ra8fbHBBSXMpi5EoOb7RvEXSsaW6O9RUTpiM6BbRHUmV2b2tlZCB0ZXN0IGtl
		eSAoaHR0cHM6Ly95b3V0dS5iZS9kUXc0dzlXZ1hjUSkgPHJldm9rZWRAdGVzdHMu
		ZXhhbXBsZT6IkAQTFgoAOBYhBCvk7spW9+zrybhhGRc92OGhKKJIBQJeC+EAAhsD
		BQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEBc92OGhKKJI9fUA/j/hskS7NSky
		eu4ombLUn08raq1gqP8ihmJWZdkAKTYmAQDfHpDYTwB8c0P7Uhviin57VQ6D/6tN
		Lxhogqm2g/iiCA==
		=l4pO
		-----END PGP PUBLIC KEY BLOCK-----
		EOT;
		$signed = <<< EOT
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		they are trashing our rights
		-----BEGIN PGP SIGNATURE-----

		iHUEARYKAB0WIQQr5O7KVvfs68m4YRkXPdjhoSiiSAUCXgvvEAAKCRAXPdjhoSii
		SF+BAQC2Chq3wdLC+wgl6A+wH445FZ1c3rDBvSL8QBm7QJtqNwEAvB576Ul309Jk
		GZQieJeMWJDGOhHDmJwJJ863acE5zgQ=
		=o4vs
		-----END PGP SIGNATURE-----
		EOT;
		$this->withKeyring($key, function (string $homeDir) use ($signed): void {
			$fingerprint = '2BE4EECA56F7ECEBC9B86119173DD8E1A128A248';
			$verified = new SecurityTxtSignatureGnuPgProvider($homeDir)->verify($signed);
			Assert::same([$fingerprint, GNUPG_SIGSUM_KEY_REVOKED, 117440606], [$verified->getFingerprint(), $verified->getSummary(), $verified->getStatus()]);
			$e = Assert::throws(function () use ($homeDir, $signed): void {
				new SecurityTxtSignature(new SecurityTxtSignatureGnuPgProvider($homeDir))->verify($signed);
			}, SecurityTxtError::class);
			assert($e instanceof SecurityTxtError);
			Assert::equal(new SecurityTxtSignatureKeyRevoked($fingerprint), $e->getViolation());
		});
	}


	/**
	 * A key that expired in 2020 after it signed, GnuPG says the signature is good and the key has expired
	 */
	public function testVerifyExpiredKey(): void
	{
		$key = <<< EOT
		-----BEGIN PGP PUBLIC KEY BLOCK-----

		mDMEXgvhABYJKwYBBAHaRw8BAQdAPgByjhW5IJrrzDgpbqiiRU3l5qCSiKVGC7VA
		XU6TLey0R0V4cGlyZWQgdGVzdCBrZXkgKGh0dHBzOi8veW91dHUuYmUvZFF3NHc5
		V2dYY1EpIDxleHBpcmVkQHRlc3RzLmV4YW1wbGU+iJYEExYKAD4WIQT5UiLlVwFo
		yy/qz/g3xaGfQQq6ZAUCXgvhAAIbAwUJAAFRgAULCQgHAgYVCgkICwIEFgIDAQIe
		AQIXgAAKCRA3xaGfQQq6ZLlkAP9Evd/uxtG0ZYuO55lOan9PBLTpb4zgNzrKspyc
		CoSesQEA8NlkElH61dSpbvXw5XuTV7MDJj/r6oQqnH5tOalSLA4=
		=7mh3
		-----END PGP PUBLIC KEY BLOCK-----
		EOT;
		$signed = <<< EOT
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		mess with the best, die like the rest
		-----BEGIN PGP SIGNATURE-----

		iHUEARYKAB0WIQT5UiLlVwFoyy/qz/g3xaGfQQq6ZAUCXgvvEAAKCRA3xaGfQQq6
		ZELFAP9zHEL/CWIkxtOr5lC7OzA3ps0BQJuRieiRL5Z+gMUN4gD9EB/yrXaewnIe
		objK9EKOdNl762LaZCEs4zvS3Y4Y5wM=
		=NEc7
		-----END PGP SIGNATURE-----
		EOT;
		$this->withKeyring($key, function (string $homeDir) use ($signed): void {
			$fingerprint = 'F95222E5570168CB2FEACFF837C5A19F410ABA64';
			$verified = new SecurityTxtSignatureGnuPgProvider($homeDir)->verify($signed);
			Assert::same([$fingerprint, GNUPG_SIGSUM_KEY_EXPIRED, 117440665], [$verified->getFingerprint(), $verified->getSummary(), $verified->getStatus()]);
			$e = Assert::throws(function () use ($homeDir, $signed): void {
				new SecurityTxtSignature(new SecurityTxtSignatureGnuPgProvider($homeDir))->verify($signed);
			}, SecurityTxtError::class);
			assert($e instanceof SecurityTxtError);
			Assert::equal(new SecurityTxtSignatureKeyExpired($fingerprint), $e->getViolation());
			$verified = new SecurityTxtSignatureGnuPgProvider($homeDir)->verify(str_replace('the best', 'the rest', $signed));
			Assert::same([GNUPG_SIGSUM_RED, 117440520], [$verified->getSummary(), $verified->getStatus()]);
		});
	}


	/**
	 * A key that expired in 2020 and was revoked, the summary says only that it has expired, so a signature by an expired key can't be accepted as GnuPG accepts it
	 */
	public function testVerifyExpiredAndRevokedKey(): void
	{
		$key = <<< EOT
		-----BEGIN PGP PUBLIC KEY BLOCK-----

		mDMEXgvhABYJKwYBBAHaRw8BAQdAZwEuXZMzW11IDGChREyYxMqU+sNNDEwmY1OX
		xEguF7OIeAQgFgoAIBYhBEl6Z8SOMVbjwEpkWhoKRAxP7RNaBQJeC+ECAh0AAAoJ
		EBoKRAxP7RNazaYBAMHwR/0PLs5NEkTevsdmDnm/DmF6OSdCzCFDAdE5fbD+AP94
		ViTlvoi/3/ZFDy7geHQ2e3c1iY6/E7x9vopi/N2DAbRbRXhwaXJlZCBhbmQgcmV2
		b2tlZCB0ZXN0IGtleSAoaHR0cHM6Ly95b3V0dS5iZS9kUXc0dzlXZ1hjUSkgPGV4
		cGlyZWQtcmV2b2tlZEB0ZXN0cy5leGFtcGxlPoiWBBMWCgA+FiEESXpnxI4xVuPA
		SmRaGgpEDE/tE1oFAl4L4QACGwMFCQABUYAFCwkIBwIGFQoJCAsCBBYCAwECHgEC
		F4AACgkQGgpEDE/tE1qNQgD9FrksscHm6r+vSxE9VzdeNZHc46bNnd+TvdciGvXV
		jnQA/3gDExWFDUcxKiggCuxRUSuQ9JHRy8uqatmDTN7P5wIC
		=wfNQ
		-----END PGP PUBLIC KEY BLOCK-----
		EOT;
		$signed = <<< EOT
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		never send a boy to do a woman's job
		-----BEGIN PGP SIGNATURE-----

		iHUEARYKAB0WIQRJemfEjjFW48BKZFoaCkQMT+0TWgUCXgvvEAAKCRAaCkQMT+0T
		WiV9AQClKKvUq6ZwoW6PI2TM0jRHWILFbRBTTbotxJgC1JwQzQD7BI+rPCpLKAdY
		Z/R0FfyyO2/Ul30MIXe3315jaTLMJgs=
		=3IhB
		-----END PGP SIGNATURE-----
		EOT;
		$this->withKeyring($key, function (string $homeDir) use ($signed): void {
			$fingerprint = '497A67C48E3156E3C04A645A1A0A440C4FED135A';
			$keyInfo = new gnupg(['home_dir' => $homeDir])->keyinfo($fingerprint);
			Assert::true(is_array($keyInfo[0] ?? null) && $keyInfo[0]['revoked'] === true);
			$verified = new SecurityTxtSignatureGnuPgProvider($homeDir)->verify($signed);
			Assert::same([$fingerprint, GNUPG_SIGSUM_KEY_EXPIRED, 117440665], [$verified->getFingerprint(), $verified->getSummary(), $verified->getStatus()]);
			$e = Assert::throws(function () use ($homeDir, $signed): void {
				new SecurityTxtSignature(new SecurityTxtSignatureGnuPgProvider($homeDir))->verify($signed);
			}, SecurityTxtError::class);
			assert($e instanceof SecurityTxtError);
			Assert::equal(new SecurityTxtSignatureKeyExpired($fingerprint), $e->getViolation());
		});
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


	/**
	 * @param Closure(string): void $test Gets the home directory of a keyring that holds only the key
	 */
	private function withKeyring(string $key, Closure $test): void
	{
		$homeDir = sys_get_temp_dir() . '/security-txt-' . bin2hex(random_bytes(8));
		mkdir($homeDir, 0700);
		try {
			new gnupg(['home_dir' => $homeDir])->import($key);
			$test($homeDir);
		} finally {
			foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($homeDir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $file) {
				assert($file instanceof SplFileInfo);
				$file->isDir() && !$file->isLink() ? rmdir($file->getPathname()) : unlink($file->getPathname());
			}
			rmdir($homeDir);
		}
	}

}

(new SecurityTxtSignatureGnuPgProviderTest())->run();
