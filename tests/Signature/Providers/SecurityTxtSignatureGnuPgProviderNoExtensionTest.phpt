<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature\Providers;

use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotCreateSignatureExtensionNotLoadedException;
use Tester\Assert;
use Tester\Environment;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtSignatureGnuPgProviderNoExtensionTest extends TestCase
{

	public function testExceptionWhenGnupgExtensionNotLoaded(): void
	{
		if (extension_loaded('gnupg')) {
			if (getenv('TEST_CASE_RUNNER_FORCE_EXT_GNUPG_NOT_LOADED') === '1') {
				Assert::fail('The gnupg extension must not be loaded for this test, run with the php-unix-no-extensions.ini configuration');
			} else {
				Environment::skip('Run this test with the php-unix-no-extensions.ini configuration');
			}
		}

		$gnuPg = new SecurityTxtSignatureGnuPgProvider();
		Assert::throws(function () use ($gnuPg) {
			$gnuPg->getErrorInfo();
		}, SecurityTxtCannotCreateSignatureExtensionNotLoadedException::class);
	}

}

(new SecurityTxtSignatureGnuPgProviderNoExtensionTest())->run();
