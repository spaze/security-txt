<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature\Providers;

use Spaze\SecurityTxt\Signature\Exceptions\SecurityTxtCannotCreateSignatureExtensionNotLoadedException;
use Tester\Assert;
use Tester\TestCase;
use function Spaze\SecurityTxt\Test\skipIfExtensionLoaded;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtSignatureGnuPgProviderNoExtensionTest extends TestCase
{

	public function testExceptionWhenGnupgExtensionNotLoaded(): void
	{
		skipIfExtensionLoaded('gnupg');
		$gnuPg = new SecurityTxtSignatureGnuPgProvider();
		Assert::throws(function () use ($gnuPg) {
			$gnuPg->getErrorInfo();
		}, SecurityTxtCannotCreateSignatureExtensionNotLoadedException::class);
	}

}

(new SecurityTxtSignatureGnuPgProviderNoExtensionTest())->run();
