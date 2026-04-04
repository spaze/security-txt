<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlExtensionNotLoadedException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherCurlClient;
use Tester\Assert;
use Tester\Environment;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtFetcherCurlClientNoExtensionTest extends TestCase
{

	public function testExceptionWhenExtensionNotLoaded(): void
	{
		if (extension_loaded('curl')) {
			if (getenv('TEST_CASE_RUNNER_FORCE_EXTENSIONS_NOT_LOADED') === '1') {
				Assert::fail('The curl extension must not be loaded for this test, run with the php-unix-no-extensions.ini configuration');
			} else {
				Environment::skip('Run this test with the php-unix-no-extensions.ini configuration');
			}
		}

		$client = new SecurityTxtFetcherCurlClient();
		Assert::throws(function () use ($client) {
			$client->getResponse(new SecurityTxtFetcherUrl('https://example.com/', []), 'example.com', '192.0.2.1', SecurityTxtIpAddressType::V4);
		}, SecurityTxtCannotOpenUrlExtensionNotLoadedException::class);
	}

}

(new SecurityTxtFetcherCurlClientNoExtensionTest())->run();
