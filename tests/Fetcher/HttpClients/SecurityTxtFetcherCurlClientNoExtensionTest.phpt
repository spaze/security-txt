<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlExtensionNotLoadedException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherCurlClient;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;
use function Spaze\SecurityTxt\Test\skipIfExtensionLoaded;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtFetcherCurlClientNoExtensionTest extends TestCase
{

	public function testExceptionWhenExtensionNotLoaded(): void
	{
		skipIfExtensionLoaded('curl');
		$client = new SecurityTxtFetcherCurlClient();
		Assert::throws(function () use ($client) {
			$client->getResponse(new SecurityTxtFetcherUrl(new Url('https://example.com/'), []), 'example.com', '192.0.2.1', SecurityTxtIpAddressType::V4);
		}, SecurityTxtCannotOpenUrlExtensionNotLoadedException::class);
	}

}

(new SecurityTxtFetcherCurlClientNoExtensionTest())->run();
