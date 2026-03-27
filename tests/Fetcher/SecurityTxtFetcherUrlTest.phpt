<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlUnsupportedSchemeException;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtFetcherUrlTest extends TestCase
{

	public function testGetters(): void
	{
		$url = new SecurityTxtFetcherUrl('https://example.com/', ['https://1.example/', 'https://2.example/'], '1.1.1.0', DNS_A);
		Assert::same('https://example.com/', $url->getUrl());
		Assert::same(['https://1.example/', 'https://2.example/'], $url->getRedirects());
	}


	public function testUnsupportedScheme(): void
	{
		Assert::noError(function (): void {
			new SecurityTxtFetcherUrl('http://example.com/', [], '1.1.1.0', DNS_A);
			new SecurityTxtFetcherUrl('https://example.com/', [], '1.1.1.0', DNS_A);
			new SecurityTxtFetcherUrl('HTTP://example.com/', [], '1.1.1.0', DNS_A);
			new SecurityTxtFetcherUrl('HTTPS://example.com/', [], '1.1.1.0', DNS_A);
		});

		Assert::throws(function (): void {
			new SecurityTxtFetcherUrl('scheme://example/', ['https://1.example/', 'file:///foo/bar'], '1.1.1.0', DNS_A);
		}, SecurityTxtUrlUnsupportedSchemeException::class, 'URL scheme://example/ has an unsupported scheme (redirects: https://1.example/ → file:///foo/bar)');
	}

}

(new SecurityTxtFetcherUrlTest())->run();
