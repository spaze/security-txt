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
		$url = new SecurityTxtFetcherUrl('https://example.com/', ['https://1.example/', 'https://2.example/']);
		Assert::same('https://example.com/', $url->getUrl());
		Assert::same(['https://1.example/', 'https://2.example/'], $url->getRedirects());
	}


	public function testUnsupportedScheme(): void
	{
		Assert::noError(function (): void {
			new SecurityTxtFetcherUrl('http://example.com/', []);
			new SecurityTxtFetcherUrl('https://example.com/', []);
			new SecurityTxtFetcherUrl('HTTP://example.com/', []);
			new SecurityTxtFetcherUrl('HTTPS://example.com/', []);
		});

		Assert::throws(function (): void {
			new SecurityTxtFetcherUrl('scheme://example/', ['https://1.example/', 'file:///foo/bar']);
		}, SecurityTxtUrlUnsupportedSchemeException::class, 'URL scheme://example/ has an unsupported scheme (redirects: https://1.example/ → file:///foo/bar)');
	}

}

(new SecurityTxtFetcherUrlTest())->run();
