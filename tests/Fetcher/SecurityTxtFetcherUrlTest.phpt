<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlUnsupportedSchemeException;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtFetcherUrlTest extends TestCase
{

	public function testGetters(): void
	{
		$url = new SecurityTxtFetcherUrl(new Url('https://example.com/'), ['https://1.example/', 'https://2.example/']);
		Assert::same('https://example.com/', $url->getUrl()->toUnicodeString());
		Assert::same(['https://1.example/', 'https://2.example/'], $url->getRedirects());
	}


	public function testUnsupportedScheme(): void
	{
		Assert::noError(function (): void {
			new SecurityTxtFetcherUrl(new Url('http://example.com/'), []);
			new SecurityTxtFetcherUrl(new Url('https://example.com/'), []);
			new SecurityTxtFetcherUrl(new Url('HTTP://example.com/'), []);
			new SecurityTxtFetcherUrl(new Url('HTTPS://example.com/'), []);
		});

		Assert::throws(function (): void {
			new SecurityTxtFetcherUrl(new Url('scheme://example/'), ['https://1.example/', 'file:///foo/bar']);
		}, SecurityTxtUrlUnsupportedSchemeException::class, 'URL scheme://example/ has an unsupported scheme (redirects: https://1.example/ → file:///foo/bar)');
	}

}

(new SecurityTxtFetcherUrlTest())->run();
