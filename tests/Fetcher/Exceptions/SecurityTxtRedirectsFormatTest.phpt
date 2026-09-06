<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtConnectedToWrongIpAddressException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoHttpCodeException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlUnsupportedSchemeException;
use Spaze\SecurityTxt\Fetcher\SecurityTxtRedirects;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;

require __DIR__ . '/../../bootstrap.php';

/**
 * The format and the values have to agree on how many placeholders there are, so every exception that lists redirects is built here with none, one and two of them.
 *
 * @testCase
 */
final class SecurityTxtRedirectsFormatTest extends TestCase
{

	public function testNoHttpCode(): void
	{
		Assert::same('Missing HTTP code when fetching https://1.example/', new SecurityTxtNoHttpCodeException(new Url('https://1.example/'), new SecurityTxtRedirects())->getMessage());
		Assert::same('Missing HTTP code when fetching https://1.example/ (redirects: https://2.example/)', new SecurityTxtNoHttpCodeException(new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/'))->getMessage());
		Assert::same('Missing HTTP code when fetching https://1.example/ (redirects: https://2.example/ → https://3.example/)', new SecurityTxtNoHttpCodeException(new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/', 'https://3.example/'))->getMessage());
	}


	public function testUrlUnsupportedScheme(): void
	{
		Assert::same('URL https://1.example/ has an unsupported scheme', new SecurityTxtUrlUnsupportedSchemeException(new Url('https://1.example/'), new SecurityTxtRedirects())->getMessage());
		Assert::same('URL https://1.example/ has an unsupported scheme (redirects: https://2.example/)', new SecurityTxtUrlUnsupportedSchemeException(new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/'))->getMessage());
		Assert::same('URL https://1.example/ has an unsupported scheme (redirects: https://2.example/ → https://3.example/)', new SecurityTxtUrlUnsupportedSchemeException(new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/', 'https://3.example/'))->getMessage());
	}


	public function testConnectedToWrongIpAddress(): void
	{
		Assert::same(
			"Can't open https://1.example/, connected to 192.0.2.2 instead of 192.0.2.1 as expected",
			new SecurityTxtConnectedToWrongIpAddressException('192.0.2.1', '192.0.2.2', new Url('https://1.example/'), new SecurityTxtRedirects())->getMessage(),
		);
		Assert::same(
			"Can't open https://1.example/ (redirects: https://2.example/), connected to 192.0.2.2 instead of 192.0.2.1 as expected",
			new SecurityTxtConnectedToWrongIpAddressException('192.0.2.1', '192.0.2.2', new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/'))->getMessage(),
		);
		Assert::same(
			"Can't open https://1.example/ (redirects: https://2.example/ → https://3.example/), connected to 192.0.2.2 instead of 192.0.2.1 as expected",
			new SecurityTxtConnectedToWrongIpAddressException('192.0.2.1', '192.0.2.2', new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/', 'https://3.example/'))->getMessage(),
		);
	}


	public function testTooManyRedirects(): void
	{
		// Same redirect syntax as the others, plus the note that the last one was never fetched; an empty list used to make `vsprintf()` throw
		Assert::same("Can't read https://1.example/, too many redirects, max allowed is 5", new SecurityTxtTooManyRedirectsException(new Url('https://1.example/'), new SecurityTxtRedirects(), 5)->getMessage());
		Assert::same("Can't read https://1.example/, too many redirects, max allowed is 5 (redirects: https://2.example/, the last one not loaded)", new SecurityTxtTooManyRedirectsException(new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/'), 5)->getMessage());
		// The chain is in the message, so it belongs in the structured getter a consumer reads too, and comes back as the chain it was handed
		$redirects = new SecurityTxtRedirects('https://2.example/');
		Assert::same($redirects, new SecurityTxtTooManyRedirectsException(new Url('https://1.example/'), $redirects, 5)->getRedirects());
		Assert::same("Can't read https://1.example/, too many redirects, max allowed is 5 (redirects: https://2.example/ → https://3.example/, the last one not loaded)", new SecurityTxtTooManyRedirectsException(new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/', 'https://3.example/'), 5)->getMessage());
	}

}

new SecurityTxtRedirectsFormatTest()->run();
