<?php
/**
 * @testCase
 * @noinspection PhpDocMissingThrowsInspection
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtConnectedToWrongIpAddressException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressInvalidException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressNotPublicException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoHttpCodeException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoLocationHeaderException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtOnlyIpv6HostButIpv6DisabledException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtRedirectLoopException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtRedirectUrlTooLongException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlUnsupportedSchemeException;
use Spaze\SecurityTxt\Fetcher\SecurityTxtIpAddressType;
use Spaze\SecurityTxt\Fetcher\SecurityTxtRedirects;
use Spaze\SecurityTxt\SecurityTxtHost;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;

require __DIR__ . '/../../bootstrap.php';

/**
 * The format and the values have to agree on how many placeholders there are, so every exception that lists redirects is built here with none, one and two of them.
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


	public function testHostNotFound(): void
	{
		$host = new SecurityTxtHost(new Url('https://1.example/'));
		Assert::same("Can't open https://1.example/, can't resolve 1.example", new SecurityTxtHostNotFoundException(new Url('https://1.example/'), $host)->getMessage());
		Assert::same("Can't open https://1.example/ (redirects: https://2.example/), can't resolve 1.example", new SecurityTxtHostNotFoundException(new Url('https://1.example/'), $host, new SecurityTxtRedirects('https://2.example/'))->getMessage());
		Assert::same("Can't open https://1.example/ (redirects: https://2.example/ → https://3.example/), can't resolve 1.example", new SecurityTxtHostNotFoundException(new Url('https://1.example/'), $host, new SecurityTxtRedirects('https://2.example/', 'https://3.example/'))->getMessage());
	}


	public function testHostIpAddressNotFound(): void
	{
		$host = new SecurityTxtHost(new Url('https://1.example/'));
		Assert::same("Can't open https://1.example/, no IP address for 1.example found", new SecurityTxtHostIpAddressNotFoundException(new Url('https://1.example/'), $host)->getMessage());
		Assert::same("Can't open https://1.example/ (redirects: https://2.example/), no IP address for 1.example found", new SecurityTxtHostIpAddressNotFoundException(new Url('https://1.example/'), $host, new SecurityTxtRedirects('https://2.example/'))->getMessage());
		Assert::same("Can't open https://1.example/ (redirects: https://2.example/ → https://3.example/), no IP address for 1.example found", new SecurityTxtHostIpAddressNotFoundException(new Url('https://1.example/'), $host, new SecurityTxtRedirects('https://2.example/', 'https://3.example/'))->getMessage());
	}


	public function testHostIpAddressNotPublic(): void
	{
		$host = new SecurityTxtHost(new Url('https://1.example/'));
		Assert::same('Host 1.example resolves to a non-public IP address 127.0.0.1', new SecurityTxtHostIpAddressNotPublicException($host, '127.0.0.1', new Url('https://1.example/'))->getMessage());
		Assert::same('Host 1.example resolves to a non-public IP address 127.0.0.1 (redirects: https://2.example/)', new SecurityTxtHostIpAddressNotPublicException($host, '127.0.0.1', new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/'))->getMessage());
		Assert::same('Host 1.example resolves to a non-public IP address 127.0.0.1 (redirects: https://2.example/ → https://3.example/)', new SecurityTxtHostIpAddressNotPublicException($host, '127.0.0.1', new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/', 'https://3.example/'))->getMessage());
	}


	public function testHostIpAddressInvalid(): void
	{
		$host = new SecurityTxtHost(new Url('https://1.example/'));
		Assert::same('Host 1.example resolves to an invalid IPv6 address 1.2.3.4', new SecurityTxtHostIpAddressInvalidException($host, '1.2.3.4', SecurityTxtIpAddressType::V6, new Url('https://1.example/'))->getMessage());
		Assert::same('Host 1.example resolves to an invalid IPv6 address 1.2.3.4 (redirects: https://2.example/)', new SecurityTxtHostIpAddressInvalidException($host, '1.2.3.4', SecurityTxtIpAddressType::V6, new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/'))->getMessage());
		Assert::same('Host 1.example resolves to an invalid IPv6 address 1.2.3.4 (redirects: https://2.example/ → https://3.example/)', new SecurityTxtHostIpAddressInvalidException($host, '1.2.3.4', SecurityTxtIpAddressType::V6, new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/', 'https://3.example/'))->getMessage());
	}


	public function testOnlyIpv6HostButIpv6Disabled(): void
	{
		$host = new SecurityTxtHost(new Url('https://1.example/'));
		Assert::same('Only IPv6 host is available (1.example, 2001:db8::1) but IPv6 is disabled', new SecurityTxtOnlyIpv6HostButIpv6DisabledException($host, '2001:db8::1', new Url('https://1.example/'))->getMessage());
		Assert::same('Only IPv6 host is available (1.example, 2001:db8::1) but IPv6 is disabled (redirects: https://2.example/)', new SecurityTxtOnlyIpv6HostButIpv6DisabledException($host, '2001:db8::1', new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/'))->getMessage());
		Assert::same('Only IPv6 host is available (1.example, 2001:db8::1) but IPv6 is disabled (redirects: https://2.example/ → https://3.example/)', new SecurityTxtOnlyIpv6HostButIpv6DisabledException($host, '2001:db8::1', new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/', 'https://3.example/'))->getMessage());
	}


	public function testNoLocationHeader(): void
	{
		Assert::same('HTTP response with code 302 is missing a Location header when fetching https://1.example/', new SecurityTxtNoLocationHeaderException(new Url('https://1.example/'), 302)->getMessage());
		Assert::same('HTTP response with code 302 is missing a Location header when fetching https://1.example/ (redirects: https://2.example/)', new SecurityTxtNoLocationHeaderException(new Url('https://1.example/'), 302, new SecurityTxtRedirects('https://2.example/'))->getMessage());
		Assert::same('HTTP response with code 302 is missing a Location header when fetching https://1.example/ (redirects: https://2.example/ → https://3.example/)', new SecurityTxtNoLocationHeaderException(new Url('https://1.example/'), 302, new SecurityTxtRedirects('https://2.example/', 'https://3.example/'))->getMessage());
	}


	public function testRedirectLoop(): void
	{
		Assert::same("Can't read https://1.example/, the redirects go in a loop", new SecurityTxtRedirectLoopException(new Url('https://1.example/'), new SecurityTxtRedirects())->getMessage());
		Assert::same("Can't read https://1.example/, the redirects go in a loop (redirects: https://2.example/)", new SecurityTxtRedirectLoopException(new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/'))->getMessage());
		Assert::same("Can't read https://1.example/, the redirects go in a loop (redirects: https://2.example/ → https://3.example/)", new SecurityTxtRedirectLoopException(new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/', 'https://3.example/'))->getMessage());
	}


	public function testRedirectUrlTooLong(): void
	{
		Assert::same("Can't read https://1.example/, it redirects to a URL longer than 1000 characters", new SecurityTxtRedirectUrlTooLongException(new Url('https://1.example/'), new SecurityTxtRedirects(), 1000)->getMessage());
		Assert::same("Can't read https://1.example/, it redirects to a URL longer than 42 characters (redirects: https://2.example/)", new SecurityTxtRedirectUrlTooLongException(new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/'), 42)->getMessage());
		Assert::same("Can't read https://1.example/, it redirects to a URL longer than 1000 characters (redirects: https://2.example/ → https://3.example/)", new SecurityTxtRedirectUrlTooLongException(new Url('https://1.example/'), new SecurityTxtRedirects('https://2.example/', 'https://3.example/'), 1000)->getMessage());
	}

}

new SecurityTxtRedirectsFormatTest()->run();
