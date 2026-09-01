<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtCannotOpenUrlExceptionTest extends TestCase
{

	public function testGetters(): void
	{
		$exception = new SecurityTxtCannotOpenUrlException('https://com.example/', []);
		Assert::same("Can't open https://com.example/", $exception->getMessage());
		Assert::same([], $exception->getRedirects());
		Assert::null($exception->getIpAddress());
		Assert::null($exception->getIpAddressType());

		$redirects = ['https://redir1.example/', 'https://redir2.example/'];
		$exception = new SecurityTxtCannotOpenUrlException('https://com.example/', $redirects);
		Assert::same("Can't open https://com.example/ (redirects: https://redir1.example/ → https://redir2.example/)", $exception->getMessage());
		Assert::same($redirects, $exception->getRedirects());

		$exception = new SecurityTxtCannotOpenUrlException('https://com.example/', [], '192.0.2.1', SecurityTxtIpAddressType::V4);
		Assert::same("Can't open https://com.example/ using its IPv4 address 192.0.2.1", $exception->getMessage());
		Assert::same('192.0.2.1', $exception->getIpAddress());
		Assert::same(SecurityTxtIpAddressType::V4, $exception->getIpAddressType());

		$exception = new SecurityTxtCannotOpenUrlException('https://com.example/', [], '2001:DB8::1', SecurityTxtIpAddressType::V6, 'Could not connect to server');
		Assert::same("Can't open https://com.example/ using its IPv6 address 2001:DB8::1 (Could not connect to server)", $exception->getMessage());
		Assert::same('2001:DB8::1', $exception->getIpAddress());
		Assert::same(SecurityTxtIpAddressType::V6, $exception->getIpAddressType());

		$exception = new SecurityTxtCannotOpenUrlException('https://com.example/', $redirects, '2001:DB8::1', SecurityTxtIpAddressType::V6, 'Could not connect to server');
		Assert::same("Can't open https://com.example/ (redirects: https://redir1.example/ → https://redir2.example/) using its IPv6 address 2001:DB8::1 (Could not connect to server)", $exception->getMessage());

		// What a host sends is encoded in the message, and left alone in the values, which are for a caller that knows what it renders into
		$exception = new SecurityTxtCannotOpenUrlException("https://evil.example/\x1b[2K", []);
		Assert::same("Can't open https://evil.example/%1B[2K", $exception->getMessage());
		Assert::same(["https://evil.example/\x1b[2K"], $exception->getMessageValues());

		$exception = new SecurityTxtCannotOpenUrlException('https://com.example/', ['https://redir1.example/']);
		Assert::same("Can't open https://com.example/ (redirects: https://redir1.example/)", $exception->getMessage());

		$exception = new SecurityTxtCannotOpenUrlException('https://com.example/', [], '192.0.2.1');
		Assert::same("Can't open https://com.example/ using its IP address 192.0.2.1", $exception->getMessage());
		Assert::null($exception->getIpAddressType());
	}

}

(new SecurityTxtCannotOpenUrlExceptionTest())->run();
