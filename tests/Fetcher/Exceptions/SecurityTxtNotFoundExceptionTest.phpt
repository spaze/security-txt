<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtNotFoundExceptionTest extends TestCase
{

	public function testGetters(): void
	{
		$exception = new SecurityTxtNotFoundException([
			'https://1.example/' => [
				'ip' => '192.0.2.1',
				'type' => SecurityTxtIpAddressType::V4->value,
				'code' => 200,
				'redirects' => ['https://redir1.example/'],
				'html' => false,
				'truncated' => true,
			],
			'https://2.example/' => [
				'ip' => '2001:DB8::2',
				'type' => SecurityTxtIpAddressType::V6->value,
				'code' => 200,
				'redirects' => [],
				'html' => false,
				'truncated' => false,
			],
			'https://3.example/' => [
				'ip' => '2001:DB8::3',
				'type' => SecurityTxtIpAddressType::V6->value,
				'code' => 200,
				'redirects' => ['https://redir3.example/'],
				'html' => false,
				'truncated' => false,
			],
			'https://4.example/' => [
				'ip' => '2001:DB8::4',
				'type' => SecurityTxtIpAddressType::V6->value,
				'code' => 200,
				'redirects' => [],
				'html' => true,
				'truncated' => true,
			],
			'https://5.example/' => [
				'ip' => '2001:DB8::5',
				'type' => SecurityTxtIpAddressType::V6->value,
				'code' => 200,
				'redirects' => [],
				'html' => true,
				'truncated' => false,
			],
		], 'https://1.example/');
		$redirects = [
			'https://1.example/' => ['https://redir1.example/'],
			'https://3.example/' => ['https://redir3.example/'],
		];
		Assert::same($redirects, $exception->getAllRedirects());
		Assert::same([], $exception->getRedirects());
		$allIps = [
			'192.0.2.1' => [SecurityTxtIpAddressType::V4->value, 200],
			'2001:DB8::2' => [SecurityTxtIpAddressType::V6->value, 200],
			'2001:DB8::3' => [SecurityTxtIpAddressType::V6->value, 200],
			'2001:DB8::4' => [SecurityTxtIpAddressType::V6->value, 200],
			'2001:DB8::5' => [SecurityTxtIpAddressType::V6->value, 200],
		];
		Assert::same($allIps, $exception->getIpAddresses());
		Assert::same(
			"Can't read security.txt: "
				. 'https://1.example/ (192.0.2.1) => response too long (final page after redirects), '
				. 'https://2.example/ (2001:DB8::2) => 200, '
				. 'https://3.example/ (2001:DB8::3) => 200 (final code after redirects), '
				. 'https://4.example/ (2001:DB8::4) => regular HTML page and too long, '
				. 'https://5.example/ (2001:DB8::5) => regular HTML page',
			$exception->getMessage(),
		);
	}

}

(new SecurityTxtNotFoundExceptionTest())->run();
