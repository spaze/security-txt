<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundWrongUrlStructureException;
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


	/**
	 * @return list<array{0:array<array-key, mixed>, 1:string}>
	 */
	public function getErrors(): array
	{
		return [
			[
				[],
				'securityTxtUrls is empty',
			],
			[
				['https://example.net/' => []],
				'securityTxtUrls does not contain the well-known URL https://example.com/',
			],
			[
				[0 => [], 'https://example.com/' => []],
				'securityTxtUrls key is not a string',
			],
			[
				['https://example.com/' => 'foo'],
				'securityTxtUrls > https://example.com/ is not an array',
			],
			[
				['https://example.com/' => []],
				'securityTxtUrls > https://example.com/ > ip is not set or not a string',
			],
			[
				['https://example.com/' => ['ip' => 42]],
				'securityTxtUrls > https://example.com/ > ip is not set or not a string',
			],
			[
				['https://example.com/' => ['ip' => '192.0.2.1']],
				'securityTxtUrls > https://example.com/ > type is not set or not an int',
			],
			[
				['https://example.com/' => ['ip' => '192.0.2.1', 'type' => 'foo']],
				'securityTxtUrls > https://example.com/ > type is not set or not an int',
			],
			[
				['https://example.com/' => ['ip' => '192.0.2.1', 'type' => 808]],
				'securityTxtUrls > https://example.com/ > type is not a value of ' . SecurityTxtIpAddressType::class,
			],
			[
				['https://example.com/' => ['ip' => '192.0.2.1', 'type' => SecurityTxtIpAddressType::V4->value]],
				'securityTxtUrls > https://example.com/ > code is not set or not an int',
			],
			[
				['https://example.com/' => ['ip' => '192.0.2.1', 'type' => SecurityTxtIpAddressType::V4->value, 'code' => 'foo']],
				'securityTxtUrls > https://example.com/ > code is not set or not an int',
			],
			[
				['https://example.com/' => ['ip' => '192.0.2.1', 'type' => SecurityTxtIpAddressType::V4->value, 'code' => 200]],
				'securityTxtUrls > https://example.com/ > redirects is not set or not an array',
			],
			[
				['https://example.com/' => ['ip' => '192.0.2.1', 'type' => SecurityTxtIpAddressType::V4->value, 'code' => 200, 'redirects' => 1]],
				'securityTxtUrls > https://example.com/ > redirects is not set or not an array',
			],
			[
				['https://example.com/' => ['ip' => '192.0.2.1', 'type' => SecurityTxtIpAddressType::V4->value, 'code' => 200, 'redirects' => ['https://1.example/' => 42]]],
				'securityTxtUrls > https://example.com/ > redirects > https://1.example/ is not a string',
			],
			[
				['https://example.com/' => ['ip' => '192.0.2.1', 'type' => SecurityTxtIpAddressType::V4->value, 'code' => 200, 'redirects' => ['https://1.example/' => 'https://2.example/']]],
				'securityTxtUrls > https://example.com/ > html is not set or not a bool',
			],
			[
				['https://example.com/' => ['ip' => '192.0.2.1', 'type' => SecurityTxtIpAddressType::V4->value, 'code' => 200, 'redirects' => ['https://1.example/' => 'https://2.example/'], 'html' => 'foo']],
				'securityTxtUrls > https://example.com/ > html is not set or not a bool',
			],
			[
				['https://example.com/' => ['ip' => '192.0.2.1', 'type' => SecurityTxtIpAddressType::V4->value, 'code' => 200, 'redirects' => ['https://1.example/' => 'https://2.example/'], 'html' => true]],
				'securityTxtUrls > https://example.com/ > truncated is not set or not a bool',
			],
			[
				['https://example.com/' => ['ip' => '192.0.2.1', 'type' => SecurityTxtIpAddressType::V4->value, 'code' => 200, 'redirects' => ['https://1.example/' => 'https://2.example/'], 'html' => true, 'truncated' => 'foo']],
				'securityTxtUrls > https://example.com/ > truncated is not set or not a bool',
			],
		];
	}


	/**
	 * @dataProvider getErrors
	 * @param array<array-key, mixed> $urls
	 */
	public function testErrors(array $urls, string $error): void
	{
		Assert::throws(function () use ($urls): void {
			new SecurityTxtNotFoundException($urls, 'https://example.com/');
		}, SecurityTxtNotFoundWrongUrlStructureException::class, 'Cannot create Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException: ' . $error);
	}

}

(new SecurityTxtNotFoundExceptionTest())->run();
