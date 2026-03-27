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
		$result1 = new SecurityTxtFetcherFetchHostResult(
			'https://1.example/',
			'https://final1.example/',
			'192.0.2.1',
			DNS_A,
			200,
			new SecurityTxtFetcherResponse(200, [], '', true, '1.1.1.0', DNS_A),
		);
		$result2 = new SecurityTxtFetcherFetchHostResult(
			'https://2.example/',
			'https://2.example/',
			'2001:DB8::2',
			DNS_AAAA,
			200,
			new SecurityTxtFetcherResponse(200, [], '', false, '1.1.1.0', DNS_A),
		);
		$result3 = new SecurityTxtFetcherFetchHostResult(
			'https://3.example/',
			'https://3.example/',
			'2001:DB8::3',
			DNS_AAAA,
			200,
			new SecurityTxtFetcherResponse(200, [], '', false, '1.1.1.0', DNS_A),
		);
		$result4 = new SecurityTxtFetcherFetchHostResult(
			'https://4.example/',
			'https://final4.example/',
			'2001:DB8::4',
			DNS_AAAA,
			200,
			new SecurityTxtFetcherResponse(200, ['content-type' => 'text/html'], '<body', true, '1.1.1.0', DNS_A),
		);
		$result5 = new SecurityTxtFetcherFetchHostResult(
			'https://5.example/',
			'https://final5.example/',
			'2001:DB8::5',
			DNS_AAAA,
			200,
			new SecurityTxtFetcherResponse(200, ['content-type' => 'text/html'], '<body', false, '1.1.1.0', DNS_A),
		);
		$redirects = [
			'https://1.example/' => ['https://redir1.example/'],
			'https://3.example/' => ['https://redir3.example/'],
		];
		$exception = new SecurityTxtNotFoundException([$result1, $result2, $result3, $result4, $result5], $redirects);
		Assert::same($redirects, $exception->getAllRedirects());
		Assert::same([], $exception->getRedirects());
		$allIps = [
			'192.0.2.1' => [DNS_A, 200],
			'2001:DB8::2' => [DNS_AAAA, 200],
			'2001:DB8::3' => [DNS_AAAA, 200],
			'2001:DB8::4' => [DNS_AAAA, 200],
			'2001:DB8::5' => [DNS_AAAA, 200],
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
