<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoHttpCodeException;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class SecurityTxtNoHttpCodeExceptionTest extends TestCase
{

	public function testGetters(): void
	{
		$exception = new SecurityTxtNoHttpCodeException('https://no.code.example/', []);
		Assert::same('Missing HTTP code when fetching https://no.code.example/', $exception->getMessage());
		Assert::same([], $exception->getRedirects());

		$redirects = ['https://redir1.example/', 'https://redir2.example/'];
		$exception = new SecurityTxtNoHttpCodeException('https://no.code.example/', $redirects);
		Assert::same('Missing HTTP code when fetching https://no.code.example/ (redirects: https://redir1.example/ → https://redir2.example/)', $exception->getMessage());
		Assert::same($redirects, $exception->getRedirects());
	}

}

(new SecurityTxtNoHttpCodeExceptionTest())->run();
