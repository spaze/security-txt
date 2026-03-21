<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

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

}

(new SecurityTxtFetcherUrlTest())->run();
