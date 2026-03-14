<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtCsafTest extends TestCase
{

	/**
	 * @return list<list<string>>
	 * @noinspection HttpUrlsUsage
	 */
	public function getUris(): array
	{
		return [
			['http://example.com/provider-metadata.json'],
			['https://example.com/provider-metadata.json'],
			['https://example.com/csaf.txt'],
			['ftp://foo.bar.example.net/provider-metadata.json'],
		];
	}


	/**
	 * @dataProvider getUris
	 */
	public function testValues(string $uri): void
	{
		Assert::noError(function () use ($uri): void {
			Assert::same($uri, (new SecurityTxtCsaf($uri))->getUri());
		});
	}

}

(new SecurityTxtCsafTest())->run();
