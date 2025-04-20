<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtEncryptionTest extends TestCase
{

	/**
	 * @return list<list<string>>
	 * @noinspection HttpUrlsUsage
	 */
	public function getUris(): array
	{
		return [
			['http://example.com/key.txt'],
			['https://example.com/key.txt'],
			['ftp://foo.bar.example.net/key.txt'],
			['a e i o u'],
		];
	}


	/**
	 * @dataProvider getUris
	 */
	public function testValues(string $uri): void
	{
		Assert::noError(function () use ($uri): void {
			Assert::same($uri, new SecurityTxtEncryption($uri)->getUri());
		});
	}

}

new SecurityTxtEncryptionTest()->run();
