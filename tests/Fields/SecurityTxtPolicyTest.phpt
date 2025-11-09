<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtPolicyTest extends TestCase
{

	/**
	 * @return list<list<string>>
	 * @noinspection HttpUrlsUsage
	 */
	public function getUris(): array
	{
		return [
			['http://example.com/policy.txt'],
			['https://example.com/policy.txt'],
			['ftp://foo.bar.example.net/policy.txt'],
			['totus tuus'],
		];
	}


	/**
	 * @dataProvider getUris
	 */
	public function testValues(string $uri): void
	{
		Assert::noError(function () use ($uri): void {
			Assert::same($uri, (new SecurityTxtPolicy($uri))->getUri());
		});
	}

}

(new SecurityTxtPolicyTest())->run();
