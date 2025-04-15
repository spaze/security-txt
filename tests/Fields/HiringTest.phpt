<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class HiringTest extends TestCase
{

	/**
	 * @return list<list<string>>
	 * @noinspection HttpUrlsUsage
	 */
	public function getUris(): array
	{
		return [
			['http://example.com/hiring.txt'],
			['https://example.com/hiring.txt'],
			['ftp://foo.bar.example.net/hiring.txt'],
			['festina lente'],
		];
	}


	/**
	 * @dataProvider getUris
	 */
	public function testValues(string $uri): void
	{
		Assert::noError(function () use ($uri): void {
			Assert::same($uri, new Hiring($uri)->getUri());
		});
	}

}

new HiringTest()->run();
