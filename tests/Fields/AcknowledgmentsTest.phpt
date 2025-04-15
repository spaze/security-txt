<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class AcknowledgmentsTest extends TestCase
{

	/**
	 * @return list<list<string>>
	 * @noinspection HttpUrlsUsage
	 */
	public function getUris(): array
	{
		return [
			['http://example.com/ack.txt'],
			['https://example.com/ack.txt'],
			['ftp://foo.bar.example.net/ack.txt'],
			['fiat lux'],
		];
	}


	/**
	 * @dataProvider getUris
	 */
	public function testValues(string $uri): void
	{
		Assert::noError(function () use ($uri): void {
			Assert::same($uri, new Acknowledgments($uri)->getUri());
		});
	}

}

new AcknowledgmentsTest()->run();
