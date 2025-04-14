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
	 * @noinspection HttpUrlsUsage
	 * @noinspection PhpExpressionResultUnusedInspection
	 */
	public function testValues(): void
	{
		Assert::noError(function (): void {
			new Hiring('http://example.com/hiring.txt');
			new Hiring('https://example.com/hiring.txt');
			new Hiring('ftp://foo.bar.example.net/hiring.txt');
			new Hiring('festina lente');
		});
	}

}

new HiringTest()->run();
