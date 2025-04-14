<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class PolicyTest extends TestCase
{

	/**
	 * @noinspection HttpUrlsUsage
	 * @noinspection PhpExpressionResultUnusedInspection
	 */
	public function testValues(): void
	{
		Assert::noError(function (): void {
			new Policy('http://example.com/policy.txt');
			new Policy('https://example.com/policy.txt');
			new Policy('ftp://foo.bar.example.net/policy.txt');
			new Policy('totus tuus');
		});
	}

}

new PolicyTest()->run();
