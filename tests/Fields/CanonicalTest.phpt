<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class CanonicalTest extends TestCase
{

	/**
	 * @noinspection HttpUrlsUsage
	 * @noinspection PhpExpressionResultUnusedInspection
	 */
	public function testValues(): void
	{
		Assert::noError(function (): void {
			new Canonical('http://example.com/.well-known/security.txt');
			new Canonical('https://example.com/.well-known/security.txt');
			new Canonical('ftp://foo.bar.example.net/security.txt');
		});
	}

}

new CanonicalTest()->run();
