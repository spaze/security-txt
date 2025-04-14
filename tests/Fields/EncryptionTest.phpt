<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class EncryptionTest extends TestCase
{

	/**
	 * @noinspection HttpUrlsUsage
	 * @noinspection PhpExpressionResultUnusedInspection
	 */
	public function testValues(): void
	{
		Assert::noError(function (): void {
			new Encryption('http://example.com/key.txt');
			new Encryption('https://example.com/key.txt');
			new Encryption('ftp://foo.bar.example.net/key.txt');
			new Encryption('a e i o u');
		});
	}

}

new EncryptionTest()->run();
