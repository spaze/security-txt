<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class AcknowledgmentsTest extends TestCase
{

	/**
	 * @noinspection HttpUrlsUsage
	 * @noinspection PhpExpressionResultUnusedInspection
	 */
	public function testValues(): void
	{
		Assert::noError(function (): void {
			new Acknowledgments('http://example.com/ack.txt');
			new Acknowledgments('https://example.com/ack.txt');
			new Acknowledgments('ftp://foo.bar.example.net/ack.txt');
			new Acknowledgments('fiat lux');
		});
	}

}

new AcknowledgmentsTest()->run();
