<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

use DateTimeImmutable;
use Spaze\SecurityTxt\Fields\Expires;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/bootstrap.php';

/** @testCase */
class SecurityTxtTest extends TestCase
{

	public function testSetExpires(): void
	{
		$securityTxt = new SecurityTxt();
		$in2Weeks = new Expires(new DateTimeImmutable('+2 weeks'));
		$in3Weeks = new Expires(new DateTimeImmutable('+3 weeks'));
		$securityTxt->setExpires($in2Weeks);
		$securityTxt->setExpires($in3Weeks);
		Assert::equal($in3Weeks, $securityTxt->getExpires());
	}

}

(new SecurityTxtTest())->run();
