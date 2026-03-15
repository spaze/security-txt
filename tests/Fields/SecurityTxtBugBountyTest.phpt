<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtBugBountyTest extends TestCase
{

	public function testValues(): void
	{
		Assert::true((new SecurityTxtBugBounty(true))->rewards());
		Assert::false((new SecurityTxtBugBounty(false))->rewards());
	}

}

(new SecurityTxtBugBountyTest())->run();
