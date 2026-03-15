<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtBugBountyWrongCase;
use Spaze\SecurityTxt\Violations\SecurityTxtBugBountyWrongValue;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class BugBountySetFieldValueTest extends TestCase
{

	public function testProcess(): void
	{
		$securityTxt = new SecurityTxt();
		$processor = new BugBountySetFieldValue();

		$processor->process('True', $securityTxt);
		Assert::true($securityTxt->getBugBounty()?->rewards());

		$processor->process('False', $securityTxt);
		Assert::false($securityTxt->getBugBounty()?->rewards());

		$e = Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('true', $securityTxt);
		}, SecurityTxtError::class);
		assert($e instanceof SecurityTxtError);
		Assert::type(SecurityTxtBugBountyWrongCase::class, $e->getViolation());

		$e = Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('31337', $securityTxt);
		}, SecurityTxtError::class);
		assert($e instanceof SecurityTxtError);
		Assert::type(SecurityTxtBugBountyWrongValue::class, $e->getViolation());
	}

}

(new BugBountySetFieldValueTest())->run();
