<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Fields\SecurityTxtBugBounty;
use Spaze\SecurityTxt\SecurityTxt;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class BugBountyCheckMultipleFieldsTest extends TestCase
{

	public function testProcess(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->setBugBounty(new SecurityTxtBugBounty(true));

		$processor = new BugBountyCheckMultipleFields();
		Assert::throws(function () use ($securityTxt, $processor) {
			$processor->process('True', $securityTxt);
		}, SecurityTxtError::class, 'The Bug-Bounty field must not appear more than once');
	}

}

(new BugBountyCheckMultipleFieldsTest())->run();
