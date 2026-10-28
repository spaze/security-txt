<?php
/**
 * @testCase
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\SecurityTxt;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

final class BugBountyCheckMultipleFieldsTest extends TestCase
{

	public function testProcess(): void
	{
		$securityTxt = new SecurityTxt();
		$processor = new BugBountyCheckMultipleFields();
		Assert::noError(function () use ($securityTxt, $processor): void {
			$processor->process('maybe', $securityTxt);
		});
		Assert::throws(function () use ($securityTxt, $processor) {
			$processor->process('True', $securityTxt);
		}, SecurityTxtError::class, 'The Bug-Bounty field must not appear more than once');
		Assert::noError(function () use ($processor): void {
			$processor->process('True', new SecurityTxt());
		});
	}

}

(new BugBountyCheckMultipleFieldsTest())->run();
