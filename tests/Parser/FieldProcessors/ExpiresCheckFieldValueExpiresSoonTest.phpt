<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use DateTimeImmutable;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fields\SecurityTxtExpires;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\SecurityTxtValidationLevel;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresSoon;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class ExpiresCheckFieldValueExpiresSoonTest extends TestCase
{

	public function testProcessNoThreshold(): void
	{
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently);
		$processor = new ExpiresCheckFieldValueExpiresSoon(fn(): ?int => null);

		Assert::noError(function () use ($processor, $securityTxt): void {
			$processor->process('unused', securityTxt: $securityTxt);
		});

		$securityTxt->setExpires(new SecurityTxtExpires(new DateTimeImmutable('-2 weeks'), true, 14));
		Assert::noError(function () use ($processor, $securityTxt): void {
			$processor->process('unused', securityTxt: $securityTxt);
		});
		$securityTxt->setExpires(new SecurityTxtExpires(new DateTimeImmutable('-2 weeks'), false, 14));
		Assert::noError(function () use ($processor, $securityTxt): void {
			$processor->process('unused', securityTxt: $securityTxt);
		});
		$securityTxt->setExpires(new SecurityTxtExpires(new DateTimeImmutable('+3 days'), false, 3));
		Assert::noError(function () use ($processor, $securityTxt): void {
			$processor->process('unused', securityTxt: $securityTxt);
		});
	}


	public function testProcess(): void
	{
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently);
		$processor = new ExpiresCheckFieldValueExpiresSoon(fn(): int => 10);

		Assert::noError(function () use ($processor, $securityTxt): void {
			$processor->process('unused', securityTxt: $securityTxt);
		});

		$securityTxt->setExpires(new SecurityTxtExpires(new DateTimeImmutable('-2 weeks'), true, 14));
		Assert::noError(function () use ($processor, $securityTxt): void {
			$processor->process('unused', securityTxt: $securityTxt);
		});
		$securityTxt->setExpires(new SecurityTxtExpires(new DateTimeImmutable('+2 weeks'), false, 14));
		Assert::noError(function () use ($processor, $securityTxt): void {
			$processor->process('unused', securityTxt: $securityTxt);
		});

		$expires = new SecurityTxtExpires(new DateTimeImmutable('+3 days'), false, 3);
		$securityTxt->setExpires($expires);
		$e = Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('unused', securityTxt: $securityTxt);
		}, SecurityTxtWarning::class);
		assert($e instanceof SecurityTxtWarning);
		Assert::type(SecurityTxtExpiresSoon::class, $e->getViolation());
		Assert::same('The file will be considered stale in 3 days', $e->getMessage());

		$expires = new SecurityTxtExpires(new DateTimeImmutable('+3 hours'), false, 0);
		$securityTxt->setExpires($expires);
		$e = Assert::throws(function () use ($processor, $securityTxt): void {
			$processor->process('unused', securityTxt: $securityTxt);
		}, SecurityTxtWarning::class);
		assert($e instanceof SecurityTxtWarning);
		Assert::type(SecurityTxtExpiresSoon::class, $e->getViolation());
		Assert::same('The file will be considered stale later today', $e->getMessage());
	}

}

new ExpiresCheckFieldValueExpiresSoonTest()->run();
