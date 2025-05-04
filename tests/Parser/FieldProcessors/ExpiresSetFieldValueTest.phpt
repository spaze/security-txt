<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use DateTimeImmutable;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Fields\SecurityTxtExpires;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresOldFormat;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresWrongFormat;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class ExpiresSetFieldValueTest extends TestCase
{

	public function testProcess(): void
	{
		$securityTxt = new SecurityTxt();
		$processor = new ExpiresSetFieldValue(new SecurityTxtExpiresFactory());
		$expires = new DateTimeImmutable('+2 weeks');

		$processor->process($expires->format(SecurityTxtExpires::FORMAT), $securityTxt);
		Assert::same($expires->format(SecurityTxtExpires::FORMAT), $securityTxt->getExpires()?->getDateTime()->format(SecurityTxtExpires::FORMAT));

		$processor->process($expires->format(DATE_RFC3339_EXTENDED), $securityTxt);
		Assert::same($expires->format(SecurityTxtExpires::FORMAT), $securityTxt->getExpires()?->getDateTime()->format(SecurityTxtExpires::FORMAT));

		$e = Assert::throws(function () use ($processor, $expires, $securityTxt): void {
			$processor->process($expires->format(DATE_RFC2822), $securityTxt);
		}, SecurityTxtError::class);
		assert($e instanceof SecurityTxtError);
		Assert::type(SecurityTxtExpiresOldFormat::class, $e->getViolation());

		$e = Assert::throws(function () use ($processor, $expires, $securityTxt): void {
			$processor->process($expires->format(DATE_RFC850), $securityTxt);
		}, SecurityTxtError::class);
		assert($e instanceof SecurityTxtError);
		Assert::type(SecurityTxtExpiresWrongFormat::class, $e->getViolation());

		$e = Assert::throws(function () use ($processor, $expires, $securityTxt): void {
			$processor->process($expires->format('Y-m-d H:i:s'), $securityTxt);
		}, SecurityTxtError::class);
		assert($e instanceof SecurityTxtError);
		Assert::type(SecurityTxtExpiresWrongFormat::class, $e->getViolation());
	}

}

new ExpiresSetFieldValueTest()->run();
