<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\LineProcessors;

use DateTimeImmutable;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresOldFormatError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresWrongFormatError;
use Spaze\SecurityTxt\SecurityTxt;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
class ExpiresSetFieldValueTest extends TestCase
{

	public function testProcess(): void
	{
		$securityTxt = new SecurityTxt();
		$processor = new ExpiresSetFieldValue();
		$expires = new DateTimeImmutable('+2 weeks');

		$processor->process($expires->format(DATE_RFC3339), $securityTxt);
		Assert::same($expires->format(DATE_RFC3339), $securityTxt->getExpires()->getDateTime()->format(DATE_RFC3339));

		$processor->process($expires->format(DATE_RFC3339_EXTENDED), $securityTxt);
		Assert::same($expires->format(DATE_RFC3339), $securityTxt->getExpires()->getDateTime()->format(DATE_RFC3339));

		Assert::throws(function () use ($processor, $expires, $securityTxt): void {
			$processor->process($expires->format(DATE_RFC2822), $securityTxt);
		}, SecurityTxtExpiresOldFormatError::class);

		Assert::throws(function () use ($processor, $expires, $securityTxt): void {
			$processor->process($expires->format(DATE_RFC850), $securityTxt);
		}, SecurityTxtExpiresWrongFormatError::class);

		Assert::throws(function () use ($processor, $expires, $securityTxt): void {
			$processor->process($expires->format('Y-m-d H:i:s'), $securityTxt);
		}, SecurityTxtExpiresWrongFormatError::class);
	}

}

(new ExpiresSetFieldValueTest())->run();
