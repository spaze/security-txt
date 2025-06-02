<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser\FieldProcessors;

use DateTimeImmutable;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\SecurityTxt;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../../bootstrap.php';

/** @testCase */
final class ExpiresSetFieldValueTest extends TestCase
{

	/**
	 * @return list<array{0:string, 1:bool}>
	 */
	public function getFormats(): array
	{
		return [
			[DATE_RFC3339, true],
			[DATE_RFC3339_EXTENDED, true],
			[DATE_RFC2822, true],
			[DATE_RFC850, true],
			['ěšč', false],
		];
	}


	/**
	 * @dataProvider getFormats
	 */
	public function testProcess(string $format, bool $valid): void
	{
		$securityTxt = new SecurityTxt();
		$processor = new ExpiresSetFieldValue(new SecurityTxtExpiresFactory());
		$expires = new DateTimeImmutable('+2 weeks noon -1 second +00:00');

		$processor->process($expires->format($format), $securityTxt);
		if ($valid) {
			Assert::equal($expires, $securityTxt->getExpires()?->getDateTime());
		} else {
			Assert::null($securityTxt->getExpires());
		}
	}

}

new ExpiresSetFieldValueTest()->run();
