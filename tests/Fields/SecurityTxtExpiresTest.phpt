<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use DateInterval;
use DateTimeImmutable;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtExpiresTest extends TestCase
{

	/**
	 * @return array<string, array{0:DateTimeImmutable, 1:DateTimeImmutable, 2:bool, 3:int}>
	 */
	public function getExpiresField(): array
	{
		$now = new DateTimeImmutable();
		$twoDays = new DateInterval('P2D');
		return [
			'now' => [$now, $now, false, 0],
			'tomorrow' => [$now, $now->add($twoDays), false, 2],
			'in yesterday' => [$now, $now->sub($twoDays), true, -2],
		];
	}


	/** @dataProvider getExpiresField */
	public function testIsExpiredInDays(DateTimeImmutable $now, DateTimeImmutable $expires, bool $isExpired, int $expireDays): void
	{
		$interval = $now->diff($expires);
		$negativePeriod = $interval->invert === 1;
		$days = (int)$interval->days;
		$expiresObject = new SecurityTxtExpires($expires, $negativePeriod, $negativePeriod ? -$days : $days);
		Assert::same($isExpired, $expiresObject->isExpired());
		Assert::same($expireDays, $expiresObject->inDays());
	}

}

new SecurityTxtExpiresTest()->run();
