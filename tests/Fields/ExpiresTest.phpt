<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use DateInterval;
use DateTimeImmutable;
use ReflectionProperty;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class ExpiresTest extends TestCase
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
		$expiresObject = new Expires($expires);
		new ReflectionProperty($expiresObject, 'interval')->setValue($expiresObject, $now->diff($expires));
		Assert::same($isExpired, $expiresObject->isExpired());
		Assert::same($expireDays, $expiresObject->inDays());
	}

}

new ExpiresTest()->run();
