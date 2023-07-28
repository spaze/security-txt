<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use DateInterval;
use DateTimeImmutable;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class ExpiresTest extends TestCase
{

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
		Assert::with($expiresObject, function () use ($now, $expires): void {
			/** @noinspection PhpDynamicFieldDeclarationInspection Closure bound to $expiresObject */
			$this->interval = $now->diff($expires);
		});
		Assert::same($isExpired, $expiresObject->isExpired());
		Assert::same($expireDays, $expiresObject->inDays());
	}

}

(new ExpiresTest())->run();
