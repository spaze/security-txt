<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature;

use DateTimeImmutable;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtSignatureVerifyResultTest extends TestCase
{

	public function testValidateMissingCanonicalWhenSigned(): void
	{
		$result = new SecurityTxtSignatureVerifyResult('4BD4C403AF2F9FCCB151FE61B64BDD6E464AB529', new DateTimeImmutable('-1 week'));
		Assert::same('B64BDD6E464AB529', $result->getKeyId());
		Assert::same('464AB529', $result->getShortKeyId());
	}

}

new SecurityTxtSignatureVerifyResultTest()->run();
