<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use DateTimeImmutable;
use Spaze\SecurityTxt\Exceptions\SecurityTxtNoContactError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtNoExpiresError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtSignedButNoCanonicalWarning;
use Spaze\SecurityTxt\Exceptions\SecurityTxtThrowable;
use Spaze\SecurityTxt\Fields\Expires;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureVerifyResult;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class SecurityTxtValidatorTest extends TestCase
{

	private SecurityTxtValidator $securityTxtValidator;


	protected function setUp(): void
	{
		$this->securityTxtValidator = new SecurityTxtValidator();
	}


	public function testValidateMissingContact(): void
	{
		$securityTxt = new SecurityTxt();
		$this->assertThrowable($securityTxt, SecurityTxtNoContactError::class);
	}


	public function testValidateMissingExpires(): void
	{
		$securityTxt = new SecurityTxt();
		$this->assertThrowable($securityTxt, SecurityTxtNoExpiresError::class);
	}


	public function testValidateMissingCanonicalWhenSigned(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->setExpires(new Expires(new DateTimeImmutable('+1 month')));
		$securityTxt->setSignatureVerifyResult(new SecurityTxtSignatureVerifyResult('fingerprint', new DateTimeImmutable('-1 week')));
		$this->assertThrowable($securityTxt, SecurityTxtSignedButNoCanonicalWarning::class);
	}


	/**
	 * @param SecurityTxt $securityTxt
	 * @param class-string $throwableClass
	 * @return void
	 */
	private function assertThrowable(SecurityTxt $securityTxt, string $throwableClass): void
	{
		$result = $this->securityTxtValidator->validate($securityTxt);
		Assert::contains($throwableClass, array_map(function (SecurityTxtThrowable $throwable): string {
			return $throwable::class;
		}, array_merge($result->getErrors(), $result->getWarnings())));
	}

}

(new SecurityTxtValidatorTest())->run();
