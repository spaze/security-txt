<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use DateTimeImmutable;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureVerifyResult;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Spaze\SecurityTxt\Violations\SecurityTxtNoContact;
use Spaze\SecurityTxt\Violations\SecurityTxtNoExpires;
use Spaze\SecurityTxt\Violations\SecurityTxtSignedButNoCanonical;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtValidatorTest extends TestCase
{

	private SecurityTxtValidator $securityTxtValidator;
	private SecurityTxtExpiresFactory $securityTxtExpiresFactory;


	public function __construct()
	{
		$this->securityTxtValidator = new SecurityTxtValidator();
		$this->securityTxtExpiresFactory = new SecurityTxtExpiresFactory();
	}


	public function testValidateMissingContact(): void
	{
		$securityTxt = new SecurityTxt();
		$this->assertThrowable($securityTxt, SecurityTxtNoContact::class);
	}


	public function testValidateMissingExpires(): void
	{
		$securityTxt = new SecurityTxt();
		$this->assertThrowable($securityTxt, SecurityTxtNoExpires::class);
	}


	public function testValidateMissingCanonicalWhenSigned(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create(new DateTimeImmutable('+1 month')));
		$securityTxt = $securityTxt->withSignatureVerifyResult(new SecurityTxtSignatureVerifyResult('fingerprint', new DateTimeImmutable('-1 week')));
		$this->assertThrowable($securityTxt, SecurityTxtSignedButNoCanonical::class);
	}


	/**
	 * @param SecurityTxt $securityTxt
	 * @param class-string $throwableClass
	 * @return void
	 */
	private function assertThrowable(SecurityTxt $securityTxt, string $throwableClass): void
	{
		$result = $this->securityTxtValidator->validate($securityTxt);
		Assert::contains($throwableClass, array_map(function (SecurityTxtSpecViolation $throwable): string {
			return $throwable::class;
		}, array_merge($result->getErrors(), $result->getWarnings())));
	}

}

new SecurityTxtValidatorTest()->run();
