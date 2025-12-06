<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use DateTimeImmutable;
use Spaze\SecurityTxt\Fields\SecurityTxtCanonical;
use Spaze\SecurityTxt\Fields\SecurityTxtContact;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureVerifyResult;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Spaze\SecurityTxt\Violations\SecurityTxtCanonicalUriMismatch;
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
		$this->assertViolation($securityTxt, SecurityTxtNoContact::class);
	}


	public function testValidateCanonicalUriMatch(): void
	{
		$securityTxt = new SecurityTxt();
		$fileLocation = 'https://example.com/.well-known/security.txt';
		$securityTxt->setFileLocation($fileLocation);
		$securityTxt->addCanonical(new SecurityTxtCanonical('https://foo.example/.well-known/security.txt'));
		$securityTxt->addCanonical(new SecurityTxtCanonical($fileLocation));
		$securityTxt->addContact(new SecurityTxtContact('mailto:foo@example.com'));
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create(new DateTimeImmutable('+1 month')));
		$this->assertNoViolation($securityTxt);
	}


	public function testValidateNoCanonicalNoMismatch(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->setFileLocation('https://example.com/.well-known/security.txt');
		$securityTxt->addContact(new SecurityTxtContact('mailto:foo@example.com'));
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create(new DateTimeImmutable('+1 month')));
		$this->assertNoViolation($securityTxt);
	}


	public function testValidateNoFileLocationNoMismatch(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->addContact(new SecurityTxtContact('mailto:foo@example.com'));
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create(new DateTimeImmutable('+1 month')));
		$securityTxt->addCanonical(new SecurityTxtCanonical('https://foo.example/.well-known/security.txt'));
		$this->assertNoViolation($securityTxt);
	}


	public function testValidateNoFileLocationNoCanonicalNoMismatch(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->addContact(new SecurityTxtContact('mailto:foo@example.com'));
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create(new DateTimeImmutable('+1 month')));
		$this->assertNoViolation($securityTxt);
	}


	public function testValidateCanonicalUriMismatch(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->setFileLocation('https://example.com/.well-known/security.txt');
		$securityTxt->addCanonical(new SecurityTxtCanonical('https://foo.example/.well-known/security.txt'));
		$securityTxt->addContact(new SecurityTxtContact('mailto:foo@example.com'));
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create(new DateTimeImmutable('+1 month')));
		$this->assertViolation($securityTxt, SecurityTxtCanonicalUriMismatch::class);
	}


	public function testValidateMultipleCanonicalUriMismatch(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->setFileLocation('https://example.com/.well-known/security.txt');
		$securityTxt->addCanonical(new SecurityTxtCanonical('https://foo.example/.well-known/security.txt'));
		$securityTxt->addCanonical(new SecurityTxtCanonical('https://bar.example/security.txt'));
		$securityTxt->addContact(new SecurityTxtContact('mailto:foo@example.com'));
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create(new DateTimeImmutable('+1 month')));
		$this->assertViolation($securityTxt, SecurityTxtCanonicalUriMismatch::class);
	}


	public function testValidateMissingExpires(): void
	{
		$securityTxt = new SecurityTxt();
		$this->assertViolation($securityTxt, SecurityTxtNoExpires::class);
	}


	public function testValidateMissingCanonicalWhenSigned(): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create(new DateTimeImmutable('+1 month')));
		$securityTxt = $securityTxt->withSignatureVerifyResult(new SecurityTxtSignatureVerifyResult('fingerprint', new DateTimeImmutable('-1 week')));
		$this->assertViolation($securityTxt, SecurityTxtSignedButNoCanonical::class);
	}


	/**
	 * @param class-string $violationClass
	 */
	private function assertViolation(SecurityTxt $securityTxt, string $violationClass): void
	{
		$result = $this->securityTxtValidator->validate($securityTxt);
		Assert::contains($violationClass, array_map(function (SecurityTxtSpecViolation $violation): string {
			return $violation::class;
		}, array_merge($result->getErrors(), $result->getWarnings())));
	}


	/**
	 * @param SecurityTxt $securityTxt
	 * @return void
	 */
	private function assertNoViolation(SecurityTxt $securityTxt): void
	{
		$result = $this->securityTxtValidator->validate($securityTxt);
		Assert::same([], $result->getErrors());
		Assert::same([], $result->getWarnings());
	}

}

(new SecurityTxtValidatorTest())->run();
