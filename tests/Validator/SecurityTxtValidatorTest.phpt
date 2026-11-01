<?php
/**
 * @testCase
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use DateTimeImmutable;
use Spaze\SecurityTxt\Fields\SecurityTxtCanonical;
use Spaze\SecurityTxt\Fields\SecurityTxtContact;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\SecurityTxtValidationLevel;
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


	/**
	 * @dataProvider getSameUriDifferentlyWritten
	 */
	public function testValidateCanonicalUriMatchHoweverItIsWritten(string $canonical): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->setFileLocation('https://example.com/.well-known/security.txt');
		$securityTxt->addCanonical(new SecurityTxtCanonical($canonical));
		$securityTxt->addContact(new SecurityTxtContact('mailto:foo@example.com'));
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create(new DateTimeImmutable('+1 month')));
		$this->assertNoViolation($securityTxt);
	}


	/**
	 * @return array<string, array{0:string}>
	 */
	public function getSameUriDifferentlyWritten(): array
	{
		// The field says where the file is, and these all say the same place, so none of them is a mismatch
		return [
			'as written' => ['https://example.com/.well-known/security.txt'],
			'scheme in a different case' => ['HTTPS://example.com/.well-known/security.txt'],
			'host in a different case' => ['https://EXAMPLE.COM/.well-known/security.txt'],
			'default port spelled out' => ['https://example.com:443/.well-known/security.txt'],
		];
	}


	/**
	 * @dataProvider getDifferentUri
	 */
	public function testValidateCanonicalUriMismatchStillReported(string $canonical): void
	{
		$securityTxt = new SecurityTxt();
		$securityTxt->setFileLocation('https://example.com/.well-known/security.txt');
		$securityTxt->addCanonical(new SecurityTxtCanonical($canonical));
		$securityTxt->addContact(new SecurityTxtContact('mailto:foo@example.com'));
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create(new DateTimeImmutable('+1 month')));
		$this->assertViolation($securityTxt, SecurityTxtCanonicalUriMismatch::class);
	}


	/**
	 * @return array<string, array{0:string}>
	 */
	public function getDifferentUri(): array
	{
		// A fragment counts, like it does when the fetcher compares two final URLs, and a value that will not parse can only be compared as written
		return [
			'another path' => ['https://example.com/security.txt'],
			'another host' => ['https://other.example/.well-known/security.txt'],
			'another port' => ['https://example.com:8443/.well-known/security.txt'],
			'a fragment' => ['https://example.com/.well-known/security.txt#fragment'],
		];
	}


	public function testValidateCanonicalThatWillNotParseIsAMismatch(): void
	{
		// The parser keeps a value that is not a URI, reporting it separately, so the comparison still has to cope with one, and one that names nothing lists nothing
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently);
		$securityTxt->setFileLocation('https://example.com/.well-known/security.txt');
		$securityTxt->addCanonical(new SecurityTxtCanonical('not a uri at all'));
		$securityTxt->addContact(new SecurityTxtContact('mailto:foo@example.com'));
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create(new DateTimeImmutable('+1 month')));
		$this->assertViolation($securityTxt, SecurityTxtCanonicalUriMismatch::class);
	}


	/**
	 * @dataProvider getFileLocationsWorthNoComparison
	 */
	public function testValidateNoCanonicalComparisonWhenTheLocationItselfIsWrong(string $fileLocation): void
	{
		// The location has a violation of its own saying the real thing; comparing against it would add a second complaint telling a correct Canonical field it is wrong
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently);
		$securityTxt->setFileLocation($fileLocation);
		$securityTxt->addCanonical(new SecurityTxtCanonical('https://example.com/.well-known/security.txt'));
		$securityTxt->addContact(new SecurityTxtContact('mailto:foo@example.com'));
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create(new DateTimeImmutable('+1 month')));
		$this->assertNoViolation($securityTxt);
	}


	/**
	 * @return array<string, array{0:string}>
	 */
	public function getFileLocationsWorthNoComparison(): array
	{
		return [
			'fetched over http' => ['http://example.com/.well-known/security.txt'],
			'not a URI' => ['not a uri at all'],
			'the same nothing the Canonical field could name' => ['foo'],
		];
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


	public function testValidateCanonicalUriMismatchReason(): void
	{
		$wellKnown = 'https://example.com/.well-known/security.txt';
		$topLevel = 'https://example.com/security.txt';
		$cases = [
			"{$wellKnown} | https://example.com/security.txt" => [$wellKnown, 'https://example.com/security.txt'],
			"{$wellKnown} | https://example.com/.well-known/sercurity.txt" => [$wellKnown, 'https://example.com/.well-known/sercurity.txt'],
			"{$wellKnown} | https://example.com/.well-known/security.txt/" => [$wellKnown, 'https://example.com/.well-known/security.txt/'],
			"{$wellKnown} | https://example.com:8443/.well-known/security.txt" => [$wellKnown, 'https://example.com:8443/.well-known/security.txt'],
			"{$wellKnown} | http://example.com/.well-known/security.txt" => [$wellKnown, 'http://example.com/.well-known/security.txt'],
			"{$wellKnown} | https://www.example.com/.well-known/security.txt" => [$wellKnown, 'https://www.example.com/.well-known/security.txt'],
			"{$wellKnown} | not a uri" => [$wellKnown, 'not a uri'],
			"{$wellKnown} | .well-known/security.txt" => [$wellKnown, '.well-known/security.txt'],
			"{$topLevel} | not a uri" => [$topLevel, 'not a uri'],
			"{$topLevel} | https://example.com/.well-known/security.txt" => [$topLevel, 'https://example.com/.well-known/security.txt'],
			"{$topLevel} | https://example.com/.well-known/sercurity.txt" => [$topLevel, 'https://example.com/.well-known/sercurity.txt'],
			'https://example.com/files/security.txt | https://example.com/.well-known/security.txt' => ['https://example.com/files/security.txt', 'https://example.com/.well-known/security.txt'],
			'https://example.com/security.txt?x=1 | https://example.com/.well-known/security.txt' => ['https://example.com/security.txt?x=1', 'https://example.com/.well-known/security.txt'],
			"{$wellKnown}?x=1 | {$wellKnown}" => ["{$wellKnown}?x=1", $wellKnown],
			"{$wellKnown}#top | {$wellKnown}" => ["{$wellKnown}#top", $wellKnown],
			"https://h\u{E1}\u{10D}ky.example/.well-known/security.txt | https://xn--hky-ela4t.example/security.txt" => ["https://h\u{E1}\u{10D}ky.example/.well-known/security.txt", 'https://xn--hky-ela4t.example/security.txt'],
		];
		$params = [];
		foreach ($cases as $name => [$fileLocation, $canonical]) {
			$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently);
			$securityTxt->setFileLocation($fileLocation);
			$securityTxt->addCanonical(new SecurityTxtCanonical($canonical));
			$params[$name] = array_map(function (SecurityTxtSpecViolation $warning): array {
				$stored = $warning->jsonSerialize()['params'] ?? null;
				assert(is_array($stored));
				return array_slice($stored, 2);
			}, $this->securityTxtValidator->validate($securityTxt)->getWarnings());
		}
		Assert::same([
			"{$wellKnown} | https://example.com/security.txt" => [['top-level-listed']],
			"{$wellKnown} | https://example.com/.well-known/sercurity.txt" => [['same-host']],
			"{$wellKnown} | https://example.com/.well-known/security.txt/" => [['same-host']],
			"{$wellKnown} | https://example.com:8443/.well-known/security.txt" => [['same-host']],
			"{$wellKnown} | http://example.com/.well-known/security.txt" => [['same-host']],
			"{$wellKnown} | https://www.example.com/.well-known/security.txt" => [[]],
			"{$wellKnown} | not a uri" => [['not-uri']],
			"{$wellKnown} | .well-known/security.txt" => [['not-uri']],
			"{$topLevel} | not a uri" => [[]],
			"{$topLevel} | https://example.com/.well-known/security.txt" => [['well-known-listed']],
			"{$topLevel} | https://example.com/.well-known/sercurity.txt" => [[]],
			'https://example.com/files/security.txt | https://example.com/.well-known/security.txt' => [[]],
			'https://example.com/security.txt?x=1 | https://example.com/.well-known/security.txt' => [[]],
			"{$wellKnown}?x=1 | {$wellKnown}" => [[]],
			"{$wellKnown}#top | {$wellKnown}" => [[]],
			"https://h\u{E1}\u{10D}ky.example/.well-known/security.txt | https://xn--hky-ela4t.example/security.txt" => [['top-level-listed']],
		], $params);
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
