<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use DateTime;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiredError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresOldFormatError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresTooLongWarning;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresWrongFormatError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtMultipleExpiresError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtNoExpiresError;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class SecurityTxtParserTest extends TestCase
{

	private SecurityTxtParser $securityTxtParser;
	private SecurityTxtValidator $securityTxtValidator;


	protected function setUp(): void
	{
		$this->securityTxtValidator = new SecurityTxtValidator();
		$this->securityTxtParser = new SecurityTxtParser($this->securityTxtValidator);
	}


	public function getExpiresField(): array
	{
		return [
			'expired' => ['-5 days', true, [2 => [SecurityTxtExpiredError::class]]],
			'not expired' => ['+37 days', false, []],
		];
	}


	/** @dataProvider getExpiresField */
	public function testParseStringExpiresField(string $fieldValue, bool $isExpired, array $errors): void
	{
		$contents = "Foo: bar\nExpires: " . (new DateTime($fieldValue))->format(DATE_RFC3339) . "\nBar: foo";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::same($isExpired, $parseResult->getSecurityTxt()->getExpires()->isExpired());
		foreach ($parseResult->getParseErrors() as $lineNumber => $lineErrors) {
			foreach ($lineErrors as $key => $lineError) {
				Assert::type($errors[$lineNumber][$key], $lineError);
			}
		}
	}


	public function testParseStringExpiresFieldWrongFormat(): void
	{
		$contents = 'Expires: 4020-10-05 03:21:00 Europe/Prague';
		$parseResult = $this->securityTxtParser->parseString($contents);
		/** @var SecurityTxtExpiresWrongFormatError $expiresError */
		$expiresError = $parseResult->getParseErrors()[1][0];
		Assert::type(SecurityTxtExpiresWrongFormatError::class, $expiresError);
		Assert::same('4020-10-05T03:21:00+02:00', $expiresError->getCorrectValue());
	}


	public function testParseStringExpiresFieldOldFormat(): void
	{
		$contents = 'Expires: Mon, 15 Aug 2005 15:52:01 +0000';
		$parseResult = $this->securityTxtParser->parseString($contents);
		/** @var SecurityTxtExpiresOldFormatError $expiresError */
		$expiresError = $parseResult->getParseErrors()[1][0];
		Assert::type(SecurityTxtExpiresOldFormatError::class, $expiresError);
		Assert::same('2005-08-15T15:52:01+00:00', $expiresError->getCorrectValue());
	}


	public function testParseStringMissingExpires(): void
	{
		$contents = "Foo: bar\nBar: foo";
		$parseResult = $this->securityTxtParser->parseString($contents);
		$expiresError = $parseResult->getFileErrors()[0];
		Assert::type(SecurityTxtNoExpiresError::class, $expiresError);
	}


	public function testParseStringMultipleExpires(): void
	{
		$contents = "Foo: bar\nExpires: " . (new DateTime('+2 months'))->format(DATE_RFC3339) . "\nExpires: " . (new DateTime('+3 months'))->format(DATE_RFC3339) . "\nBar: foo";
		$parseResult = $this->securityTxtParser->parseString($contents);
		$expiresError = $parseResult->getParseErrors()[3][0];
		Assert::type(SecurityTxtMultipleExpiresError::class, $expiresError);
	}


	public function testParseStringMultipleExpiresAllWrong(): void
	{
		$contents = "Foo: bar\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nExpires: Mon, 15 Aug 2015 15:52:01 +0000\nBar: foo";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormatError::class, $parseResult->getParseErrors()[2][0]);
		Assert::type(SecurityTxtExpiresOldFormatError::class, $parseResult->getParseErrors()[3][0]);
	}


	public function testParseStringMultipleExpiresFirstWrong(): void
	{
		$contents = "Foo: bar\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nExpires: " . (new DateTime('+2 months'))->format(DATE_RFC3339) . "\nBar: foo";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormatError::class, $parseResult->getParseErrors()[2][0]);
	}


	public function testParseStringMultipleExpiresFirstCorrect(): void
	{
		$contents = "Foo: bar\nExpires: " . (new DateTime('+2 months'))->format(DATE_RFC3339) . "\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nBar: foo";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(2, $parseResult->getParseErrors()[3]);
		Assert::type(SecurityTxtMultipleExpiresError::class, $parseResult->getParseErrors()[3][0]);
		Assert::type(SecurityTxtExpiresOldFormatError::class, $parseResult->getParseErrors()[3][1]);
	}


	public function testParseMultipleFiles(): void
	{
		$expires1 = (new DateTime('+2 months'))->format(DATE_RFC3339);
		$contents = 'Expires: ' . $expires1;
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::same($expires1, $parseResult->getSecurityTxt()->getExpires()->getDateTime()->format(DATE_RFC3339));
		Assert::count(0, $parseResult->getParseErrors());
		Assert::count(0, $parseResult->getFileErrors());

		$expires2 = (new DateTime('+3 months'))->format(DATE_RFC3339);
		$contents = 'Expires: ' . $expires2;
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::same($expires2, $parseResult->getSecurityTxt()->getExpires()->getDateTime()->format(DATE_RFC3339));
		Assert::count(0, $parseResult->getParseErrors());
		Assert::count(0, $parseResult->getFileErrors());

		Assert::notSame($expires1, $expires2);
	}


	public function testParseMultipleBadFiles(): void
	{
		$contents = "Foo: bar\nExpires: " . (new DateTime('+2 months'))->format(DATE_RFC3339) . "\nExpires: " . (new DateTime('+3 months'))->format(DATE_RFC3339) . "\nBar: foo";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtMultipleExpiresError::class, $parseResult->getParseErrors()[3][0]);

		$contents = 'Expires: Mon, 15 Aug 2005 15:52:01 +0000';
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormatError::class, $parseResult->getParseErrors()[1][0]);
	}


	public function testParseStringExpiresTooLong(): void
	{
		$contents = "Foo: bar\nExpires: " . (new DateTime('+2 years'))->format(DATE_RFC3339);
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(0, $parseResult->getParseErrors());
		Assert::count(1, $parseResult->getParseWarnings());
		Assert::count(1, $parseResult->getParseWarnings()[2]);
		Assert::type(SecurityTxtExpiresTooLongWarning::class, $parseResult->getParseWarnings()[2][0]);
	}

}

(new SecurityTxtParserTest())->run();
