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
use Spaze\SecurityTxt\Exceptions\SecurityTxtNoContactError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtNoExpiresError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtThrowable;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherFopenClient;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherHttpClient;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcher;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
class SecurityTxtParserTest extends TestCase
{

	private SecurityTxtParser $securityTxtParser;
	private SecurityTxtValidator $securityTxtValidator;
	private SecurityTxtSignature $securityTxtSignature;
	private SecurityTxtFetcher $securityTxtFetcher;
	private SecurityTxtFetcherHttpClient $securityTxtFetcherHttpClient;


	protected function setUp(): void
	{
		$this->securityTxtValidator = new SecurityTxtValidator();
		$this->securityTxtSignature = new SecurityTxtSignature();
		$this->securityTxtFetcherHttpClient = new SecurityTxtFetcherFopenClient();
		$this->securityTxtFetcher = new SecurityTxtFetcher($this->securityTxtFetcherHttpClient);
		$this->securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, $this->securityTxtSignature, $this->securityTxtFetcher);
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
		Assert::contains(SecurityTxtNoExpiresError::class, array_map(function (SecurityTxtThrowable $throwable): string {
			return $throwable::class;
		}, $parseResult->getFileErrors()));
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
		$assertParsed = function (string $mailto, string $expires): void {
			$contents = "Contact: {$mailto}\nExpires: {$expires}";
			$parseResult = $this->securityTxtParser->parseString($contents);
			Assert::same($mailto, $parseResult->getSecurityTxt()->getContact()[0]->getUri());
			Assert::same($expires, $parseResult->getSecurityTxt()->getExpires()->getDateTime()->format(DATE_RFC3339));
			Assert::count(0, $parseResult->getParseErrors());
			Assert::count(0, $parseResult->getFileErrors());
		};
		$assertParsed('mailto:foo@bar.example', (new DateTime('+2 months'))->format(DATE_RFC3339));
		$assertParsed('mailto:bar@foo.example', (new DateTime('+3 months'))->format(DATE_RFC3339));
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


	public function testParseStringMissingContact(): void
	{
		$contents = "Foo: bar\nBar: foo";
		$parseResult = $this->securityTxtParser->parseString($contents);
		$contactError = $parseResult->getFileErrors()[0];
		Assert::type(SecurityTxtNoContactError::class, $contactError);
	}

}

(new SecurityTxtParserTest())->run();
