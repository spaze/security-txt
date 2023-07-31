<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use DateTime;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiredError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresOldFormatError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresTooLongWarning;
use Spaze\SecurityTxt\Exceptions\SecurityTxtExpiresWrongFormatError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtLineNoEolError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtMultipleExpiresError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtMultiplePreferredLanguagesError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtNoContactError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtNoExpiresError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtPossibelFieldTypoWarning;
use Spaze\SecurityTxt\Exceptions\SecurityTxtPreferredLanguagesCommonMistakeError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtPreferredLanguagesSeparatorNotCommaError;
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
		$contents = "Foo: bar\nExpires: " . (new DateTime($fieldValue))->format(DATE_RFC3339) . "\nBar: foo\n";
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
		$contents = "Expires: 4020-10-05 03:21:00 Europe/Prague\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		/** @var SecurityTxtExpiresWrongFormatError $expiresError */
		$expiresError = $parseResult->getParseErrors()[1][0];
		Assert::type(SecurityTxtExpiresWrongFormatError::class, $expiresError);
		Assert::same('4020-10-05T03:21:00+02:00', $expiresError->getCorrectValue());
	}


	public function testParseStringExpiresFieldOldFormat(): void
	{
		$contents = "Expires: Mon, 15 Aug 2005 15:52:01 +0000\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		/** @var SecurityTxtExpiresOldFormatError $expiresError */
		$expiresError = $parseResult->getParseErrors()[1][0];
		Assert::type(SecurityTxtExpiresOldFormatError::class, $expiresError);
		Assert::same('2005-08-15T15:52:01+00:00', $expiresError->getCorrectValue());
	}


	public function testParseStringMissingExpires(): void
	{
		$contents = "Foo: bar\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::contains(SecurityTxtNoExpiresError::class, array_map(function (SecurityTxtThrowable $throwable): string {
			return $throwable::class;
		}, $parseResult->getFileErrors()));
	}


	public function testParseStringMultipleExpires(): void
	{
		$contents = "Foo: bar\nExpires: " . (new DateTime('+2 months'))->format(DATE_RFC3339) . "\nExpires: " . (new DateTime('+3 months'))->format(DATE_RFC3339) . "\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		$expiresError = $parseResult->getParseErrors()[3][0];
		Assert::type(SecurityTxtMultipleExpiresError::class, $expiresError);
	}


	public function testParseStringMultipleExpiresAllWrong(): void
	{
		$contents = "Foo: bar\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nExpires: Mon, 15 Aug 2015 15:52:01 +0000\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormatError::class, $parseResult->getParseErrors()[2][0]);
		Assert::type(SecurityTxtExpiresOldFormatError::class, $parseResult->getParseErrors()[3][0]);
	}


	public function testParseStringMultipleExpiresFirstWrong(): void
	{
		$contents = "Foo: bar\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nExpires: " . (new DateTime('+2 months'))->format(DATE_RFC3339) . "\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormatError::class, $parseResult->getParseErrors()[2][0]);
	}


	public function testParseStringMultipleExpiresFirstCorrect(): void
	{
		$contents = "Foo: bar\nExpires: " . (new DateTime('+2 months'))->format(DATE_RFC3339) . "\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(2, $parseResult->getParseErrors()[3]);
		Assert::type(SecurityTxtMultipleExpiresError::class, $parseResult->getParseErrors()[3][0]);
		Assert::type(SecurityTxtExpiresOldFormatError::class, $parseResult->getParseErrors()[3][1]);
	}


	public function testParseMultipleFiles(): void
	{
		$assertParsed = function (string $mailto, string $expires): void {
			$contents = "Contact: {$mailto}\nExpires: {$expires}\n";
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
		$contents = "Foo: bar\nExpires: " . (new DateTime('+2 months'))->format(DATE_RFC3339) . "\nExpires: " . (new DateTime('+3 months'))->format(DATE_RFC3339) . "\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtMultipleExpiresError::class, $parseResult->getParseErrors()[3][0]);

		$contents = "Expires: Mon, 15 Aug 2005 15:52:01 +0000\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormatError::class, $parseResult->getParseErrors()[1][0]);
	}


	public function testParseStringExpiresTooLong(): void
	{
		$contents = "Foo: bar\nExpires: " . (new DateTime('+2 years'))->format(DATE_RFC3339) . "\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(0, $parseResult->getParseErrors());
		Assert::count(1, $parseResult->getParseWarnings());
		Assert::count(1, $parseResult->getParseWarnings()[2]);
		Assert::type(SecurityTxtExpiresTooLongWarning::class, $parseResult->getParseWarnings()[2][0]);
	}


	public function testParseStringMissingContact(): void
	{
		$contents = "Foo: bar\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		$contactError = $parseResult->getFileErrors()[0];
		Assert::type(SecurityTxtNoContactError::class, $contactError);
	}


	public function testParseStringNoEol(): void
	{
		$contents = 'Expires: ' . (new DateTime('+3 months'))->format(DATE_RFC3339) . "\nContact: https://foo.example/";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(1, $parseResult->getParseErrors());
		Assert::count(1, $parseResult->getParseErrors()[2]);
		Assert::type(SecurityTxtLineNoEolError::class, $parseResult->getParseErrors()[2][0]);
	}


	public function testParseStringPreferredLanguages(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: en,CS\n");
		Assert::count(0, $parseResult->getParseErrors());
		Assert::same(['en', 'CS'], $parseResult->getSecurityTxt()->getPreferredLanguages()->getLanguages());
	}


	public function testParseStringMultiplePreferredLanguages(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: en\nPreferred-Languages: cs\n");
		Assert::count(1, $parseResult->getParseErrors());
		Assert::type(SecurityTxtMultiplePreferredLanguagesError::class, $parseResult->getParseErrors()[2][0]);
	}


	public function testParseStringPreferredLanguagesBadSeparator(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: en, cs;fi; nl\n");
		$error = $parseResult->getParseErrors()[1][0];
		Assert::count(1, $parseResult->getParseErrors());
		Assert::type(SecurityTxtPreferredLanguagesSeparatorNotCommaError::class, $error);
		Assert::same('The `Preferred-Languages` field uses a wrong separator (`;` at positions 6, 9 characters from the start), separate multiple values with a comma (`,`)', $error->getMessage());
		Assert::same('en, cs, fi, nl', $error->getCorrectValue());
	}


	public function testParseStringPreferredLanguagesCommonMistake(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: CZ,en\n");
		$error = $parseResult->getParseErrors()[1][0];
		Assert::count(1, $parseResult->getParseErrors());
		Assert::type(SecurityTxtPreferredLanguagesCommonMistakeError::class, $error);
		Assert::same('The language tag #1 `CZ` in the `Preferred-Languages` field is not correct, the code for Czech language is `cs`, not `cz`', $error->getMessage());
		Assert::same(['CZ', 'en'], $parseResult->getSecurityTxt()->getPreferredLanguages()->getLanguages());

		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: CZ-Czechia,en\n");
		$error = $parseResult->getParseErrors()[1][0];
		Assert::type(SecurityTxtPreferredLanguagesCommonMistakeError::class, $error);
		Assert::same('cs-Czechia', $error->getCorrectValue());
		Assert::same(['CZ-Czechia', 'en'], $parseResult->getSecurityTxt()->getPreferredLanguages()->getLanguages());
	}


	public function testParseStringAcknowledgments(): void
	{
		$uri = 'https://example.com/ack.gif';
		$parseResult = $this->securityTxtParser->parseString("Acknowledgments: {$uri}\n");
		Assert::count(0, $parseResult->getParseErrors());
		Assert::same($uri, $parseResult->getSecurityTxt()->getAcknowledgments()[0]->getUri());
	}


	public function testParseStringAcknowledgementsTypo(): void
	{
		$uri1 = "https://example.example/whole-of-fame";
		$uri2 = 'https://example.com/ack.gif';
		$parseResult = $this->securityTxtParser->parseString("Acknowledgments: {$uri1}\nAcknowledgements: {$uri2}\n");
		Assert::count(0, $parseResult->getParseErrors());
		$warning = $parseResult->getParseWarnings()[2][0];
		Assert::type(SecurityTxtPossibelFieldTypoWarning::class, $warning);
		Assert::same("Acknowledgments: {$uri2}", $warning->getCorrectValue());
		Assert::count(1, $parseResult->getSecurityTxt()->getAcknowledgments());
		Assert::same($uri1, $parseResult->getSecurityTxt()->getAcknowledgments()[0]->getUri());
	}

}

(new SecurityTxtParserTest())->run();
