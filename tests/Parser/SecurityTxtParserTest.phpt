<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use DateTime;
use DateTimeImmutable;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherFopenClient;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcher;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeWrongCharset;
use Spaze\SecurityTxt\Violations\SecurityTxtExpired;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresOldFormat;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresTooLong;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresWrongFormat;
use Spaze\SecurityTxt\Violations\SecurityTxtLineNoEol;
use Spaze\SecurityTxt\Violations\SecurityTxtMultipleExpires;
use Spaze\SecurityTxt\Violations\SecurityTxtMultiplePreferredLanguages;
use Spaze\SecurityTxt\Violations\SecurityTxtNoContact;
use Spaze\SecurityTxt\Violations\SecurityTxtNoExpires;
use Spaze\SecurityTxt\Violations\SecurityTxtPossibelFieldTypo;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesCommonMistake;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesSeparatorNotComma;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelPathOnly;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtParserTest extends TestCase
{

	private SecurityTxtParser $securityTxtParser;


	protected function setUp(): void
	{
		$securityTxtValidator = new SecurityTxtValidator();
		$securityTxtSignature = new SecurityTxtSignature();
		$securityTxtFetcherHttpClient = new SecurityTxtFetcherFopenClient();
		$securityTxtFetcher = new SecurityTxtFetcher($securityTxtFetcherHttpClient);
		$this->securityTxtParser = new SecurityTxtParser($securityTxtValidator, $securityTxtSignature, $securityTxtFetcher);
	}


	public function getExpiresField(): array
	{
		return [
			'expired' => ['-5 days', true, [2 => [SecurityTxtExpired::class]]],
			'not expired' => ['+37 days', false, []],
		];
	}


	/** @dataProvider getExpiresField */
	public function testParseStringExpiresField(string $fieldValue, bool $isExpired, array $errors): void
	{
		$contents = "Foo: bar\nExpires: " . new DateTime($fieldValue)->format(DATE_RFC3339) . "\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::same($isExpired, $parseResult->getSecurityTxt()->getExpires()->isExpired());
		foreach ($parseResult->getLineErrors() as $lineNumber => $lineErrors) {
			foreach ($lineErrors as $key => $lineError) {
				Assert::type($errors[$lineNumber][$key], $lineError);
			}
		}
	}


	public function testParseStringExpiresFieldWrongFormat(): void
	{
		$contents = "Expires: 4020-10-05 03:21:00 Europe/Prague\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		/** @var SecurityTxtExpiresWrongFormat $expiresError */
		$expiresError = $parseResult->getLineErrors()[1][0];
		Assert::type(SecurityTxtExpiresWrongFormat::class, $expiresError);
		Assert::same('4020-10-05T03:21:00+02:00', $expiresError->getCorrectValue());
	}


	public function testParseStringExpiresFieldOldFormat(): void
	{
		$contents = "Expires: Mon, 15 Aug 2005 15:52:01 +0000\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		/** @var SecurityTxtExpiresOldFormat $expiresError */
		$expiresError = $parseResult->getLineErrors()[1][0];
		Assert::type(SecurityTxtExpiresOldFormat::class, $expiresError);
		Assert::same('2005-08-15T15:52:01+00:00', $expiresError->getCorrectValue());
	}


	public function testParseStringMissingExpires(): void
	{
		$contents = "Foo: bar\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::contains(SecurityTxtNoExpires::class, array_map(function (SecurityTxtSpecViolation $throwable): string {
			return $throwable::class;
		}, $parseResult->getFileErrors()));
	}


	public function testParseStringMultipleExpires(): void
	{
		$contents = "Foo: bar\nExpires: " . new DateTime('+2 months')->format(DATE_RFC3339) . "\nExpires: " . new DateTime('+3 months')->format(DATE_RFC3339) . "\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		$expiresError = $parseResult->getLineErrors()[3][0];
		Assert::type(SecurityTxtMultipleExpires::class, $expiresError);
	}


	public function testParseStringMultipleExpiresAllWrong(): void
	{
		$contents = "Foo: bar\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nExpires: Mon, 15 Aug 2015 15:52:01 +0000\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormat::class, $parseResult->getLineErrors()[2][0]);
		Assert::type(SecurityTxtExpiresOldFormat::class, $parseResult->getLineErrors()[3][0]);
	}


	public function testParseStringMultipleExpiresFirstWrong(): void
	{
		$contents = "Foo: bar\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nExpires: " . new DateTime('+2 months')->format(DATE_RFC3339) . "\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormat::class, $parseResult->getLineErrors()[2][0]);
	}


	public function testParseStringMultipleExpiresFirstCorrect(): void
	{
		$contents = "Foo: bar\nExpires: " . new DateTime('+2 months')->format(DATE_RFC3339) . "\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(2, $parseResult->getLineErrors()[3]);
		Assert::type(SecurityTxtMultipleExpires::class, $parseResult->getLineErrors()[3][0]);
		Assert::type(SecurityTxtExpiresOldFormat::class, $parseResult->getLineErrors()[3][1]);
	}


	public function testParseMultipleFiles(): void
	{
		$assertParsed = function (string $mailto, string $expires): void {
			$contents = "Contact: {$mailto}\nExpires: {$expires}\n";
			$parseResult = $this->securityTxtParser->parseString($contents);
			Assert::same($mailto, $parseResult->getSecurityTxt()->getContact()[0]->getUri());
			Assert::same($expires, $parseResult->getSecurityTxt()->getExpires()->getDateTime()->format(DATE_RFC3339));
			Assert::count(0, $parseResult->getLineErrors());
			Assert::count(0, $parseResult->getFileErrors());
		};
		$assertParsed('mailto:foo@bar.example', new DateTime('+2 months')->format(DATE_RFC3339));
		$assertParsed('mailto:bar@foo.example', new DateTime('+3 months')->format(DATE_RFC3339));
	}


	public function testParseMultipleBadFiles(): void
	{
		$contents = "Foo: bar\nExpires: " . new DateTime('+2 months')->format(DATE_RFC3339) . "\nExpires: " . new DateTime('+3 months')->format(DATE_RFC3339) . "\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtMultipleExpires::class, $parseResult->getLineErrors()[3][0]);

		$contents = "Expires: Mon, 15 Aug 2005 15:52:01 +0000\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormat::class, $parseResult->getLineErrors()[1][0]);
	}


	public function testParseStringExpiresTooLong(): void
	{
		$contents = "Foo: bar\nExpires: " . new DateTime('+2 years')->format(DATE_RFC3339) . "\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(0, $parseResult->getLineErrors());
		Assert::count(1, $parseResult->getLineWarnings());
		Assert::count(1, $parseResult->getLineWarnings()[2]);
		Assert::type(SecurityTxtExpiresTooLong::class, $parseResult->getLineWarnings()[2][0]);
	}


	public function testParseStringMissingContact(): void
	{
		$contents = "Foo: bar\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		$contactError = $parseResult->getFileErrors()[0];
		Assert::type(SecurityTxtNoContact::class, $contactError);
	}


	public function testParseStringNoEol(): void
	{
		$contents = 'Expires: ' . new DateTime('+3 months')->format(DATE_RFC3339) . "\nContact: https://foo.example/";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(1, $parseResult->getLineErrors());
		Assert::count(1, $parseResult->getLineErrors()[2]);
		Assert::type(SecurityTxtLineNoEol::class, $parseResult->getLineErrors()[2][0]);
	}


	public function testParseStringPreferredLanguages(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: en,CS\n");
		Assert::count(0, $parseResult->getLineErrors());
		Assert::same(['en', 'CS'], $parseResult->getSecurityTxt()->getPreferredLanguages()->getLanguages());
	}


	public function testParseStringMultiplePreferredLanguages(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: en\nPreferred-Languages: cs\n");
		Assert::count(1, $parseResult->getLineErrors());
		Assert::type(SecurityTxtMultiplePreferredLanguages::class, $parseResult->getLineErrors()[2][0]);
	}


	public function testParseStringPreferredLanguagesBadSeparator(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: en, cs;fi. nl\n");
		$error = $parseResult->getLineErrors()[1][0];
		Assert::count(1, $parseResult->getLineErrors());
		Assert::type(SecurityTxtPreferredLanguagesSeparatorNotComma::class, $error);
		Assert::same('The `Preferred-Languages` field uses wrong separators (#2 `;`, #3 `.`), separate multiple values with a comma (`,`)', $error->getMessage());
		Assert::same('en, cs, fi, nl', $error->getCorrectValue());
	}


	public function testParseStringPreferredLanguagesCommonMistake(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: CZ,en\n");
		$error = $parseResult->getLineErrors()[1][0];
		Assert::count(1, $parseResult->getLineErrors());
		Assert::type(SecurityTxtPreferredLanguagesCommonMistake::class, $error);
		Assert::same('The language tag #1 `CZ` in the `Preferred-Languages` field is not correct, the code for Czech language is `cs`, not `cz`', $error->getMessage());
		Assert::same(['CZ', 'en'], $parseResult->getSecurityTxt()->getPreferredLanguages()->getLanguages());

		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: CZ-Czechia,en\n");
		$error = $parseResult->getLineErrors()[1][0];
		Assert::type(SecurityTxtPreferredLanguagesCommonMistake::class, $error);
		Assert::same('cs-Czechia', $error->getCorrectValue());
		Assert::same(['CZ-Czechia', 'en'], $parseResult->getSecurityTxt()->getPreferredLanguages()->getLanguages());
	}


	public function testParseStringAcknowledgments(): void
	{
		$uri = 'https://example.com/ack.gif';
		$parseResult = $this->securityTxtParser->parseString("Acknowledgments: {$uri}\n");
		Assert::count(0, $parseResult->getLineErrors());
		Assert::same($uri, $parseResult->getSecurityTxt()->getAcknowledgments()[0]->getUri());
	}


	public function testParseStringAcknowledgementsTypo(): void
	{
		$uri1 = "https://example.example/whole-of-fame";
		$uri2 = 'https://example.com/ack.gif';
		$parseResult = $this->securityTxtParser->parseString("Acknowledgments: {$uri1}\nAcknowledgements: {$uri2}\n");
		Assert::count(0, $parseResult->getLineErrors());
		$warning = $parseResult->getLineWarnings()[2][0];
		Assert::type(SecurityTxtPossibelFieldTypo::class, $warning);
		Assert::same("Acknowledgments: {$uri2}", $warning->getCorrectValue());
		Assert::count(1, $parseResult->getSecurityTxt()->getAcknowledgments());
		Assert::same($uri1, $parseResult->getSecurityTxt()->getAcknowledgments()[0]->getUri());
	}


	public function testParseStringHiring(): void
	{
		$uri = 'https://example.com/cv.psd';
		$parseResult = $this->securityTxtParser->parseString("Hiring: {$uri}\n");
		Assert::count(0, $parseResult->getLineErrors());
		Assert::same($uri, $parseResult->getSecurityTxt()->getHiring()[0]->getUri());
	}


	public function testParseStringPolicy(): void
	{
		$uri = 'https://example.com/policy.pcx';
		$parseResult = $this->securityTxtParser->parseString("Policy: {$uri}\n");
		Assert::count(0, $parseResult->getLineErrors());
		Assert::same($uri, $parseResult->getSecurityTxt()->getPolicy()[0]->getUri());
	}


	public function testParseStringEncryption(): void
	{
		$uri = 'https://example.com/keys.ico';
		$parseResult = $this->securityTxtParser->parseString("Encryption: {$uri}\n");
		Assert::count(0, $parseResult->getLineErrors());
		Assert::same($uri, $parseResult->getSecurityTxt()->getEncryption()[0]->getUri());
	}


	public function testParseFetchResult(): void
	{
		$fetchResult = new SecurityTxtFetchResult(
			'https://example.com/security.txt',
			'https://www.example.com/security.txt',
			[
				'https://example.com/.well-known/security.txt' => ['https://www.example.com/.well-known/security.txt'],
				'https://example.com/security.txt' => ['https://www.example.com/security.txt'],
			],
			"Contact: mailto:example@example.com\r\nExpires: 2020-12-31T23:59:59.000Z",
			[new SecurityTxtContentTypeWrongCharset('https://example.com/security.txt', 'text/plain', null)],
			[new SecurityTxtTopLevelPathOnly()],
		);
		$parseResult = $this->securityTxtParser->parseFetchResult($fetchResult);
		Assert::same("The line (`Expires: 2020-12-31T23:59:59.000Z`) doesn't end with neither <CRLF> nor <LF>", $parseResult->getLineErrors()[2][0]->getMessage());
		Assert::same("The file is considered stale and should not be used", $parseResult->getLineErrors()[2][1]->getMessage());
		Assert::same([], $parseResult->getLineWarnings());
		Assert::same([], $parseResult->getFileErrors());
		Assert::same([], $parseResult->getFileWarnings());
		Assert::false($parseResult->isExpiresSoon());
		Assert::false($parseResult->isValid());

		$expires = new DateTimeImmutable('+7 days');
		$fetchResult = new SecurityTxtFetchResult(
			'https://example.com/security.txt',
			'https://www.example.com/security.txt',
			[],
			"Contact: mailto:example@example.com\r\nExpires: " . $expires->format(DATE_RFC3339) . "\r\n",
			[],
			[],
		);
		$parseResult = $this->securityTxtParser->parseFetchResult($fetchResult, 14);
		Assert::same([], $parseResult->getLineErrors());
		Assert::same([], $parseResult->getLineWarnings());
		Assert::same([], $parseResult->getFileErrors());
		Assert::same([], $parseResult->getFileWarnings());
		Assert::true($parseResult->isExpiresSoon());
		Assert::true($parseResult->isValid());

		$parseResult = $this->securityTxtParser->parseFetchResult($fetchResult, 14, true);
		Assert::false($parseResult->isValid());
	}

}

new SecurityTxtParserTest()->run();
