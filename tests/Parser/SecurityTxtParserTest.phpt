<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use DateTime;
use DateTimeImmutable;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\Fields\SecurityTxtExpires;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Signature\Providers\SecurityTxtSignatureGnuPgProvider;
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


	public function __construct()
	{
		$securityTxtValidator = new SecurityTxtValidator();
		$securityTxtSignatureGnuPgProvider = new SecurityTxtSignatureGnuPgProvider();
		$securityTxtSignature = new SecurityTxtSignature($securityTxtSignatureGnuPgProvider);
		$securityTxtExpiresFactory = new SecurityTxtExpiresFactory();
		$securityTxtSplitLines = new SecurityTxtSplitLines();
		$this->securityTxtParser = new SecurityTxtParser($securityTxtValidator, $securityTxtSignature, $securityTxtExpiresFactory, $securityTxtSplitLines);
	}


	/**
	 * @return array<string, array{0:string, 1:bool, 2:array<int, list<class-string<SecurityTxtExpired>>>}>
	 */
	public function getExpiresField(): array
	{
		return [
			'expired' => ['-5 days', true, [2 => [SecurityTxtExpired::class]]],
			'not expired' => ['+37 days', false, []],
		];
	}


	/**
	 * @param array<int, list<class-string<SecurityTxtExpired>>> $errors
	 * @dataProvider getExpiresField
	 */
	public function testParseStringExpiresField(string $fieldValue, bool $isExpired, array $errors): void
	{
		$contents = "Foo: bar\nExpires: " . new DateTime($fieldValue)->format(SecurityTxtExpires::FORMAT) . "\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::same($isExpired, $parseResult->getSecurityTxt()->getExpires()?->isExpired());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
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
		Assert::true($parseResult->hasErrors());
		Assert::true($parseResult->hasWarnings());
		Assert::type(SecurityTxtExpiresTooLong::class, $parseResult->getLineWarnings()[1][0]);
	}


	/**
	 * @return list<array{0:string, 1:int, 2:int}>
	 */
	public function getUnknownFormats(): array
	{
		return [
			['+3 weeks', 20, 22],
			['±3 days', 364, 366],
		];
	}


	/**
	 * @dataProvider getUnknownFormats
	 */
	public function testParseStringExpiresFieldWrongUnknownFormat(string $expires, int $minDays, int $maxDays): void
	{
		$contents = "Expires: {$expires}\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		/** @var SecurityTxtExpiresWrongFormat $expiresError */
		$expiresError = $parseResult->getLineErrors()[1][0];
		Assert::type(SecurityTxtExpiresWrongFormat::class, $expiresError);
		$correctValue = $expiresError->getCorrectValue();
		assert(is_string($correctValue));
		$correctExpires = DateTimeImmutable::createFromFormat(SecurityTxtExpires::FORMAT, $correctValue);
		assert($correctExpires instanceof DateTimeImmutable);
		$days = $correctExpires->diff(new DateTimeImmutable())->days;
		Assert::true($minDays <= $days && $days <= $maxDays, "Should be ±{$days} days ({$minDays} <= {$days} <= {$maxDays})");
	}


	public function testParseStringExpiresFieldOldFormat(): void
	{
		$expires = new DateTimeImmutable('+3 months midnight -1 second +00:00');
		$contents = 'Expires: ' . $expires->format(DATE_RFC2822) . "\nContact: mailto:foo@example.com\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		/** @var SecurityTxtExpiresOldFormat $expiresError */
		$expiresError = $parseResult->getLineErrors()[1][0];
		Assert::type(SecurityTxtExpiresOldFormat::class, $expiresError);
		Assert::same($expires->format(DATE_RFC3339), $expiresError->getCorrectValue());
		Assert::same([], $parseResult->getFileErrors());
		Assert::equal($expires, $parseResult->getSecurityTxt()->getExpires()?->getDateTime());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringMissingExpires(): void
	{
		$contents = "Foo: bar\nBar: foo\n#Expires: 2020-10-05T10:20:30+00:00\nExpires\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::contains(SecurityTxtNoExpires::class, array_map(function (SecurityTxtSpecViolation $throwable): string {
			return $throwable::class;
		}, $parseResult->getFileErrors()));
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringMultipleExpires(): void
	{
		$contents = "Foo: bar\nExpires: " . new DateTime('+2 months')->format(SecurityTxtExpires::FORMAT) . "\nExpires: " . new DateTime('+3 months')->format(SecurityTxtExpires::FORMAT) . "\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		$expiresError = $parseResult->getLineErrors()[3][0];
		Assert::type(SecurityTxtMultipleExpires::class, $expiresError);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringMultipleExpiresAllWrong(): void
	{
		$contents = "Foo: bar\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nExpires: Mon, 15 Aug 2015 15:52:01 +0000\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormat::class, $parseResult->getLineErrors()[2][0]);
		Assert::type(SecurityTxtMultipleExpires::class, $parseResult->getLineErrors()[3][0]);
		Assert::count(2, $parseResult->getLineErrors());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringMultipleExpiresFirstWrong(): void
	{
		$contents = "Foo: bar\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nExpires: " . new DateTime('+2 months')->format(SecurityTxtExpires::FORMAT) . "\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormat::class, $parseResult->getLineErrors()[2][0]);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringMultipleExpiresFirstCorrect(): void
	{
		$contents = "Foo: bar\nExpires: " . new DateTime('+2 months')->format(SecurityTxtExpires::FORMAT) . "\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(3, $parseResult->getLineErrors()[3]);
		Assert::type(SecurityTxtMultipleExpires::class, $parseResult->getLineErrors()[3][0]);
		Assert::type(SecurityTxtExpiresOldFormat::class, $parseResult->getLineErrors()[3][1]);
		Assert::type(SecurityTxtExpired::class, $parseResult->getLineErrors()[3][2]);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseMultipleFiles(): void
	{
		$assertParsed = function (string $mailto, string $expires): void {
			$contents = "Contact: {$mailto}\nExpires: {$expires}\n";
			$parseResult = $this->securityTxtParser->parseString($contents);
			Assert::same($mailto, $parseResult->getSecurityTxt()->getContact()[0]->getUri());
			Assert::same($expires, $parseResult->getSecurityTxt()->getExpires()?->getDateTime()->format(SecurityTxtExpires::FORMAT));
			Assert::count(0, $parseResult->getLineErrors());
			Assert::count(0, $parseResult->getFileErrors());
			Assert::false($parseResult->hasErrors());
			Assert::false($parseResult->hasWarnings());
		};
		$assertParsed('mailto:foo@bar.example', new DateTime('+2 months')->format(SecurityTxtExpires::FORMAT));
		$assertParsed('mailto:bar@foo.example', new DateTime('+3 months')->format(SecurityTxtExpires::FORMAT));
	}


	public function testParseMultipleBadFiles(): void
	{
		$contents = "Foo: bar\nExpires: " . new DateTime('+2 months')->format(SecurityTxtExpires::FORMAT) . "\nExpires: " . new DateTime('+3 months')->format(SecurityTxtExpires::FORMAT) . "\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtMultipleExpires::class, $parseResult->getLineErrors()[3][0]);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());

		$contents = "Expires: Mon, 15 Aug 2005 15:52:01 +0000\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormat::class, $parseResult->getLineErrors()[1][0]);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringExpiresTooLong(): void
	{
		$contents = "Contact: mailto:bar@foo.example\nExpires: " . new DateTime('+2 years')->format(SecurityTxtExpires::FORMAT) . "\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(0, $parseResult->getLineErrors());
		Assert::count(1, $parseResult->getLineWarnings());
		Assert::count(1, $parseResult->getLineWarnings()[2]);
		Assert::type(SecurityTxtExpiresTooLong::class, $parseResult->getLineWarnings()[2][0]);
		Assert::false($parseResult->hasErrors());
		Assert::true($parseResult->hasWarnings());
	}


	public function testParseStringMissingContact(): void
	{
		$contents = "Foo: bar\nBar: foo\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		$contactError = $parseResult->getFileErrors()[0];
		Assert::type(SecurityTxtNoContact::class, $contactError);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringNoEol(): void
	{
		$contents = 'Expires: ' . new DateTime('+3 months')->format(SecurityTxtExpires::FORMAT) . "\nContact: https://foo.example/";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(1, $parseResult->getLineErrors());
		Assert::count(1, $parseResult->getLineErrors()[2]);
		Assert::type(SecurityTxtLineNoEol::class, $parseResult->getLineErrors()[2][0]);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringPreferredLanguages(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Contact: mailto:foo@bar.example\nExpires: " . new DateTime('+3 months')->format(SecurityTxtExpires::FORMAT) . "\nPreferred-Languages: en,CS\n");
		Assert::count(0, $parseResult->getLineErrors());
		Assert::same(['en', 'CS'], $parseResult->getSecurityTxt()->getPreferredLanguages()?->getLanguages());
		Assert::false($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringMultiplePreferredLanguages(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: en\nPreferred-Languages: cs\n");
		Assert::count(1, $parseResult->getLineErrors());
		Assert::type(SecurityTxtMultiplePreferredLanguages::class, $parseResult->getLineErrors()[2][0]);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringPreferredLanguagesBadSeparator(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: en, cs;fi. nl\n");
		$error = $parseResult->getLineErrors()[1][0];
		Assert::count(1, $parseResult->getLineErrors());
		Assert::type(SecurityTxtPreferredLanguagesSeparatorNotComma::class, $error);
		Assert::same('The Preferred-Languages field uses wrong separators (#2 ;, #3 .), separate multiple values with a comma (,)', $error->getMessage());
		Assert::same('en, cs, fi, nl', $error->getCorrectValue());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());

		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: en, cs; fi, nl\n");
		$error = $parseResult->getLineErrors()[1][0];
		Assert::count(1, $parseResult->getLineErrors());
		Assert::type(SecurityTxtPreferredLanguagesSeparatorNotComma::class, $error);
		Assert::same('The Preferred-Languages field uses a wrong separator (#2 ;), separate multiple values with a comma (,)', $error->getMessage());
		Assert::same('en, cs, fi, nl', $error->getCorrectValue());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringPreferredLanguagesCommonMistake(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: CZ,en\n");
		$error = $parseResult->getLineErrors()[1][0];
		Assert::count(1, $parseResult->getLineErrors());
		Assert::type(SecurityTxtPreferredLanguagesCommonMistake::class, $error);
		Assert::same('The language tag #1 CZ in the Preferred-Languages field is not correct, the code for Czech language is cs, not cz', $error->getMessage());
		Assert::same(['CZ', 'en'], $parseResult->getSecurityTxt()->getPreferredLanguages()?->getLanguages());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());

		$parseResult = $this->securityTxtParser->parseString("Preferred-Languages: CZ-Czechia,en\n");
		$error = $parseResult->getLineErrors()[1][0];
		Assert::type(SecurityTxtPreferredLanguagesCommonMistake::class, $error);
		Assert::same('cs-Czechia', $error->getCorrectValue());
		Assert::same(['CZ-Czechia', 'en'], $parseResult->getSecurityTxt()->getPreferredLanguages()?->getLanguages());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringAcknowledgments(): void
	{
		$uri = 'https://example.com/ack.gif';
		$parseResult = $this->securityTxtParser->parseString("Acknowledgments: {$uri}\n");
		Assert::count(0, $parseResult->getLineErrors());
		Assert::same($uri, $parseResult->getSecurityTxt()->getAcknowledgments()[0]->getUri());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
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
		Assert::true($parseResult->hasErrors());
		Assert::true($parseResult->hasWarnings());
	}


	public function testParseStringHiring(): void
	{
		$uri = 'https://example.com/cv.psd';
		$parseResult = $this->securityTxtParser->parseString("Hiring: {$uri}\n");
		Assert::count(0, $parseResult->getLineErrors());
		Assert::same($uri, $parseResult->getSecurityTxt()->getHiring()[0]->getUri());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringPolicy(): void
	{
		$uri = 'https://example.com/policy.pcx';
		$parseResult = $this->securityTxtParser->parseString("Policy: {$uri}\n");
		Assert::count(0, $parseResult->getLineErrors());
		Assert::same($uri, $parseResult->getSecurityTxt()->getPolicy()[0]->getUri());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringEncryption(): void
	{
		$uri = 'https://example.com/keys.ico';
		$parseResult = $this->securityTxtParser->parseString("Encryption: {$uri}\n");
		Assert::count(0, $parseResult->getLineErrors());
		Assert::same($uri, $parseResult->getSecurityTxt()->getEncryption()[0]->getUri());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseFetchResult(): void
	{
		$lines = ["Contact: mailto:example@example.com\r\n", "Expires: 2020-12-31T23:59:59.000Z"];
		$fetchResult = new SecurityTxtFetchResult(
			'https://example.com/security.txt',
			'https://www.example.com/security.txt',
			[
				'https://example.com/.well-known/security.txt' => ['https://www.example.com/.well-known/security.txt'],
				'https://example.com/security.txt' => ['https://www.example.com/security.txt'],
			],
			implode('', $lines),
			true,
			$lines,
			[new SecurityTxtContentTypeWrongCharset('https://example.com/security.txt', 'text/plain', 'charset=utf-9')],
			[new SecurityTxtTopLevelPathOnly()],
		);
		$parseResult = $this->securityTxtParser->parseFetchResult($fetchResult);
		Assert::same("The line (Expires: 2020-12-31T23:59:59.000Z) doesn't end with neither <CRLF> nor <LF>", $parseResult->getLineErrors()[2][0]->getMessage());
		Assert::same("The file is considered stale and should not be used", $parseResult->getLineErrors()[2][1]->getMessage());
		Assert::same([], $parseResult->getLineWarnings());
		Assert::same([], $parseResult->getFileErrors());
		Assert::same([], $parseResult->getFileWarnings());
		Assert::count(1, $parseResult->getFetchErrors());
		Assert::type(SecurityTxtContentTypeWrongCharset::class, $parseResult->getFetchErrors()[0]);
		Assert::same('The file at https://example.com/security.txt has a correct Content-Type of text/plain but the charset=utf-9 parameter should be changed to charset=utf-8', $parseResult->getFetchErrors()[0]->getMessage());
		Assert::count(1, $parseResult->getFetchWarnings());
		Assert::type(SecurityTxtTopLevelPathOnly::class, $parseResult->getFetchWarnings()[0]);
		Assert::same("security.txt wasn't found under the /.well-known/ path", $parseResult->getFetchWarnings()[0]->getMessage());
		Assert::false($parseResult->isExpiresSoon());
		Assert::false($parseResult->isValid());
		Assert::true($parseResult->hasErrors());
		Assert::true($parseResult->hasWarnings());
		Assert::true($parseResult->getFetchResult()->isTruncated());

		$expires = new DateTimeImmutable('+7 days');
		$lines = ["Contact: mailto:example@example.com\r\n", 'Expires: ' . $expires->format(SecurityTxtExpires::FORMAT) . "\r\n"];
		$fetchResult = new SecurityTxtFetchResult(
			'https://example.com/security.txt',
			'https://www.example.com/security.txt',
			[],
			implode('', $lines),
			false,
			$lines,
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
		Assert::false($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
		Assert::false($parseResult->getFetchResult()->isTruncated());

		$parseResult = $this->securityTxtParser->parseFetchResult($fetchResult, 14, true);
		Assert::false($parseResult->isValid());
	}

}

new SecurityTxtParserTest()->run();
