<?php
/**
 * @testCase
 * @noinspection PhpDocMissingThrowsInspection
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use DateTime;
use DateTimeImmutable;
use Override;
use SensitiveParameter;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\Fetcher\SecurityTxtRedirects;
use Spaze\SecurityTxt\Fields\SecurityTxtExpires;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Json\SecurityTxtJsonValueFactory;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\SecurityTxtPrintableValue;
use Spaze\SecurityTxt\Signature\Providers\SecurityTxtSignatureGnuPgProvider;
use Spaze\SecurityTxt\Signature\Providers\SecurityTxtSignatureProvider;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureErrorInfo;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureVerifySignatureInfo;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Spaze\SecurityTxt\Violations\SecurityTxtBugBountyWrongCase;
use Spaze\SecurityTxt\Violations\SecurityTxtBugBountyWrongValue;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtContentNotUtf8;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeInvalid;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeWrongCharset;
use Spaze\SecurityTxt\Violations\SecurityTxtCsafNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtExpired;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresOldFormat;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresTooLong;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresWrongFormat;
use Spaze\SecurityTxt\Violations\SecurityTxtFieldNotCoveredBySignature;
use Spaze\SecurityTxt\Violations\SecurityTxtFieldWhitespaceBeforeColon;
use Spaze\SecurityTxt\Violations\SecurityTxtFieldWrongSpaceAfterColon;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtLineLeadingWhitespace;
use Spaze\SecurityTxt\Violations\SecurityTxtLineNoEol;
use Spaze\SecurityTxt\Violations\SecurityTxtLineNulByte;
use Spaze\SecurityTxt\Violations\SecurityTxtLineWrongEol;
use Spaze\SecurityTxt\Violations\SecurityTxtMultipleExpires;
use Spaze\SecurityTxt\Violations\SecurityTxtMultiplePreferredLanguages;
use Spaze\SecurityTxt\Violations\SecurityTxtNoContact;
use Spaze\SecurityTxt\Violations\SecurityTxtNoExpires;
use Spaze\SecurityTxt\Violations\SecurityTxtPossibelFieldTypo;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesCommonMistake;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesSeparatorNotComma;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureCannotVerify;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureExtensionNotLoaded;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureInvalid;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureMultipleCleartextHeaders;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelPathOnly;
use Spaze\SecurityTxt\Violations\SecurityTxtUnknownField;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;
use function Spaze\SecurityTxt\Test\gnupgHomeDir;

require __DIR__ . '/../bootstrap.php';

final class SecurityTxtParserTest extends TestCase
{

	private SecurityTxtValidator $securityTxtValidator;
	private SecurityTxtExpiresFactory $securityTxtExpiresFactory;
	private SecurityTxtPregSplitProvider $securityTxtPregSplitProvider;
	private SecurityTxtSplitLines $securityTxtSplitLines;
	private SecurityTxtJsonValueFactory $securityTxtJsonValueFactory;
	private SecurityTxtParser $securityTxtParser;


	public function __construct()
	{
		$this->securityTxtValidator = new SecurityTxtValidator();
		$securityTxtSignatureGnuPgProvider = new SecurityTxtSignatureGnuPgProvider(gnupgHomeDir());
		$securityTxtSignature = new SecurityTxtSignature($securityTxtSignatureGnuPgProvider);
		$this->securityTxtExpiresFactory = new SecurityTxtExpiresFactory();
		$this->securityTxtPregSplitProvider = new SecurityTxtPregSplitProvider();
		$this->securityTxtSplitLines = new SecurityTxtSplitLines($this->securityTxtPregSplitProvider);
		$this->securityTxtJsonValueFactory = new SecurityTxtJsonValueFactory();
		$this->securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, $securityTxtSignature, $this->securityTxtExpiresFactory, $this->securityTxtSplitLines, $this->securityTxtPregSplitProvider, $this->securityTxtJsonValueFactory);
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
		$contents = "Contact: https://example.com/\nExpires: " . (new DateTime($fieldValue))->format(SecurityTxtExpires::FORMAT) . "\nHiring: https://com.example\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::same($isExpired, $parseResult->getSecurityTxt()->getExpires()?->isExpired());
		Assert::same($isExpired, $parseResult->hasErrors());
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


	public function testParseStringLineWithNulByte(): void
	{
		$reported = [];
		$lines = [
			"Expires: x\0y",
			"Expires: x\0\0y",
			"Expires: 2030-01-01T00:00:00.000Z\0garbage",
			"Expires : 2030-01-01\0T00:00:00+00:00",
			"\0",
			"\0Contact: https://example.com/",
			"# A comment\0",
			"Cont\0act: https://example.com/",
			"Contact: https://example.com/\0\r",
		];
		foreach ($lines as $line) {
			$lineErrors = $this->securityTxtParser->parseString("{$line}\n")->getLineErrors();
			$reported[$line] = array_map(fn(SecurityTxtSpecViolation $violation): string => $violation->getMessage(), $lineErrors[1] ?? []);
		}
		Assert::same([
			"Expires: x\0y" => ['The line (Expires: x%00y) contains a NUL byte', 'The format of the value of the Expires field is wrong'],
			"Expires: x\0\0y" => ['The line (Expires: x%00%00y) contains a NUL byte', 'The format of the value of the Expires field is wrong'],
			"Expires: 2030-01-01T00:00:00.000Z\0garbage" => ['The line (Expires: 2030-01-01T00:00:00.000Z%00garbage) contains a NUL byte', 'The format of the value of the Expires field is wrong'],
			"Expires : 2030-01-01\0T00:00:00+00:00" => [
				'The line (Expires : 2030-01-01%00T00:00:00+00:00) contains a NUL byte',
				'The line (Expires : 2030-01-01T00:00:00+00:00) has whitespace between the field name and the colon',
			],
			"\0" => ['The line (%00) contains a NUL byte'],
			"\0Contact: https://example.com/" => ['The line (%00Contact: https://example.com/) contains a NUL byte'],
			"# A comment\0" => ['The line (# A comment%00) contains a NUL byte'],
			"Cont\0act: https://example.com/" => ['The line (Cont%00act: https://example.com/) contains a NUL byte'],
			"Contact: https://example.com/\0\r" => ['The line (Contact: https://example.com/%00) contains a NUL byte'],
		], $reported);
	}


	public function testParseStringLineWithNulByteIsStillParsed(): void
	{
		$parseResult = $this->securityTxtParser->parseString(" Cont\0act: https://example.com/\nExpires: " . new DateTimeImmutable('+42 days')->format(SecurityTxtExpires::FORMAT) . "\n");
		Assert::count(1, $parseResult->getSecurityTxt()->getContact());
		Assert::same('https://example.com/', $parseResult->getSecurityTxt()->getContact()[0]->getUri());
		$correctValues = array_map(fn(SecurityTxtSpecViolation $violation): array => [$violation::class, $violation->getCorrectValue()], $parseResult->getLineErrors()[1]);
		Assert::same([
			[SecurityTxtLineNulByte::class, 'Contact: https://example.com/'],
			[SecurityTxtLineLeadingWhitespace::class, 'Contact: https://example.com/'],
		], $correctValues);
		Assert::null($this->securityTxtParser->parseString("\0\n")->getLineErrors()[1][0]->getCorrectValue());
		Assert::same('Contact: https://example.com/', $this->securityTxtParser->parseString("Contact: https://example.com/ \0\n")->getLineErrors()[1][0]->getCorrectValue());
		Assert::false($parseResult->isValid());
	}


	public function testParseStringSignatureIsVerifiedOverTheFileAsServed(): void
	{
		$signatureProvider = new class implements SecurityTxtSignatureProvider {

			public ?string $verified = null;


			#[Override]
			public function addSignKey(string $fingerprint, #[SensitiveParameter] string $passphrase = ''): bool
			{
				return true;
			}


			#[Override]
			public function getErrorInfo(): SecurityTxtSignatureErrorInfo
			{
				return new SecurityTxtSignatureErrorInfo(false, 0, 'Unspecified source', 'Success');
			}


			#[Override]
			public function sign(string $text): false|string
			{
				return false;
			}


			#[Override]
			public function verify(string $text): SecurityTxtSignatureVerifySignatureInfo
			{
				$this->verified = $text;
				throw new SecurityTxtWarning(new SecurityTxtSignatureExtensionNotLoaded());
			}

		};
		$securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, new SecurityTxtSignature($signatureProvider), $this->securityTxtExpiresFactory, $this->securityTxtSplitLines, $this->securityTxtPregSplitProvider, $this->securityTxtJsonValueFactory);
		$contents = "-----BEGIN PGP SIGNED\x00 MESSAGE-----\nHash: SHA\x00512\n\x00\nContact: https://exa\x00mple.com/\n-----BEGIN PGP\x00 SIGNATURE-----\nComment: c\n\nfake\x00\n-----END PGP\x00 SIGNATURE-----\nHiring: https://example.com/\n";
		$parseResult = $securityTxtParser->parseString($contents);
		$reported = [];
		foreach ($parseResult->getLineErrors() as $lineNumber => $violations) {
			$reported[$lineNumber] = array_map(fn(SecurityTxtSpecViolation $violation): string => $violation::class, $violations);
		}
		Assert::same($contents, $signatureProvider->verified);
		Assert::same([
			1 => [SecurityTxtLineNulByte::class],
			2 => [SecurityTxtLineNulByte::class],
			3 => [SecurityTxtLineNulByte::class],
			4 => [SecurityTxtLineNulByte::class],
			5 => [SecurityTxtLineNulByte::class],
			8 => [SecurityTxtLineNulByte::class],
			9 => [SecurityTxtLineNulByte::class],
			10 => [SecurityTxtFieldNotCoveredBySignature::class],
		], $reported);
		Assert::same('https://example.com/', $parseResult->getSecurityTxt()->getContact()[0]->getUri());
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
		$contents = "Contact: https://example.com/\nHiring: https://com.example\n#Expires: 2020-10-05T10:20:30+00:00\nExpires\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(0, $parseResult->getLineErrors());
		Assert::count(1, $parseResult->getFileErrors());
		Assert::type(SecurityTxtNoExpires::class, $parseResult->getFileErrors()[0]);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringMultipleExpires(): void
	{
		$contents = "Contact: https://example.com/\nExpires: " . (new DateTime('+2 months'))->format(SecurityTxtExpires::FORMAT) . "\nExpires: " . (new DateTime('+3 months'))->format(SecurityTxtExpires::FORMAT) . "\nHiring: https://com.example/\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		$expiresError = $parseResult->getLineErrors()[3][0];
		Assert::type(SecurityTxtMultipleExpires::class, $expiresError);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringMultipleExpiresAllWrong(): void
	{
		$contents = "Contact: https://example.com/\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nExpires: Mon, 15 Aug 2015 15:52:01 +0000\nHiring: https://com.example/\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormat::class, $parseResult->getLineErrors()[2][0]);
		Assert::type(SecurityTxtMultipleExpires::class, $parseResult->getLineErrors()[3][0]);
		Assert::count(2, $parseResult->getLineErrors());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringMultipleExpiresFirstWrong(): void
	{
		$contents = "Contact: https://example.com/\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nExpires: " . (new DateTime('+2 months'))->format(SecurityTxtExpires::FORMAT) . "\nHiring: https://com.example/\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::type(SecurityTxtExpiresOldFormat::class, $parseResult->getLineErrors()[2][0]);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringMultipleExpiresFirstCorrect(): void
	{
		$contents = "Contact: https://example.com/\nExpires: " . (new DateTime('+2 months'))->format(SecurityTxtExpires::FORMAT) . "\nExpires: Mon, 15 Aug 2005 15:52:01 +0000\nHiring: https://com.example/\n";
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
		$assertParsed('mailto:foo@bar.example', (new DateTime('+2 months'))->format(SecurityTxtExpires::FORMAT));
		$assertParsed('mailto:bar@foo.example', (new DateTime('+3 months'))->format(SecurityTxtExpires::FORMAT));
	}


	public function testParseMultipleBadFiles(): void
	{
		$contents = "Contact: https://example.com/\nExpires: " . (new DateTime('+2 months'))->format(SecurityTxtExpires::FORMAT) . "\nExpires: " . (new DateTime('+3 months'))->format(SecurityTxtExpires::FORMAT) . "\nHiring: https://com.example/\n";
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
		$contents = "Contact: mailto:bar@foo.example\nExpires: " . (new DateTime('+2 years'))->format(SecurityTxtExpires::FORMAT) . "\n";
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
		$contents = "Acknowledgments: https://example.com/\nHiring: https://com.example/\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		$contactError = $parseResult->getFileErrors()[0];
		Assert::type(SecurityTxtNoContact::class, $contactError);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringContentNotUtf8(): void
	{
		$parseResult = $this->securityTxtParser->parseString("\xFF\xFE");
		$errors = $parseResult->getFileErrors();
		Assert::count(1, $errors);
		Assert::type(SecurityTxtContentNotUtf8::class, $errors[0]);
		Assert::same([], $parseResult->getFileWarnings());
		Assert::same([], $parseResult->getLineErrors());
		Assert::same([], $parseResult->getLineWarnings());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
		Assert::false($parseResult->isValid());
	}


	public function testParseStringNoEol(): void
	{
		$contents = 'Expires: ' . (new DateTime('+3 months'))->format(SecurityTxtExpires::FORMAT) . "\nContact: https://foo.example/";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(1, $parseResult->getLineErrors());
		Assert::count(1, $parseResult->getLineErrors()[2]);
		Assert::type(SecurityTxtLineNoEol::class, $parseResult->getLineErrors()[2][0]);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringLineStartingWithWhitespace(): void
	{
		$reported = [];
		foreach ([' Contact: https://example.com/', "\tContact: https://example.com/", "\x0BContact: https://example.com/", '  # A comment: with a colon', ' Not a field', " \t ", 'Contact: https://example.com/ '] as $line) {
			$parseResult = $this->securityTxtParser->parseString("{$line}\n{$this->getValidContents()}");
			$violations = [...$parseResult->getLineErrors()[1] ?? [], ...$parseResult->getLineWarnings()[1] ?? []];
			$reported[$line] = array_map(fn(SecurityTxtSpecViolation $violation): string => $violation->getMessage(), $violations);
		}
		Assert::same([
			' Contact: https://example.com/' => ['The line ( Contact: https://example.com/) starts with whitespace'],
			"\tContact: https://example.com/" => ['The line (→Contact: https://example.com/) starts with whitespace'],
			"\x0BContact: https://example.com/" => ['The line (%0BContact: https://example.com/) starts with whitespace'],
			'  # A comment: with a colon' => ['The line (  # A comment: with a colon) starts with whitespace'],
			' Not a field' => ['The line ( Not a field) starts with whitespace'],
			" \t " => [],
			'Contact: https://example.com/ ' => [],
		], $reported);
	}


	public function testParseStringLineStartingWithWhitespaceIsStillParsed(): void
	{
		$parseResult = $this->securityTxtParser->parseString(" Contact: https://example.com/\nExpires: " . new DateTimeImmutable('+42 days')->format(SecurityTxtExpires::FORMAT) . "\n");
		Assert::count(1, $parseResult->getSecurityTxt()->getContact());
		Assert::same('https://example.com/', $parseResult->getSecurityTxt()->getContact()[0]->getUri());
		Assert::type(SecurityTxtLineLeadingWhitespace::class, $parseResult->getLineErrors()[1][0]);
		Assert::same('Contact: https://example.com/', $parseResult->getLineErrors()[1][0]->getCorrectValue());
		Assert::false($parseResult->isValid());
	}


	public function testParseStringWhitespaceOnTheSignatureFramingIsNotReported(): void
	{
		$expires = new DateTimeImmutable('+2 weeks')->format(SecurityTxtExpires::FORMAT);
		$contents = <<< EOT
		-----BEGIN PGP SIGNED MESSAGE-----\x0B
		 Hash: SHA512\x0B

		 Contact: https://example.com/
		Expires: {$expires}\x0B
		-----BEGIN PGP SIGNATURE-----\x0B
		 Version: GnuPG v2\x0B

		 fake\x0B
		-----END PGP SIGNATURE-----\x0B
		# After the signature\x0B
		EOT . "\n";
		$signatureProvider = $this->getSignatureProvider(new SecurityTxtWarning(new SecurityTxtSignatureExtensionNotLoaded()));
		$securityTxtSignature = new SecurityTxtSignature($signatureProvider);
		$securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, $securityTxtSignature, $this->securityTxtExpiresFactory, $this->securityTxtSplitLines, $this->securityTxtPregSplitProvider, $this->securityTxtJsonValueFactory);
		$reported = [];
		foreach ($securityTxtParser->parseString($contents)->getLineErrors() as $lineNumber => $violations) {
			$reported[$lineNumber] = array_map(fn(SecurityTxtSpecViolation $violation): string => $violation::class, $violations);
		}
		Assert::same([4 => [SecurityTxtLineLeadingWhitespace::class], 5 => [SecurityTxtLineWrongEol::class], 11 => [SecurityTxtLineWrongEol::class]], $reported);
	}


	public function testParseStringLineEndingWithWrongWhitespace(): void
	{
		$reported = [];
		$lines = [
			"\x0B",
			" \x0B ",
			" \t",
			"X-Foo: bar\x0B",
			"Contact: https://example.com/\r\r",
			"Contact: https://example.com/\r",
			"Contact: https://example.com/ \t",
			" Contact: https://example.com/\x0B",
		];
		foreach ($lines as $line) {
			$parseResult = $this->securityTxtParser->parseString("{$line}\n{$this->getValidContents()}");
			$violations = [...$parseResult->getLineErrors()[1] ?? [], ...$parseResult->getLineWarnings()[1] ?? []];
			$reported[$line] = array_map(fn(SecurityTxtSpecViolation $violation): string => $violation->getMessage(), $violations);
		}
		Assert::same([
			"\x0B" => ['The line (%0B) ends with whitespace other than spaces and tabs'],
			" \x0B " => ['The line ( %0B ) ends with whitespace other than spaces and tabs'],
			" \t" => [],
			"X-Foo: bar\x0B" => ['The line (X-Foo: bar%0B) ends with whitespace other than spaces and tabs', 'Field X-Foo is unknown'],
			"Contact: https://example.com/\r\r" => ['The line (Contact: https://example.com/%0D) ends with whitespace other than spaces and tabs'],
			"Contact: https://example.com/\r" => [],
			"Contact: https://example.com/ \t" => [],
			" Contact: https://example.com/\x0B" => [
				'The line ( Contact: https://example.com/) starts with whitespace',
				'The line ( Contact: https://example.com/%0B) ends with whitespace other than spaces and tabs',
			],
		], $reported);
		$lastLine = $this->securityTxtParser->parseString("{$this->getValidContents()}Contact: https://example.com/\x0B")->getLineErrors()[3] ?? [];
		Assert::same([SecurityTxtLineNoEol::class, SecurityTxtLineWrongEol::class], array_map(fn(SecurityTxtSpecViolation $violation): string => $violation::class, $lastLine));
		Assert::null($this->securityTxtParser->parseString("\x0B\n{$this->getValidContents()}")->getLineErrors()[1][0]->getCorrectValue());
	}


	public function testParseStringLineEndingWithWrongWhitespaceIsStillParsed(): void
	{
		$parseResult = $this->securityTxtParser->parseString(" Contact: https://example.com/\x0B\nExpires: " . new DateTimeImmutable('+42 days')->format(SecurityTxtExpires::FORMAT) . "\n");
		Assert::count(1, $parseResult->getSecurityTxt()->getContact());
		Assert::same('https://example.com/', $parseResult->getSecurityTxt()->getContact()[0]->getUri());
		$correctValues = array_map(fn(SecurityTxtSpecViolation $violation): array => [$violation::class, $violation->getCorrectValue()], $parseResult->getLineErrors()[1]);
		Assert::same([
			[SecurityTxtLineLeadingWhitespace::class, 'Contact: https://example.com/'],
			[SecurityTxtLineWrongEol::class, 'Contact: https://example.com/'],
		], $correctValues);
		Assert::false($parseResult->isValid());
	}


	public function testParseStringSpaceAfterColon(): void
	{
		$reported = [];
		$expires = 'Expires:  ' . new DateTimeImmutable('+42 days')->format(SecurityTxtExpires::FORMAT);
		$lines = [
			'Contact:https://example.com/',
			"Contact:\thttps://example.com/",
			'Contact:  https://example.com/',
			'contact:https://example.com/',
			'Contact: https://example.com/',
			'Contact:',
			'Contact: ',
			'Acknowledgments:  https://example.com/thanks',
			'Canonical:  https://example.com/.well-known/security.txt',
			'Encryption:  https://example.com/key.asc',
			$expires,
			'Hiring:  https://example.com/jobs',
			'Policy:  https://example.com/policy',
			'Preferred-Languages:  en',
			'CSAF:https://example.com/provider-metadata.json',
			"CSAF:\thttps://example.com/provider-metadata.json",
			"CSAF: \thttps://example.com/provider-metadata.json",
			"CSAF: \x0Bhttps://example.com/provider-metadata.json",
			'Bug-Bounty:True',
			'Bug-Bounty:  True',
			'X-Foo:bar',
		];
		foreach ($lines as $line) {
			$lineErrors = $this->securityTxtParser->parseString("{$line}\n{$this->getValidContents()}")->getLineErrors();
			$violations = array_filter($lineErrors[1] ?? [], fn(SecurityTxtSpecViolation $violation): bool => $violation instanceof SecurityTxtFieldWrongSpaceAfterColon);
			$reported[$line] = array_values(array_map(fn(SecurityTxtSpecViolation $violation): string => $violation->getMessage(), $violations));
		}
		Assert::same([
			'Contact:https://example.com/' => ['The line (Contact:https://example.com/) should have one space between the colon and the value'],
			"Contact:\thttps://example.com/" => ['The line (Contact:→https://example.com/) should have one space between the colon and the value'],
			'Contact:  https://example.com/' => ['The line (Contact:  https://example.com/) should have one space between the colon and the value'],
			'contact:https://example.com/' => ['The line (contact:https://example.com/) should have one space between the colon and the value'],
			'Contact: https://example.com/' => [],
			'Contact:' => [],
			'Contact: ' => [],
			'Acknowledgments:  https://example.com/thanks' => ['The line (Acknowledgments:  https://example.com/thanks) should have one space between the colon and the value'],
			'Canonical:  https://example.com/.well-known/security.txt' => ['The line (Canonical:  https://example.com/.well-known/security.txt) should have one space between the colon and the value'],
			'Encryption:  https://example.com/key.asc' => ['The line (Encryption:  https://example.com/key.asc) should have one space between the colon and the value'],
			$expires => ["The line ({$expires}) should have one space between the colon and the value"],
			'Hiring:  https://example.com/jobs' => ['The line (Hiring:  https://example.com/jobs) should have one space between the colon and the value'],
			'Policy:  https://example.com/policy' => ['The line (Policy:  https://example.com/policy) should have one space between the colon and the value'],
			'Preferred-Languages:  en' => ['The line (Preferred-Languages:  en) should have one space between the colon and the value'],
			'CSAF:https://example.com/provider-metadata.json' => ['The line (CSAF:https://example.com/provider-metadata.json) should have one space between the colon and the value'],
			"CSAF:\thttps://example.com/provider-metadata.json" => ['The line (CSAF:→https://example.com/provider-metadata.json) should have one space between the colon and the value'],
			"CSAF: \thttps://example.com/provider-metadata.json" => [],
			"CSAF: \x0Bhttps://example.com/provider-metadata.json" => ['The line (CSAF: %0Bhttps://example.com/provider-metadata.json) should have one space between the colon and the value'],
			'Bug-Bounty:True' => ['The line (Bug-Bounty:True) should have one space between the colon and the value'],
			'Bug-Bounty:  True' => [],
			'X-Foo:bar' => [],
		], $reported);
	}


	public function testParseStringSpaceAfterColonIsStillParsed(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Contact:\thttps://example.com/\nExpires: " . new DateTimeImmutable('+42 days')->format(SecurityTxtExpires::FORMAT) . "\n");
		Assert::count(1, $parseResult->getSecurityTxt()->getContact());
		Assert::same('https://example.com/', $parseResult->getSecurityTxt()->getContact()[0]->getUri());
		Assert::type(SecurityTxtFieldWrongSpaceAfterColon::class, $parseResult->getLineErrors()[1][0]);
		Assert::same('Contact: https://example.com/', $parseResult->getLineErrors()[1][0]->getCorrectValue());
		Assert::false($parseResult->isValid());
	}


	public function testParseStringWhitespaceBeforeColon(): void
	{
		$reported = [];
		foreach (['Contact : https://example.com/', "Contact\t: https://example.com/", "Contact\x0B: https://example.com/", 'Contact :https://example.com/', 'X-Foo : bar', 'Contactt : https://example.com/', '# Note : a comment', 'Contact: https://example.com/'] as $line) {
			$parseResult = $this->securityTxtParser->parseString("{$line}\n{$this->getValidContents()}");
			$violations = [...$parseResult->getLineErrors()[1] ?? [], ...$parseResult->getLineWarnings()[1] ?? []];
			$reported[$line] = array_map(fn(SecurityTxtSpecViolation $violation): string => $violation->getMessage(), $violations);
		}
		Assert::same([
			'Contact : https://example.com/' => ['The line (Contact : https://example.com/) has whitespace between the field name and the colon'],
			"Contact\t: https://example.com/" => ['The line (Contact→: https://example.com/) has whitespace between the field name and the colon'],
			"Contact\x0B: https://example.com/" => ['The line (Contact%0B: https://example.com/) has whitespace between the field name and the colon'],
			'Contact :https://example.com/' => [
				'The line (Contact :https://example.com/) has whitespace between the field name and the colon',
				'The line (Contact :https://example.com/) should have one space between the colon and the value',
			],
			'X-Foo : bar' => ['The line (X-Foo : bar) has whitespace between the field name and the colon', 'Field X-Foo is unknown'],
			'Contactt : https://example.com/' => ['The line (Contactt : https://example.com/) has whitespace between the field name and the colon', 'Field Contactt may be a typo, did you mean Contact?'],
			'# Note : a comment' => [],
			'Contact: https://example.com/' => [],
		], $reported);
	}


	public function testParseStringWhitespaceBeforeColonIsStillParsed(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Contact :\thttps://example.com/\nExpires: " . new DateTimeImmutable('+42 days')->format(SecurityTxtExpires::FORMAT) . "\n");
		Assert::count(1, $parseResult->getSecurityTxt()->getContact());
		Assert::same('https://example.com/', $parseResult->getSecurityTxt()->getContact()[0]->getUri());
		$correctValues = array_map(fn(SecurityTxtSpecViolation $violation): array => [$violation::class, $violation->getCorrectValue()], $parseResult->getLineErrors()[1]);
		Assert::same([
			[SecurityTxtFieldWhitespaceBeforeColon::class, 'Contact: https://example.com/'],
			[SecurityTxtFieldWrongSpaceAfterColon::class, 'Contact: https://example.com/'],
		], $correctValues);
		Assert::false($parseResult->isValid());
	}


	public function testParseStringPreferredLanguages(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Contact: mailto:foo@bar.example\nExpires: " . (new DateTime('+3 months'))->format(SecurityTxtExpires::FORMAT) . "\nPreferred-Languages: en,CS\n");
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


	/**
	 * @param class-string<SecurityTxtSpecViolation> $violationClass
	 * @dataProvider getInvalidFileLocations
	 */
	public function testParseStringInvalidFileLocationIsReportedNotThrown(string $fileLocation, string $violationClass, ?string $correctValue): void
	{
		$parseResult = $this->securityTxtParser->parseString($this->getValidContents(), $fileLocation);
		Assert::count(1, $parseResult->getFileErrors());
		Assert::type($violationClass, $parseResult->getFileErrors()[0]);
		// The value offered as the fix has to differ from the one just rejected, whatever case the scheme was written in
		$actualCorrectValue = $parseResult->getFileErrors()[0]->getCorrectValue();
		Assert::same($correctValue, $actualCorrectValue !== null ? new SecurityTxtPrintableValue($actualCorrectValue)->render() : null);
		Assert::same([], $parseResult->getLineErrors());
		Assert::same([], $parseResult->getLineWarnings());
		Assert::false($parseResult->isValid());
	}


	/**
	 * @return array<string, array{0:string, 1:class-string<SecurityTxtSpecViolation>, 2:?string}>
	 */
	public function getInvalidFileLocations(): array
	{
		return [
			'http' => ['http://example.com/.well-known/security.txt', SecurityTxtFileLocationNotHttps::class, 'https://example.com/.well-known/security.txt'],
			'HTTP uppercase' => ['HTTP://example.com/.well-known/security.txt', SecurityTxtFileLocationNotHttps::class, 'https://example.com/.well-known/security.txt'],
			'not a URI' => ['example.com/.well-known/security.txt', SecurityTxtFileLocationNotUri::class, null],
		];
	}


	public function testParseStringInvalidFileLocationIsReportedWithContentThatIsNotUtf8(): void
	{
		// Both are wrong at once and the early return for the contents must still carry the location, which is the other line this reaches
		$parseResult = $this->securityTxtParser->parseString("\xFF\xFE", 'http://example.com/.well-known/security.txt');
		Assert::count(2, $parseResult->getFileErrors());
		Assert::type(SecurityTxtFileLocationNotHttps::class, $parseResult->getFileErrors()[0]);
		Assert::type(SecurityTxtContentNotUtf8::class, $parseResult->getFileErrors()[1]);
		Assert::false($parseResult->isValid());
	}


	public function testParseFetchResultHttpFinalUrlIsReportedNotThrown(): void
	{
		// The way the bug was actually reached: the fetcher allows http, so a host redirecting its security.txt to one leaves an http final URL for the parser
		$contents = $this->getValidContents();
		$fetchResult = new SecurityTxtFetchResult(
			new Url('https://example.com/.well-known/security.txt'),
			new Url('http://example.com/security.txt'),
			[],
			$contents,
			false,
			$this->securityTxtSplitLines->splitLines($contents),
			[],
			[],
		);
		$parseResult = $this->securityTxtParser->parseFetchResult($fetchResult);
		Assert::count(1, $parseResult->getFileErrors());
		Assert::type(SecurityTxtFileLocationNotHttps::class, $parseResult->getFileErrors()[0]);
		Assert::same('http://example.com/security.txt', $parseResult->getSecurityTxt()->getFileLocation());
		Assert::false($parseResult->isValid());
	}


	private function getValidContents(): string
	{
		return "Contact: mailto:foo@example.com\nExpires: " . new DateTimeImmutable('+42 days')->format(SecurityTxtExpires::FORMAT) . "\n";
	}


	public function testParseStringCsaf(): void
	{
		$uri = 'HTTP://example.net/';
		$parseResult = $this->securityTxtParser->parseString("CSAF: {$uri}\n");
		Assert::count(1, $parseResult->getLineErrors());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
		Assert::same(SecurityTxtCsafNotHttps::class, $parseResult->getLineErrors()[1][0]::class);
		Assert::same('If the CSAF field indicates a web URI, then it must begin with "https://"', $parseResult->getLineErrors()[1][0]->getMessage());
		// A correct value the violation knows to be a URL is handed over as one, so it reads as itself wherever it is printed
		$correctValue = $parseResult->getLineErrors()[1][0]->getCorrectValue();
		Assert::equal(new Url('https://example.net/'), $correctValue);
		Assert::same('https://example.net/', new SecurityTxtPrintableValue($correctValue ?? '')->render());

		$uri = 'https://example.net/data/provider-metadata.json';
		$parseResult = $this->securityTxtParser->parseString("CSAF: {$uri}\n");
		Assert::count(0, $parseResult->getLineErrors());
		Assert::same($uri, $parseResult->getSecurityTxt()->getCsaf()[0]->getUri());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringBugBounty(): void
	{
		$parseResult = $this->securityTxtParser->parseString("Bug-Bounty: true\n");
		Assert::count(1, $parseResult->getLineErrors());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
		Assert::same(SecurityTxtBugBountyWrongCase::class, $parseResult->getLineErrors()[1][0]::class);
		Assert::same('The first letter of the Bug-Bounty field value true should be uppercase', $parseResult->getLineErrors()[1][0]->getMessage());
		Assert::same('True', $parseResult->getLineErrors()[1][0]->getCorrectValue());

		$parseResult = $this->securityTxtParser->parseString("Bug-Bounty: pizza\n");
		Assert::count(1, $parseResult->getLineErrors());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
		Assert::same(SecurityTxtBugBountyWrongValue::class, $parseResult->getLineErrors()[1][0]::class);
		Assert::same('The value of the Bug-Bounty field (pizza) should be either True or False', $parseResult->getLineErrors()[1][0]->getMessage());
		Assert::same('Change the value of the Bug-Bounty field to True or False', $parseResult->getLineErrors()[1][0]->getHowToFix());

		$parseResult = $this->securityTxtParser->parseString("Bug-Bounty: True\n");
		Assert::count(0, $parseResult->getLineErrors());
		Assert::true($parseResult->getSecurityTxt()->getBugBounty()?->rewards());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
	}


	public function testParseStringUnknownField(): void
	{
		$contents = "Foo: bar\nHash: file-not-signed-0123\nContact: https://example.com/\nExpires: " . (new DateTime('+3 weeks'))->format(SecurityTxtExpires::FORMAT) . "\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::count(0, $parseResult->getLineErrors());
		Assert::false($parseResult->hasErrors());
		Assert::true($parseResult->hasWarnings());
		Assert::count(2, $parseResult->getLineWarnings());
		Assert::count(0, $parseResult->getFileWarnings());
		Assert::type(SecurityTxtUnknownField::class, $parseResult->getLineWarnings()[1][0]);
		Assert::type(SecurityTxtUnknownField::class, $parseResult->getLineWarnings()[2][0]);
	}


	public function testParseStringSignedFile(): void
	{
		$expires = (new DateTime('+2 weeks'))->format(SecurityTxtExpires::FORMAT);
		$contents = <<< EOT
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		Contact: https://example.com/
		Expires: {$expires}
		Canonical: https://foo.bar.example/
		-----BEGIN PGP SIGNATURE-----

		iJIEARYKADoWIQSvbhd14xH/eOkR59x/h5ABqcj1CgUCaH7y/xwcc3RpbGwudGVz
		dHNAbGlicmFyeS5leGFtcGxlAAoJEH+HkAGpyPUKRvEA/2cVGZs54ieQ7s1nSTla
		6O+JHJNaLOf3llvGRi55gW+BAQCDVLTj2q7cbHPS78lD/uvsgFI3NVWwZx8m72sx
		SmjCCQ==
		=bZYA
		-----END PGP SIGNATURE-----
		EOT . "\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::false($parseResult->hasErrors());
		// Not hasWarnings() so that a failure says what the warning was, verifying a signature can fail for environmental reasons
		Assert::same([], $parseResult->getLineWarnings());
		Assert::same([], $parseResult->getFileWarnings());
		Assert::same('AF6E1775E311FF78E911E7DC7F879001A9C8F50A', $parseResult->getSecurityTxt()->getSignatureVerifyResult()?->getKeyFingerprint());
	}


	public function testParseStringSignedFileDamaged(): void
	{
		$expires = (new DateTime('+2 weeks'))->format(SecurityTxtExpires::FORMAT);
		$contents = <<< EOT
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		Contact: https://example.com/
		Expires: {$expires}
		Canonical: https://foo.bar.example/
		-----BEGIN PGP SIGNATURE-----
		yes, but
		-----END PGP SIGNATURE-----
		EOT . "\n";
		$parseResult = $this->securityTxtParser->parseString($contents);
		Assert::false($parseResult->hasErrors());
		Assert::true($parseResult->hasWarnings());
		Assert::count(1, $parseResult->getLineWarnings());
		Assert::type(SecurityTxtSignatureCannotVerify::class, $parseResult->getLineWarnings()[1][0]);
	}


	public function testParseStringSignatureFailures(): void
	{
		$expires = (new DateTime('+2 weeks'))->format(SecurityTxtExpires::FORMAT);
		$contents = <<< EOT
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		Contact: https://example.com/
		Expires: {$expires}
		Canonical: https://foo.bar.example/
		-----BEGIN PGP SIGNATURE-----
		yes, but
		-----END PGP SIGNATURE-----
		EOT . "\n";

		$signatureProvider = $this->getSignatureProvider(new SecurityTxtError(new SecurityTxtSignatureInvalid()));
		$securityTxtSignature = new SecurityTxtSignature($signatureProvider);
		$securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, $securityTxtSignature, $this->securityTxtExpiresFactory, $this->securityTxtSplitLines, $this->securityTxtPregSplitProvider, $this->securityTxtJsonValueFactory);
		$parseResult = $securityTxtParser->parseString($contents);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
		Assert::count(1, $parseResult->getLineErrors());
		Assert::count(0, $parseResult->getLineWarnings());
		Assert::type(SecurityTxtSignatureInvalid::class, $parseResult->getLineErrors()[1][0]);

		$signatureProvider = $this->getSignatureProvider(new SecurityTxtWarning(new SecurityTxtSignatureExtensionNotLoaded()));
		$securityTxtSignature = new SecurityTxtSignature($signatureProvider);
		$securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, $securityTxtSignature, $this->securityTxtExpiresFactory, $this->securityTxtSplitLines, $this->securityTxtPregSplitProvider, $this->securityTxtJsonValueFactory);
		$parseResult = $securityTxtParser->parseString($contents);
		Assert::false($parseResult->hasErrors());
		Assert::true($parseResult->hasWarnings());
		Assert::count(0, $parseResult->getLineErrors());
		Assert::count(1, $parseResult->getLineWarnings());
		Assert::type(SecurityTxtSignatureExtensionNotLoaded::class, $parseResult->getLineWarnings()[1][0]);
	}


	public function testParseStringVerifiesTheSignatureOnceOnly(): void
	{
		// A file may carry one cleartext signature, so a second header is malformed input, not a second thing to verify.
		// verify() is handed the whole file every time, so repeating it burns time proportional to the file for each header.
		$signatureProvider = new class implements SecurityTxtSignatureProvider {

			public int $verifyCalls = 0;


			#[Override]
			public function addSignKey(string $fingerprint, #[SensitiveParameter] string $passphrase = ''): bool
			{
				return true;
			}


			#[Override]
			public function getErrorInfo(): SecurityTxtSignatureErrorInfo
			{
				return new SecurityTxtSignatureErrorInfo(false, 0, 'Unspecified source', 'Success');
			}


			#[Override]
			public function sign(string $text): false|string
			{
				return false;
			}


			#[Override]
			public function verify(string $text): SecurityTxtSignatureVerifySignatureInfo
			{
				$this->verifyCalls++;
				throw new SecurityTxtWarning(new SecurityTxtSignatureExtensionNotLoaded());
			}

		};
		$securityTxtSignature = new SecurityTxtSignature($signatureProvider);
		$securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, $securityTxtSignature, $this->securityTxtExpiresFactory, $this->securityTxtSplitLines, $this->securityTxtPregSplitProvider, $this->securityTxtJsonValueFactory);
		$securityTxtParser->parseString(str_repeat("-----BEGIN PGP SIGNED MESSAGE-----\n\n", 50));
		Assert::same(1, $signatureProvider->verifyCalls);
	}


	public function testParseStringFieldsOutsideSignedPartOfFile(): void
	{
		$expires = (new DateTime('+2 weeks'))->format(SecurityTxtExpires::FORMAT);
		$contents = <<< EOT
		Contact: https://before.example/
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		Contact: https://example.com/
		Expires: {$expires}
		Canonical: https://foo.bar.example/
		-----BEGIN PGP SIGNATURE-----

		fake
		-----END PGP SIGNATURE-----
		Contact: https://after.example/
		EOT . "\n";
		$signatureProvider = $this->getSignatureProvider(new SecurityTxtWarning(new SecurityTxtSignatureExtensionNotLoaded()));
		$securityTxtSignature = new SecurityTxtSignature($signatureProvider);
		$securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, $securityTxtSignature, $this->securityTxtExpiresFactory, $this->securityTxtSplitLines, $this->securityTxtPregSplitProvider, $this->securityTxtJsonValueFactory);
		$parseResult = $securityTxtParser->parseString($contents);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->isValid());
		Assert::count(2, $parseResult->getLineErrors());
		Assert::type(SecurityTxtFieldNotCoveredBySignature::class, $parseResult->getLineErrors()[1][0]);
		Assert::same(['Contact'], $parseResult->getLineErrors()[1][0]->getMessageValues());
		Assert::type(SecurityTxtFieldNotCoveredBySignature::class, $parseResult->getLineErrors()[12][0]);
		// the fields are still parsed, the errors are what makes the file invalid
		$contacts = $parseResult->getSecurityTxt()->getContact();
		Assert::count(3, $contacts);
		Assert::same('https://before.example/', $contacts[0]->getUri());
		Assert::same('https://example.com/', $contacts[1]->getUri());
		Assert::same('https://after.example/', $contacts[2]->getUri());
	}


	public function testParseStringMultipleCleartextHeaders(): void
	{
		$expires = (new DateTime('+2 weeks'))->format(SecurityTxtExpires::FORMAT);
		$contents = <<< EOT
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		Contact: https://example.com/
		Expires: {$expires}
		-----BEGIN PGP SIGNATURE-----

		fake
		-----END PGP SIGNATURE-----
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		Contact: https://attacker.example/
		EOT . "\n";
		$signatureProvider = $this->getSignatureProvider(new SecurityTxtWarning(new SecurityTxtSignatureExtensionNotLoaded()));
		$securityTxtSignature = new SecurityTxtSignature($signatureProvider);
		$securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, $securityTxtSignature, $this->securityTxtExpiresFactory, $this->securityTxtSplitLines, $this->securityTxtPregSplitProvider, $this->securityTxtJsonValueFactory);
		$parseResult = $securityTxtParser->parseString($contents);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->isValid());
		Assert::count(2, $parseResult->getLineErrors());
		Assert::type(SecurityTxtSignatureMultipleCleartextHeaders::class, $parseResult->getLineErrors()[10][0]);
		Assert::type(SecurityTxtFieldNotCoveredBySignature::class, $parseResult->getLineErrors()[13][0]);
	}


	public function testParseStringSignatureArmorContentsNotParsed(): void
	{
		$expires = (new DateTime('+2 weeks'))->format(SecurityTxtExpires::FORMAT);
		$contents = <<< EOT
		-----BEGIN PGP SIGNED MESSAGE-----
		Hash: SHA512

		Contact: https://example.com/
		Expires: {$expires}
		Canonical: https://foo.bar.example/
		-----BEGIN PGP SIGNATURE-----
		Version: GnuPG v2

		Contact: https://attacker.example/
		-----END PGP SIGNATURE-----
		EOT . "\n";
		$signatureProvider = $this->getSignatureProvider(new SecurityTxtWarning(new SecurityTxtSignatureExtensionNotLoaded()));
		$securityTxtSignature = new SecurityTxtSignature($signatureProvider);
		$securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, $securityTxtSignature, $this->securityTxtExpiresFactory, $this->securityTxtSplitLines, $this->securityTxtPregSplitProvider, $this->securityTxtJsonValueFactory);
		$parseResult = $securityTxtParser->parseString($contents);
		Assert::false($parseResult->hasErrors());
		// no SecurityTxtUnknownField warning for the Version armor header, only the one thrown by the verify() stub
		Assert::count(1, $parseResult->getLineWarnings());
		Assert::type(SecurityTxtSignatureExtensionNotLoaded::class, $parseResult->getLineWarnings()[1][0]);
		$contacts = $parseResult->getSecurityTxt()->getContact();
		Assert::count(1, $contacts);
		Assert::same('https://example.com/', $contacts[0]->getUri());
	}


	private function getSignatureProvider(SecurityTxtError|SecurityTxtWarning $verifyThrows): SecurityTxtSignatureProvider
	{
		return new readonly class ($verifyThrows) implements SecurityTxtSignatureProvider {

			public function __construct(
				private SecurityTxtError|SecurityTxtWarning $verifyThrows,
			) {
			}


			#[Override]
			public function addSignKey(string $fingerprint, #[SensitiveParameter] string $passphrase = ''): bool
			{
				return true;
			}


			#[Override]
			public function getErrorInfo(): SecurityTxtSignatureErrorInfo
			{
				return new SecurityTxtSignatureErrorInfo(false, 0, 'Unspecified source', 'Success');
			}


			#[Override]
			public function sign(string $text): false|string
			{
				return false;
			}


			#[Override]
			public function verify(string $text): SecurityTxtSignatureVerifySignatureInfo
			{
				throw $this->verifyThrows;
			}

		};
	}


	public function testParseStringUriNotHttps(): void
	{
		$uri = 'HTTP://EXAMPLE.COM/';
		$parseResult = $this->securityTxtParser->parseString("Contact: {$uri}\n");
		Assert::count(1, $parseResult->getLineErrors());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
		Assert::same(SecurityTxtContactNotHttps::class, $parseResult->getLineErrors()[1][0]::class);
		Assert::same('If the Contact field indicates a web URI, then it must begin with "https://"', $parseResult->getLineErrors()[1][0]->getMessage());
		// Parsing would lowercase the host, and the case is what this is about, so it stays the string that was written
		Assert::same('https://EXAMPLE.COM/', $parseResult->getLineErrors()[1][0]->getCorrectValue());
	}


	/**
	 * Where a file was found is reported at the host it was fetched from. Decoded instead, a file on `xn--khby.example` is reported at `ؤ.example`, which resolves to
	 * `xn--jgb.example`, and `SecurityTxtSpecViolation::asUrl()` cannot read that spelling back either, so it prints percent encoded beside a host that reads.
	 */
	public function testTheFileIsReportedAtTheHostItWasFetchedFrom(): void
	{
		$url = new Url('http://xn--khby.example/.well-known/security.txt');
		$lines = ["Contact: https://example.com/\n"];
		$fetchResult = new SecurityTxtFetchResult($url, $url, [], implode($lines), false, $lines, [], []);
		$fileErrors = $this->securityTxtParser->parseFetchResult($fetchResult)->getFileErrors();
		Assert::same('The file at http://xn--khby.example/.well-known/security.txt must use HTTPS', $fileErrors[0]->getMessage());
	}


	public function testParseFetchResult(): void
	{
		$lines = ["Contact: mailto:example@example.com\r\n", "Expires: 2020-12-31T23:59:59.000Z"];
		$fetchResult = new SecurityTxtFetchResult(
			new Url('https://example.com/security.txt'),
			new Url('https://www.example.com/security.txt'),
			[
				'https://example.com/.well-known/security.txt' => new SecurityTxtRedirects('https://www.example.com/.well-known/security.txt'),
				'https://example.com/security.txt' => new SecurityTxtRedirects('https://www.example.com/security.txt'),
			],
			implode('', $lines),
			true,
			$lines,
			[new SecurityTxtContentTypeWrongCharset(new Url('https://example.com/security.txt'), 'text/plain', 'charset=utf-9')],
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
		Assert::false($parseResult->isValid());
		Assert::true($parseResult->hasErrors());
		Assert::true($parseResult->hasWarnings());
		Assert::true($parseResult->getFetchResult()->isTruncated());

		$expires = new DateTimeImmutable('+7 days');
		$lines = ["Contact: mailto:example@example.com\r\n", 'Expires: ' . $expires->format(SecurityTxtExpires::FORMAT) . "\r\n"];
		$fetchResult = new SecurityTxtFetchResult(
			new Url('https://example.com/security.txt'),
			new Url('https://www.example.com/security.txt'),
			[],
			implode('', $lines),
			false,
			$lines,
			[],
			[],
		);
		$parseResult = $this->securityTxtParser->parseFetchResult($fetchResult, 14);
		Assert::same([], $parseResult->getLineErrors());
		Assert::count(1, $parseResult->getLineWarnings());
		Assert::same('The file will be considered stale in 7 days', $parseResult->getLineWarnings()[2][0]->getMessage());
		Assert::same([], $parseResult->getFileErrors());
		Assert::same([], $parseResult->getFileWarnings());
		Assert::true($parseResult->isValid());
		Assert::false($parseResult->hasErrors());
		Assert::true($parseResult->hasWarnings());
		Assert::false($parseResult->getFetchResult()->isTruncated());

		$parseResult = $this->securityTxtParser->parseFetchResult($fetchResult, 14, true);
		Assert::false($parseResult->isValid());

		$fetchResult = new SecurityTxtFetchResult(
			new Url('https://example.com/security.txt'),
			new Url('https://www.example.com/security.txt'),
			[],
			implode('', $lines),
			false,
			$lines,
			[new SecurityTxtContentTypeInvalid(new Url('https://example.com/security.txt'), 'foo/bar')],
			[],
		);
		$parseResult = $this->securityTxtParser->parseFetchResult($fetchResult, 14, true);
		Assert::type(SecurityTxtContentTypeInvalid::class, $parseResult->getFetchErrors()[0]);
		Assert::same(
			'The file at https://example.com/security.txt has a Content-Type of foo/bar but it should be a Content-Type of text/plain with the charset parameter set to charset=utf-8',
			$parseResult->getFetchErrors()[0]->getMessage(),
		);

		$fetchResult = new SecurityTxtFetchResult(
			new Url('https://example.com/security.txt'),
			new Url('https://www.example.com/security.txt'),
			[],
			implode('', $lines),
			false,
			$lines,
			[new SecurityTxtContentTypeInvalid(new Url('https://example.com/security.txt'), null)],
			[],
		);
		$parseResult = $this->securityTxtParser->parseFetchResult($fetchResult, 14, true);
		Assert::type(SecurityTxtContentTypeInvalid::class, $parseResult->getFetchErrors()[0]);
		Assert::same(
			'The file at https://example.com/security.txt has no Content-Type but it should be a Content-Type of text/plain with the charset parameter set to charset=utf-8',
			$parseResult->getFetchErrors()[0]->getMessage(),
		);
	}

}

(new SecurityTxtParserTest())->run();
