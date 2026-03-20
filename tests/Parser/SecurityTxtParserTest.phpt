<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Parser;

use DateTime;
use DateTimeImmutable;
use Override;
use SensitiveParameter;
use Spaze\SecurityTxt\Exceptions\SecurityTxtError;
use Spaze\SecurityTxt\Exceptions\SecurityTxtWarning;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\Fields\SecurityTxtExpires;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\Signature\Providers\SecurityTxtSignatureGnuPgProvider;
use Spaze\SecurityTxt\Signature\Providers\SecurityTxtSignatureProvider;
use Spaze\SecurityTxt\Signature\SecurityTxtSignature;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureErrorInfo;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureVerifySignatureInfo;
use Spaze\SecurityTxt\Validator\SecurityTxtValidator;
use Spaze\SecurityTxt\Violations\SecurityTxtBugBountyWrongCase;
use Spaze\SecurityTxt\Violations\SecurityTxtBugBountyWrongValue;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeWrongCharset;
use Spaze\SecurityTxt\Violations\SecurityTxtCsafNotHttps;
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
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureCannotVerify;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureExtensionNotLoaded;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureInvalid;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelPathOnly;
use Spaze\SecurityTxt\Violations\SecurityTxtUnknownField;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtParserTest extends TestCase
{

	private SecurityTxtValidator $securityTxtValidator;
	private SecurityTxtExpiresFactory $securityTxtExpiresFactory;
	private SecurityTxtPregSplitProvider $securityTxtPregSplitProvider;
	private SecurityTxtSplitLines $securityTxtSplitLines;
	private SecurityTxtParser $securityTxtParser;


	public function __construct()
	{
		$this->securityTxtValidator = new SecurityTxtValidator();
		$securityTxtSignatureGnuPgProvider = new SecurityTxtSignatureGnuPgProvider();
		$securityTxtSignature = new SecurityTxtSignature($securityTxtSignatureGnuPgProvider);
		$this->securityTxtExpiresFactory = new SecurityTxtExpiresFactory();
		$this->securityTxtPregSplitProvider = new SecurityTxtPregSplitProvider();
		$this->securityTxtSplitLines = new SecurityTxtSplitLines($this->securityTxtPregSplitProvider);
		$this->securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, $securityTxtSignature, $this->securityTxtExpiresFactory, $this->securityTxtSplitLines, $this->securityTxtPregSplitProvider);
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


	public function testParseStringCsaf(): void
	{
		$uri = 'HTTP://example.net/';
		$parseResult = $this->securityTxtParser->parseString("CSAF: {$uri}\n");
		Assert::count(1, $parseResult->getLineErrors());
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
		Assert::same(SecurityTxtCsafNotHttps::class, $parseResult->getLineErrors()[1][0]::class);
		Assert::same('If the CSAF field indicates a web URI, then it must begin with "https://"', $parseResult->getLineErrors()[1][0]->getMessage());
		Assert::same('https://example.net/', $parseResult->getLineErrors()[1][0]->getCorrectValue());

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
		Assert::false($parseResult->hasWarnings());
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
		$securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, $securityTxtSignature, $this->securityTxtExpiresFactory, $this->securityTxtSplitLines, $this->securityTxtPregSplitProvider);
		$parseResult = $securityTxtParser->parseString($contents);
		Assert::true($parseResult->hasErrors());
		Assert::false($parseResult->hasWarnings());
		Assert::count(1, $parseResult->getLineErrors());
		Assert::count(0, $parseResult->getLineWarnings());
		Assert::type(SecurityTxtSignatureInvalid::class, $parseResult->getLineErrors()[1][0]);

		$signatureProvider = $this->getSignatureProvider(new SecurityTxtWarning(new SecurityTxtSignatureExtensionNotLoaded()));
		$securityTxtSignature = new SecurityTxtSignature($signatureProvider);
		$securityTxtParser = new SecurityTxtParser($this->securityTxtValidator, $securityTxtSignature, $this->securityTxtExpiresFactory, $this->securityTxtSplitLines, $this->securityTxtPregSplitProvider);
		$parseResult = $securityTxtParser->parseString($contents);
		Assert::false($parseResult->hasErrors());
		Assert::true($parseResult->hasWarnings());
		Assert::count(0, $parseResult->getLineErrors());
		Assert::count(1, $parseResult->getLineWarnings());
		Assert::type(SecurityTxtSignatureExtensionNotLoaded::class, $parseResult->getLineWarnings()[1][0]);
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
		Assert::same('https://EXAMPLE.COM/', $parseResult->getLineErrors()[1][0]->getCorrectValue());
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
	}

}

(new SecurityTxtParserTest())->run();
