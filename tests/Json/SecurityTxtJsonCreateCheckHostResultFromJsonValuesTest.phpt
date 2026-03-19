<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Json;

use DateTimeImmutable;
use Spaze\SecurityTxt\Check\Exceptions\SecurityTxtCannotParseJsonException;
use Spaze\SecurityTxt\Check\SecurityTxtCheckHostResult;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\Fields\SecurityTxtAcknowledgments;
use Spaze\SecurityTxt\Fields\SecurityTxtBugBounty;
use Spaze\SecurityTxt\Fields\SecurityTxtCanonical;
use Spaze\SecurityTxt\Fields\SecurityTxtContact;
use Spaze\SecurityTxt\Fields\SecurityTxtCsaf;
use Spaze\SecurityTxt\Fields\SecurityTxtEncryption;
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\Fields\SecurityTxtHiring;
use Spaze\SecurityTxt\Fields\SecurityTxtPolicy;
use Spaze\SecurityTxt\Fields\SecurityTxtPreferredLanguages;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\SecurityTxtValidationLevel;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureVerifyResult;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresOldFormat;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresSoon;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtLineNoEol;
use Spaze\SecurityTxt\Violations\SecurityTxtNoContact;
use Spaze\SecurityTxt\Violations\SecurityTxtPossibelFieldTypo;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureExtensionNotLoaded;
use Spaze\SecurityTxt\Violations\SecurityTxtWellKnownPathOnly;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtJsonCreateCheckHostResultFromJsonValuesTest extends TestCase
{

	private SecurityTxtJson $securityTxtJson;

	private SecurityTxtExpiresFactory $securityTxtExpiresFactory;


	public function __construct()
	{
		$this->securityTxtExpiresFactory = new SecurityTxtExpiresFactory();
		$this->securityTxtJson = new SecurityTxtJson(new SecurityTxtSplitLines());
	}


	public function testCreateCheckHostResultFromJsonValues(): void
	{
		$expectedResult = $this->getCheckHostResult();
		$encoded = json_encode($expectedResult);
		assert(is_string($encoded));
		$decoded = json_decode($encoded, true);
		assert(is_array($decoded));
		$actualResult = $this->securityTxtJson->createCheckHostResultFromJsonValues($decoded);
		Assert::equal($expectedResult, $actualResult);
	}


	private function getCheckHostResult(): SecurityTxtCheckHostResult
	{
		$securityTxt = new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently);
		$dateTime = new DateTimeImmutable('2022-08-08T02:40:54+00:00');
		$securityTxt->setFileLocation('https://example.com/.well-known/security.txt');
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create($dateTime));
		$securityTxt->setPreferredLanguages(new SecurityTxtPreferredLanguages(['en', 'de']));
		$securityTxt->setBugBounty(new SecurityTxtBugBounty(true));
		$securityTxt->addPolicy(new SecurityTxtPolicy('https://example.com/1'));
		$securityTxt->addPolicy(new SecurityTxtPolicy('https://example.com/2'));
		$securityTxt->addHiring(new SecurityTxtHiring('https://example.com/'));
		$securityTxt->addContact(new SecurityTxtContact('https://example.com/'));
		$securityTxt->addAcknowledgments(new SecurityTxtAcknowledgments('https://example.com/1'));
		$securityTxt->addAcknowledgments(new SecurityTxtAcknowledgments('https://example.com/2'));
		$securityTxt->addCsaf(new SecurityTxtCsaf('https://example.com/'));
		$securityTxt->addEncryption(new SecurityTxtEncryption('https://example.com/'));
		$securityTxt->addCanonical(new SecurityTxtCanonical('https://example.com/'));
		$securityTxt = $securityTxt->withSignatureVerifyResult(new SecurityTxtSignatureVerifyResult('LeKeyFingerPrint', new DateTimeImmutable('-2 weeks noon +02:00')));
		$lines = ["Hi-ring: https://example.com/hiring\n", "Bug-Bounty: True\n", 'Expires: ' . $dateTime->format(DATE_RFC2822)];
		$fetchResult = new SecurityTxtFetchResult(
			'http://www.example.com/.well-known/security.txt',
			'https://www.example.com/.well-known/security.txt',
			['http://example.com' => ['https://example.com', 'https://www.example.com']],
			implode('', $lines),
			true,
			$lines,
			[new SecurityTxtFileLocationNotHttps('http://example.com')],
			[new SecurityTxtWellKnownPathOnly()],
		);

		return new SecurityTxtCheckHostResult(
			'www.example.com',
			$fetchResult,
			$fetchResult->getErrors(),
			$fetchResult->getWarnings(),
			[2 => [new SecurityTxtLineNoEol('Contact: https://example.com/contact'), new SecurityTxtExpiresOldFormat('a correct value')]],
			[1 => [new SecurityTxtPossibelFieldTypo('Hi-ring', SecurityTxtField::Hiring->value, 'Hi-ring: https://example.com/hiring')]],
			[new SecurityTxtNoContact()],
			[new SecurityTxtExpiresSoon(11), new SecurityTxtSignatureExtensionNotLoaded()],
			$securityTxt,
			true,
			10,
			false,
			true,
			15,
		);
	}


	public function testCreateCheckHostResultFromJsonValuesInvalidJson(): void
	{
		$values = [];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: class is not set or not a string');

		$values = [
			'class' => 303,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: class is not set or not a string');

		$values = [
			'class' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: class is not ' . SecurityTxtCheckHostResult::class);

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: host is not set or not a string');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => 808,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: host is not set or not a string');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fetchResult is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fetchResult is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fetchErrors is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fetchErrors is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fetchWarnings is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fetchWarnings is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: lineErrors is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: lineErrors is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [
				'foo' => [],
			],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: lineErrors > foo key is not an int');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [
				0 => [],
			],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: lineErrors > 0 key is less than 1');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [
				1 => 'foo',
			],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: lineErrors > 1 is not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: lineWarnings is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: lineWarnings is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [
				'foo' => [],
			],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: lineWarnings > foo key is not an int');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [
				0 => [],
			],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: lineWarnings > 0 key is less than 1');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [
				1 => 'foo',
			],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: lineWarnings > 1 is not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fileErrors is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
			'fileErrors' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fileErrors is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
			'fileErrors' => [],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fileWarnings is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
			'fileErrors' => [],
			'fileWarnings' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fileWarnings is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
			'fileErrors' => [],
			'fileWarnings' => [],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: securityTxt is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
			'fileErrors' => [],
			'fileWarnings' => [],
			'securityTxt' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: securityTxt is not set or not an array');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
			'fileErrors' => [],
			'fileWarnings' => [],
			'securityTxt' => [],
			'expired' => 303,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: expired is not a bool');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
			'fileErrors' => [],
			'fileWarnings' => [],
			'securityTxt' => [],
			'expired' => false,
			'expiryDays' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: expiryDays is not an int');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
			'fileErrors' => [],
			'fileWarnings' => [],
			'securityTxt' => [],
			'expired' => false,
			'expiryDays' => 42,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: valid is not set or not a bool');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
			'fileErrors' => [],
			'fileWarnings' => [],
			'securityTxt' => [],
			'expired' => false,
			'expiryDays' => 42,
			'valid' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: valid is not set or not a bool');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
			'fileErrors' => [],
			'fileWarnings' => [],
			'securityTxt' => [],
			'expired' => false,
			'expiryDays' => 42,
			'valid' => true,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: strictMode is not set or not a bool');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
			'fileErrors' => [],
			'fileWarnings' => [],
			'securityTxt' => [],
			'expired' => false,
			'expiryDays' => 42,
			'valid' => true,
			'strictMode' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: strictMode is not set or not a bool');

		$values = [
			'class' => SecurityTxtCheckHostResult::class,
			'host' => '808',
			'fetchResult' => [],
			'fetchErrors' => [],
			'fetchWarnings' => [],
			'lineErrors' => [],
			'lineWarnings' => [],
			'fileErrors' => [],
			'fileWarnings' => [],
			'securityTxt' => [],
			'expired' => false,
			'expiryDays' => 42,
			'valid' => true,
			'strictMode' => false,
			'expiresWarningThreshold' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createCheckHostResultFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: expiresWarningThreshold is not an int');
	}

}

(new SecurityTxtJsonCreateCheckHostResultFromJsonValuesTest())->run();
