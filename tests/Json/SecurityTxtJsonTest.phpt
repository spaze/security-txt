<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Json;

use DateTimeImmutable;
use Spaze\SecurityTxt\Check\Exceptions\SecurityTxtCannotParseJsonException;
use Spaze\SecurityTxt\Check\SecurityTxtCheckHostResult;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNotFoundException;
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
use Spaze\SecurityTxt\Violations\SecurityTxtBugBountyWrongCase;
use Spaze\SecurityTxt\Violations\SecurityTxtBugBountyWrongValue;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeWrongCharset;
use Spaze\SecurityTxt\Violations\SecurityTxtCsafNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtCsafNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtCsafWrongFile;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresOldFormat;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresSoon;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtHiringNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtLineNoEol;
use Spaze\SecurityTxt\Violations\SecurityTxtMultipleBugBounty;
use Spaze\SecurityTxt\Violations\SecurityTxtNoContact;
use Spaze\SecurityTxt\Violations\SecurityTxtPossibelFieldTypo;
use Spaze\SecurityTxt\Violations\SecurityTxtSignatureExtensionNotLoaded;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelPathOnly;
use Spaze\SecurityTxt\Violations\SecurityTxtWellKnownPathOnly;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtJsonTest extends TestCase
{

	private SecurityTxtJson $securityTxtJson;
	private SecurityTxtExpiresFactory $securityTxtExpiresFactory;


	public function __construct()
	{
		$this->securityTxtExpiresFactory = new SecurityTxtExpiresFactory();
		$this->securityTxtJson = new SecurityTxtJson(new SecurityTxtSplitLines());
	}


	public function testCreateViolationsFromJsonValues(): void
	{
		Assert::same([], $this->securityTxtJson->createViolationsFromJsonValues([]));
		Assert::throws(function (): void {
			$this->securityTxtJson->createViolationsFromJsonValues(['string']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: class is missing or not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createViolationsFromJsonValues([[]]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: class is missing or not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createViolationsFromJsonValues([['class' => 303]]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: class is missing or not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createViolationsFromJsonValues([['class' => 'foo bar']]);
		}, SecurityTxtCannotParseJsonException::class, "Cannot parse JSON: class foo bar doesn't exist");
		Assert::throws(function (): void {
			$this->securityTxtJson->createViolationsFromJsonValues([['class' => DateTimeImmutable::class]]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: params is missing or not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createViolationsFromJsonValues([['class' => DateTimeImmutable::class, 'params' => 'string']]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: params is missing or not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createViolationsFromJsonValues([['class' => DateTimeImmutable::class, 'params' => []]]);
		}, SecurityTxtCannotParseJsonException::class, sprintf("Cannot parse JSON: class %s doesn't extend %s", DateTimeImmutable::class, SecurityTxtSpecViolation::class));
		Assert::equal([new SecurityTxtNoContact()], $this->securityTxtJson->createViolationsFromJsonValues([['class' => SecurityTxtNoContact::class, 'params' => []]]));
	}


	public function testSerializeViolationsThenCreateFromJsonValues(): void
	{
		$json = json_encode([
			new SecurityTxtContactNotUri('le big mac'),
			new SecurityTxtHiringNotHttps('http://example.com/'),
			new SecurityTxtCsafNotUri('with cheese'),
			new SecurityTxtCsafNotHttps('http://example.com/bar.txt'),
			new SecurityTxtCsafWrongFile('https://example.com/foo/bar.txt'),
			new SecurityTxtBugBountyWrongCase('false'),
			new SecurityTxtBugBountyWrongValue('cash only'),
			new SecurityTxtMultipleBugBounty(),
		]);
		assert(is_string($json));
		$decoded = json_decode($json, true);
		assert(is_array($decoded));
		$violations = $this->securityTxtJson->createViolationsFromJsonValues(array_values($decoded));
		Assert::same("The Contact value (le big mac) doesn't follow the URI syntax described in RFC 3986, the scheme is missing", $violations[0]->getMessage());
		Assert::same('If the Hiring field indicates a web URI, then it must begin with "https://"', $violations[1]->getMessage());
		Assert::same("The CSAF value (with cheese) doesn't follow the URI syntax described in RFC 3986, the scheme is missing", $violations[2]->getMessage());
		Assert::same('If the CSAF field indicates a web URI, then it must begin with "https://"', $violations[3]->getMessage());
		Assert::same('The file with the Common Security Advisory Framework (CSAF) metadata currently located at https://example.com/foo/bar.txt must be called provider-metadata.json', $violations[4]->getMessage());
		Assert::same('The first letter of the Bug-Bounty field value false should be uppercase', $violations[5]->getMessage());
		Assert::same('The value of the Bug-Bounty field (cash only) should be either True or False', $violations[6]->getMessage());
		Assert::same('The Bug-Bounty field must not appear more than once', $violations[7]->getMessage());
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


	public function testCreateFetchResultFromJsonValues(): void
	{
		$lines = ["Contact: mailto:example@example.com\r\n", "Expires: 2030-12-31T23:59:59.000Z\r\n", "Preferred-Languages: en; cs"];
		$result = new SecurityTxtFetchResult(
			'https://example.com/security.txt',
			'https://www.example.com/security.txt',
			[
				'https://example.com/.well-known/security.txt' => ['https://www.example.com/.well-known/security.txt'],
				'https://example.com/security.txt' => ['https://www.example.com/security.txt'],
			],
			implode($lines),
			true,
			$lines,
			[new SecurityTxtContentTypeWrongCharset('https://example.com/security.txt', 'text/plain', null)],
			[new SecurityTxtTopLevelPathOnly()],
		);
		$encoded = json_encode($result);
		assert(is_string($encoded));
		$decoded = json_decode($encoded, true);
		assert(is_array($decoded));
		Assert::equal($result, $this->securityTxtJson->createFetchResultFromJsonValues($decoded));
	}


	public function testCreateFetchResultFromJsonValuesErrors(): void
	{
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues([]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: class is not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => 808]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: class is not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => DateTimeImmutable::class]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: class is not ' . SecurityTxtFetchResult::class);
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: constructedUrl is not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 303]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: constructedUrl is not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: finalUrl is not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url', 'finalUrl' => 808]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: finalUrl is not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url', 'finalUrl' => 'url2']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: redirects is not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url', 'finalUrl' => 'url2', 'redirects' => 'string']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: redirects is not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url', 'finalUrl' => 'url2', 'redirects' => []]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: contents is not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url', 'finalUrl' => 'url2', 'redirects' => [], 'contents' => 303]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: contents is not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url', 'finalUrl' => 'url2', 'redirects' => [], 'contents' => '303']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: isTruncated is not a bool');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url', 'finalUrl' => 'url2', 'redirects' => [], 'contents' => '303', 'isTruncated' => 'maybe']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: isTruncated is not a bool');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url', 'finalUrl' => 'url2', 'redirects' => [], 'contents' => '303', 'isTruncated' => false]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: errors is not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url', 'finalUrl' => 'url2', 'redirects' => [], 'contents' => '303', 'isTruncated' => false, 'errors' => true]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: errors is not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url', 'finalUrl' => 'url2', 'redirects' => [], 'contents' => '303', 'isTruncated' => false, 'errors' => []]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: warnings is not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url', 'finalUrl' => 'url2', 'redirects' => [], 'contents' => '303', 'isTruncated' => false, 'errors' => [], 'warnings' => 'none']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: warnings is not an array');
		Assert::type(SecurityTxtFetchResult::class, $this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'url', 'finalUrl' => 'url2', 'redirects' => [], 'contents' => '303', 'isTruncated' => false, 'errors' => [], 'warnings' => []]));
	}


	public function testCreateFetcherExceptionFromJsonValues(): void
	{
		$exception = new SecurityTxtTooManyRedirectsException('https://example.com', ['https://example.com', 'https://www.example.com'], 1);
		$encoded = json_encode(['error' => $exception]);
		assert(is_string($encoded));
		$decoded = json_decode($encoded, true);
		assert(is_array($decoded));
		$exceptionFromJson = $this->securityTxtJson->createFetcherExceptionFromJsonValues($decoded);
		Assert::type($exception::class, $exceptionFromJson);
		Assert::same($exception->getMessage(), $exceptionFromJson->getMessage());
	}


	public function testCreateFetcherExceptionFromJsonValuesErrors(): void
	{
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetcherExceptionFromJsonValues([]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: error > class is missing, not a string or not an existing class');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => 'string']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: error > class is missing, not a string or not an existing class');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => []]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: error > class is missing, not a string or not an existing class');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => 123]]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: error > class is missing, not a string or not an existing class');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => 'foo bar']]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: error > class is missing, not a string or not an existing class');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => DateTimeImmutable::class]]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: error > params is missing or not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => DateTimeImmutable::class, 'params' => 'string']]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: error > params is missing or not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => DateTimeImmutable::class, 'params' => []]]);
		}, SecurityTxtCannotParseJsonException::class, sprintf('Cannot parse JSON: The exception is %s, not %s', DateTimeImmutable::class, SecurityTxtFetcherException::class));
		Assert::type(SecurityTxtUrlNotFoundException::class, $this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => SecurityTxtUrlNotFoundException::class, 'params' => ['url', 303]]]));
	}


	public function testCreateSecurityTxtFromJsonValues(): void
	{
		Assert::equal(new SecurityTxt(SecurityTxtValidationLevel::AllowInvalidValuesSilently), $this->securityTxtJson->createSecurityTxtFromJsonValues([]));

		$values = [
			'fileLocation' => null,
			'fields' => [
				['Preferred-Languages' => ['languages' => ['cs', 'en']]],
				['Canonical' => ['uri' => 'https://example.com/.well-known/security.txt']],
				['Contact' => ['uri' => 'https://example.com/contact']],
				['Acknowledgments' => ['uri' => 'https://example.com/acknowledgments']],
				['Hiring' => ['uri' => 'https://example.com/hiring']],
				['Policy' => ['uri' => 'https://example.com/policy']],
				['Encryption' => ['uri' => 'https://example.com/encryption']],
				['CSAF' => ['uri' => 'https://example.com/csaf']],
				['Bug-Bounty' => ['rewards' => true]],
			],
			'signatureVerifyResult' => [
				'dateTime' => '2025-09-23T17:02:54+02:00',
				'keyFingerprint' => '4BCAFED00D5CAFEBABE5DEADBEEF1234',
			],
		];
		$securityTxt = $this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		Assert::null($securityTxt->getFileLocation());
		Assert::null($securityTxt->getExpires());
		Assert::same('2025-09-23T17:02:54+02:00', $securityTxt->getSignatureVerifyResult()?->getDate()->format(DATE_RFC3339));
		Assert::same('4BCAFED00D5CAFEBABE5DEADBEEF1234', $securityTxt->getSignatureVerifyResult()?->getKeyFingerprint());
		Assert::same(['cs', 'en'], $securityTxt->getPreferredLanguages()?->getLanguages());
		Assert::same('https://example.com/.well-known/security.txt', $securityTxt->getCanonical()[0]->getUri());
		Assert::same('https://example.com/contact', $securityTxt->getContact()[0]->getUri());
		Assert::same('https://example.com/acknowledgments', $securityTxt->getAcknowledgments()[0]->getUri());
		Assert::same('https://example.com/hiring', $securityTxt->getHiring()[0]->getUri());
		Assert::same('https://example.com/policy', $securityTxt->getPolicy()[0]->getUri());
		Assert::same('https://example.com/encryption', $securityTxt->getEncryption()[0]->getUri());
		Assert::same('https://example.com/csaf', $securityTxt->getCsaf()[0]->getUri());
		Assert::true($securityTxt->getBugBounty()?->rewards());

		$values['fileLocation'] = 'https://foo/bar';
		$securityTxt = $this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		Assert::same('https://foo/bar', $securityTxt->getFileLocation());

		$values['fileLocation'] = 'foo';
		$securityTxt = $this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		Assert::same('foo', $securityTxt->getFileLocation());
	}


	public function testCreateSecurityTxtFromJsonValuesEmptyRequiredOnly(): void
	{
		$values = [
			'fileLocation' => null,
			'signatureVerifyResult' => null,
		];
		Assert::noError(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		});

		$values = [
			'fileLocation' => null,
			'fields' => null,
			'signatureVerifyResult' => null,
		];
		Assert::noError(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		});

		$values = [
			'fileLocation' => null,
			'fields' => [],
			'signatureVerifyResult' => null,
		];
		$securityTxt = $this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		Assert::null($securityTxt->getFileLocation());
		Assert::null($securityTxt->getExpires());
		Assert::null($securityTxt->getPreferredLanguages());
		Assert::same([], $securityTxt->getCanonical());
		Assert::same([], $securityTxt->getContact());
		Assert::same([], $securityTxt->getAcknowledgments());
		Assert::same([], $securityTxt->getHiring());
		Assert::same([], $securityTxt->getPolicy());
		Assert::same([], $securityTxt->getEncryption());
		Assert::same([], $securityTxt->getCsaf());
	}


	public function testCreateSecurityTxtFromJsonValuesInvalidJsonFields(): void
	{
		$values = [
			'fileLocation' => null,
			'fields' => 'foo',
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields is not an array');

		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Bug-Bounty' => null,
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > Bug-Bounty is not an array');

		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Bug-Bounty' => [],
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > Bug-Bounty > rewards is missing or not a bool');

		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Canonical' => null,
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > Canonical is not an array');

		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Canonical' => [],
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > Canonical > uri is missing or not a string');

		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Expires' => null,
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > Expires is not an array');

		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Expires' => [],
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > Expires > dateTime is missing or not a string');

		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Expires' => [
						'dateTime' => '2025-09-23T17:02:54+02:00',
					],
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > Expires > isExpired is missing or not a bool');


		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Expires' => [
						'dateTime' => '2025-09-23T17:02:54+02:00',
						'isExpired' => true,
					],
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > Expires > inDays is missing or not an int');


		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Expires' => [
						'dateTime' => 'foo',
						'isExpired' => true,
						'inDays' => 5,
					],
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > Expires > dateTime is wrong format');

		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Preferred-Languages' => null,
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > Preferred-Languages is not an array');


		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Preferred-Languages' => [],
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > Preferred-Languages > languages is missing or not an array');

		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Preferred-Languages' => [
						'languages' => ['1', 2],
					],
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > Preferred-Languages > languages contains an item which is not a string');

		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Preferred-Languages' => [
						'languages' => ['cs', 'en'],
					],
				],
				[
					'Canonical' => [],
					'Preferred-Languages' => [],
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > 1 must be a single-entry map');

		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					13 => 37,
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: field name is not a string');

		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'foo' => [],
				],
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields > foo is an unsupported field');
	}

}

(new SecurityTxtJsonTest())->run();
