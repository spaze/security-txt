<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Json;

use DateInterval;
use DateTimeImmutable;
use Spaze\SecurityTxt\Check\Exceptions\SecurityTxtCannotParseJsonException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNotFoundException;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\SecurityTxtValidationLevel;
use Spaze\SecurityTxt\Violations\SecurityTxtBugBountyWrongCase;
use Spaze\SecurityTxt\Violations\SecurityTxtBugBountyWrongValue;
use Spaze\SecurityTxt\Violations\SecurityTxtContactNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeWrongCharset;
use Spaze\SecurityTxt\Violations\SecurityTxtCsafNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtCsafNotUri;
use Spaze\SecurityTxt\Violations\SecurityTxtCsafWrongFile;
use Spaze\SecurityTxt\Violations\SecurityTxtHiringNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtMultipleBugBounty;
use Spaze\SecurityTxt\Violations\SecurityTxtNoContact;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelPathOnly;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtJsonTest extends TestCase
{

	private SecurityTxtJson $securityTxtJson;


	public function __construct()
	{
		$this->securityTxtJson = new SecurityTxtJson(new SecurityTxtSplitLines(new SecurityTxtPregSplitProvider()));
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
		Assert::type(SecurityTxtUrlNotFoundException::class, $this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => SecurityTxtUrlNotFoundException::class, 'params' => ['url', 303, '1.1.1.0', DNS_A]]]));
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


	public function testCreateSecurityTxtFromJsonValuesIncorrectValuesNoWarnings(): void
	{
		$days = 2600;
		$dateTime = (new DateTimeImmutable())->add(new DateInterval('P' . $days . 'D'))->format(DATE_RFC3339);
		$values = [
			'fileLocation' => null,
			'fields' => [
				[
					'Expires' => [
						'dateTime' => $dateTime,
						'isExpired' => true,
						'inDays' => $days,
					],
				],
			],
			'signatureVerifyResult' => null,
		];
		$securityTxt = $this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		Assert::same($dateTime, $securityTxt->getExpires()?->getDateTime()->format(DATE_RFC3339));
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
			'fileLocation' => 42,
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fileLocation is not a string');

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
				'foo',
				'bar',
			],
			'signatureVerifyResult' => null,
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: fields is not an array of arrays');

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


	public function testCreateSecurityTxtFromJsonValuesInvalidSignatureVerifyResult(): void
	{
		$values = [
			'signatureVerifyResult' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: signatureVerifyResult is not an array');

		$values = [
			'signatureVerifyResult' => [],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: signatureVerifyResult > keyFingerprint is missing or not a string');

		$values = [
			'signatureVerifyResult' => [
				'keyFingerprint' => '1234',
			],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: signatureVerifyResult > dateTime is missing or not a string');

		$values = [
			'signatureVerifyResult' => [
				'keyFingerprint' => '1234',
				'dateTime' => 'foo',
			],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: signatureVerifyResult > dateTime is wrong format');
	}


	public function testCreateRedirectsFromJsonValues(): void
	{
		$values = [
			'https://example.com/' => [
				'https://example.net/',
				'https://com.example/',
			],
			'https://example.org/' => [
				'https://net.example/',
				'https://com.example/',
			],
		];
		Assert::same($values, $this->securityTxtJson->createRedirectsFromJsonValues($values));
	}


	public function testCreateRedirectsFromJsonValuesInvalidJson(): void
	{
		$values = [
			123 => [],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createRedirectsFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: redirects key is of type int, not a string');

		$values = [
			'https://example.com/' => 'foo',
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createRedirectsFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: redirects > https://example.com/ is not an array');

		$values = [
			'https://example.com/' => [
				'https://example.net/',
				909,
			],
		];
		Assert::throws(function () use ($values): void {
			$this->securityTxtJson->createRedirectsFromJsonValues($values);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: redirects contains an item which is not a string');
	}

}

(new SecurityTxtJsonTest())->run();
