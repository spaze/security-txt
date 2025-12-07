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
use Spaze\SecurityTxt\Fields\SecurityTxtExpiresFactory;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\SecurityTxtValidationLevel;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureVerifyResult;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeWrongCharset;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresOldFormat;
use Spaze\SecurityTxt\Violations\SecurityTxtExpiresSoon;
use Spaze\SecurityTxt\Violations\SecurityTxtFileLocationNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtLineNoEol;
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
		$securityTxt->setExpires($this->securityTxtExpiresFactory->create($dateTime));
		$securityTxt = $securityTxt->withSignatureVerifyResult(new SecurityTxtSignatureVerifyResult('LeKeyFingerPrint', new DateTimeImmutable('-2 weeks noon +02:00')));
		$lines = ["Hi-ring: https://example.com/hiring\n", 'Expires: ' . $dateTime->format(DATE_RFC2822)];
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
		Assert::throws(function (): void {
			$this->securityTxtJson->createSecurityTxtFromJsonValues([]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: Field canonical is missing or not an array');

		$values = [
			'fileLocation' => null,
			'expires' => null,
			'signatureVerifyResult' => null,
			'preferredLanguages' => null,
			'canonical' => [],
			'contact' => [],
			'acknowledgments' => [],
			'hiring' => [],
			'policy' => [],
			'encryption' => [],
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

		$values['fileLocation'] = 'https://foo/bar';
		$securityTxt = $this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		Assert::same('https://foo/bar', $securityTxt->getFileLocation());

		$values['fileLocation'] = 'foo';
		$securityTxt = $this->securityTxtJson->createSecurityTxtFromJsonValues($values);
		Assert::same('foo', $securityTxt->getFileLocation());
	}

}

(new SecurityTxtJsonTest())->run();
