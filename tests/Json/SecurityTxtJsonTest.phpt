<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Json;

use ArgumentCountError;
use BackedEnum;
use DateInterval;
use DateTimeImmutable;
use LogicException;
use ReflectionClass;
use ReflectionParameter;
use Spaze\SecurityTxt\Check\Exceptions\SecurityTxtCannotParseJsonException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotParseHostnameException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundWrongUrlStructureException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtOnlyIpv6HostButIpv6DisabledException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNotFoundException;
use Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult;
use Spaze\SecurityTxt\Fetcher\SecurityTxtIpAddressType;
use Spaze\SecurityTxt\Fields\SecurityTxtField;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\SecurityTxt;
use Spaze\SecurityTxt\SecurityTxtHost;
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
use Spaze\SecurityTxt\Violations\SecurityTxtPolicyNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesCommonMistake;
use Spaze\SecurityTxt\Violations\SecurityTxtPreferredLanguagesCommonMistakeReason;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelPathOnly;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;
use ValueError;

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
		$e = Assert::throws(function (): void {
			$this->securityTxtJson->createViolationsFromJsonValues([['class' => SecurityTxtPolicyNotHttps::class, 'params' => []]]);
		}, SecurityTxtCannotParseJsonException::class, sprintf('Cannot parse JSON: Cannot create an object of class %s', SecurityTxtPolicyNotHttps::class));
		Assert::type(ArgumentCountError::class, $e?->getPrevious());
		Assert::equal([new SecurityTxtNoContact()], $this->securityTxtJson->createViolationsFromJsonValues([['class' => SecurityTxtNoContact::class, 'params' => []]]));
	}


	public function testCreateViolationsFromJsonValuesCannotForgeAFormat(): void
	{
		// The reason is an enum case on the wire, so JSON that carries format text instead of a case value fails from() inside the guard and never reaches vsprintf()
		$e = Assert::throws(function (): void {
			$this->securityTxtJson->createViolationsFromJsonValues([[
				'class' => SecurityTxtPreferredLanguagesCommonMistake::class,
				'params' => [1, 'cz', 'cs', "forged, \033[2J wiped your terminal because %s"],
			]]);
		}, SecurityTxtCannotParseJsonException::class, sprintf('Cannot parse JSON: Cannot create an object of class %s', SecurityTxtPreferredLanguagesCommonMistake::class));
		Assert::type(ValueError::class, $e?->getPrevious());
		// A format and values that disagree fail in vsprintf() with a ValueError wrapped the same way, so pin the one that means the reason gate refused the value
		Assert::contains('not a valid backing value', $e?->getPrevious()?->getMessage() ?? '');
		// A forged format with no placeholders would construct fine if the gate ever went away, because no argument count mismatch would catch it
		Assert::throws(function (): void {
			$this->securityTxtJson->createViolationsFromJsonValues([[
				'class' => SecurityTxtPreferredLanguagesCommonMistake::class,
				'params' => [1, 'cz', 'cs', 'forged with no placeholders at all'],
			]]);
		}, SecurityTxtCannotParseJsonException::class, sprintf('Cannot parse JSON: Cannot create an object of class %s', SecurityTxtPreferredLanguagesCommonMistake::class));
		$violations = $this->securityTxtJson->createViolationsFromJsonValues([[
			'class' => SecurityTxtPreferredLanguagesCommonMistake::class,
			'params' => [1, 'cz', 'cs', SecurityTxtPreferredLanguagesCommonMistakeReason::CzechUsesCsNotCz->value],
		]]);
		Assert::same('The language tag #1 cz in the Preferred-Languages field is not correct, the code for Czech language is cs, not cz', $violations[0]->getMessage());
	}


	public function testSerializePreferredLanguagesCommonMistakeThenCreateFromJsonValues(): void
	{
		$violation = new SecurityTxtPreferredLanguagesCommonMistake(2, 'cz-CZ', 'cs-CZ', SecurityTxtPreferredLanguagesCommonMistakeReason::CzechUsesCsNotCz);
		$json = json_encode([$violation]);
		assert(is_string($json));
		$decoded = json_decode($json, true);
		assert(is_array($decoded));
		assert(is_array($decoded[0]));
		// The params are all that a replay reads, and they carry the case value, not the format the case maps to; the rendered message is serialized too, but only read by people
		Assert::same([2, 'cz-CZ', 'cs-CZ', 'czech-uses-cs-not-cz'], $decoded[0]['params']);
		$violations = $this->securityTxtJson->createViolationsFromJsonValues(array_values($decoded));
		Assert::same($violation->getMessage(), $violations[0]->getMessage());
		Assert::same(json_encode([$violations[0]]), $json);
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


	/**
	 * @return array<class-string<SecurityTxtSpecViolation>, array{0:SecurityTxtSpecViolation}>
	 */
	public function getViolations(): array
	{
		$files = glob(__DIR__ . '/../../src/Violations/*.php');
		assert(is_array($files));
		$namespace = (new ReflectionClass(SecurityTxtSpecViolation::class))->getNamespaceName();
		$violations = [];
		foreach ($files as $file) {
			$class = $namespace . '\\' . basename($file, '.php');
			assert(class_exists($class));
			$reflection = new ReflectionClass($class);
			// The directory also holds support types like the reason enum, and only violations can be instantiated and replayed
			if ($reflection->isAbstract() || !$reflection->isSubclassOf(SecurityTxtSpecViolation::class)) {
				continue;
			}
			$params = [];
			foreach ($reflection->getConstructor()?->getParameters() ?? [] as $parameter) {
				$params[] = $this->getConstructorParamValue($class, $parameter);
			}
			$violation = $reflection->newInstanceArgs($params);
			$violations[$violation::class] = [$violation];
		}
		assert($violations !== []); // Would be empty and the test would pass without testing anything if the path above was wrong
		return $violations;
	}


	/**
	 * @return string|int|list<string>
	 */
	private function getConstructorParamValue(string $class, ReflectionParameter $parameter): string|int|array
	{
		// A field name is used for all strings because some violations read the value as a field name, and the constructor doesn't say which ones
		$string = SecurityTxtField::Contact->value;
		$type = (string)$parameter->getType();
		// An enum param goes on the wire as its backing value, so any case proves the round trip, and the first one is used
		foreach (explode('|', $type) as $part) {
			if (is_subclass_of($part, BackedEnum::class)) {
				$cases = $part::cases();
				assert($cases !== []);
				return $cases[0]->value;
			}
		}
		return match ($type) {
			'string', '?string' => $string,
			'int' => 303,
			'array' => [$string],
			// Objects would be serialized to JSON as an array and the violation couldn't be recreated from it
			default => throw new LogicException(sprintf('%s::__construct() has the $%s param of an unsupported type %s', $class, $parameter->getName(), $type)),
		};
	}


	/**
	 * @dataProvider getViolations
	 */
	public function testSerializeViolationThenCreateFromJsonValues(SecurityTxtSpecViolation $violation): void
	{
		$encoded = json_encode([$violation]);
		assert(is_string($encoded));
		$decoded = json_decode($encoded, true);
		assert(is_array($decoded));
		Assert::equal([$violation], $this->securityTxtJson->createViolationsFromJsonValues(array_values($decoded)));
	}


	public function testCreateFetchResultFromJsonValues(): void
	{
		$lines = ["Contact: mailto:example@example.com\r\n", "Expires: 2030-12-31T23:59:59.000Z\r\n", "Preferred-Languages: en; cs"];
		$result = new SecurityTxtFetchResult(
			new Url('https://example.com/security.txt'),
			new Url('https://www.example.com/security.txt'),
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
		$actualResult = $this->securityTxtJson->createFetchResultFromJsonValues($decoded);
		// Assert::equal() compares objects cast to arrays and a Uri\WhatWg\Url casts to an empty one, so the URL fields are pinned by the string comparisons and the byte comparison below
		Assert::equal($result, $actualResult);
		Assert::same($result->getConstructedUrl()->toUnicodeString(), $actualResult->getConstructedUrl()->toUnicodeString());
		Assert::same($result->getFinalUrl()->toUnicodeString(), $actualResult->getFinalUrl()->toUnicodeString());
		Assert::same($encoded, json_encode($actualResult));
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
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: constructedUrl is not a URL');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'HTTPS://url.example/']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: constructedUrl is not a URL');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://xn--bcher-kva.example/']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: constructedUrl is not a URL');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: finalUrl is not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 808]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: finalUrl is not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 'url2']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: finalUrl is not a URL');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 'https://url2.example/']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: redirects is not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 'https://url2.example/', 'redirects' => 'string']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: redirects is not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 'https://url2.example/', 'redirects' => []]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: contents is not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 'https://url2.example/', 'redirects' => [], 'contents' => 303]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: contents is not a string');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 'https://url2.example/', 'redirects' => [], 'contents' => '303']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: isTruncated is not a bool');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 'https://url2.example/', 'redirects' => [], 'contents' => '303', 'isTruncated' => 'maybe']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: isTruncated is not a bool');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 'https://url2.example/', 'redirects' => [], 'contents' => '303', 'isTruncated' => false]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: errors is not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 'https://url2.example/', 'redirects' => [], 'contents' => '303', 'isTruncated' => false, 'errors' => true]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: errors is not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 'https://url2.example/', 'redirects' => [], 'contents' => '303', 'isTruncated' => false, 'errors' => []]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: warnings is not an array');
		Assert::throws(function (): void {
			$this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 'https://url2.example/', 'redirects' => [], 'contents' => '303', 'isTruncated' => false, 'errors' => [], 'warnings' => 'none']);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: warnings is not an array');
		Assert::type(SecurityTxtFetchResult::class, $this->securityTxtJson->createFetchResultFromJsonValues(['class' => SecurityTxtFetchResult::class, 'constructedUrl' => 'https://url.example/', 'finalUrl' => 'https://url2.example/', 'redirects' => [], 'contents' => '303', 'isTruncated' => false, 'errors' => [], 'warnings' => []]));
	}


	/**
	 * @return array<class-string<SecurityTxtFetcherException>, array{0:SecurityTxtFetcherException}>
	 */
	public function getExceptions(): array
	{
		// A host outside ASCII, because a host reads as itself where a string is encoded, so these are the rows that notice if a replay stops turning the wire's string back
		// into a host and the same failure starts saying `h%C3%A1%C4%8Dky.example` from a cache and `háčky.example` live
		$host = SecurityTxtHost::fromString("h\u{E1}\u{10D}ky.example");
		return [
			SecurityTxtHostNotFoundException::class => [
				new SecurityTxtHostNotFoundException('https://example.com/.well-known/security.txt', $host),
			],
			SecurityTxtHostIpAddressNotFoundException::class => [
				new SecurityTxtHostIpAddressNotFoundException('https://example.com/.well-known/security.txt', $host),
			],
			SecurityTxtOnlyIpv6HostButIpv6DisabledException::class => [
				new SecurityTxtOnlyIpv6HostButIpv6DisabledException($host, '2001:DB8::1', 'https://example.com/.well-known/security.txt'),
			],
			SecurityTxtTooManyRedirectsException::class => [
				new SecurityTxtTooManyRedirectsException('https://example.com', ['https://example.com', 'https://www.example.com'], 1),
			],
			SecurityTxtCannotOpenUrlException::class => [
				new SecurityTxtCannotOpenUrlException(
					'https://example.com/.well-known/security.txt',
					['https://redir1.example/'],
					'2001:DB8::1',
					SecurityTxtIpAddressType::V6->value,
					'Could not connect to server',
				),
			],
			SecurityTxtNotFoundException::class => [
				new SecurityTxtNotFoundException([
					'https://1.example/' => [
						'ip' => '192.0.2.1',
						'type' => SecurityTxtIpAddressType::V4->value,
						'code' => 200,
						'redirects' => ['https://redir1.example/'],
						'html' => false,
						'truncated' => true,
					],
					'https://2.example/' => [
						'ip' => '2001:DB8::2',
						'type' => SecurityTxtIpAddressType::V6->value,
						'code' => 200,
						'redirects' => ['https://redir1.example/'],
						'html' => false,
						'truncated' => false,
					],
				], 'https://1.example/'),
			],
		];
	}


	/**
	 * @dataProvider getExceptions
	 */
	public function testCreateFetcherExceptionFromJsonValues(SecurityTxtFetcherException $exception): void
	{
		$encoded = json_encode(['error' => $exception]);
		assert(is_string($encoded));
		$decoded = json_decode($encoded, true);
		assert(is_array($decoded));
		$exceptionFromJson = $this->securityTxtJson->createFetcherExceptionFromJsonValues($decoded);
		Assert::type($exception::class, $exceptionFromJson);
		Assert::same($exception->getMessage(), $exceptionFromJson->getMessage());
		if ($exception instanceof SecurityTxtNotFoundException) {
			assert($exceptionFromJson instanceof SecurityTxtNotFoundException);
			Assert::same($exception->getIpAddresses(), $exceptionFromJson->getIpAddresses());
		}
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
			$this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => DateInterval::class, 'params' => []]]); // If the constructor was called, it would generate a different message because we're passing it a wrong number of arguments
		}, SecurityTxtCannotParseJsonException::class, sprintf('Cannot parse JSON: The exception class %s is not a subclass of %s', DateInterval::class, SecurityTxtFetcherException::class));
		$e = Assert::throws(function (): void {
			$this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => SecurityTxtNotFoundException::class, 'params' => [['https://example.com/' => []], 'https://example.com/']]]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: Cannot create an object of class ' . SecurityTxtNotFoundException::class);
		Assert::type(SecurityTxtNotFoundWrongUrlStructureException::class, $e?->getPrevious());
		Assert::same('Cannot create Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException: securityTxtUrls > https://example.com/ > ip is not set or not a string', $e?->getPrevious()?->getMessage());
		$e = Assert::throws(function (): void {
			$this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => SecurityTxtCannotOpenUrlException::class, 'params' => ['https://example.com/', [], '192.0.2.1', 1337, null]]]);
		}, SecurityTxtCannotParseJsonException::class, 'Cannot parse JSON: Cannot create an object of class ' . SecurityTxtCannotOpenUrlException::class);
		Assert::type(ValueError::class, $e?->getPrevious());
		Assert::same('1337 is not a valid backing value for enum Spaze\SecurityTxt\Fetcher\SecurityTxtIpAddressType', $e?->getPrevious()?->getMessage());
		Assert::type(SecurityTxtUrlNotFoundException::class, $this->securityTxtJson->createFetcherExceptionFromJsonValues(['error' => ['class' => SecurityTxtUrlNotFoundException::class, 'params' => ['url', 303, '1.1.1.0', SecurityTxtIpAddressType::V4->value]]]));
	}


	/**
	 * A host string the wire can genuinely carry but `SecurityTxtHost::fromString()` refuses still has to replay. `getUnicode()` and `fromString()` are not quite inverses: a
	 * punycode label whose payload decodes out of normalization order comes back as a spelling that reparses to a different host. Such a host reads encoded, which is what it
	 * did before any of this, rather than taking the whole stored result down with it.
	 *
	 * Built from the live object rather than pinned to a literal, because which labels do this is ICU's decision and moves with its version.
	 */
	public function testCreateFetcherExceptionFromJsonValuesKeepsAHostItCannotParseBack(): void
	{
		$host = new SecurityTxtHost(new Url('https://xn--wuao.example/'));
		Assert::throws(function () use ($host): void {
			SecurityTxtHost::fromString($host->getUnicode());
		}, SecurityTxtCannotParseHostnameException::class);

		$live = new SecurityTxtHostNotFoundException('https://example.com/', $host);
		$encoded = json_encode(['error' => $live]);
		assert(is_string($encoded));
		$decoded = json_decode($encoded, true);
		assert(is_array($decoded));
		$replayed = $this->securityTxtJson->createFetcherExceptionFromJsonValues($decoded);
		Assert::type(SecurityTxtHostNotFoundException::class, $replayed);
		Assert::contains(rawurlencode($host->getUnicode()), $replayed->getMessage());
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
