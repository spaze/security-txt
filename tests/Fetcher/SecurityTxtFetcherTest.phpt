<?php
/** @noinspection PhpDocMissingThrowsInspection */
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use LogicException;
use Override;
use ReflectionMethod;
use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtDnsProvider;
use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtDnsRecords;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressInvalidException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressNotPublicException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoLocationHeaderException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtOnlyIpv6HostButIpv6DisabledException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlNoSchemeException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlUnsupportedSchemeException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherHttpClient;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\SecurityTxtContentType;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeWrongCharset;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelDiffers;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../bootstrap.php';

/** @testCase */
final class SecurityTxtFetcherTest extends TestCase
{

	private SecurityTxtSplitLines $splitLines;
	private SecurityTxtUrlParser $urlParser;


	public function __construct()
	{
		$this->splitLines = new SecurityTxtSplitLines(new SecurityTxtPregSplitProvider());
		$this->urlParser = new SecurityTxtUrlParser();
	}


	private function getHttpClient(SecurityTxtFetcherResponse ...$fetcherResponse): SecurityTxtFetcherHttpClient
	{
		return new class (...$fetcherResponse) implements SecurityTxtFetcherHttpClient {

			/**
			 * @var list<SecurityTxtFetcherResponse>
			 */
			private array $fetcherResponse;
			private int $position = 0;
			private int $lastKey;


			public function __construct(SecurityTxtFetcherResponse ...$fetcherResponse)
			{
				$this->fetcherResponse = array_values($fetcherResponse);
				$this->lastKey = count($fetcherResponse) - 1;
			}


			#[Override]
			public function getResponse(SecurityTxtFetcherUrl $url, string $host, string $ipAddress, SecurityTxtIpAddressType $ipAddressType): SecurityTxtFetcherResponse
			{
				return $this->fetcherResponse[$this->position++] ?? $this->fetcherResponse[$this->lastKey];
			}

		};
	}


	/**
	 * @return array<string, array{0:int, 1:array<string, string>, 2:int, 3:string|null, 4:class-string<SecurityTxtFetcherException>|null}>
	 */
	public function getHeaders(): array
	{
		return [
			'301 redirect with Location' => [
				301,
				[
					'Foo' => 'bar',
					'Location' => 'https://example.example/example',
				],
				301,
				null,
				SecurityTxtTooManyRedirectsException::class, // The only way to test redirects is to catch en exception
			],
			'302 redirect with no Location' => [
				302,
				[
					'Foo' => 'bar',
				],
				302,
				null,
				SecurityTxtNoLocationHeaderException::class,
			],
			'Random redirect with location' => [
				399,
				[
					'Foo' => 'bar',
					'location' => 'https://example.org/example',
				],
				399,
				null,
				SecurityTxtTooManyRedirectsException::class, // The only way to test redirects is to catch en exception
			],
			'Success' => [
				200,
				[],
				200,
				null,
				null,
			],
			'Random success with nonsensical Location' => [
				299,
				[
					'Foo' => 'bar',
					'Location' => 'https://example.org/example',
				],
				299,
				'https://example.org/example',
				null,
			],
		];
	}


	/**
	 * @param array<string, string> $headers
	 * @param class-string<SecurityTxtFetcherException>|null $expectedException
	 * @dataProvider getHeaders
	 */
	public function testGetResponse(int $httpCode, array $headers, int $expectedHttpCode, ?string $expectedLocation, ?string $expectedException): void
	{
		$lowercaseHeaders = [];
		foreach ($headers as $key => $value) {
			$lowercaseHeaders[strtolower($key)] = $value;
		}
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse($httpCode, $lowercaseHeaders, 'some random contents', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider());
		$method = new ReflectionMethod($fetcher, 'getResponse');
		$finalUrl = 'passed by ref';
		if ($expectedException !== null) {
			Assert::throws(function () use ($method, $fetcher, $finalUrl): void {
				$method->invokeArgs($fetcher, [new SecurityTxtFetcherUrl('https://example.com/foo', []), 'example.com', 'https://example.com/foo', &$finalUrl, true]);
			}, $expectedException);
		} else {
			$response = $method->invokeArgs($fetcher, [new SecurityTxtFetcherUrl('https://example.com/foo', []), 'example.com', 'https://example.com/foo', &$finalUrl, true]);
			assert($response instanceof SecurityTxtFetcherResponse);
			Assert::same($expectedHttpCode, $response->getHttpCode());
			Assert::same($expectedLocation, $response->getHeader('location'));
			Assert::false($response->isTruncated());
		}
	}


	/**
	 * @return array<string, array{0:string|null, 1:string|null, 2:bool, 3:bool, 4:bool}>
	 */
	public function getContents(): array
	{
		return [
			'both 200' => ['well-known', 'top-level', false, false, true],
			'both 200 but top-level truncated' => ['well-known', 'top-level', false, true, true],
			'both 200 but well-known truncated' => ['well-known', 'top-level', true, false, false],
			'top-level 404' => ['well-known', null, false, false, true],
			'well-known 404' => [null, 'top-level', false, false, false],
			'same' => ['same', 'same', false, false, true],
			'same but top-level truncated' => ['same', 'same', false, true, true],
			'same but well-known truncated' => ['same', 'same', true, false, false],
		];
	}


	/** @dataProvider getContents */
	public function testGetResult(?string $wellKnownContents, ?string $topLevelContents, bool $wellKnownTruncated, bool $topLevelTruncated, bool $wellKnownWins): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'contents', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider());
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', '192.0.2.1', SecurityTxtIpAddressType::V4, 200, $wellKnownContents !== null ? new SecurityTxtFetcherResponse(200, [], $wellKnownContents, $wellKnownTruncated, '1.1.1.0', SecurityTxtIpAddressType::V4) : null);
		$topLevel = new SecurityTxtFetcherFetchHostResult('bar', 'bar2', '198.51.100.1', SecurityTxtIpAddressType::V4, 200, $topLevelContents !== null ? new SecurityTxtFetcherResponse(200, [], $topLevelContents, $topLevelTruncated, '1.1.1.0', SecurityTxtIpAddressType::V4) : null);
		$method = new ReflectionMethod($fetcher, 'getResult');
		$expected = $wellKnownWins ? $wellKnown->getContents() : $topLevel->getContents();
		$result = $method->invoke($fetcher, $wellKnown, $topLevel, true);
		assert($result instanceof SecurityTxtFetchResult);
		Assert::same($expected, $result->getContents());
	}


	public function testGetResultGetLine(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'contents', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider());
		$lines = ["Contact: 123\n", "Hiring: 456\n"];
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', '192.0.2.1', SecurityTxtIpAddressType::V4, 200, new SecurityTxtFetcherResponse(200, [], implode('', $lines), false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$topLevel = new SecurityTxtFetcherFetchHostResult('bar', 'bar2', '198.51.100.1', SecurityTxtIpAddressType::V4, 200, null);
		$method = new ReflectionMethod($fetcher, 'getResult');
		$result = $method->invoke($fetcher, $wellKnown, $topLevel, true);
		assert($result instanceof SecurityTxtFetchResult);
		Assert::null($result->getLine(-1)); /** @phpstan-ignore argument.type (Testing invalid line number) */
		Assert::null($result->getLine(0)); /** @phpstan-ignore argument.type (Testing another invalid line number) */
		Assert::same($lines[0], $result->getLine(1));
		Assert::same($lines[1], $result->getLine(2));
		Assert::null($result->getLine(3));
	}


	public function testGetResultTruncated(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'contents', true, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider());
		$wellKnown = new SecurityTxtFetcherFetchHostResult('foo', 'foo2', '192.0.2.1', SecurityTxtIpAddressType::V4, 200, new SecurityTxtFetcherResponse(200, [], 'well-known', true, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$topLevel = new SecurityTxtFetcherFetchHostResult('bar', 'bar2', '198.51.100.1', SecurityTxtIpAddressType::V4, 200, new SecurityTxtFetcherResponse(200, [], 'top-level', true, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$method = new ReflectionMethod($fetcher, 'getResult');
		Assert::throws(function () use ($method, $fetcher, $wellKnown, $topLevel) {
			$method->invoke($fetcher, $wellKnown, $topLevel, true);
		}, SecurityTxtNotFoundException::class, "Can't read security.txt: foo (192.0.2.1) => response too long, bar (198.51.100.1) => response too long");
	}


	/**
	 * @return array<string, array{0:string, 1:string, 2:string, 3:string, 4:SecurityTxtTopLevelDiffers|null}>
	 */
	public function getResults(): array
	{
		$finalUrl1 = 'https://final1.example/';
		$finalUrl2 = 'https://final2.example/';
		$contents1 = 'contents1';
		$contents2 = 'contents2';
		return [
			'different final URL, same response' => [$finalUrl1, $finalUrl2, $contents1, $contents1, null],
			'different final URL, different response' => [$finalUrl1, $finalUrl2, $contents1, $contents2, new SecurityTxtTopLevelDiffers($contents1, $contents2)],
			'same final URL, different response' => [$finalUrl1, $finalUrl1, $contents1, $contents2, null],
		];
	}


	/** @dataProvider getResults */
	public function testGetResultTopLevelDiffers(string $finalUrlWellKnown, string $finalUrlTopLevel, string $contentsWellKnown, string $contentsTopLevel, ?SecurityTxtTopLevelDiffers $violation): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider());
		$fetcherResponseWellKnown = new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], $contentsWellKnown, false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$fetcherResponseTopLevel = new SecurityTxtFetcherResponse(200, [], $contentsTopLevel, false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$wellKnown = new SecurityTxtFetcherFetchHostResult('https://url1.example/', $finalUrlWellKnown, '192.0.2.1', SecurityTxtIpAddressType::V4, 200, $fetcherResponseWellKnown);
		$topLevel = new SecurityTxtFetcherFetchHostResult('https://url2.example/', $finalUrlTopLevel, '198.51.100.1', SecurityTxtIpAddressType::V4, 200, $fetcherResponseTopLevel);
		$method = new ReflectionMethod($fetcher, 'getResult');
		$result = $method->invoke($fetcher, $wellKnown, $topLevel, true);
		assert($result instanceof SecurityTxtFetchResult);
		Assert::same([], $result->getErrors());
		if ($violation !== null) {
			Assert::notSame($violation->getTopLevelContents(), $violation->getWellKnownContents());
			Assert::equal([$violation], $result->getWarnings());
		} else {
			Assert::equal([], $result->getWarnings());
		}
	}


	public function testFetchNoRecords(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, [], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(null, new SecurityTxtDnsRecords(null, null)));
		Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch('https://example.com/');
		}, SecurityTxtHostIpAddressNotFoundException::class);
	}


	public function testFetchOnlyIpv6Address(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(null, new SecurityTxtDnsRecords(null, '2001:cafe:f00d::1')));
		Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch('https://example.com/', false, true);
		}, SecurityTxtOnlyIpv6HostButIpv6DisabledException::class);

		$fetchResult = $fetcher->fetch('https://example.net/');
		Assert::same([], $fetchResult->getErrors());
		Assert::same([], $fetchResult->getWarnings());
		Assert::same('random', $fetchResult->getContents());
		Assert::same('https://example.net/.well-known/security.txt', $fetchResult->getFinalUrl());
		Assert::same('https://example.net/.well-known/security.txt', $fetchResult->getConstructedUrl());
	}


	public function testFetch(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider());
		$fetchResult = $fetcher->fetch('https://com.example/', false, true);
		Assert::same([], $fetchResult->getErrors());
		Assert::same([], $fetchResult->getWarnings());
		Assert::same('random', $fetchResult->getContents());
		Assert::same('https://com.example/.well-known/security.txt', $fetchResult->getFinalUrl());
		Assert::same('https://com.example/.well-known/security.txt', $fetchResult->getConstructedUrl());
		Assert::same([], $fetchResult->getRedirects());
	}


	public function testFetchRedirects(): void
	{
		$httpClient = $this->getHttpClient(
			// For the first fetch(), well-known location
			new SecurityTxtFetcherResponse(301, ['location' => 'https://location1.example/.well-known/'], 'random location', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random final', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			// For the first fetch(), top-level location
			new SecurityTxtFetcherResponse(301, ['location' => 'https://location1.example/'], 'random location', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random final', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			// For the second fetch(), well-known location
			new SecurityTxtFetcherResponse(301, ['location' => 'https://location2.example/.well-known/'], 'random location', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random final', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			// For the second fetch(), top-level location
			new SecurityTxtFetcherResponse(301, ['location' => 'https://location2.example/'], 'random location', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random final', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider());
		$fetchResult = $fetcher->fetch('https://com.example/', false, true);
		Assert::same([], $fetchResult->getErrors());
		Assert::same([], $fetchResult->getWarnings());
		Assert::same('random final', $fetchResult->getContents());
		Assert::same('https://location1.example/.well-known/', $fetchResult->getFinalUrl());
		Assert::same('https://com.example/.well-known/security.txt', $fetchResult->getConstructedUrl());
		$redirects = [
			'https://com.example/.well-known/security.txt' => ['https://location1.example/.well-known/'],
			'https://com.example/security.txt' => ['https://location1.example/'],
		];
		Assert::same($redirects, $fetchResult->getRedirects());

		$redirects = [
			'https://com.example/.well-known/security.txt' => ['https://location2.example/.well-known/'],
			'https://com.example/security.txt' => ['https://location2.example/'],
		];
		$fetchResult = $fetcher->fetch('https://com.example/', false, true);
		Assert::same($redirects, $fetchResult->getRedirects());
	}


	public function testFetchWrongCharset(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => 'text/plain; charset=utf-42'], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider());
		$fetchResult = $fetcher->fetch('https://com.example/', false, true);
		$expectedError = new SecurityTxtContentTypeWrongCharset('https://com.example/.well-known/security.txt', 'text/plain', 'charset=utf-42');
		Assert::equal([$expectedError], $fetchResult->getErrors());
		Assert::same([], $fetchResult->getWarnings());
		Assert::same('random', $fetchResult->getContents());
		Assert::same('https://com.example/.well-known/security.txt', $fetchResult->getFinalUrl());
		Assert::same('https://com.example/.well-known/security.txt', $fetchResult->getConstructedUrl());
		Assert::same([], $fetchResult->getRedirects());
	}


	public function testFetchNotFound(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(404, ['content-type' => 'text/plain; charset=utf-42'], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider());
		$exception = Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch('https://com.example/');
		}, SecurityTxtNotFoundException::class, "Can't read security.txt: https://com.example/.well-known/security.txt (1.1.1.0) => 404, https://com.example/security.txt (1.1.1.0) => 404");
		assert($exception instanceof SecurityTxtNotFoundException);
		Assert::same(['1.1.1.0' => [SecurityTxtIpAddressType::V4->value, 404]], $exception->getIpAddresses());
		Assert::same([], $exception->getAllRedirects());
	}


	public function testFetchCallbacks(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider());
		$onUrl = $onFinalUrl = null;
		$fetcher->addOnUrl(function (string $url) use (&$onUrl): void {
			$onUrl = $url;
		});
		$fetcher->addOnFinalUrl(function (string $url) use (&$onFinalUrl): void {
			$onFinalUrl = $url;
		});
		$fetcher->fetch('https://com.example/');
		Assert::same('https://com.example/security.txt', $onUrl);
		Assert::same('https://com.example/.well-known/security.txt', $onFinalUrl);

		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(301, ['location' => 'https://location.example/'], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), 0);
		$onRedirectUrl = $onRedirectDestination = null;
		$fetcher->addOnRedirect(function (string $url, string $destination) use (&$onRedirectUrl, &$onRedirectDestination): void {
			$onRedirectUrl = $url;
			$onRedirectDestination = $destination;
		});
		Assert::throws(function () use (&$fetcher): void {
			$fetcher->fetch('https://com.example/');
		}, SecurityTxtTooManyRedirectsException::class);
		Assert::same('https://com.example/.well-known/security.txt', $onRedirectUrl);
		Assert::same('https://location.example/', $onRedirectDestination);

		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(404, [], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), 0);
		$onUrlNotFound = null;
		$fetcher->addOnUrlNotFound(function (string $url) use (&$onUrlNotFound): void {
			$onUrlNotFound = $url;
		});
		Assert::throws(function () use (&$fetcher): void {
			$fetcher->fetch('https://com.example/');
		}, SecurityTxtNotFoundException::class);
		Assert::same('https://com.example/security.txt', $onUrlNotFound);
	}


	public function testFetchNoScheme(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, [], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider());

		$method = new ReflectionMethod($fetcher, 'fetchUrl');
		Assert::throws(function () use ($method, $fetcher): void {
			$method->invoke($fetcher, '//foo/bar', 'foo', false);
		}, SecurityTxtUrlNoSchemeException::class);

		Assert::throws(function () use ($method, $fetcher): void {
			$method->invoke($fetcher, ':', 'foo', false);
		}, SecurityTxtUrlNoSchemeException::class);
	}


	public function testFetchUnsupportedScheme(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, [], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider());

		$method = new ReflectionMethod($fetcher, 'fetchUrl');
		Assert::throws(function () use ($method, $fetcher): void {
			$method->invoke($fetcher, 'file://foo/bar', 'foo', false);
		}, SecurityTxtUrlUnsupportedSchemeException::class, 'URL file://foo/bar has an unsupported scheme');
	}


	public function testFetchUnsupportedSchemeRedirect(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(301, ['location' => 'file:///etc/passwd'], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(
			null,
			new SecurityTxtDnsRecords('1.1.1.0', null),
			new SecurityTxtDnsRecords(null, null),
		));
		$method = new ReflectionMethod($fetcher, 'fetchUrl');
		Assert::throws(function () use ($method, $fetcher): void {
			$method->invoke($fetcher, 'https://foo/bar', 'foo', false);
		}, SecurityTxtUrlUnsupportedSchemeException::class, 'URL file:///etc/passwd has an unsupported scheme (redirects: https://foo/bar → file:///etc/passwd)');
	}


	public function testCheckMaxAllowedRedirects(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(301, [], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		Assert::throws(function () use ($httpClient): void {
			new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), -1);
		}, LogicException::class, 'maxAllowedRedirects must be greater than or equal to 0 (0 means no redirects allowed)');
	}


	/**
	 * @return list<array{0:string|null, 1:string|null, 2:bool}>
	 */
	public function getIpAddresses(): array
	{
		return [
			['1.1.1.1', null, true],
			[null, '2001:1337:42:ec00:2468:7ea:cafe:d00d', true],
			['127.0.0.1', null, false],
			['192.168.1.1', null, false],
			['10.1.2.3', null, false],
			[null, '::1', false],
			[null, 'fe80::1ff:fe23:4567:890a', false],
			[null, '2001:3f48:2244:344::127.0.0.1', false],
			[null, '2001:3f48:2244:344::192.168.1.1', false],
			[null, '2001:3f48:2244:344::10.1.2.3', false],
			[null, '2001:3f48:2244:344::192.0.2.33', false],
			[null, '::ffff:127.0.0.1', false],
			[null, '::ffff:192.168.1.1', false],
			[null, '::ffff:10.1.2.3', false],
			[null, '::ffff:192.0.2.33', false],
			['foo', '2001:1337:42:ec00:2468:7ea:cafe:d00d', true], // IPv6 address preference
		];
	}


	/**
	 * @dataProvider getIpAddresses
	 */
	public function testFetchNonPublicIpAddress(?string $ipRecord, ?string $ipv6Record, bool $isValid): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, [], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(null, new SecurityTxtDnsRecords($ipRecord, $ipv6Record)));
		if ($isValid) {
			Assert::noError(function () use ($fetcher): void {
				$fetcher->fetch('https://example.com/');
			});
		} else {
			Assert::throws(function () use ($fetcher): void {
				$fetcher->fetch('https://example.com/');
			}, SecurityTxtHostIpAddressNotPublicException::class);
		}
	}


	/**
	 * @return list<array{0:string|null, 1:string|null, 2:SecurityTxtIpAddressType}>
	 */
	public function getInvalidIpAddresses(): array
	{
		return [
			[null, 'fe80::1ff:fe23:4567:890a%3', SecurityTxtIpAddressType::V6],
			['foo', null, SecurityTxtIpAddressType::V4],
			[null, 'foo', SecurityTxtIpAddressType::V6],
			['foo', 'foo', SecurityTxtIpAddressType::V6],
			['2001:1337:42:ec00:2468:7ea:cafe:d00d', '1.1.1.0', SecurityTxtIpAddressType::V6], // IPv4 vs IPv6 mix up
		];
	}


	/**
	 * @dataProvider getInvalidIpAddresses
	 */
	public function testFetchInvalidIpAddress(?string $ipRecord, ?string $ipv6Record, SecurityTxtIpAddressType $invalidType): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, [], 'random', false, 'anyway', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(null, new SecurityTxtDnsRecords($ipRecord, $ipv6Record)));
		if ($invalidType === SecurityTxtIpAddressType::V4) {
			$type = 'IPv4';
			$address = $ipRecord;
		} else {
			$type = 'IPv6';
			$address = $ipv6Record;
		}
		Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch('https://example.com/');
		}, SecurityTxtHostIpAddressInvalidException::class, "Host example.com resolves to an invalid {$type} address {$address}");
	}


	public function testFetchNonPublicIpAddressRedirect(): void
	{
		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(302, ['location' => 'https://example.net/foo'], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(200, [], 'lolcat host', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$dnsProvider = $this->getDnsProvider(
			null,
			new SecurityTxtDnsRecords('1.1.1.1', null),
			new SecurityTxtDnsRecords('127.0.0.1', null),
		);
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $dnsProvider);
		Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch('https://example.com/');
		}, SecurityTxtHostIpAddressNotPublicException::class, 'Host example.net resolves to a non-public IP address 127.0.0.1');
	}


	public function testFetchIpAddressNoDnsLookup(): void
	{
		$ipAddress = '1.1.1.0';
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, $ipAddress, SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(new LogicException('Resolver should not be called for IPv4 addresses')));
		$result = null;
		Assert::noError(function () use (&$result, $fetcher, $ipAddress): void {
			$result = (new ReflectionMethod($fetcher, 'fetchUrl'))->invoke($fetcher, "https://{$ipAddress}/", $ipAddress, false);
		});
		assert($result instanceof SecurityTxtFetcherFetchHostResult);
		Assert::same($ipAddress, $result->getIpAddress());
	}


	public function testFetchIpv6AddressNoDnsLookup(): void
	{
		$ipv6Address = '2001:db42::1';
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, $ipv6Address, SecurityTxtIpAddressType::V6));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(new LogicException('Resolver should not be called for IPv6 addresses')));
		$result = null;
		Assert::noError(function () use (&$result, $fetcher, $ipv6Address): void {
			$result = (new ReflectionMethod($fetcher, 'fetchUrl'))->invoke($fetcher, "https://[{$ipv6Address}]/", "[{$ipv6Address}]", false);
		});
		assert($result instanceof SecurityTxtFetcherFetchHostResult);
		Assert::same($ipv6Address, $result->getIpAddress());
	}


	private function getDnsProvider(?LogicException $throw = null, SecurityTxtDnsRecords ...$dnsRecords): SecurityTxtDnsProvider
	{
		if ($dnsRecords === []) {
			$dnsRecords = [new SecurityTxtDnsRecords('1.1.1.0', null)];
		}
		return new class ($throw, ...$dnsRecords) implements SecurityTxtDnsProvider {

			/**
			 * @var list<SecurityTxtDnsRecords>
			 */
			private array $dnsRecords;
			private int $position = 0;
			private int $lastKey;


			public function __construct(
				private readonly ?LogicException $throw = null,
				SecurityTxtDnsRecords ...$dnsRecords,
			) {
				$this->dnsRecords = array_values($dnsRecords);
				$this->lastKey = count($dnsRecords) - 1;
			}


			#[Override]
			public function getRecords(string $url, string $host): SecurityTxtDnsRecords
			{
				if ($this->throw !== null) {
					throw $this->throw;
				}
				return $this->dnsRecords[$this->position++] ?? $this->dnsRecords[$this->lastKey];
			}

		};
	}

}

(new SecurityTxtFetcherTest())->run();
