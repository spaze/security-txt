<?php
/**
 * @testCase
 * @noinspection PhpDocMissingThrowsInspection
 * @noinspection PhpUnhandledExceptionInspection
 */
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher;

use Closure;
use LogicException;
use Override;
use ReflectionMethod;
use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtDnsProvider;
use Spaze\SecurityTxt\Fetcher\DnsLookup\SecurityTxtDnsRecords;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotOpenUrlException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtCannotParseHostnameException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtConnectedToWrongIpAddressException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtFetcherException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressInvalidException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostIpAddressNotPublicException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtHostNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNoLocationHeaderException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtNotFoundException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtOnlyIpv6HostButIpv6DisabledException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtRedirectLoopException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtRedirectUrlTooLongException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtTooManyRedirectsException;
use Spaze\SecurityTxt\Fetcher\Exceptions\SecurityTxtUrlUnsupportedSchemeException;
use Spaze\SecurityTxt\Fetcher\HttpClients\SecurityTxtFetcherHttpClient;
use Spaze\SecurityTxt\Fetcher\SecurityTxtRedirects;
use Spaze\SecurityTxt\Json\SecurityTxtJson;
use Spaze\SecurityTxt\Parser\SecurityTxtSplitLines;
use Spaze\SecurityTxt\Parser\SecurityTxtUrlParser;
use Spaze\SecurityTxt\Parser\SplitProviders\SecurityTxtPregSplitProvider;
use Spaze\SecurityTxt\SecurityTxtContentType;
use Spaze\SecurityTxt\SecurityTxtHost;
use Spaze\SecurityTxt\Violations\SecurityTxtContentTypeWrongCharset;
use Spaze\SecurityTxt\Violations\SecurityTxtRedirectNotHttps;
use Spaze\SecurityTxt\Violations\SecurityTxtSpecViolation;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelDiffers;
use Spaze\SecurityTxt\Violations\SecurityTxtTopLevelPathOnly;
use Spaze\SecurityTxt\Violations\SecurityTxtWellKnownPathOnly;
use Tester\Assert;
use Tester\TestCase;
use Uri\WhatWg\Url;

require __DIR__ . '/../bootstrap.php';

final class SecurityTxtFetcherTest extends TestCase
{

	private SecurityTxtSplitLines $splitLines;
	private SecurityTxtUrlParser $urlParser;
	private SecurityTxtIpAddressValidator $ipAddressValidator;


	public function __construct()
	{
		$this->splitLines = new SecurityTxtSplitLines(new SecurityTxtPregSplitProvider());
		$this->urlParser = new SecurityTxtUrlParser();
		$this->ipAddressValidator = new SecurityTxtIpAddressValidator();
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
			public function getResponse(SecurityTxtFetcherUrl $url, SecurityTxtHost $host, string $ipAddress, SecurityTxtIpAddressType $ipAddressType): SecurityTxtFetcherResponse
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
				SecurityTxtRedirectLoopException::class, // The client sends the same Location every time, and the only way to test redirects is to catch an exception
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
				SecurityTxtRedirectLoopException::class, // The client sends the same Location every time, and the only way to test redirects is to catch an exception
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
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$method = new ReflectionMethod($fetcher, 'getResponse');
		$finalUrl = new Url('https://passed-by-ref.example/');
		if ($expectedException !== null) {
			Assert::throws(function () use ($method, $fetcher, $finalUrl): void {
				$method->invokeArgs($fetcher, [new SecurityTxtFetcherUrl(new Url('https://example.com/foo'), new SecurityTxtRedirects()), new SecurityTxtHost(new Url('https://example.com/')), new Url('https://example.com/foo'), &$finalUrl, true, null]);
			}, $expectedException);
		} else {
			$response = $method->invokeArgs($fetcher, [new SecurityTxtFetcherUrl(new Url('https://example.com/foo'), new SecurityTxtRedirects()), new SecurityTxtHost(new Url('https://example.com/')), new Url('https://example.com/foo'), &$finalUrl, true, null]);
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
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$wellKnown = new SecurityTxtFetcherFetchHostResult(new Url('https://foo.example/'), new Url('https://foo2.example/'), '192.0.2.1', SecurityTxtIpAddressType::V4, 200, $wellKnownContents !== null ? new SecurityTxtFetcherResponse(200, [], $wellKnownContents, $wellKnownTruncated, '1.1.1.0', SecurityTxtIpAddressType::V4) : null);
		$topLevel = new SecurityTxtFetcherFetchHostResult(new Url('https://bar.example/'), new Url('https://bar2.example/'), '198.51.100.1', SecurityTxtIpAddressType::V4, 200, $topLevelContents !== null ? new SecurityTxtFetcherResponse(200, [], $topLevelContents, $topLevelTruncated, '1.1.1.0', SecurityTxtIpAddressType::V4) : null);
		$method = new ReflectionMethod($fetcher, 'getResult');
		$expected = $wellKnownWins ? $wellKnown->getContents() : $topLevel->getContents();
		$result = $method->invoke($fetcher, $wellKnown, $topLevel, true);
		assert($result instanceof SecurityTxtFetchResult);
		Assert::same($expected, $result->getContents());
	}


	public function testGetResultGetLine(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'contents', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$lines = ["Contact: 123\n", "Hiring: 456\n"];
		$wellKnown = new SecurityTxtFetcherFetchHostResult(new Url('https://foo.example/'), new Url('https://foo2.example/'), '192.0.2.1', SecurityTxtIpAddressType::V4, 200, new SecurityTxtFetcherResponse(200, [], implode('', $lines), false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$topLevel = new SecurityTxtFetcherFetchHostResult(new Url('https://bar.example/'), new Url('https://bar2.example/'), '198.51.100.1', SecurityTxtIpAddressType::V4, 200, null);
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
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$wellKnown = new SecurityTxtFetcherFetchHostResult(new Url('https://foo.example/'), new Url('https://foo2.example/'), '192.0.2.1', SecurityTxtIpAddressType::V4, 200, new SecurityTxtFetcherResponse(200, [], 'well-known', true, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$topLevel = new SecurityTxtFetcherFetchHostResult(new Url('https://bar.example/'), new Url('https://bar2.example/'), '198.51.100.1', SecurityTxtIpAddressType::V4, 200, new SecurityTxtFetcherResponse(200, [], 'top-level', true, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$method = new ReflectionMethod($fetcher, 'getResult');
		Assert::throws(function () use ($method, $fetcher, $wellKnown, $topLevel) {
			$method->invoke($fetcher, $wellKnown, $topLevel, true);
		}, SecurityTxtNotFoundException::class, "Can't read security.txt: https://foo.example/ (192.0.2.1) => response too long, https://bar.example/ (198.51.100.1) => response too long");
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
			'final URLs differing only by fragment, different response' => [$finalUrl1 . '#one', $finalUrl1 . '#two', $contents1, $contents2, new SecurityTxtTopLevelDiffers($contents1, $contents2)],
		];
	}


	/** @dataProvider getResults */
	public function testGetResultTopLevelDiffers(string $finalUrlWellKnown, string $finalUrlTopLevel, string $contentsWellKnown, string $contentsTopLevel, ?SecurityTxtTopLevelDiffers $violation): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(123, [], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$fetcherResponseWellKnown = new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], $contentsWellKnown, false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$fetcherResponseTopLevel = new SecurityTxtFetcherResponse(200, [], $contentsTopLevel, false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$wellKnown = new SecurityTxtFetcherFetchHostResult(new Url('https://url1.example/'), new Url($finalUrlWellKnown), '192.0.2.1', SecurityTxtIpAddressType::V4, 200, $fetcherResponseWellKnown);
		$topLevel = new SecurityTxtFetcherFetchHostResult(new Url('https://url2.example/'), new Url($finalUrlTopLevel), '198.51.100.1', SecurityTxtIpAddressType::V4, 200, $fetcherResponseTopLevel);
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
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(null, new SecurityTxtDnsRecords(null, null)), $this->ipAddressValidator);
		Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://example.com/'));
		}, SecurityTxtHostIpAddressNotFoundException::class);
	}


	public function testFetchOnlyIpv6Address(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(null, new SecurityTxtDnsRecords(null, '2001:cafe:f00d::1')), $this->ipAddressValidator);
		Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://example.com/'), false, true);
		}, SecurityTxtOnlyIpv6HostButIpv6DisabledException::class);

		$fetchResult = $fetcher->fetch(new Url('https://example.net/'));
		Assert::same([], $fetchResult->getErrors());
		Assert::same([], $fetchResult->getWarnings());
		Assert::same('random', $fetchResult->getContents());
		Assert::same('https://example.net/.well-known/security.txt', $fetchResult->getFinalUrl()->toUnicodeString());
		Assert::same('https://example.net/.well-known/security.txt', $fetchResult->getConstructedUrl()->toUnicodeString());
	}


	public function testFetch(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$fetchResult = $fetcher->fetch(new Url('https://com.example/'), false, true);
		Assert::same([], $fetchResult->getErrors());
		Assert::same([], $fetchResult->getWarnings());
		Assert::same('random', $fetchResult->getContents());
		Assert::same('https://com.example/.well-known/security.txt', $fetchResult->getFinalUrl()->toUnicodeString());
		Assert::same('https://com.example/.well-known/security.txt', $fetchResult->getConstructedUrl()->toUnicodeString());
		Assert::same([], array_map(fn(SecurityTxtRedirects $r): array => $r->toStrings(), $fetchResult->getRedirects()));
	}


	public function testFetchIpv6Address(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, '2001:1337:42:ec00:2468:7ea:cafe:d00d', SecurityTxtIpAddressType::V6));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$fetchResult = $fetcher->fetch(new Url('https://[2001:1337:42:ec00:2468:7ea:cafe:d00d]/'), false, false);
		Assert::same([], $fetchResult->getErrors());
		Assert::same([], $fetchResult->getWarnings());
		Assert::same('random', $fetchResult->getContents());
		Assert::same('https://[2001:1337:42:ec00:2468:7ea:cafe:d00d]/.well-known/security.txt', $fetchResult->getFinalUrl()->toUnicodeString());
		Assert::same('https://[2001:1337:42:ec00:2468:7ea:cafe:d00d]/.well-known/security.txt', $fetchResult->getConstructedUrl()->toUnicodeString());
		Assert::same([], array_map(fn(SecurityTxtRedirects $r): array => $r->toStrings(), $fetchResult->getRedirects()));
	}


	public function testFetchPortSpecified(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$fetchResult = $fetcher->fetch(new Url('https://example.com:4433/'), false, false);
		Assert::same([], $fetchResult->getErrors());
		Assert::same([], $fetchResult->getWarnings());
		Assert::same('random', $fetchResult->getContents());
		Assert::same('https://example.com:4433/.well-known/security.txt', $fetchResult->getFinalUrl()->toUnicodeString());
		Assert::same('https://example.com:4433/.well-known/security.txt', $fetchResult->getConstructedUrl()->toUnicodeString());
		Assert::same([], array_map(fn(SecurityTxtRedirects $r): array => $r->toStrings(), $fetchResult->getRedirects()));
	}


	public function testFetchPortSpecifiedIpv6Address(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, '2001:1337:42:ec00:2468:7ea:cafe:d00d', SecurityTxtIpAddressType::V6));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$fetchResult = $fetcher->fetch(new Url('https://[2001:1337:42:ec00:2468:7ea:cafe:d00d]:4433/'), false, false);
		Assert::same([], $fetchResult->getErrors());
		Assert::same([], $fetchResult->getWarnings());
		Assert::same('random', $fetchResult->getContents());
		Assert::same('https://[2001:1337:42:ec00:2468:7ea:cafe:d00d]:4433/.well-known/security.txt', $fetchResult->getFinalUrl()->toUnicodeString());
		Assert::same('https://[2001:1337:42:ec00:2468:7ea:cafe:d00d]:4433/.well-known/security.txt', $fetchResult->getConstructedUrl()->toUnicodeString());
		Assert::same([], array_map(fn(SecurityTxtRedirects $r): array => $r->toStrings(), $fetchResult->getRedirects()));
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
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$fetchResult = $fetcher->fetch(new Url('https://com.example/'), false, true);
		Assert::same([], $fetchResult->getErrors());
		Assert::same([], $fetchResult->getWarnings());
		Assert::same('random final', $fetchResult->getContents());
		Assert::same('https://location1.example/.well-known/', $fetchResult->getFinalUrl()->toUnicodeString());
		Assert::same('https://com.example/.well-known/security.txt', $fetchResult->getConstructedUrl()->toUnicodeString());
		$redirects = [
			'https://com.example/.well-known/security.txt' => ['https://location1.example/.well-known/'],
			'https://com.example/security.txt' => ['https://location1.example/'],
		];
		Assert::same($redirects, array_map(fn(SecurityTxtRedirects $r): array => $r->toStrings(), $fetchResult->getRedirects()));

		$redirects = [
			'https://com.example/.well-known/security.txt' => ['https://location2.example/.well-known/'],
			'https://com.example/security.txt' => ['https://location2.example/'],
		];
		$fetchResult = $fetcher->fetch(new Url('https://com.example/'), false, true);
		Assert::same($redirects, array_map(fn(SecurityTxtRedirects $r): array => $r->toStrings(), $fetchResult->getRedirects()));
	}


	/**
	 * Answers by URL, a 404 for anything not listed, so a test can lay out a whole redirect chain; an exception listed for a URL is thrown, the way a client reports a
	 * transfer that failed.
	 *
	 * @param array<string, SecurityTxtFetcherResponse|SecurityTxtFetcherException> $responses Keyed by the ASCII URL requested
	 * @param (Closure(string): void)|null $observe Called with the ASCII URL of every request
	 */
	private function getRoutedHttpClient(array $responses, ?Closure $observe = null): SecurityTxtFetcherHttpClient
	{
		return new class ($responses, $observe) implements SecurityTxtFetcherHttpClient {

			/**
			 * @param array<string, SecurityTxtFetcherResponse|SecurityTxtFetcherException> $responses
			 * @param (Closure(string): void)|null $observe
			 */
			public function __construct(private readonly array $responses, private readonly ?Closure $observe)
			{
			}


			#[Override]
			public function getResponse(SecurityTxtFetcherUrl $url, SecurityTxtHost $host, string $ipAddress, SecurityTxtIpAddressType $ipAddressType): SecurityTxtFetcherResponse
			{
				if ($this->observe !== null) {
					($this->observe)($url->getUrl()->toAsciiString());
				}
				$response = $this->responses[$url->getUrl()->toAsciiString()] ?? new SecurityTxtFetcherResponse(404, [], '', false, $ipAddress, $ipAddressType);
				if ($response instanceof SecurityTxtFetcherException) {
					throw $response;
				}
				return $response;
			}

		};
	}


	/**
	 * A location that fails, by a redirect loop or a transfer that does not complete, has no file there, so the file at the other location is what gets checked. Without a
	 * file anywhere the failure is what gets reported, the /.well-known/ one's first, since RFC 9116 has that location used and the top-level one only for legacy
	 * compatibility. The callback for a failure is called only when it is swallowed, a thrown one reports itself.
	 */
	public function testAFailingLocationHasNoFileThere(): void
	{
		$redirect = fn(string $location): SecurityTxtFetcherResponse => new SecurityTxtFetcherResponse(301, ['location' => $location], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$file = new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'Contact: https://example.com/', false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$wellKnown = 'https://start.example/.well-known/security.txt';
		$topLevel = 'https://start.example/security.txt';
		$cannotOpen = new SecurityTxtCannotOpenUrlException(new Url($topLevel), new SecurityTxtRedirects(), '1.1.1.0', SecurityTxtIpAddressType::V4, 'Unrecognized or bad HTTP Content or Transfer-Encoding');
		$wrongIp = new SecurityTxtConnectedToWrongIpAddressException('1.1.1.0', '1.1.1.1', new Url($topLevel), new SecurityTxtRedirects());
		$html = new SecurityTxtFetcherResponse(200, ['content-type' => 'text/html'], '<html><body>Not here</body></html>', false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$truncated = new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'Contact: https://exa', true, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$locations = [
			'a top-level redirect loop' => [[$wellKnown => $file, $topLevel => $redirect($topLevel)], false],
			'a top-level transfer that fails' => [[$wellKnown => $file, $topLevel => $cannotOpen], false],
			'a top-level connection to the wrong address' => [[$wellKnown => $file, $topLevel => $wrongIp], false],
			'a top-level redirect loop, the top-level location required' => [[$wellKnown => $file, $topLevel => $redirect($topLevel)], true],
			'a top-level redirect loop and no file at all' => [[$topLevel => $redirect($topLevel)], false],
			'a top-level redirect loop and an HTML page at /.well-known/' => [[$wellKnown => $html, $topLevel => $redirect($topLevel)], false],
			'a top-level redirect loop and a truncated file at /.well-known/' => [[$wellKnown => $truncated, $topLevel => $redirect($topLevel)], false],
			'a /.well-known/ redirect loop and the file at the top level' => [[$wellKnown => $redirect($wellKnown), $topLevel => $file], false],
			'a /.well-known/ redirect loop and nothing at the top level' => [[$wellKnown => $redirect($wellKnown)], false],
			'both locations in a redirect loop' => [[$wellKnown => $redirect($wellKnown), $topLevel => $redirect($topLevel)], false],
		];
		$reported = $messages = $failed = [];
		foreach ($locations as $name => [$responses, $requireTopLevelLocation]) {
			$fetcher = new SecurityTxtFetcher($this->getRoutedHttpClient($responses), $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
			$failed[$name] = [];
			$fetcher->addOnUrlFailed(function (SecurityTxtFetcherException $e) use (&$failed, $name): void {
				$failed[$name][] = [$e::class, $e->getUrl()?->toAsciiString()];
			});
			try {
				$result = $fetcher->fetch(new Url('https://start.example/'), $requireTopLevelLocation);
				$reported[$name] = [
					$result->getFinalUrl()->toAsciiString(),
					array_map(fn(SecurityTxtSpecViolation $violation): string => $violation::class, $result->getErrors()),
					array_map(fn(SecurityTxtSpecViolation $violation): string => $violation::class, $result->getWarnings()),
				];
				$messages[$name] = array_map(fn(SecurityTxtSpecViolation $violation): string => $violation->getMessage(), [...$result->getErrors(), ...$result->getWarnings()]);
			} catch (SecurityTxtFetcherException $e) {
				$reported[$name] = [$e::class, $e->getUrl()?->toAsciiString()];
			}
		}
		Assert::same([
			'a top-level redirect loop' => [$wellKnown, [], []],
			'a top-level transfer that fails' => [$wellKnown, [], []],
			'a top-level connection to the wrong address' => [$wellKnown, [], []],
			'a top-level redirect loop, the top-level location required' => [$wellKnown, [], [SecurityTxtWellKnownPathOnly::class]],
			'a top-level redirect loop and no file at all' => [SecurityTxtRedirectLoopException::class, $topLevel],
			'a top-level redirect loop and an HTML page at /.well-known/' => [SecurityTxtRedirectLoopException::class, $topLevel],
			'a top-level redirect loop and a truncated file at /.well-known/' => [SecurityTxtRedirectLoopException::class, $topLevel],
			'a /.well-known/ redirect loop and the file at the top level' => [$topLevel, [SecurityTxtTopLevelPathOnly::class], []],
			'a /.well-known/ redirect loop and nothing at the top level' => [SecurityTxtRedirectLoopException::class, $wellKnown],
			'both locations in a redirect loop' => [SecurityTxtRedirectLoopException::class, $wellKnown],
		], $reported);
		// The violation for a location that has no file says why, when it was a failure
		Assert::same([
			"security.txt wasn't found under the /.well-known/ path: Can't read {$wellKnown}, the redirects go in a loop (redirects: {$wellKnown} → {$wellKnown})",
		], $messages['a /.well-known/ redirect loop and the file at the top level'] ?? null);
		Assert::same([
			"security.txt not found at the top-level path: Can't read {$topLevel}, the redirects go in a loop (redirects: {$topLevel} → {$topLevel})",
		], $messages['a top-level redirect loop, the top-level location required'] ?? null);
		Assert::same([
			'a top-level redirect loop' => [[SecurityTxtRedirectLoopException::class, $topLevel]],
			'a top-level transfer that fails' => [[SecurityTxtCannotOpenUrlException::class, $topLevel]],
			'a top-level connection to the wrong address' => [[SecurityTxtConnectedToWrongIpAddressException::class, $topLevel]],
			'a top-level redirect loop, the top-level location required' => [[SecurityTxtRedirectLoopException::class, $topLevel]],
			'a top-level redirect loop and no file at all' => [],
			'a top-level redirect loop and an HTML page at /.well-known/' => [],
			'a top-level redirect loop and a truncated file at /.well-known/' => [],
			'a /.well-known/ redirect loop and the file at the top level' => [[SecurityTxtRedirectLoopException::class, $wellKnown]],
			'a /.well-known/ redirect loop and nothing at the top level' => [],
			'both locations in a redirect loop' => [],
		], $failed);
	}


	/**
	 * A firewall or a bot protection answering for /.well-known/security.txt is a different fix than a file in the wrong place, so the error says what that location answered
	 * when it was an error other than one saying there is no file there. The callback for a location without a file is told the code too.
	 */
	public function testOnlyTheTopLevelFileSaysWhatTheWellKnownLocationAnswered(): void
	{
		$file = new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'Contact: https://example.com/', false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$answers = [
			'404' => new SecurityTxtFetcherResponse(404, [], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			'410' => new SecurityTxtFetcherResponse(410, [], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			'400' => new SecurityTxtFetcherResponse(400, [], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			'403' => new SecurityTxtFetcherResponse(403, ['content-type' => 'text/html'], '<html><body>Blocked</body></html>', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			'500' => new SecurityTxtFetcherResponse(500, [], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			'an HTML page with 200' => new SecurityTxtFetcherResponse(200, ['content-type' => 'text/html'], '<html><body>Not here</body></html>', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		];
		$reported = [];
		foreach ($answers as $name => $answer) {
			$responses = ['https://start.example/.well-known/security.txt' => $answer, 'https://start.example/security.txt' => $file];
			$fetcher = new SecurityTxtFetcher($this->getRoutedHttpClient($responses), $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
			$notFound = [];
			$fetcher->addOnUrlNotFound(function (Url $url, int $httpCode) use (&$notFound): void {
				$notFound[] = "{$httpCode} {$url->toAsciiString()}";
			});
			$errors = $fetcher->fetch(new Url('https://start.example/'))->getErrors();
			$reported[$name] = [array_map(fn(SecurityTxtSpecViolation $violation): array => [$violation->getMessage(), $violation->getHowToFix()], $errors), $notFound];
		}
		$notFound = ["security.txt wasn't found under the /.well-known/ path", 'Move the security.txt file from the top-level location under the /.well-known/ path and redirect /security.txt to /.well-known/security.txt'];
		$answered = fn(int $code): array => [
			"/.well-known/security.txt answered with HTTP code {$code}, only the top-level security.txt was found",
			'Make /.well-known/security.txt available to everyone, a firewall or a bot protection may be what answers instead, and redirect /security.txt to it',
		];
		Assert::same([
			'404' => [[$notFound], ['404 https://start.example/.well-known/security.txt']],
			'410' => [[$notFound], ['410 https://start.example/.well-known/security.txt']],
			'400' => [[$answered(400)], ['400 https://start.example/.well-known/security.txt']],
			'403' => [[$answered(403)], ['403 https://start.example/.well-known/security.txt']],
			'500' => [[$answered(500)], ['500 https://start.example/.well-known/security.txt']],
			'an HTML page with 200' => [[$notFound], []],
		], $reported);
	}


	/**
	 * The final URL is where the file was read, so it decides whether the file came over HTTPS and what `Canonical` is compared with. It has to be the last hop as fetched,
	 * whatever the number of hops, and settled like every other URL a check goes to.
	 */
	public function testTheFinalUrlIsTheLastHop(): void
	{
		$redirect = fn(string $location): SecurityTxtFetcherResponse => new SecurityTxtFetcherResponse(301, ['location' => $location], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$file = new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'Contact: https://example.com/', false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$start = 'https://start.example/.well-known/security.txt';
		$chains = [
			'one redirect' => [$start => $redirect('https://one.example/a'), 'https://one.example/a' => $file],
			'two redirects' => [$start => $redirect('https://one.example/a'), 'https://one.example/a' => $redirect('https://two.example/b'), 'https://two.example/b' => $file],
			'two redirects, the second to HTTP' => [$start => $redirect('https://one.example/a'), 'https://one.example/a' => $redirect('http://two.example/b'), 'http://two.example/b' => $file],
			'a redirect to a host with an escaped capital' => [$start => $redirect('https://tw%4F.example/b'), 'https://two.example/b' => $file],
			'two redirects to a URL that is not found' => [$start => $redirect('https://one.example/a'), 'https://one.example/a' => $redirect('https://two.example/b')],
		];
		$reported = [];
		foreach ($chains as $name => $responses) {
			$fetcher = new SecurityTxtFetcher($this->getRoutedHttpClient($responses), $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
			$onFinalUrl = $onUrlNotFound = [];
			$fetcher->addOnFinalUrl(function (Url $url) use (&$onFinalUrl): void {
				$onFinalUrl[] = $url->toAsciiString();
			});
			$fetcher->addOnUrlNotFound(function (Url $url) use (&$onUrlNotFound): void {
				$onUrlNotFound[] = $url->toAsciiString();
			});
			try {
				$finalUrl = $fetcher->fetch(new Url('https://start.example/'))->getFinalUrl()->toAsciiString();
			} catch (SecurityTxtNotFoundException) {
				$finalUrl = null;
			}
			$reported[$name] = [$finalUrl, $onFinalUrl, $onUrlNotFound];
		}
		Assert::same([
			'one redirect' => ['https://one.example/a', ['https://one.example/a'], ['https://start.example/security.txt']],
			'two redirects' => ['https://two.example/b', ['https://two.example/b'], ['https://start.example/security.txt']],
			'two redirects, the second to HTTP' => ['http://two.example/b', ['http://two.example/b'], ['https://start.example/security.txt']],
			'a redirect to a host with an escaped capital' => ['https://two.example/b', ['https://two.example/b'], ['https://start.example/security.txt']],
			'two redirects to a URL that is not found' => [null, [], ['https://two.example/b', 'https://start.example/security.txt']],
		], $reported);
	}


	/**
	 * A redirect back to a URL the chain already went through can only go round, so the fetch stops there and says so, instead of making the requests the limit still allows
	 * and calling it too many. An empty `Location` and a bare fragment both point back at the URL that sent them.
	 */
	public function testARedirectLoopStopsAtTheFirstRepeat(): void
	{
		$redirect = fn(string $location): SecurityTxtFetcherResponse => new SecurityTxtFetcherResponse(301, ['location' => $location], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$file = new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'Contact: https://example.com/', false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$start = 'https://start.example/.well-known/security.txt';
		$chains = [
			'a redirect to itself' => [$start => $redirect($start)],
			'a redirect to itself with an escaped capital' => [$start => $redirect('https://st%41rt.example/.well-known/security.txt')],
			'a later hop redirecting to itself' => [$start => $redirect('https://one.example/a'), 'https://one.example/a' => $redirect('https://one.example/a')],
			'an empty Location' => [$start => $redirect('')],
			'a fragment only' => [$start => $redirect('#x')],
			'back to the start' => [$start => $redirect('https://one.example/a'), 'https://one.example/a' => $redirect('https://two.example/b'), 'https://two.example/b' => $redirect($start)],
			'between two later hops' => [
				$start => $redirect('https://one.example/a'),
				'https://one.example/a' => $redirect('https://two.example/b'),
				'https://two.example/b' => $redirect('https://one.example/a'),
			],
			'a loop longer than the limit' => [
				$start => $redirect('https://one.example/1'),
				'https://one.example/1' => $redirect('https://one.example/2'),
				'https://one.example/2' => $redirect('https://one.example/3'),
				'https://one.example/3' => $redirect('https://one.example/4'),
				'https://one.example/4' => $redirect('https://one.example/5'),
				'https://one.example/5' => $redirect('https://one.example/6'),
				'https://one.example/6' => $redirect('https://one.example/1'),
			],
			'the same path on another host' => [$start => $redirect('https://one.example/a'), 'https://one.example/a' => $redirect('https://two.example/a'), 'https://two.example/a' => $file],
			'the same path with another query' => [$start => $redirect('https://one.example/a?1'), 'https://one.example/a?1' => $redirect('https://one.example/a?2'), 'https://one.example/a?2' => $file],
			'both locations to the same URL' => [$start => $redirect('https://one.example/a'), 'https://start.example/security.txt' => $redirect('https://one.example/a'), 'https://one.example/a' => $file],
		];
		$reported = [];
		foreach ($chains as $name => $responses) {
			$requested = [];
			$client = $this->getRoutedHttpClient($responses, function (string $url) use (&$requested): void {
				$requested[] = $url;
			});
			$fetcher = new SecurityTxtFetcher($client, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
			try {
				$outcome = 'fetched ' . $fetcher->fetch(new Url('https://start.example/'))->getFinalUrl()->toAsciiString();
			} catch (SecurityTxtRedirectLoopException | SecurityTxtTooManyRedirectsException $e) {
				$outcome = $e::class . ': ' . $e->getMessage();
			}
			$reported[$name] = [$outcome, count($requested)];
		}
		$loop = SecurityTxtRedirectLoopException::class;
		Assert::same([
			'a redirect to itself' => ["{$loop}: Can't read {$start}, the redirects go in a loop (redirects: {$start} → {$start})", 2],
			'a redirect to itself with an escaped capital' => ["{$loop}: Can't read {$start}, the redirects go in a loop (redirects: {$start} → {$start})", 2],
			'a later hop redirecting to itself' => ["{$loop}: Can't read https://one.example/a, the redirects go in a loop (redirects: {$start} → https://one.example/a → https://one.example/a)", 3],
			'an empty Location' => ["{$loop}: Can't read {$start}, the redirects go in a loop (redirects: {$start} → {$start})", 2],
			'a fragment only' => ["{$loop}: Can't read {$start}, the redirects go in a loop (redirects: {$start} → {$start}#x)", 2],
			'back to the start' => ["{$loop}: Can't read https://two.example/b, the redirects go in a loop (redirects: {$start} → https://one.example/a → https://two.example/b → {$start})", 4],
			'between two later hops' => ["{$loop}: Can't read https://two.example/b, the redirects go in a loop (redirects: {$start} → https://one.example/a → https://two.example/b → https://one.example/a)", 4],
			'a loop longer than the limit' => [SecurityTxtTooManyRedirectsException::class . ": Can't read https://one.example/5, too many redirects, max allowed is 5 (redirects: {$start} → https://one.example/1 → https://one.example/2 → https://one.example/3 → https://one.example/4 → https://one.example/5 → https://one.example/6, the last one not loaded)", 7],
			'the same path on another host' => ['fetched https://two.example/a', 4],
			'the same path with another query' => ['fetched https://one.example/a?2', 4],
			'both locations to the same URL' => ['fetched https://one.example/a', 4],
		], $reported);

		// The chain is in the message, so it belongs in the structured getter too
		$fetcher = new SecurityTxtFetcher($this->getRoutedHttpClient($chains['back to the start']), $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$exception = Assert::exception(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://start.example/'));
		}, SecurityTxtRedirectLoopException::class);
		assert($exception instanceof SecurityTxtRedirectLoopException);
		Assert::same([$start, 'https://one.example/a', 'https://two.example/b', $start], $exception->getRedirects()->toStrings());

		// The hop that closes the loop is also one too many here, and it is still the loop that gets reported
		$fetcher = new SecurityTxtFetcher($this->getRoutedHttpClient($chains['between two later hops']), $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		Assert::exception(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://start.example/'), maxAllowedRedirects: 2);
		}, SecurityTxtRedirectLoopException::class);
	}


	/**
	 * A redirect sent over plain HTTP can be changed to point anywhere, so a chain that passes through one is an error even when it ends at HTTPS. A chain that ends at
	 * HTTP is the file location check's to report, and only the chain of the location whose file is used counts.
	 */
	public function testARedirectThroughHttpIsAnError(): void
	{
		$redirect = fn(string $location): SecurityTxtFetcherResponse => new SecurityTxtFetcherResponse(301, ['location' => $location], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$file = new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'Contact: https://example.com/', false, '1.1.1.0', SecurityTxtIpAddressType::V4);
		$start = 'https://start.example/.well-known/security.txt';
		$chains = [
			'HTTPS all the way' => [$start => $redirect('https://one.example/a'), 'https://one.example/a' => $file],
			'through HTTP and back to HTTPS' => [$start => $redirect('http://one.example/a'), 'http://one.example/a' => $redirect('https://two.example/b'), 'https://two.example/b' => $file],
			'through HTTP twice' => [
				$start => $redirect('http://one.example/a'),
				'http://one.example/a' => $redirect('http://two.example/b'),
				'http://two.example/b' => $redirect('https://three.example/c'),
				'https://three.example/c' => $file,
			],
			'through HTTP after an HTTPS hop' => [
				$start => $redirect('https://one.example/a'),
				'https://one.example/a' => $redirect('http://two.example/b'),
				'http://two.example/b' => $redirect('https://three.example/c'),
				'https://three.example/c' => $file,
			],
			'to HTTP, and served there' => [$start => $redirect('http://one.example/a'), 'http://one.example/a' => $file],
			'through HTTP at the top-level location, which is used' => [
				'https://start.example/security.txt' => $redirect('http://one.example/a'),
				'http://one.example/a' => $redirect('https://two.example/b'),
				'https://two.example/b' => $file,
			],
			'through HTTP at the location not used' => [
				$start => $file,
				'https://start.example/security.txt' => $redirect('http://one.example/a'),
				'http://one.example/a' => $redirect('https://start.example/.well-known/security.txt'),
			],
		];
		$reported = [];
		foreach ($chains as $name => $responses) {
			$fetcher = new SecurityTxtFetcher($this->getRoutedHttpClient($responses), $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
			$errors = $fetcher->fetch(new Url('https://start.example/'))->getErrors();
			$reported[$name] = array_map(fn(SecurityTxtSpecViolation $violation): array => [$violation::class, $violation->getMessage()], $errors);
		}
		Assert::same([
			'HTTPS all the way' => [],
			'through HTTP and back to HTTPS' => [[SecurityTxtRedirectNotHttps::class, 'The redirects from https://start.example/.well-known/security.txt go through http://one.example/a, which does not use HTTPS']],
			'through HTTP twice' => [[SecurityTxtRedirectNotHttps::class, 'The redirects from https://start.example/.well-known/security.txt go through http://one.example/a, which does not use HTTPS']],
			'through HTTP after an HTTPS hop' => [[SecurityTxtRedirectNotHttps::class, 'The redirects from https://start.example/.well-known/security.txt go through http://two.example/b, which does not use HTTPS']],
			'to HTTP, and served there' => [],
			'through HTTP at the top-level location, which is used' => [
				[SecurityTxtTopLevelPathOnly::class, "security.txt wasn't found under the /.well-known/ path"],
				[SecurityTxtRedirectNotHttps::class, 'The redirects from https://start.example/security.txt go through http://one.example/a, which does not use HTTPS'],
			],
			'through HTTP at the location not used' => [],
		], $reported);
	}


	/**
	 * The header a content type violation reports came from the response, and after a redirect that response is at the final URL, not the one the check was built from. Naming
	 * the constructed one puts a URL in the message that never sent the header, one line under the callback that says where the file was actually read.
	 */
	public function testAContentTypeIsReportedAtTheUrlThatSentIt(): void
	{
		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(301, ['location' => 'https://cdn.example/securitytxt'], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(200, ['content-type' => 'text/html'], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$fetchResult = $fetcher->fetch(new Url('https://com.example/'), false, true);
		Assert::same('https://cdn.example/securitytxt', $fetchResult->getFinalUrl()->toUnicodeString());
		Assert::contains('https://cdn.example/securitytxt', $fetchResult->getErrors()[0]->getMessage());
	}


	public function testFetchWrongCharset(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => 'text/plain; charset=utf-42'], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$fetchResult = $fetcher->fetch(new Url('https://com.example/'), false, true);
		$expectedError = new SecurityTxtContentTypeWrongCharset(new Url('https://com.example/.well-known/security.txt'), 'text/plain', 'charset=utf-42');
		Assert::equal([$expectedError], $fetchResult->getErrors());
		Assert::same([], $fetchResult->getWarnings());
		Assert::same('random', $fetchResult->getContents());
		Assert::same('https://com.example/.well-known/security.txt', $fetchResult->getFinalUrl()->toUnicodeString());
		Assert::same('https://com.example/.well-known/security.txt', $fetchResult->getConstructedUrl()->toUnicodeString());
		Assert::same([], array_map(fn(SecurityTxtRedirects $r): array => $r->toStrings(), $fetchResult->getRedirects()));
	}


	public function testFetchNotFound(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(404, ['content-type' => 'text/plain; charset=utf-42'], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$exception = Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://com.example/'));
		}, SecurityTxtNotFoundException::class, "Can't read security.txt: https://com.example/.well-known/security.txt (1.1.1.0) => 404, https://com.example/security.txt (1.1.1.0) => 404");
		assert($exception instanceof SecurityTxtNotFoundException);
		Assert::same(['1.1.1.0' => [SecurityTxtIpAddressType::V4, 404]], $exception->getIpAddresses());
		Assert::same([], $exception->getAllRedirects());
	}


	/**
	 * The same shape over IPv6, because the V4 one cannot tell the address family being carried from `SecurityTxtUrlNotFoundException` through to here from a constant: with
	 * only that test, replacing the carry with a hardcoded `V4` left the suite green, so every 404'd IPv6 host could be reported as IPv4.
	 */
	public function testFetchNotFoundIpv6(): void
	{
		$ipAddress = '2001:1337:42:ec00:2468:7ea:cafe:d00d';
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(404, ['content-type' => 'text/plain; charset=utf-42'], 'random', false, $ipAddress, SecurityTxtIpAddressType::V6));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$exception = Assert::throws(function () use ($fetcher, $ipAddress): void {
			$fetcher->fetch(new Url("https://[{$ipAddress}]/"), false, false);
		}, SecurityTxtNotFoundException::class, "Can't read security.txt: https://[{$ipAddress}]/.well-known/security.txt ({$ipAddress}) => 404, https://[{$ipAddress}]/security.txt ({$ipAddress}) => 404");
		assert($exception instanceof SecurityTxtNotFoundException);
		Assert::same([$ipAddress => [SecurityTxtIpAddressType::V6, 404]], $exception->getIpAddresses());
	}


	/**
	 * @return array<string, array{0:int}>
	 */
	public function getSuccessfulCodes(): array
	{
		// Everything `getResponse()` lets through: it throws above 400 and follows a redirect above 300, so any other 2xx arrives here as an ordinary success
		return [
			'200 OK' => [200],
			'203 Non-Authoritative Information' => [203],
			'206 Partial Content' => [206],
		];
	}


	/**
	 * The code recorded for a host is the one it answered with. It used to be a hardcoded `200` on the success path, so a 203 or a 206 was reported as a 200 in
	 * `getIpAddresses()` and in the serialized params, and `isRegularHtmlPage` keyed on `httpCode === 200`, which that hardcode made permanently true.
	 *
	 * @dataProvider getSuccessfulCodes
	 */
	public function testFetchRecordsTheCodeItWasServed(int $code): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse($code, ['content-type' => 'text/html'], '<html><body>nope</body></html>', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$exception = Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://com.example/'));
		}, SecurityTxtNotFoundException::class);
		assert($exception instanceof SecurityTxtNotFoundException);
		Assert::same(['1.1.1.0' => [SecurityTxtIpAddressType::V4, $code]], $exception->getIpAddresses());
		// An HTML page is one whichever 2xx carried it, so the code moving does not change what the bytes are taken for
		Assert::contains('regular HTML page', $exception->getMessage());
	}


	/**
	 * The other half: a body that is not an HTML page is parsed whatever 2xx carried it, so keying the HTML test on the code cannot be replaced by keying the parse on it.
	 *
	 * @dataProvider getSuccessfulCodes
	 */
	public function testFetchParsesANonHtmlBodyWhateverTheCode(int $code): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse($code, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'Contact: https://example.com/contact', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$fetchResult = $fetcher->fetch(new Url('https://com.example/'));
		Assert::same('Contact: https://example.com/contact', $fetchResult->getContents());
	}


	/**
	 * @return array<string, array{0:string, 1:string, 2:string}>
	 */
	public function getUrlsToNormalize(): array
	{
		return [
			'percent escape uncovering a capital' => ['https://ex%41mple.com/', 'example.com', 'https://example.com/.well-known/security.txt'],
			'capitals in the host' => ['https://EXAMPLE.com/', 'example.com', 'https://example.com/.well-known/security.txt'],
			'readable internationalized' => ["https://h\u{E1}\u{10D}ky.example/", 'xn--hky-ela4t.example', 'https://xn--hky-ela4t.example/.well-known/security.txt'],
			'punycode in capitals' => ['https://XN--HKY-ELA4T.example/', 'xn--hky-ela4t.example', 'https://xn--hky-ela4t.example/.well-known/security.txt'],
			'already settled' => ['https://example.com/', 'example.com', 'https://example.com/.well-known/security.txt'],
			'a port, which is authority but not host' => ['https://ex%41mple.com:8443/', 'example.com', 'https://example.com:8443/.well-known/security.txt'],
			'an escape uncovering a punycode prefix' => ['https://%78%6E--%78%6E--.example/', 'xn-.example', 'https://xn-.example/.well-known/security.txt'],
			'http, which the fetcher forces to https' => ['http://ex%41mple.com/', 'example.com', 'https://example.com/.well-known/security.txt'],
			'credentials, query and fragment, all dropped' => ['https://user:pass@ex%41mple.com/p?q=1#f', 'example.com', 'https://example.com/.well-known/security.txt'],
		];
	}


	/**
	 * The invariant the `CURLOPT_RESOLVE` pin rests on: the host keying it has to be the one curl reads out of the URL it is handed, or curl finds no entry and resolves the
	 * name itself, reaching an address this library never validated. Deriving both from one normalized URL is what makes that structural rather than a coincidence.
	 *
	 * @dataProvider getUrlsToNormalize
	 */
	public function testTheFetchedUrlAndThePinnedHostAgree(string $url, string $expectedHost, string $expectedWellKnownUrl): void
	{
		$seen = [];
		$client = $this->getObservingHttpClient(function (string $url, string $host) use (&$seen): void {
			$seen[] = ['url' => $url, 'host' => $host];
		});
		$fetcher = new SecurityTxtFetcher($client, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		Assert::exception(function () use ($fetcher, $url): void {
			$fetcher->fetch(new Url($url));
		}, SecurityTxtNotFoundException::class);
		$first = $seen[0] ?? null;
		Assert::notSame(null, $first);
		assert($first !== null);
		// The request goes to the settled URL, and the host it is pinned by is that URL's host
		Assert::same($expectedWellKnownUrl, $first['url']);
		Assert::same($expectedHost, $first['host']);
		foreach ($seen as $one) {
			// The host as curl reads it, a raw substring of the URL string, not reparsed: reparsing would re-apply the settling under test
			preg_match('~^https://([^/?#]+)~', $one['url'], $matches);
			$authority = $matches[1] ?? null;
			Assert::type('string', $authority);
			assert(is_string($authority));
			// The authority is not the host: strip any userinfo and any port, or a URL carrying either fails an invariant that is about neither
			$at = strrpos($authority, '@');
			$curlReads = $at === false ? $authority : substr($authority, $at + 1);
			$colon = strrpos($curlReads, ':');
			if ($colon !== false && !str_contains(substr($curlReads, $colon), ']')) {
				$curlReads = substr($curlReads, 0, $colon);
			}
			// Identical, not merely equal ignoring case: curl would match a case difference, but after settling there is no case difference left to allow for, and allowing
			// for one would let a settling that only folded case pass as though it had settled the host
			Assert::same($one['host'], $curlReads);
			Assert::same($expectedHost, $one['host']);
		}
	}


	/**
	 * Records what each request was actually given: the URL string a client would hand to curl, and the host that keys the pin.
	 *
	 * @param Closure(string, string): void $observe
	 */
	private function getObservingHttpClient(Closure $observe): SecurityTxtFetcherHttpClient
	{
		return new class ($observe) implements SecurityTxtFetcherHttpClient {

			/**
			 * @param Closure(string, string): void $observe
			 */
			public function __construct(private readonly Closure $observe)
			{
			}


			#[Override]
			public function getResponse(SecurityTxtFetcherUrl $url, SecurityTxtHost $host, string $ipAddress, SecurityTxtIpAddressType $ipAddressType): SecurityTxtFetcherResponse
			{
				($this->observe)($url->getUrl()->toAsciiString(), $host->getAscii());
				return new SecurityTxtFetcherResponse(404, [], '', false, $ipAddress, $ipAddressType);
			}

		};
	}


	/**
	 * A redirect names the next host, and it is the checked host that names it, so it is settled exactly like the URL a check starts from. Otherwise a `Location:` reaching a
	 * host one way and a caller typing the same host another way would be two different checks of one host.
	 */
	public function testARedirectedUrlIsSettledToo(): void
	{
		$seen = [];
		$client = $this->getObservingHttpClient(function (string $url, string $host) use (&$seen): void {
			$seen[] = ['url' => $url, 'host' => $host];
		});
		$httpClient = new class ($client) implements SecurityTxtFetcherHttpClient {

			private int $requests = 0;


			public function __construct(private readonly SecurityTxtFetcherHttpClient $inner)
			{
			}


			#[Override]
			public function getResponse(SecurityTxtFetcherUrl $url, SecurityTxtHost $host, string $ipAddress, SecurityTxtIpAddressType $ipAddressType): SecurityTxtFetcherResponse
			{
				$this->inner->getResponse($url, $host, $ipAddress, $ipAddressType);
				return $this->requests++ === 0
					? new SecurityTxtFetcherResponse(301, ['location' => 'https://ex%41mple.com/redirected'], '', false, $ipAddress, $ipAddressType)
					: new SecurityTxtFetcherResponse(404, [], '', false, $ipAddress, $ipAddressType);
			}

		};
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		Assert::exception(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://start.example/'));
		}, SecurityTxtNotFoundException::class);
		$redirected = $seen[1] ?? null;
		Assert::notSame(null, $redirected);
		assert($redirected !== null);
		// Not `exAmple.com`, which is what the escape decodes to before a second parse folds the case it uncovered
		Assert::same('https://example.com/redirected', $redirected['url']);
		Assert::same('example.com', $redirected['host']);
	}


	/**
	 * Settling folds the case an escape uncovered and nothing else. A redirect to `http://` is still followed to `http://`, which the fetcher allows and reports as a file
	 * location that is not https, so settling must not quietly promote it.
	 */
	public function testSettlingARedirectLeavesItsSchemeAlone(): void
	{
		$seen = [];
		$client = $this->getObservingHttpClient(function (string $url, string $host) use (&$seen): void {
			$seen[] = ['url' => $url, 'host' => $host];
		});
		$httpClient = new class ($client) implements SecurityTxtFetcherHttpClient {

			private int $requests = 0;


			public function __construct(private readonly SecurityTxtFetcherHttpClient $inner)
			{
			}


			#[Override]
			public function getResponse(SecurityTxtFetcherUrl $url, SecurityTxtHost $host, string $ipAddress, SecurityTxtIpAddressType $ipAddressType): SecurityTxtFetcherResponse
			{
				$this->inner->getResponse($url, $host, $ipAddress, $ipAddressType);
				return $this->requests++ === 0
					? new SecurityTxtFetcherResponse(301, ['location' => 'http://ex%41mple.com/redirected'], '', false, $ipAddress, $ipAddressType)
					: new SecurityTxtFetcherResponse(404, [], '', false, $ipAddress, $ipAddressType);
			}

		};
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		Assert::exception(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://start.example/'));
		}, SecurityTxtNotFoundException::class);
		$redirected = $seen[1] ?? null;
		Assert::notSame(null, $redirected);
		assert($redirected !== null);
		Assert::same('http://example.com/redirected', $redirected['url']);
	}


	/**
	 * A `Location` the fetcher will not follow still says where the host sent us, and the exception saying so can be stored and read back. A redirect is settled before its
	 * scheme is refused, so an unsupported one is named the way this library writes a URL: refused unsettled, `ftp://ex%41mple.com/` was stored as `ftp://exAmple.com/`,
	 * which reading it back refuses. A host that will not settle is a hostname error, and it carries the chain as well.
	 */
	public function testARefusedRedirectStillReportsWhereItPointed(): void
	{
		$json = new SecurityTxtJson($this->splitLines);
		$start = 'https://start.example/.well-known/security.txt';
		$next = 'https://start.example/next';
		$locations = [
			'an unsupported scheme with an escape in the host' => 'ftp://ex%41mple.com/',
			'an unsupported scheme with a host that will not settle' => 'ftp://%78n--a.example/',
			'a host that will not settle' => 'https://%78n--a.example/',
			'a URL that will not parse' => 'ws://',
		];
		$refused = [];
		foreach ($locations as $name => $location) {
			// A hop before the refused one, so the chain has a redirect to carry even where the refused one never becomes a URL to add to it
			$httpClient = $this->getRoutedHttpClient([
				$start => new SecurityTxtFetcherResponse(301, ['location' => $next], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
				$next => new SecurityTxtFetcherResponse(301, ['location' => $location], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			]);
			$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
			try {
				$fetcher->fetch(new Url('https://start.example/'));
				$refused[$name] = 'not refused';
			} catch (SecurityTxtFetcherException $e) {
				$encoded = json_encode(['error' => $e]);
				assert(is_string($encoded));
				$decoded = json_decode($encoded, true);
				assert(is_array($decoded));
				$refused[$name] = [$e::class, $e->getMessage(), $json->createFetcherExceptionFromJsonValues($decoded)->getMessage()];
			}
		}
		$chain = fn(string ...$redirects): string => ' (redirects: ' . implode(' → ', [$start, $next, ...$redirects]) . ')';
		Assert::same([
			'an unsupported scheme with an escape in the host' => [
				SecurityTxtUrlUnsupportedSchemeException::class,
				'URL ftp://example.com/ has an unsupported scheme' . $chain('ftp://example.com/'),
				'URL ftp://example.com/ has an unsupported scheme' . $chain('ftp://example.com/'),
			],
			'an unsupported scheme with a host that will not settle' => [
				SecurityTxtCannotParseHostnameException::class,
				"Can't parse hostname from ftp://xn--a.example/" . $chain('ftp://xn--a.example/'),
				"Can't parse hostname from ftp://xn--a.example/" . $chain('ftp://xn--a.example/'),
			],
			'a host that will not settle' => [
				SecurityTxtCannotParseHostnameException::class,
				"Can't parse hostname from https://xn--a.example/" . $chain('https://xn--a.example/'),
				"Can't parse hostname from https://xn--a.example/" . $chain('https://xn--a.example/'),
			],
			'a URL that will not parse' => [
				SecurityTxtCannotParseHostnameException::class,
				"Can't parse hostname from ws://" . $chain(),
				"Can't parse hostname from ws://" . $chain(),
			],
		], $refused);
	}


	/**
	 * The header is measured before it is parsed, a character that may be percent-encoded as three and a relative one with the path it is resolved against, and the URL is
	 * refused before it is requested or handed to a callback. Before PHP 8.5.8 the last rows are where process memory would have gone, and `.` and `..` segments can cut it
	 * short of any length checked after parsing.
	 */
	public function testARedirectToALongUrlIsNotFollowed(): void
	{
		$locations = [
			'a path of 1000 characters' => '/' . str_repeat('a', 999),
			'a path of 1001 characters' => '/' . str_repeat('a', 1000),
			'a path starting with a backslash counted as 1000 characters, the backslash as three' => '\\' . str_repeat('a', 997),
			'a path and a query counted as 1000 characters, the question mark as three' => '/s?' . str_repeat('a', 995),
			'a path and a query counted as 1001 characters' => '/s?' . str_repeat('a', 996),
			'a relative path of 1000 characters with the base path' => str_repeat('a', 975),
			'a relative path of 1001 characters with the base path' => str_repeat('a', 976),
			'a path of 1000 characters once percent-encoded' => '/' . str_repeat('{', 333),
			'a path of 1003 characters once percent-encoded' => '/' . str_repeat('{', 334),
			'another host with a path of 1001 characters' => 'https://other.example/' . str_repeat('a', 1000),
			'an unsupported scheme with a path of 1001 characters' => 'ftp://other.example/' . str_repeat('a', 1000),
			'dot segments cutting a path back' => '/b/' . str_repeat('a', 1017) . '{' . str_repeat('/..', 333) . '/x',
			'a long fragment after a dot segment' => '/a/.#' . str_repeat('b', 1100),
			'a path PHP before 8.5.8 fills with process memory' => '/' . str_repeat('a', 1022) . '{',
		];
		$requested = [];
		foreach ($locations as $name => $location) {
			$paths = [];
			$httpClient = new class ($location, function (string $url) use (&$paths): void {
				$paths[] = strlen(new Url($url)->getPath());
			}) implements SecurityTxtFetcherHttpClient {

				private int $requests = 0;


				/**
				 * @param Closure(string): void $observe
				 */
				public function __construct(private readonly string $location, private readonly Closure $observe)
				{
				}


				#[Override]
				public function getResponse(SecurityTxtFetcherUrl $url, SecurityTxtHost $host, string $ipAddress, SecurityTxtIpAddressType $ipAddressType): SecurityTxtFetcherResponse
				{
					($this->observe)($url->getUrl()->toAsciiString());
					return $this->requests++ === 0
						? new SecurityTxtFetcherResponse(301, ['location' => $this->location], '', false, $ipAddress, $ipAddressType)
						: new SecurityTxtFetcherResponse(404, [], '', false, $ipAddress, $ipAddressType);
				}

			};
			$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
			$redirected = [];
			$fetcher->addOnRedirect(function (Url $url, Url $destination) use (&$redirected): void {
				$redirected[] = strlen($destination->getPath());
			});
			$exception = Assert::throws(function () use ($fetcher): void {
				$fetcher->fetch(new Url('https://start.example/'));
			}, SecurityTxtFetcherException::class);
			assert($exception instanceof SecurityTxtFetcherException);
			$requested[$name] = [$exception::class, $paths, $redirected];
		}
		Assert::same([
			'a path of 1000 characters' => [SecurityTxtNotFoundException::class, [25, 1000, 13], [1000]],
			'a path of 1001 characters' => [SecurityTxtRedirectUrlTooLongException::class, [25, 13], []],
			'a path starting with a backslash counted as 1000 characters, the backslash as three' => [SecurityTxtNotFoundException::class, [25, 998, 13], [998]],
			'a path and a query counted as 1000 characters, the question mark as three' => [SecurityTxtNotFoundException::class, [25, 2, 13], [2]],
			'a path and a query counted as 1001 characters' => [SecurityTxtRedirectUrlTooLongException::class, [25, 13], []],
			'a relative path of 1000 characters with the base path' => [SecurityTxtNotFoundException::class, [25, 988, 13], [988]],
			'a relative path of 1001 characters with the base path' => [SecurityTxtRedirectUrlTooLongException::class, [25, 13], []],
			'a path of 1000 characters once percent-encoded' => [SecurityTxtNotFoundException::class, [25, 1000, 13], [1000]],
			'a path of 1003 characters once percent-encoded' => [SecurityTxtRedirectUrlTooLongException::class, [25, 13], []],
			'another host with a path of 1001 characters' => [SecurityTxtRedirectUrlTooLongException::class, [25, 13], []],
			'an unsupported scheme with a path of 1001 characters' => [SecurityTxtRedirectUrlTooLongException::class, [25, 13], []],
			'dot segments cutting a path back' => [SecurityTxtRedirectUrlTooLongException::class, [25, 13], []],
			'a long fragment after a dot segment' => [SecurityTxtRedirectUrlTooLongException::class, [25, 13], []],
			'a path PHP before 8.5.8 fills with process memory' => [SecurityTxtRedirectUrlTooLongException::class, [25, 13], []],
		], $requested);
	}


	public function testARedirectToALongUrlAfterAnotherNamesTheChain(): void
	{
		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(301, ['location' => '/one/security.txt'], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(301, ['location' => '/' . str_repeat('a', 1000)], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$exception = Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://start.example/'));
		}, SecurityTxtRedirectUrlTooLongException::class);
		assert($exception instanceof SecurityTxtRedirectUrlTooLongException);
		Assert::same(
			"Can't read https://start.example/one/security.txt, it redirects to a URL longer than 1000 characters (redirects: https://start.example/.well-known/security.txt → https://start.example/one/security.txt)",
			$exception->getMessage(),
		);
		Assert::same('https://start.example/one/security.txt', $exception->getUrl()?->toAsciiString());
		Assert::same(['https://start.example/.well-known/security.txt', 'https://start.example/one/security.txt'], $exception->getRedirects()->toStrings());
	}


	public function testFetchCallbacks(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$onUrl = $onFinalUrl = null;
		$fetcher->addOnUrl(function (Url $url) use (&$onUrl): void {
			$onUrl = $url->toUnicodeString();
		});
		$fetcher->addOnFinalUrl(function (Url $url) use (&$onFinalUrl): void {
			$onFinalUrl = $url->toUnicodeString();
		});
		$fetcher->fetch(new Url('https://com.example/'));
		Assert::same('https://com.example/security.txt', $onUrl);
		Assert::same('https://com.example/.well-known/security.txt', $onFinalUrl);

		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(301, ['location' => 'https://location.example/'], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator, 0);
		$onRedirects = [];
		$fetcher->addOnRedirect(function (Url $url, Url $destination) use (&$onRedirects): void {
			$onRedirects[] = "{$url->toUnicodeString()} -> {$destination->toUnicodeString()}";
		});
		Assert::throws(function () use (&$fetcher): void {
			$fetcher->fetch(new Url('https://com.example/'));
		}, SecurityTxtTooManyRedirectsException::class);
		// The top-level location is tried after the /.well-known/ one fails, and the /.well-known/ failure is the one reported
		Assert::same([
			'https://com.example/.well-known/security.txt -> https://location.example/',
			'https://com.example/security.txt -> https://location.example/',
		], $onRedirects);

		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(301, ['location' => '/one/security.txt'], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(301, ['location' => '/two/security.txt'], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(404, [], 'nah', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator, 1);
		$onRedirects = [];
		$fetcher->addOnRedirect(function (Url $url, Url $destination) use (&$onRedirects): void {
			$onRedirects[] = "{$url->toUnicodeString()} -> {$destination->toUnicodeString()}";
		});
		$exception = Assert::throws(function () use (&$fetcher): void {
			$fetcher->fetch(new Url('https://com.example/'));
		}, SecurityTxtTooManyRedirectsException::class);
		assert($exception instanceof SecurityTxtTooManyRedirectsException);
		// Both the callback and the chain say where the fetcher went, so a relative `Location` is resolved rather than recorded as the host wrote it
		Assert::same([
			'https://com.example/.well-known/security.txt -> https://com.example/one/security.txt',
			'https://com.example/one/security.txt -> https://com.example/two/security.txt',
		], $onRedirects);
		// The chain starts where the check started, like the chain any other exception carries
		Assert::same(['https://com.example/.well-known/security.txt', 'https://com.example/one/security.txt', 'https://com.example/two/security.txt'], $exception->getRedirects()->toStrings());

		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(404, [], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator, 0);
		$onUrlNotFound = null;
		$fetcher->addOnUrlNotFound(function (Url $url) use (&$onUrlNotFound): void {
			$onUrlNotFound = $url->toUnicodeString();
		});
		Assert::throws(function () use (&$fetcher): void {
			$fetcher->fetch(new Url('https://com.example/'));
		}, SecurityTxtNotFoundException::class);
		Assert::same('https://com.example/security.txt', $onUrlNotFound);
	}


	public function testFetchUnsupportedScheme(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, [], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);

		$method = new ReflectionMethod($fetcher, 'fetchUrl');
		Assert::throws(function () use ($method, $fetcher): void {
			$method->invoke($fetcher, new Url('file://foo/bar'), new SecurityTxtHost(new Url('https://foo/')), false, null);
		}, SecurityTxtUrlUnsupportedSchemeException::class, 'URL file://foo/bar has an unsupported scheme');
	}


	public function testFetchUnsupportedSchemeRedirect(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(301, ['location' => 'file:///etc/passwd'], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(
			null,
			new SecurityTxtDnsRecords('1.1.1.0', null),
			new SecurityTxtDnsRecords(null, null),
		), $this->ipAddressValidator);
		$method = new ReflectionMethod($fetcher, 'fetchUrl');
		Assert::throws(function () use ($method, $fetcher): void {
			$method->invoke($fetcher, new Url('https://foo/bar'), new SecurityTxtHost(new Url('https://foo/')), false, null);
		}, SecurityTxtUrlUnsupportedSchemeException::class, 'URL file:///etc/passwd has an unsupported scheme (redirects: https://foo/bar → file:///etc/passwd)');
	}


	public function testCheckMaxAllowedRedirects(): void
	{
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, [], 'random', false, '1.1.1.0', SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		Assert::noError(function () use ($httpClient): void {
			new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator, null);
		});

		Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://example.com'), maxAllowedRedirects: -2); // @phpstan-ignore argument.type (Testing $maxAllowedRedirects validation)
		}, LogicException::class, 'maxAllowedRedirects must be greater than or equal to 0 (0 means no redirects allowed)');

		Assert::throws(function () use ($httpClient): void {
			new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator, -1); // @phpstan-ignore argument.type (Testing $maxAllowedRedirects validation)
		}, LogicException::class, 'maxAllowedRedirects must be greater than or equal to 0 (0 means no redirects allowed)');

		$httpClient = $this->getHttpClient(
			new SecurityTxtFetcherResponse(301, ['location' => 'https://redir.example/'], 'random redir', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			new SecurityTxtFetcherResponse(404, [], 'nah', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		);
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator, 5);
		Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://example.com'), maxAllowedRedirects: 0);
		}, SecurityTxtTooManyRedirectsException::class, "Can't read https://example.com/.well-known/security.txt, too many redirects, max allowed is 0 (redirects: https://example.com/.well-known/security.txt → https://redir.example/, the last one not loaded)");
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
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $dnsProvider, $this->ipAddressValidator);
		Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://example.com/'));
		}, SecurityTxtHostIpAddressNotPublicException::class, 'Host example.net resolves to a non-public IP address 127.0.0.1 (redirects: https://example.com/.well-known/security.txt → https://example.net/foo)');
	}


	/**
	 * A redirect is how a check reaches a host the caller never named, a missing slash turning `https://example.cz/.well-known/` into the host `example.cz.well-known` for
	 * one, so whatever goes wrong with that host is reported with the chain that led to it. The DNS provider is asked about one URL and is not told the chain.
	 */
	public function testAHostReachedByRedirectNamesTheChain(): void
	{
		$hosts = [
			'a host that does not resolve' => [null, false],
			'a host with no address' => [new SecurityTxtDnsRecords(null, null), false],
			'a host with only an IPv6 address, IPv6 disabled' => [new SecurityTxtDnsRecords(null, '2001:db8::1'), true],
			'a host with an invalid address' => [new SecurityTxtDnsRecords(null, '1.2.3.4'), false],
			'a host with a non-public address' => [new SecurityTxtDnsRecords('127.0.0.1', null), false],
			'a host with a NAT64 address of a non-public one' => [new SecurityTxtDnsRecords(null, '64:ff9b::7f00:1'), false],
			'a host with a NAT64 local-use address' => [new SecurityTxtDnsRecords(null, '64:ff9b:1::a9fe:a9fe'), false],
		];
		$reported = [];
		foreach ($hosts as $name => [$records, $noIpv6]) {
			$httpClient = $this->getRoutedHttpClient([
				'https://start.example/.well-known/security.txt' => new SecurityTxtFetcherResponse(301, ['location' => 'https://elsewhere.example.well-known/security.txt'], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			]);
			$dnsProvider = new class ($records) implements SecurityTxtDnsProvider {

				public function __construct(private readonly ?SecurityTxtDnsRecords $records)
				{
				}


				#[Override]
				public function getRecords(Url $url, SecurityTxtHost $host): SecurityTxtDnsRecords
				{
					if ($host->getAscii() === 'start.example') {
						return new SecurityTxtDnsRecords('1.1.1.0', null);
					}
					return $this->records ?? throw new SecurityTxtHostNotFoundException($url, $host);
				}

			};
			$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $dnsProvider, $this->ipAddressValidator);
			$exception = Assert::throws(function () use ($fetcher, $noIpv6): void {
				$fetcher->fetch(new Url('https://start.example/'), noIpv6: $noIpv6);
			}, SecurityTxtFetcherException::class);
			assert($exception instanceof SecurityTxtFetcherException);
			$reported[$name] = [$exception::class, $exception->getRedirects()->toStrings(), $exception->getPrevious() === null ? null : $exception->getPrevious()::class];
		}
		$chain = ['https://start.example/.well-known/security.txt', 'https://elsewhere.example.well-known/security.txt'];
		Assert::same([
			// The provider's own exception is kept as the previous one
			'a host that does not resolve' => [SecurityTxtHostNotFoundException::class, $chain, SecurityTxtHostNotFoundException::class],
			'a host with no address' => [SecurityTxtHostIpAddressNotFoundException::class, $chain, null],
			'a host with only an IPv6 address, IPv6 disabled' => [SecurityTxtOnlyIpv6HostButIpv6DisabledException::class, $chain, null],
			'a host with an invalid address' => [SecurityTxtHostIpAddressInvalidException::class, $chain, null],
			'a host with a non-public address' => [SecurityTxtHostIpAddressNotPublicException::class, $chain, null],
			'a host with a NAT64 address of a non-public one' => [SecurityTxtHostIpAddressNotPublicException::class, $chain, null],
			'a host with a NAT64 local-use address' => [SecurityTxtHostIpAddressNotPublicException::class, $chain, null],
		], $reported);
	}


	public function testARedirectWithoutLocationNamesTheChain(): void
	{
		$httpClient = $this->getRoutedHttpClient([
			'https://start.example/.well-known/security.txt' => new SecurityTxtFetcherResponse(301, ['location' => 'https://one.example/a'], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
			'https://one.example/a' => new SecurityTxtFetcherResponse(302, [], '', false, '1.1.1.0', SecurityTxtIpAddressType::V4),
		]);
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(), $this->ipAddressValidator);
		$exception = Assert::throws(function () use ($fetcher): void {
			$fetcher->fetch(new Url('https://start.example/'));
		}, SecurityTxtNoLocationHeaderException::class, 'HTTP response with code 302 is missing a Location header when fetching https://one.example/a (redirects: https://start.example/.well-known/security.txt → https://one.example/a)');
		assert($exception instanceof SecurityTxtNoLocationHeaderException);
		Assert::same(['https://start.example/.well-known/security.txt', 'https://one.example/a'], $exception->getRedirects()->toStrings());
	}


	public function testFetchIpAddressNoDnsLookup(): void
	{
		$ipAddress = '1.1.1.0';
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, $ipAddress, SecurityTxtIpAddressType::V4));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(new LogicException('Resolver should not be called for IPv4 addresses')), $this->ipAddressValidator);
		$result = null;
		Assert::noError(function () use (&$result, $fetcher, $ipAddress): void {
			$result = (new ReflectionMethod($fetcher, 'fetchUrl'))->invoke($fetcher, new Url("https://{$ipAddress}/"), new SecurityTxtHost(new Url("https://{$ipAddress}/")), false, null);
		});
		assert($result instanceof SecurityTxtFetcherFetchHostResult);
		Assert::same($ipAddress, $result->getIpAddress());
	}


	public function testFetchIpv6AddressNoDnsLookup(): void
	{
		$ipv6Address = '2001:db42::1';
		$httpClient = $this->getHttpClient(new SecurityTxtFetcherResponse(200, ['content-type' => SecurityTxtContentType::MEDIA_TYPE], 'random', false, $ipv6Address, SecurityTxtIpAddressType::V6));
		$fetcher = new SecurityTxtFetcher($httpClient, $this->urlParser, $this->splitLines, $this->getDnsProvider(new LogicException('Resolver should not be called for IPv6 addresses')), $this->ipAddressValidator);
		$result = null;
		Assert::noError(function () use (&$result, $fetcher, $ipv6Address): void {
			$result = (new ReflectionMethod($fetcher, 'fetchUrl'))->invoke($fetcher, new Url("https://[{$ipv6Address}]/"), new SecurityTxtHost(new Url("https://[{$ipv6Address}]/")), false, null);
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
			public function getRecords(Url $url, SecurityTxtHost $host): SecurityTxtDnsRecords
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
